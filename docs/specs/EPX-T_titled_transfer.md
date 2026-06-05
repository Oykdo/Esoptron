# EPX-T — Titled Transfer: anti-duplication artifacts, vault to vault

| Field           | Value                                               |
| --------------- | --------------------------------------------------- |
| Identifier      | EPX-T                                               |
| Status          | Draft                                               |
| Version         | 1                                                   |
| Date            | 2026-05-30                                          |
| Author          | Jérémy ZGONEC                                        |
| Layer           | `eopx.transfer` (new) + `eopx.server` (anchor)      |
| Wire compat     | Additive — extends `.eopx`, reuses the anchor ledger |
| Dependencies    | ML-DSA-87, ML-KEM-1024, SHA3, the anchor authority   |

> Naming note: the vault-protocol letters A–G are taken, and `EPX-H` already
> identifies the *Seal Revealed* rendering. This transfer protocol is the 8th
> sibling of Protocols A–G but is identified **EPX-T** (Transfer) to avoid the
> `EPX-H` clash.

## Abstract

EPX-T defines how to create a **titled artifact** — a transferable object whose
control can move from one vault to another **without duplication**. Control is
bound to a per-artifact **controller key** whose current public commitment is
recorded, per `artifact_id`, in a monotonic **anchor ledger**. A transfer is a
**forward-secure re-key**: the recipient generates a fresh controller key the
sender never learns, the sender signs the hand-off with the *current* controller
key, the confidential content is re-sealed to the recipient's ML-KEM key (the
"recovery" delivery step), and the anchor atomically advances the artifact's
sequence — **voiding the sender's key**. The first transfer to anchor wins;
every later or concurrent attempt is rejected.

## 1. The constraint EPX-T is built around

> **Theorem (double-spend).** No protocol can make an artifact simultaneously
> *offline-transferable*, *ledger-free*, and *non-duplicable* while it carries
> value. A signature proves **authenticity**; it can never prevent **copying**.

Consequences, taken as design law:

* **Anti-duplication ⇒ a ledger is mandatory.** Sharing or re-sealing material
  (the "recovery" tooling) **delivers** control to a new holder but never
  **deletes** the old holder's copy. Only an authority that *invalidates the old
  controller and designates the new one* yields non-duplication.
* EPX-T therefore splits transfer into two halves: **delivery** (offline-capable,
  via the recovery/sealing primitives) and **finalization** (online, via the
  anchor). The anchor is the source of truth; the recovery layer is a courier.

The anchor role is filled today by `eopx.server.anchor_api` + `sequence_state`
+ `http_delegate` (a monotonic, lock-serialized sequence authority). For full
decentralization the same role maps onto the ecosystem blockchain layer
(Ordinals / EVM); see §11.

## 2. Roles and terms

| Term | Meaning |
|------|---------|
| **Artifact** | A titled object: `{artifact_id, type, content_commit, …}`. |
| **`artifact_id`** | 16 random bytes; globally unique, fixed for the artifact's life. |
| **Controller key** | A per-artifact ML-DSA-87 keypair `(C_pub, C_sec)`. Holding `C_sec` = controlling the artifact *now*. Rotated on every transfer. |
| **Owner vault** | The vault that currently holds `C_sec` (and can decrypt the content). |
| **Issuer** | The vault that minted the artifact; signs the genesis record. |
| **Anchor** | The monotonic ordering authority holding the ledger. |
| **Sequence `n`** | Per-artifact monotonic counter; `n=0` at mint, `+1` per transfer. |

## 3. Artifact and ledger state

### 3.1 Titled artifact record (carried in / alongside the `.eopx`)

```
TitledArtifact {
  artifact_id      : 16 B
  type             : utf-8 tag        # "sphere" | "token" | "credential" | …
  content_commit   : SHA3-512(content_bytes)      # 0 if no confidential content
  issuer_vault_fp  : 32 B
  issue_seq        : uint              # anchor sequence at mint
  issuer_sig       : ML-DSA-87         # over ISSUE payload (§5.1)
}
```

The confidential content itself (if any) travels **encrypted** in the `.eopx`
under a random `content_key`; `content_key` is wrapped to the owner's ML-KEM
public key (reusing the manifest `kyber_pk` field, EPX-format §Manifest).

### 3.2 Anchor ledger entry (authoritative)

```
ledger[artifact_id] = {
  seq             : uint              # current sequence
  controller_pub  : ML-DSA-87 pub     # current controller (the truth of ownership)
  content_commit  : SHA3-512          # bound at mint, immutable
  issuer_fp       : 32 B
  updated_at      : RFC3339
}
```

**Ownership of an artifact is, by definition, the `controller_pub` recorded at
the latest `seq`.** Nothing else (possession of a `.eopx` file, of an old key)
confers ownership.

## 4. Cryptographic constructions

| Use | Primitive |
|-----|-----------|
| Issuer / controller / anchor signatures | ML-DSA-87 (Dilithium5) |
| Content sealing to a vault | ML-KEM-1024 (Kyber1024) + ChaCha20-Poly1305 |
| Commitments / fingerprints | SHA3-256 |
| Content commitment | SHA3-512 |

Domain separators (frozen at v1):

```
EPXT_ISSUE    = b"epx-t.issue.v1"
EPXT_TRANSFER = b"epx-t.transfer.v1"
EPXT_POP      = b"epx-t.pop.v1"        # proof of possession of a new controller key
EPXT_RECEIPT  = b"epx-t.receipt.v1"    # anchor receipt
```

A controller is indexed by `controller_fp = SHA3-256(EPXT_ISSUE ‖ C_pub)` for
compact logging; the ledger stores the full `C_pub` for verification.

## 5. Operations

### 5.1 Mint (issue a titled artifact)

1. Issuer picks `artifact_id ← random(16)`, computes
   `content_commit = SHA3-512(content)` (or `0` if public/none).
2. The first owner (often the issuer) generates `(C0_pub, C0_sec)` and keeps
   `C0_sec` under vault protection (§8).
3. Issuer signs
   `issuer_sig = MLDSA.Sign(issuer_sk, EPXT_ISSUE ‖ artifact_id ‖ type ‖ content_commit ‖ C0_pub ‖ nonce)`.
4. Issuer calls the anchor `POST /api/v1/artifact/mint` with the record +
   `C0_pub`. The anchor:
   * rejects a duplicate `artifact_id`;
   * creates `ledger[artifact_id] = {seq:0, controller_pub:C0_pub, content_commit, issuer_fp}`;
   * returns an anchor **receipt** (anchor-signed, §5.4) attesting `seq=0`.
5. The artifact is packed as a normal `.eopx` carrying `TitledArtifact` + the
   sealed content + the mint receipt.

### 5.2 Transfer A → B (forward-secure anchored re-key)

Let the current sequence be `n`, current controller `(C_n_pub, C_n_sec)` held
by A.

**Offline (no anchor needed yet):**

1. **B** generates a fresh `(C_{n+1}_pub, C_{n+1}_sec)` — *A never sees `C_sec`* —
   and a proof of possession
   `PoP_B = MLDSA.Sign(C_{n+1}_sec, EPXT_POP ‖ artifact_id ‖ nonce_B)`.
2. **B** sends `{C_{n+1}_pub, PoP_B, kyber_pk_B, nonce_B}` to A (QR, file, NFC…).
3. **A** verifies `PoP_B`, then:
   * builds `Xfer = {artifact_id, from_seq:n, prev_controller:C_n_pub, new_controller:C_{n+1}_pub, nonce_B}`;
   * signs `xfer_sig = MLDSA.Sign(C_n_sec, EPXT_TRANSFER ‖ canonical(Xfer))`;
   * **re-seals the content key to `kyber_pk_B`** (the recovery/delivery step) →
     `sealed_content_B`.

**Online (finalization at the anchor):**

4. A or B submits `{Xfer, xfer_sig, PoP_B}` to `POST /api/v1/artifact/transfer`.
   The anchor performs an **atomic compare-and-swap**:
   * check `ledger[artifact_id].seq == n` *(freshness — this is the anti-double-spend gate)*;
   * check `xfer_sig` verifies under `ledger[artifact_id].controller_pub` (= `C_n_pub`);
   * check `PoP_B` verifies under `C_{n+1}_pub`;
   * on success, set `ledger[artifact_id] = {seq:n+1, controller_pub:C_{n+1}_pub, …}`
     under the sequence lock, and return a receipt attesting `seq=n+1`.
5. B repacks the `.eopx` with `sealed_content_B` + the new receipt. **A's
   `C_n_sec` is now void**: any future `Xfer` it signs fails step 4 (stale seq).

### 5.3 Verify ownership

A verifier with the `.eopx` and anchor access:
1. reads `TitledArtifact`, checks `issuer_sig` and `content_commit` vs the pixels;
2. queries `GET /api/v1/artifact/<id>` → `{seq, controller_pub}`;
3. challenges the claimed owner to sign a fresh nonce under `controller_pub`.
Possession of the file proves nothing; only a signature under the *current*
`controller_pub` does.

### 5.4 Anchor receipt

`receipt = MLDSA.Sign(anchor_sk, EPXT_RECEIPT ‖ artifact_id ‖ seq ‖ controller_pub ‖ ts)`.
Receipts are an append-only, anchor-signed transparency record (§10) so clients
can audit the sequence and detect equivocation.

### 5.5 Escrow / conditional transfer (k-of-n) — optional

For social or held transfers, `C_{n+1}_sec` is generated then **Shamir-split**
k-of-n (`recovery.setup_recovery_flexible`) among custodians, or finalization is
gated behind k approvals / a time-lock (the 7-day escrow flavour). The anchor
advances the sequence only once the release condition is met. The on-chain truth
is unchanged; only the *unlock of `C_{n+1}_sec`* is conditional.

### 5.6 Redemption / burn — optional

A terminal transfer to a well-known **burn controller** (a public, secret-less
`C_pub` no one can sign for) marks the artifact spent/redeemed; the issuer may
treat the burn receipt as a single-use nullifier.

## 6. Anti-double-spend — why it holds

* The anchor advances `seq` only via **atomic compare-and-swap** keyed on the
  expected current `seq` (`sequence_state` + `http_delegate` lock).
* A transfer is valid **iff** signed by the controller recorded at the latest
  `seq`. After A→B anchors at `n+1`, A's `C_n` is no longer the recorded
  controller → a second A→C signed by `C_n` from `seq=n` is rejected.
* Forward-secure re-key means A never holds `C_{n+1}_sec`, so even retaining the
  full `.eopx` and `C_n_sec`, A cannot impersonate the new owner.

The only way to duplicate is to break the anchor's integrity (§9).

## 7. Offline vs online surface

| Step | Offline? |
|------|----------|
| Build/sign `Xfer`, generate `C_{n+1}`, re-seal content | ✅ fully offline |
| Hand-off B↔A (QR / file / NFC) | ✅ offline |
| **Finalization (CAS at the anchor)** | ❌ requires the anchor online |
| Verify ownership | ❌ requires anchor query (or a cached signed receipt + freshness window) |

EPX-T is "**offline to sign, online to settle**." A `.eopx` alone is never proof
of current ownership.

## 8. Controller-key custody and recovery interplay

The owner MUST be able to produce `C_n_sec` to transfer. Therefore:

* `C_sec` is **derived from / sealed to the owner vault** (e.g. wrapped under the
  vault's ML-KEM key, or derived via HKDF from `device_entropy`), so the vault's
  existing recovery already covers it.
* Loss of `C_sec` ⇒ recover the vault (Protocol A unlock / Protocol G reclaim /
  Shamir k-of-n in `recovery.py`), re-derive `C_sec`, continue.
* This is the *correct* home for "recovery" in transfer: it protects the
  controller secret, it does **not** by itself move ownership (§1).

## 9. Security considerations

* **Anchor trust / equivocation.** Anti-duplication relies on the anchor not
  equivocating (showing different current controllers to different verifiers).
  Mitigation: anchor-signed, append-only receipts (§5.4, §10) auditable by
  clients; or replace the anchor with a public chain (§11).
* **Replay.** Nonces + per-artifact `seq` + domain separators bind each message
  to one artifact and one position; replays fail the CAS.
* **Issuer equivocation.** Minting two artifacts with the same `artifact_id` is
  blocked by the anchor's uniqueness check at mint.
* **Grinding the new key.** `PoP_B` forces B to actually hold `C_{n+1}_sec`,
  preventing a transfer to a key nobody controls (accidental burn) unless burn
  is explicitly intended (§5.6).
* **Privacy.** Per-artifact controller keys avoid linking all artifacts to one
  vault key. The anchor still sees `artifact_id` and controller pubkeys; an
  optional commitment scheme can hide the owner vault from the ledger (future).
* **Content confidentiality.** Content is sealed under ML-KEM to the owner; a
  prior owner who kept the old `.eopx` keeps only the *old* ciphertext and learns
  nothing new after transfer.

## 10. Transparency log (recommended)

The anchor SHOULD expose its receipts as an append-only log
(`GET /api/v1/artifact/<id>/history`) so any party can verify the full
`seq 0 → n` chain of `(controller_pub, ts)` and detect a forked history. This is
the lightweight, centralized stand-in for an on-chain ledger.

## 11. Decentralization path

The anchor is an abstraction over "a monotonic, non-equivocating ordering
oracle." It can be:

1. the current `eopx.server` sequence authority (trusted, fast) — MVP;
2. a public blockchain (Ordinals inscription / EVM contract) holding
   `(artifact_id → controller_pub, seq)` — trustless, slower, costlier.

EPX-T's message formats are identical in both; only the finalization transport
changes.

## 12. Relationship to existing components

| Component | Role in EPX-T |
|-----------|---------------|
| `format/eopx_format.py` (`kyber_pk`, `merkle_root`) | Carries the titled artifact + sealed content. |
| `recovery.py` (ML-KEM seal, `setup_recovery_flexible`) | Content delivery (§5.2.3) + escrow k-of-n (§5.5). |
| `server/anchor_api.py`, `sequence_state.py`, `http_delegate.py` | The anchor: mint, transfer CAS, receipts. |
| `vault/reclaim.py` (Protocol G) | Recovering a lost controller secret (§8). |
| `format/shamir.py` | k-of-n custody of `C_sec` and escrow. |

## 13. Invariants / test vectors (for implementation)

1. **Uniqueness:** mint rejects a duplicate `artifact_id`.
2. **Monotonicity:** `seq` only ever increases by exactly 1 per accepted transfer.
3. **CAS double-spend:** two transfers from the same `seq=n` → exactly one
   accepted, the other rejected with `STALE_SEQUENCE`.
4. **Forward secrecy:** a transfer signed by `C_n` after the artifact has moved
   to `seq=n+1` is rejected.
5. **PoP:** a transfer whose `new_controller` lacks a valid `PoP` is rejected.
6. **Authenticity:** `issuer_sig` and `content_commit` verify against the packed
   `.eopx` pixels.
7. **Receipt soundness:** every accepted state change yields an anchor receipt
   verifying under the anchor's published key.

## 14. File manifest (to implement)

| File | Purpose |
|------|---------|
| `src/eopx/transfer/__init__.py` | `TitledArtifact`, `Xfer`, PoP, canonicalizers |
| `src/eopx/transfer/mint.py` | mint + issuer signature |
| `src/eopx/transfer/transfer.py` | build/sign/verify transfer; re-seal content |
| `src/eopx/transfer/verify.py` | ownership verification against the ledger |
| `src/eopx/server/artifact_api.py` | `mint` / `transfer` / `<id>` / `history` endpoints (CAS via `sequence_state`) |
| `tests/test_titled_transfer.py` | invariants §13 |
| `scripts/eopx_artifact.py` | CLI: mint / transfer / verify |

## 15. References

- `docs/specs/EPX-G_reclaim.md` — identity reclaim (controller recovery)
- `docs/specs/EPX-H_seal_reveal.md` — seal badge (a non-titled public artifact)
- `src/eopx/server/anchor_api.py` — existing monotonic sequence authority
- `src/eopx/recovery.py` — ML-KEM sealing + Shamir k-of-n

---

*This document is normative for `version = 1`. A title is not the paper you
hold — it is the line the ledger draws under your name.*

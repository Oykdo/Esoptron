# EPX-V — Voucher Claim: huntable relics, claimed by scanning a sheet

| Field           | Value                                                   |
| --------------- | ------------------------------------------------------- |
| Identifier      | EPX-V                                                   |
| Status          | Draft                                                   |
| Version         | 1                                                       |
| Date            | 2026-05-31                                              |
| Author          | Jérémy ZGONEC                                           |
| Layer           | `eopx.transfer` (voucher) + `eopx.server` (anchor)      |
| Wire compat     | Additive — a new unclaimed→claimed transition over EPX-T |
| Dependencies    | EPX-T, EPX-C, the Metatron scan pipeline, the anchor    |

## Abstract

EPX-V lets a titled relic be **claimed by discovery**: it is minted *unclaimed*,
the anchor holding only a **claim commitment**; its secret is printed (hidden /
scratch-off) on a scannable A4 Metatron sheet. Whoever finds the sheet, scans
it (identifying the relic) and reads the secret can **claim** the relic into
their vault — and the **first valid claim wins**, enforced by the same
compare-and-swap that prevents double-spend. This turns the Codex into a
treasure hunt and is the "parcours littéral" the project's positioning calls
for: relics are *lived*, found by walking, not assigned from a list.

The same primitive carries value: a **EIDOLON note** is a voucher whose claim
credits an amount instead of transferring a title (a scannable banknote).

## 1. The constraint

A Metatron cube carries ~32 bytes (256 bits via the Reed-Solomon private
path) — enough for a **secret or a seed**, never a 4.6 KB ML-DSA signature. So
a sheet is a **low-capacity bearer voucher**, not a self-contained signed
transaction. As always (EPX-T §1) value/ownership moves on the **ledger**; the
paper is a redemption voucher.

## 2. Commitment

For a huntable relic with id ``artifact_id`` and a 32-byte ``secret``:

```
commitment = SHA3-256(EPXT_VOUCHER ‖ lp(artifact_id, secret))
EPXT_VOUCHER = b"epx-v.claim.v1"   (frozen)
```

The anchor stores only ``commitment``; the secret never touches the anchor
until a claim reveals it. Per-relic secrets are derived from a **private master
seed** (``hunt_secret`` = SHA3-512 truncated), so the hunt is reproducible by
the issuer yet unguessable by finders.

## 3. Mint (huntable)

A huntable relic is recorded at ``seq=0`` with **no controller**
(``controller_pub = ""``) and the ``claim_commitment`` set. It cannot be
transferred (no controller); only :ref:`claim <claim>` acts on it. Minting is a
trusted genesis-seeding operation (it sets a commitment); the issuer's identity
is recorded as ``issuer_fp``.

## 4. Claim

The finder:

1. scans the A4 → reads ``artifact_id`` (public Metatron card) and ``secret``;
2. generates a fresh controller bound to their vault (EPX-T §8);
3. builds a :class:`ClaimProof` revealing ``secret`` and **binding it to that
   controller**:

   ```
   sig = MLDSA.Sign(new_controller_sk,
                    EPXT_VOUCHER_POP ‖ lp(artifact_id, new_controller_pub, secret))
   ```

The anchor verifies ``SHA3-256(EPXT_VOUCHER ‖ lp(artifact_id, secret)) ==
commitment`` **and** the binding signature under ``new_controller``, then
performs the atomic transition:

```
UPDATE artifacts SET seq=1, controller_pub=<new>, claim_commitment=NULL
WHERE artifact_id=? AND seq=0 AND claim_commitment=<expected>
```

`rowcount == 1` ⇒ claimed; otherwise the relic already moved
(``ALREADY_CLAIMED``). After a claim the relic is an ordinary EPX-T titled
artifact (transferable, sellable on the EPX-M market).

## 5. First-valid-claim-wins

* The binding signature stops an eavesdropper from re-pointing a captured
  ``secret`` at *their* controller without re-signing under a key they do not
  hold — but anyone who learns the secret can mint their own controller and
  race. That race **is** the hunt; the ledger CAS makes it fair (exactly one
  winner).
* A sequential second claim sees the commitment already cleared → rejected as
  "not huntable"; a concurrent race yields one `200` and one rejection.

## 6. Security & honesty

* **No physical-presence proof.** A photo of the *whole* sheet (including the
  secret) can claim remotely. Hide / scratch the secret; the public cube alone
  cannot claim. The fun rests partly on the race.
* **Anchor front-running.** Revealing the secret to the anchor means a
  malicious anchor could race a claim; this is the usual anchor-trust caveat
  (detectable via the EPX-T §10 transparency log, preventable under BFT/chain).
  A commit-reveal upgrade removes the window — future work.
* **Master-seed opsec.** The master seed opens every relic; keep it offline.
  ``master_secrets.json`` is operator-only.
* **Brand, not security.** The Metatron sheet's beauty is recognition; trust is
  the 91 symbols + commitment + ledger CAS.

## 7. Distribution

The Codex hunt reserves ranks 1–3 (the founder trio) for vaults 1/2/3 — minted
to them when they exist — and makes ranks 4–12 **huntable**. With the
ecosystem at genesis (few vaults), huntable distribution is the right model:
relics are not assigned to vaults that do not exist yet.

## 8. Invariants (for implementation)

1. **Commitment binding:** a secret opens only its own ``artifact_id``.
2. **Mint-huntable:** unclaimed relic has ``seq=0``, ``controller_pub=""``,
   ``claim_commitment`` set, `is_claimable` true.
3. **Claim:** valid secret + binding sig ⇒ ``seq=1``, controller = finder,
   commitment cleared.
4. **Wrong secret / bad binding:** rejected; relic stays claimable.
5. **First wins:** concurrent claims → exactly one succeeds.
6. **Not huntable:** claiming a normal (or already-claimed) artifact is refused.

## 9. File manifest

| File | Purpose |
|------|---------|
| `src/eopx/transfer/voucher.py` | `claim_commitment`, `ClaimProof`, `make_claim`, `verify_claim` |
| `src/eopx/server/artifact_ledger.py` | `claim_commitment` column, `mint(...claim_commitment=)`, `claim()` |
| `src/eopx/server/artifact_api.py` | `POST /artifact/<id>/claim` |
| `src/eopx/collection/__init__.py` | `build_hunt_distribution`, `hunt_secret` |
| `scripts/forge_hunt_sheets.py` | render A4 claim sheets + register commitments |
| `tests/test_voucher_claim.py` | invariants §8 |

## 10. References

- `docs/specs/EPX-T_titled_transfer.md` — the title CAS this rides on
- `docs/specs/EPX-C_codex.md` — the relic collection being hunted
- `docs/specs/EPX-M_market.md` — where a claimed relic trades next

---

*A relic is not given; it is found. The ledger only writes down who found it
first.*

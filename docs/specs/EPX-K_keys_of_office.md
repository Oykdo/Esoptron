# EPX-K — Keys of Office

**Status:** Draft · **Layer:** capability binding over EPX-T · **Code:**
`src/eopx/capabilities.py`, anchor `server/artifact_api.py`
(`/capability*`).

## Abstract

Each Codex relic (EPX-C) is an **office**: holding it confers exactly one
verifiable **capability** in the ecosystem. Because a relic is an EPX-T
titled artifact, the office *travels with it* — the controller the anchor
currently records for the relic's `artifact_id` **is** the current
office-holder. Transferring the relic (EPX-T) moves the power to the new
controller, with no separate grant. EPX-K specifies the frozen
capability→relic binding, the signed **office proof**, and the anchor
verification that ties a proof to live controllership.

> **Honesty (POSITIONING).** The power is not in the image or the seal. It
> is a real, post-quantum, offline-verifiable capability carried by the
> relic's controller key and the EPX-T ledger. The seal contributes ≈2 bits
> and is brand, never authority.

## 1. Motivation

Relics already have unique lore and unique mechanisms. EPX-K turns that
one-to-one correspondence into *operational* meaning: a small, legible set
of ecosystem powers (audit, enrollment, genesis hosting, …), each held by
whoever currently controls the matching relic — a **Council of Twelve**
whose seats are transferable titles, not accounts.

## 2. The twelve offices

| `cap_id` | Relic (rank) | Power |
|---|---|---|
| `EPX-K:attest` | Speculum Primum (1) | co-sign privacy-preserving personhood attestations |
| `EPX-K:seal` | Clavis (2) | bless a badge as canonically official; keep the seal registry |
| `EPX-K:sovereign` | Scintilla (3) | authorise independent anchor / registry nodes |
| `EPX-K:recover` | Unda (4) | designated witness in k-of-n recovery ceremonies |
| `EPX-K:multisig` | Stamen (5) | authorise creation of k-of-n group vaults |
| `EPX-K:audit` | Lucerna (6) | publish authoritative §10 transparency audits |
| `EPX-K:registry` | Corona Cava (7) | govern EPX-T title registry & EPX-M market parameters |
| `EPX-K:enroll` | Persona (8) | conduct per-device enrollment ceremonies (Protocol D) |
| `EPX-K:genesis` | Focus (9) | host a Genesis ceremony — one sheet → N vaults (Protocol E) |
| `EPX-K:migrate` | Limen (10) | co-sign cross-machine migrations (Protocol F) |
| `EPX-K:reclaim` | Phoenix (11) | attest a legitimate identity reclaim (Protocol G) |
| `EPX-K:challenge` | Tessera (12) | operate the card+device strong-auth gate (Protocol C) |

The power column is *presentation* (it may be reworded). The **binding**
(`cap_id`, `relic_key`, `artifact_id`) is frozen by §9.

## 3. Binding

For capability `C` with relic key `k`:

```
artifact_id(C) = artifact_id(relic k)
              = sha3_256(b"esoptron.codex.v1|aid|" + k)[:16]   # EPX-C
office_holder(C) = controller_pub of artifact_id(C) at its current seq
```

`office_holder` is read from the EPX-T anchor (`GET
/api/v1/artifact/<artifact_id>`), i.e. the authoritative current owner
(EPX-T §3.2). Until the relic is minted, the office is **not instated** and
no proof verifies.

## 4. Office proof

To exercise `C`, the holder signs a domain-separated statement with the
relic controller's ML-DSA-87 secret key:

```
DOMAIN    = b"esoptron.epx_k.office.v1"
statement = DOMAIN + b"|" + json({ "v":1, "cap":C, "action":A,
                                   "nonce":N, "ts":T },
                                 sort_keys, separators=(",",":"))
sig       = ML-DSA-87.sign(controller_sk, statement)
proof     = { cap_id:C, action:A, nonce_hex:N, ts:T, sig_b64:b64(sig) }
```

- `action` (`A`) names the operation; its vocabulary belongs to the
  subsystem consuming the capability.
- `nonce` + `ts` are replay-protection material. **The proof carries no
  public key** — it cannot assert its own authority.

### Verification

```
verify_office(proof, controller_pub):
    require proof.cap_id ∈ CAPABILITIES                  # else reject
    return ML-DSA-87.verify(controller_pub, statement(proof), proof.sig)
```

A verifier MUST supply the controller the anchor records **now** for
`artifact_id(cap_id)`. The proof is therefore valid iff the signer holds
the office at verification time. Offline verification is possible whenever
the verifier already trusts a recent `controller_pub` (e.g. a cached EPX-T
receipt chain, EPX-T §10).

## 5. Anchor API

`url_prefix = /api/v1/artifact`

- `GET  /capability` — the twelve offices, the EPX-K commitment, and each
  current holder (`controller_pub_hex`, `seq`, `instated`).
- `GET  /capability/<cap_id>` — one office's current state.
- `POST /capability/verify` — body: an office-proof dict. Looks up the
  relic's current controller and runs `verify_office`. Returns `ok` plus
  the resolved holder. `404` if the capability is unknown or **not yet
  instated**; `401` if the signature does not verify under the current
  controller; `200` on success.

The anchor does **not** track nonces; replay protection is the calling
subsystem's responsibility.

## 6. Transfer & revocation

There is no explicit grant or revoke. Minting the relic instates the
office; an EPX-T transfer of the relic moves the office to the new
controller (and atomically invalidates the old one via the ledger CAS, EPX-T
§1). "Revoking" an office = transferring its relic away. This makes every
office accountable on the same transparency log as the relic itself
(EPX-T §10).

## 7. Security considerations

1. **Controller compromise = office compromise.** The power is exactly the
   relic controller key; protect it as such. Recovery of a lost controller
   is the relic owner's EPX-T concern (re-key / reclaim), not EPX-K's.
2. **Replay.** Statements are bound to `action`/`nonce`/`ts` but the anchor
   is stateless about nonces; a consuming subsystem MUST reject reused
   `(cap_id, nonce)` within its `ts` window.
3. **Not instated.** A capability whose relic is unminted has *no* holder;
   verification returns 404, never a default-allow.
4. **Scope creep.** `action` is free-form; subsystems MUST treat an office
   proof as authority for *their* action only — never as a blanket grant.
5. **No security from the badge.** A scanned badge image is not an office
   proof; only a signature under the live controller is.

## 8. Invariants

1. **Bijection:** exactly one capability per Codex relic; 12 distinct
   `cap_id`s, 12 distinct relic keys.
2. **Binding stability:** `artifact_id(cap)` equals the EPX-C relic
   artifact id and never drifts while EPX-C `CODEX_DOMAIN` is frozen.
3. **Commitment independence:** the EPX-K commitment covers
   `(cap_id, relic_key, artifact_id)` only — rewording `title`/`power`
   leaves it unchanged.
4. **Liveness:** a proof verifies iff (a) `cap_id` is known, (b) the relic
   is minted, and (c) `sig` verifies under the relic's current controller.
5. **Transfer-follows:** after an accepted EPX-T transfer of relic `k`,
   proofs under the old controller stop verifying and proofs under the new
   controller start verifying — with no EPX-K-specific step.

## 9. Commitment

`capabilities_commitment()` = `SHA3-256` over `DOMAIN | v | n |` each
`[cap_id, relic_key, artifact_id_hex]` (sorted by `cap_id`). It freezes the
office roster independently of presentation text, mirroring
`eopx.collection.catalog_commitment_hex` for the Codex.

# EPX-C — The Codex: a curated collection of titled relics

| Field           | Value                                                  |
| --------------- | ------------------------------------------------------ |
| Identifier      | EPX-C                                                  |
| Status          | Draft                                                  |
| Version         | 1                                                      |
| Date            | 2026-05-30                                             |
| Author          | Jérémy ZGONEC                                          |
| Layer           | `eopx.collection` (new), on top of EPX-T + EPX-H       |
| Wire compat     | Additive — relics are ordinary EPX-T titled artifacts  |
| Dependencies    | EPX-T (titled transfer), EPX-H (seal badge), the anchor |

## Abstract

EPX-C defines a **curated collection** of titled artifacts — a *Codex* — and
how its members are **distributed across the founder vaults** in a way anyone
can verify. The Codex (v2) is **twelve relics**, one per mechanism of the
A–G protocol family. Each relic is an ordinary
EPX-T artifact (so it transfers, anti-duplicates, and verifies exactly like
any other), wrapped with a frozen identity (name, element, myth echo), a
deterministic Metatron badge (EPX-H), and a deterministic destination.

EPX-C adds **no new wire format**. It is a naming, rendering, and
distribution convention over EPX-T.

## 1. Why a collection needs no new supply mechanism

EPX-T artifacts are unbounded (a 16-byte `artifact_id` namespace). Scarcity in
EPX-C is therefore **curatorial, not protocol-level**: the Codex is a fixed,
published list. The list — not a minting cap — is the collection. Anyone may
mint other artifacts; only these twelve are *the Codex*.

## 2. Relic identity

```
Relic {
  rank        : 1..N            # stable ordering (N = 12 for Codex v2)
  key         : slug            # stable identifier
  name        : utf-8           # evocative title
  element     : Fire|Water|Air|Earth
  myth_echo   : utf-8           # the legend it rhymes with (not copied)
  mechanism   : utf-8           # the real system mechanic it embodies
  lore        : utf-8           # presentation (translatable)
}
```

Derived, deterministic quantities:

* `artifact_id = SHA3-256("esoptron.codex.v1|aid|" ‖ key)[:16]`
* `spinor_seed = SHA3-512("esoptron.codex.v1|spinor|" ‖ key)`  → the EPX-H badge
* `content_commit = SHA3-512(lore_payload)` where `lore_payload` is the
  canonical JSON of the relic record (identity **and** lore).

**Catalog commitment.** `catalog_commitment = SHA3-256` over
`CODEX_DOMAIN ‖ version ‖ count ‖ Σ identity_tuple(rank)` where
`identity_tuple = (rank, key, name, element, myth_echo)`. Lore is **excluded**
so translation does not move the commitment, while identity is frozen.

## 3. Distribution

Let the publicly committed Genesis Bitcoin block (the same one that seeds the
88 archetype positions, `genesis_token.derive_positions`) define the seed.

* **Founder relics** (rank ≤ 3) are placed at vault sequences **1, 2, 3** by
  rank — the founder intent, stated openly.
* **Derived relics** (rank > 3) land on positions in `[4, W]` (`W = 1000`)
  drawn deterministically from the block hash, **disjoint from the founder
  slots**:

  ```
  raw = derive_positions(btc_hash, height, total=k, window=W-3)   # k = #derived
  pos = lift(raw)   # shift each draw past the 3 reserved founder slots
  ```

  `lift` maps `[1, W-3] → [4, W] \ {1,2,3}` monotonically, so the result is
  collision-free with the founders and reproducible by any observer.

This makes the drop **provably fair**: no position is hand-picked; re-running
the derivation against the same block reproduces every assignment.

## 4. Relic ↔ badge ↔ artifact binding

Each relic is forged into three cryptographically linked objects:

1. **Badge** — a Metatron cube + revealed seal (EPX-H), rendered from
   `spinor_seed`, packed as a signed `.eopx`.
2. **Titled artifact** — minted (EPX-T §5.1) with `content = lore_payload`, so
   `content_commit` binds the lore; `artifact_id` is the relic's stable id.
3. **Initial controller** — sealed to the destination vault (EPX-T §8): a fresh
   controller whose secret is wrapped under `HKDF(device_secret, salt=
   artifact_id, info="epx-t.controller.bind.v1")`. Holding the vault wakes the
   relic.

The badge `.eopx` carries `merkle_root = SHA3-256(artifact_id ‖ content_commit)`
in its signed manifest, linking image → identity → lore. `vault_id` of the
badge equals the relic's `artifact_id`.

## 5. Claim ceremony (production) vs. forge (demo)

The initial controller must be sealed to the destination vault's
`device_secret`, which is **private to the owner**. Therefore distribution is a
**claim**, not a unilateral push:

* the destination vault's owner generates a controller bound to their
  `device_secret` (`transfer.binding.bind_new_controller`) and hands the
  issuer only the *public* controller;
* the issuer mints the relic to that controller and anchors `seq=0`.

`scripts/forge_collection.py` simulates destination vaults (`--demo-vaults`,
default) so the full pipeline can be exercised offline; production replaces the
simulated secret with the owner's real one.

## 6. Honesty (POSITIONING)

The relic's **scarcity and ownership are real** — they rest on the EPX-T anchor
ledger (monotonic CAS, non-duplication), not on the lore. The lore and the seal
are the **brand** layer (EPX-H: ≈2 bits, verified by re-rendering, never sold as
security). A relic is **discovered through the parcours**, not announced as a
roadmap. Possession of a badge file is never ownership; the anchor's current
record is.

## 7. The Codex v2 — the twelve relics

| # | Name | Element | Myth echo | Mechanism | Destination |
|---|------|---------|-----------|-----------|-------------|
| 1 | Speculum Primum | Air | Narcissus / mirror of truth | ἔσοπτρον — identity reflected | vault #1 |
| 2 | Clavis | Earth | Seal of Solomon | the EPX-H seal | vault #2 |
| 3 | Scintilla | Fire | Prometheus | sovereign self-custody | vault #3 |
| 4 | Unda | Water | waters of Mnemosyne | holographic recovery | derived ∈ [4,1000] |
| 5 | Stamen | Earth | Moirai / Norns | k-of-n custody | derived |
| 6 | Lucerna | Fire | lamp of Diogenes | verification | derived |
| 7 | Corona Cava | Air | the crown worn, not owned | titled transfer (EPX-T) | derived |
| 8 | Persona | Air | the many masks of one face | per-device enrollment (Protocol D) | derived |
| 9 | Focus | Fire | Hestia / the shared hearth-fire | the Genesis ceremony (Protocol E) | derived |
| 10 | Limen | Earth | Janus, god of thresholds | cross-machine migration (Protocol F) | derived |
| 11 | Phoenix | Fire | the phoenix reborn from ashes | identity reclaim (Protocol G) | derived |
| 12 | Tessera | Water | Shibboleth | Strong-Authentication Sheet (Protocol C) | derived |

The first three (the *primordial trio*) go to the founder vaults; relics 4–12
land on nine deterministic positions in `[4, 1000]`.

## 8. Invariants (for implementation)

1. **Catalog integrity:** 12 relics, ranks 1..12 distinct, keys distinct,
   `artifact_id`s distinct and stable (and unchanged from Codex v1 for the
   original seven — the derivation domain is frozen).
2. **Commitment stability:** `catalog_commitment` is independent of lore text.
3. **Founders fixed:** ranks 1–3 → vaults 1,2,3.
4. **Derived fair:** ranks 4–12 → distinct positions in `[4,1000]`, disjoint
   from `{1,2,3}`, deterministic per block, changing block ⇒ changing
   positions.
5. **Forge binding:** the forged artifact verifies (`verify_artifact`), its
   `content_commit` matches `lore_payload`, the badge `.eopx` verifies and
   carries the binding `merkle_root`, and the sealed controller unseals to the
   artifact's `initial_controller_pub` under the destination `device_secret`.

## 9. File manifest

| File | Purpose |
|------|---------|
| `src/eopx/collection/__init__.py` | `Relic`, the 7-relic `CODEX`, distribution, commitment |
| `src/eopx/collection/forge.py` | render badge + mint artifact + seal controller |
| `scripts/forge_collection.py` | CLI: plan / forge / anchor the Codex |
| `tests/test_collection.py` | invariants §8 |

## 10. References

- `docs/specs/EPX-T_titled_transfer.md` — the underlying titled-transfer protocol
- `docs/specs/EPX-H_seal_reveal.md` — the seal badge rendering
- `src/eopx/genesis_token.py` — `derive_positions` (the shared distribution seed)

---

*A collection is not a hoard. It is twelve lines the ledger agrees to remember
by name.*

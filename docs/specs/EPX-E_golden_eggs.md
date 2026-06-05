# EPX-E — Golden Eggs: a legend across the first 555,555,555 vaults

| Field   | Value                                                       |
| ------- | ----------------------------------------------------------- |
| Identifier | EPX-E                                                    |
| Status  | Draft                                                       |
| Version | 1                                                           |
| Date    | 2026-05-31                                                  |
| Author  | Jérémy ZGONEC                                               |
| Layer   | `eopx.egg_token` + `eopx.server.anchor_api` (genesis anchor) |
| Wire    | Additive — a signed seal alongside the Genesis seal          |
| Deps    | ML-DSA-87, the committed Genesis Bitcoin block, the anchor   |

## Abstract

EPX-E seeds **555 golden eggs** on deterministic positions in
``[1, 555_555_555]``, derived from the same publicly committed Bitcoin block
as the 88 Genesis positions. A vault that **lands on** an egg position when it
registers **auto-wins** it: the genesis anchor returns a Dilithium-signed
:class:`EggSeal`, immutable like a Genesis seal. The window is enormous, so
eggs surface slowly as the ecosystem grows — which is the point: it *makes a
legend*.

EPX-E adds **no new ledger storage** — eggs are *derived* from the block and
*sealed* by the deployment key on the fly, exactly like the Genesis seal. The
full clutch is committed before the block is mined and verifiable after.

## 1. The clutch

* ``EGG_WINDOW = 555_555_555``, ``TOTAL_EGGS = 555``.
* Five rarities, a pyramid summing to 555:
  **Cosmic ✸** (5) · **Stellar ✦** (50) · **Lunar ☾** (100) ·
  **Crystal ◈** (150) · **Stone ▣** (250).
* Positions: ``derive_egg_positions(btc_hash, height)`` — modulo-bias-free
  rejection sampling, sorted, deterministic.
* Tiers: assigned by a **block-seeded priority** (``SHA3-256(EGG_TIER_INFO ‖
  h ‖ position)``), so rarity does not correlate with raw position magnitude.

## 2. Egg identity (nomenclature)

Each egg carries:
* ``egg_number`` — 1..555, ascending by position;
* ``egg_id`` — ``"GE-007"``;
* ``tier`` + ``glyph``;
* ``name`` — ``"Golden Egg 007 ✦ — Stellar Clutch"``;
* ``egg_hash`` — ``SHA3-256(EGG_DOMAIN ‖ canonical record)``.

## 3. Winning (auto on registration)

When a vault registers and its monotonic ``sequence`` equals an egg position,
the genesis anchor (`POST /api/v1/genesis/anchor`) returns:

```
golden_egg : true
egg        : { egg_id, egg_number, tier, glyph, name, position, egg_hash }
egg_seal   : EggSeal   # Dilithium-signed by the deployment key (immutable)
```

`GET /api/v1/genesis/egg/<sequence>` re-fetches the seal for an anchored egg
position. The seal binds the egg identity + the winning vault fingerprint +
the block; altering any field invalidates it (``verify_egg_seal``).

## 4. Founder attribution (a deliberate gift)

Early founder vaults would almost never *land* on a position (555 in 555 M).
A **verifiable fair draw** lets the issuer attribute an egg to a founder
vault: ``idx = SHA3-256(EGG_FOUNDER_DRAW_INFO ‖ vault_fp ‖ block) % 555``
(`founder_egg`). This is reproducible and not cherry-picked. It is a curated
legend act, **distinct** from the organic position-landing win; the public
egg record is served at ``GET /api/v1/egg/<vault_id>`` (PWA API).

## 5. Where eggs surface

* **Esoptron** — the anchor seal (above), the PWA API egg record, the PWA 3D
  egg viewer behind a `.psnx`+`.blend_data` access window.
* **Eidolon** — the vault's home: the launcher's "Golden Eggs" entry shows
  the vault's egg + the clutch manifest, and links to the PWA 3D viewer
  (mirrors the relics entry). The engine stays in Esoptron.

## 6. Commitment & verification

* ``tiers_commitment_hex`` — SHA3-256 over the frozen tier nomenclature.
* ``egg_commitment(deployment_pk, height)`` — published before the block is
  mined; after it, anyone re-derives the 555 eggs and checks the seals.
* ``verify_egg_seal`` — schema, signer fingerprint, egg membership +
  identity, and the Dilithium signature.

## 7. Honesty

Eggs are **brand + legend**; cryptographic trust is the deployment-key
signature + the committed block, not the lore. No ledger row is required (the
seal is computed), so the Postgres/SQLite backend is unaffected. Possession
of an `EggSeal` is provable; the egg's *value* is whatever the collection
makes of it.

## 8. Invariants

1. 555 distinct positions in ``[1, 555_555_555]``, deterministic per block.
2. Tier counts: 5 / 50 / 100 / 150 / 250 = 555.
3. `egg_id`/`egg_hash` unique and stable; `egg_number` 1..555.
4. Landing on an egg position ⇒ `golden_egg=true` + a verifying `EggSeal`;
   any other sequence ⇒ `golden_egg=false`, no seal.
5. `founder_egg` deterministic and a member of the clutch.
6. `verify_egg_seal` rejects a wrong key, wrong membership, or any tamper.

## 9. File manifest

| File | Purpose |
|------|---------|
| `src/eopx/egg_token.py` | clutch derivation, tiers, seal, founder draw |
| `src/eopx/server/anchor_api.py` | auto-win on `/anchor` + `/egg/<sequence>` |
| `src/eopx/server/pwa_api.py` | `GET /egg/<vault_id>` (founder record) |
| `pwa/src/components/{EggGate,EggViewer}.tsx` | psnx+blend gate + 3D viewer |
| `<eidolon>/src/ui/launcher.py` | "Golden Eggs" menu entry |
| `tests/test_golden_eggs.py`, `tests/test_anchor_api.py` | invariants §8 |

## 10. References

- `docs/specs/EPX-C_codex.md` — the relic collection (sibling legend)
- `src/eopx/genesis_token.py` — `derive_positions` (shared block + seal pattern)

---

*Five hundred and fifty-five eggs hidden in five hundred and fifty-five
million nests. Most will wait a long time to be found — that is the legend.*

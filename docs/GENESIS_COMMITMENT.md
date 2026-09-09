# Genesis Block Commitment

This document **commits** the Esoptron ecosystem to a single Bitcoin block.
Every deterministic, publicly-verifiable distribution in the system — the 88
Genesis archetype positions (`eopx.genesis_token`), the 12 Codex relic
positions (`eopx.collection`), the 555 Golden Egg positions and founder
draws (`eopx.egg_token`) — is derived from this block's hash. Committing it
here (hash-tracked in `SPECS.SHA3-256`) freezes those distributions and
replaces the development "demo block".

## The committed block

| Field | Value |
|---|---|
| **Height** | `951848` |
| **Hash** | `00000000000000000000c253697e024b6bbe3c7702981277146fdd6767d43ee6` |
| **Block time (unix)** | `1780229113` (≈ 2026-05-31 UTC) |
| **Selection rule** | last confirmed block at commit time, taken with ≥6 confirmations (chain tip − 6) so no reorg can invalidate it |
| **Hash convention** | the standard big-endian display hash (as shown by block explorers), used verbatim as the HKDF salt |

Because this block is now **final**, it is baked into the code as the single
source of truth and the **default everywhere**:

```python
eopx.genesis_token.COMMITTED_BTC_BLOCK_HASH_HEX  # = 00000000…d43ee6
eopx.genesis_token.COMMITTED_BTC_BLOCK_HEIGHT    # = 951848
eopx.genesis_token.resolve_btc_block()           # -> (hash, height, committed=True)
```

`resolve_btc_block()` returns the committed block with `committed = True` and
no configuration, so the CLI, the Eidolon menus, and the SDK all serve the
frozen distribution out of the box — there is **no demo-block fallback** any
more. The environment variables remain an explicit *override for testing*:

```
ESOPTRON_BTC_BLOCK_HASH=00000000000000000000c253697e024b6bbe3c7702981277146fdd6767d43ee6
ESOPTRON_BTC_BLOCK_HEIGHT=951848
```

When the env override is set to a block other than the committed one,
`resolve_btc_block()` reports `committed: false` (a deliberate test block).
The genesis anchor keeps requiring the env vars explicitly on first bootstrap
(so a live anchor's persisted genesis is never silently re-derived). A
regression test (`tests/test_committed_block.py`) pins these constants to the
`catalog_commitment` below.

## What it determines

### Codex relic distribution (EPX-C)

`catalog_commitment = 3593d4d549f6fca41486de53a7423564919e130fc8c227040f30d742542b8ab4`

| # | Relic | → vault | placement |
|---|---|---|---|
| 1 | Speculum Primum | 1 | founder |
| 2 | Clavis | 2 | founder |
| 3 | Scintilla | 3 | founder |
| 4 | Unda | 138 | derived |
| 5 | Stamen | 230 | derived |
| 6 | Lucerna | 249 | derived |
| 7 | Corona Cava | 324 | derived |
| 8 | Persona | 537 | derived |
| 9 | Focus | 679 | derived |
| 10 | Limen | 689 | derived |
| 11 | Phoenix | 805 | derived |
| 12 | Tessera | 958 | derived |

The twelve relic offices (EPX-K) bind to these same artifacts; their roster
commitment is recorded with the EPX-K spec.

### Golden Eggs (EPX-E)

555 eggs across 5 tiers in `[1, 555_555_555]`, positions and tiers derived
from this block. **The clutch is fully recomputable** and was re-verified on
2026-09-09 against `eopx.egg_token.derive_eggs`.

### Founder draw — void, and why it was never verifiable

A founder draw was recorded here for **vault #1** ("zgo"): GE-111, Lunar
Clutch ☾, position 106,186,118, egg_hash `f37eaeef…50f3a6b`. It is **void**:
that vault no longer exists (decision of 2026-09-09).

Two things must be said plainly rather than quietly dropped, because the next
attribution has to avoid both.

**It was never verifiable.** The draw is
`idx = SHA3-256(domain ‖ vault_fp ‖ block) % 555`, so its input is the *whole*
32-byte vault fingerprint. This document recorded only `f02cc7…d7be` — six
leading and four trailing hex characters. Anyone can recompute the 555
positions; nobody can recompute *that* draw. The recomputability claim below
therefore held for the clutch and not for the draw, and said so nowhere.

**The identity it was drawn over is no longer the one in use.** Until
2026-09-09 three different derivations of `vault_fp` coexisted in the tree and
disagreed for the same vault. Which one produced `f02cc7…d7be` is not recorded
either. `eopx.vault.identity` now fixes a single definition —
`card_fingerprint(encode_public(spinor))`, as EPX-G §143 always required.

**Requirements for the next founder attribution:**

1. Record the **full 32-byte** `vault_fp`, hex, never truncated.
2. State that it is a card fingerprint per `eopx.vault.identity`.
3. Take the egg the draw returns. `founder_egg` exists so the attribution is
   not a choice; hand-placing an egg — including moving GE-111 to a
   replacement vault — destroys the only property that makes it legitimate.

## Verification

Anyone can recompute every **position** from the block hash alone — no secret
input. This covers the Genesis positions, the relic distribution and the
555-egg clutch. It does **not** cover a founder egg draw, which additionally
takes the vault's fingerprint: a draw is only checkable by someone holding
that fingerprint, which is why it must be recorded in full (see above).

The distributions are reproducible with:

```
py scripts/forge_collection.py --plan \
    --btc-hash 00000000000000000000c253697e024b6bbe3c7702981277146fdd6767d43ee6 \
    --btc-height 951848
```

and the founder egg via `eopx.egg_token.founder_egg(vault_fp, block, 951848)`.
The block hash itself is independently checkable against any Bitcoin node or
explorer at height 951848.

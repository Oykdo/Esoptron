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
from this block. Founder draw for **vault #1** (`f02cc7…d7be`, "zgo"):

> **GE-111 — Lunar Clutch ☾** · egg_number 111 · position 106,186,118 ·
> egg_hash `f37eaeef423922187c945caca32f55c65fd50f333564822048653853650f3a6b`

(Supersedes the demo attribution GE-254, which used the demo block.)

## Verification

Anyone can recompute every position from the block hash alone — no secret
input. The distributions above are reproducible with:

```
py scripts/forge_collection.py --plan \
    --btc-hash 00000000000000000000c253697e024b6bbe3c7702981277146fdd6767d43ee6 \
    --btc-height 951848
```

and the founder egg via `eopx.egg_token.founder_egg(vault_fp, block, 951848)`.
The block hash itself is independently checkable against any Bitcoin node or
explorer at height 951848.

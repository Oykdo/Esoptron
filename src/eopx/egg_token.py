"""Golden Eggs — a legend seeded across the first 555,555,555 vaults.

A parallel to the 88 Genesis positions, but at ecosystem scale: **555 golden
eggs** land on deterministic positions in ``[1, 555_555_555]``, derived from
the same publicly committed Bitcoin block. A vault that *lands on* an egg
position when it registers **wins** that egg — auto-revealed and sealed to it
on the immutable anchor (a Dilithium-signed :class:`EggSeal`, exactly like a
Genesis seal).

Because the window is enormous, eggs surface slowly as the ecosystem grows —
which is the whole point: it *makes a legend*. The full set (positions, tiers,
nomenclature) is **committed before the block is mined** (:func:`egg_commitment`)
and verifiable by anyone afterwards.

Each egg carries a full identity:

* ``egg_number`` — 1..555, stable (ascending by position);
* ``egg_id`` — ``"GE-007"`` nomenclature handle;
* ``tier`` — one of five rarities (Cosmic ✸ / Stellar ✦ / Lunar ☾ /
  Crystal ◈ / Stone ▣), assigned by a block-seeded priority so rarity is not
  merely "lowest position";
* ``egg_hash`` — SHA3-256 over the canonical egg record (its commitment);
* a signed :class:`EggSeal` once won (the immutable anchor sealing).

Wire format frozen at ``SCHEMA_VERSION = 1``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .format.keys import EopxKey
from .metatron.field import hkdf_sha3_256

SCHEMA_VERSION = 1

# The legendary window and clutch size.
EGG_WINDOW = 555_555_555
TOTAL_EGGS = 555

EGG_DOMAIN = b"esoptron.golden_egg.v1"
EGG_POSITIONS_INFO = b"esoptron.golden_egg.positions.v1"
EGG_SEAL_INFO = b"esoptron.golden_egg.seal.v1"
EGG_TIER_INFO = b"esoptron.golden_egg.tier.v1"

# Five rarities, a pyramid summing to 555. (name, count, glyph)
TIERS: List[Tuple[str, int, str]] = [
    ("Cosmic", 5, "✸"),    # ✸  — the rarest
    ("Stellar", 50, "✦"),  # ✦
    ("Lunar", 100, "☾"),   # ☾
    ("Crystal", 150, "◈"), # ◈
    ("Stone", 250, "▣"),   # ▣  — the most common
]
assert sum(c for _, c, _ in TIERS) == TOTAL_EGGS


# ---------------------------------------------------------------------------
# Deterministic positions (rejection sampling, like genesis_token)
# ---------------------------------------------------------------------------

def derive_egg_positions(btc_block_hash: bytes,
                         btc_block_height: int,
                         *,
                         total: int = TOTAL_EGGS,
                         window: int = EGG_WINDOW) -> List[int]:
    """Derive ``total`` distinct egg positions in ``[1, window]`` from a block.

    Deterministic for a given ``(btc_block_hash, btc_block_height)``; sorted
    ascending. Uses modulo-bias-free rejection sampling on 32-bit draws.
    """
    if len(btc_block_hash) != 32:
        raise ValueError("btc_block_hash must be 32 bytes")
    if total <= 0 or window < total:
        raise ValueError(f"need 0 < total <= window; got {total}, {window}")

    info = EGG_POSITIONS_INFO + f"|h={btc_block_height}|w={window}|n={total}".encode()
    okm = hkdf_sha3_256(ikm=EGG_DOMAIN, salt=btc_block_hash, info=info,
                        length=total * 8)  # headroom for ~9% rejection
    threshold = (2 ** 32 // window) * window
    positions: List[int] = []
    seen: set[int] = set()
    off = 0
    while len(positions) < total:
        if off + 4 > len(okm):
            okm += hkdf_sha3_256(
                ikm=EGG_DOMAIN + b"|extend", salt=btc_block_hash,
                info=info + f"|off={off}".encode(), length=total * 8)
        x = int.from_bytes(okm[off:off + 4], "big")
        off += 4
        if x >= threshold:
            continue
        pos = (x % window) + 1
        if pos in seen:
            continue
        seen.add(pos)
        positions.append(pos)
    return sorted(positions)


def _tier_order(positions: List[int], btc_block_height: int) -> List[int]:
    """Return positions ordered by a block-seeded priority (rarity ranking).

    The first 5 become Cosmic, the next 50 Stellar, etc., so a tier does not
    correlate with raw position magnitude.
    """
    def prio(pos: int) -> bytes:
        return hashlib.sha3_256(
            EGG_TIER_INFO + f"|h={btc_block_height}|p={pos}".encode()
        ).digest()
    return sorted(positions, key=prio)


def _tier_for_priority_rank(rank: int) -> Tuple[str, str]:
    """(tier_name, glyph) for a 0-based rank in the priority ordering."""
    acc = 0
    for name, count, glyph in TIERS:
        if rank < acc + count:
            return name, glyph
        acc += count
    name, _, glyph = TIERS[-1]
    return name, glyph  # pragma: no cover - defensive


# ---------------------------------------------------------------------------
# Egg records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GoldenEgg:
    """A single golden egg's frozen identity."""
    egg_number: int      # 1..TOTAL_EGGS, ascending by position
    position: int        # vault sequence that wins it
    tier: str
    glyph: str
    name: str
    egg_id: str          # "GE-007"
    egg_hash: str        # SHA3-256 of the canonical record (hex)

    def to_dict(self) -> Dict[str, object]:
        return {
            "egg_number": self.egg_number,
            "position": self.position,
            "tier": self.tier,
            "glyph": self.glyph,
            "name": self.name,
            "egg_id": self.egg_id,
            "egg_hash": self.egg_hash,
        }


def _egg_id(egg_number: int) -> str:
    return f"GE-{egg_number:03d}"


def _egg_name(egg_number: int, tier: str, glyph: str) -> str:
    return f"Golden Egg {egg_number:03d} {glyph} — {tier} Clutch"


def _egg_hash(egg_number: int, position: int, tier: str, egg_id: str,
              name: str) -> str:
    payload = json.dumps(
        {"v": SCHEMA_VERSION, "egg_number": egg_number, "position": position,
         "tier": tier, "egg_id": egg_id, "name": name},
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha3_256(EGG_DOMAIN + b"|egg|" + payload).hexdigest()


def derive_eggs(btc_block_hash: bytes,
                btc_block_height: int) -> List[GoldenEgg]:
    """The full clutch of 555 golden eggs for a committed block.

    Deterministic: positions from the block, tiers from a block-seeded
    priority. Returned ascending by ``egg_number`` (i.e. by position).
    """
    positions = derive_egg_positions(btc_block_hash, btc_block_height)
    order = _tier_order(positions, btc_block_height)
    tier_by_pos: Dict[int, Tuple[str, str]] = {
        pos: _tier_for_priority_rank(rank) for rank, pos in enumerate(order)
    }
    eggs: List[GoldenEgg] = []
    for i, pos in enumerate(positions):  # ascending by position
        number = i + 1
        tier, glyph = tier_by_pos[pos]
        egg_id = _egg_id(number)
        name = _egg_name(number, tier, glyph)
        eggs.append(GoldenEgg(
            egg_number=number, position=pos, tier=tier, glyph=glyph,
            name=name, egg_id=egg_id,
            egg_hash=_egg_hash(number, pos, tier, egg_id, name),
        ))
    return eggs


def egg_for_sequence(sequence: int,
                     eggs: List[GoldenEgg]) -> Optional[GoldenEgg]:
    """The egg won by a vault landing on ``sequence``, or ``None``."""
    for egg in eggs:
        if egg.position == sequence:
            return egg
    return None


EGG_FOUNDER_DRAW_INFO = b"esoptron.golden_egg.founder_draw.v1"


def founder_draw_index(vault_fp: bytes, btc_block_hash: bytes,
                       total: int = TOTAL_EGGS) -> int:
    """A verifiable fair-draw index in ``[0, total)`` for a founder vault.

    Deterministic from the vault fingerprint + the committed block, so a
    deliberate founder attribution (a gift to one of the first vaults, which
    would almost never *land* on an egg position organically) is reproducible
    and not cherry-picked.
    """
    digest = hashlib.sha3_256(
        EGG_FOUNDER_DRAW_INFO + b"|" + vault_fp + b"|" + btc_block_hash
    ).digest()
    return int.from_bytes(digest[:8], "big") % total


def founder_egg(vault_fp: bytes, btc_block_hash: bytes,
                btc_block_height: int) -> GoldenEgg:
    """The golden egg attributed to a founder vault by the fair draw."""
    eggs = derive_eggs(btc_block_hash, btc_block_height)
    return eggs[founder_draw_index(vault_fp, btc_block_hash, total=len(eggs))]


# ---------------------------------------------------------------------------
# Immutable seal (Dilithium-signed by the deployment key)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EggSeal:
    """A signed, immutable attestation that a vault won a golden egg."""
    schema_version: int
    egg_id: str
    egg_number: int
    position: int
    tier: str
    name: str
    egg_hash: str
    vault_fp_hex: str
    btc_block_height: int
    btc_block_hash_hex: str
    signer_pk_fp_hex: str
    signature_hex: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "egg_id": self.egg_id,
            "egg_number": self.egg_number,
            "position": self.position,
            "tier": self.tier,
            "name": self.name,
            "egg_hash": self.egg_hash,
            "vault_fp_hex": self.vault_fp_hex,
            "btc_block_height": self.btc_block_height,
            "btc_block_hash_hex": self.btc_block_hash_hex,
            "signer_pk_fp_hex": self.signer_pk_fp_hex,
            "signature_hex": self.signature_hex,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "EggSeal":
        return cls(
            schema_version=int(d["schema_version"]),  # type: ignore[arg-type]
            egg_id=str(d["egg_id"]), egg_number=int(d["egg_number"]),  # type: ignore[arg-type]
            position=int(d["position"]), tier=str(d["tier"]),  # type: ignore[arg-type]
            name=str(d["name"]), egg_hash=str(d["egg_hash"]),
            vault_fp_hex=str(d["vault_fp_hex"]),
            btc_block_height=int(d["btc_block_height"]),  # type: ignore[arg-type]
            btc_block_hash_hex=str(d["btc_block_hash_hex"]),
            signer_pk_fp_hex=str(d["signer_pk_fp_hex"]),
            signature_hex=str(d["signature_hex"]),
        )


def _egg_seal_message(*, egg: GoldenEgg, vault_fp: bytes,
                      btc_block_height: int, btc_block_hash: bytes) -> bytes:
    return b"|".join([
        EGG_SEAL_INFO,
        str(SCHEMA_VERSION).encode(),
        egg.egg_id.encode(),
        str(egg.egg_number).encode(),
        str(egg.position).encode(),
        egg.tier.encode(),
        egg.egg_hash.encode(),
        vault_fp,
        str(btc_block_height).encode(),
        btc_block_hash,
    ])


def mint_egg_seal(*, egg: GoldenEgg, vault_fp: bytes,
                  btc_block_hash: bytes, btc_block_height: int,
                  eggs: List[GoldenEgg], deployment_key: EopxKey) -> EggSeal:
    """Seal a golden egg to the winning vault (Dilithium-signed, immutable).

    Raises ``ValueError`` if ``egg`` is not part of the published clutch.
    """
    if egg.position not in {e.position for e in eggs}:
        raise ValueError("egg is not part of the published clutch")
    msg = _egg_seal_message(egg=egg, vault_fp=vault_fp,
                            btc_block_height=btc_block_height,
                            btc_block_hash=btc_block_hash)
    sig = deployment_key.sign(msg)
    return EggSeal(
        schema_version=SCHEMA_VERSION, egg_id=egg.egg_id,
        egg_number=egg.egg_number, position=egg.position, tier=egg.tier,
        name=egg.name, egg_hash=egg.egg_hash, vault_fp_hex=vault_fp.hex(),
        btc_block_height=btc_block_height,
        btc_block_hash_hex=btc_block_hash.hex(),
        signer_pk_fp_hex=hashlib.sha3_256(deployment_key.dilithium_pk).hexdigest(),
        signature_hex=sig.hex(),
    )


def verify_egg_seal(seal: EggSeal, *, deployment_pk: bytes,
                    eggs: List[GoldenEgg]) -> bool:
    """Verify an egg seal against the published deployment key + clutch."""
    if seal.schema_version != SCHEMA_VERSION:
        return False
    if seal.signer_pk_fp_hex != hashlib.sha3_256(deployment_pk).hexdigest():
        return False
    egg = egg_for_sequence(seal.position, eggs)
    if egg is None or egg.egg_id != seal.egg_id or egg.egg_hash != seal.egg_hash:
        return False
    if egg.tier != seal.tier or egg.egg_number != seal.egg_number:
        return False
    msg = _egg_seal_message(
        egg=egg, vault_fp=bytes.fromhex(seal.vault_fp_hex),
        btc_block_height=seal.btc_block_height,
        btc_block_hash=bytes.fromhex(seal.btc_block_hash_hex))
    try:
        sig = bytes.fromhex(seal.signature_hex)
    except ValueError:
        return False
    return EopxKey(dilithium_pk=deployment_pk, kyber_pk=b"").verify(msg, sig)


# ---------------------------------------------------------------------------
# Commitments (published before the block is mined)
# ---------------------------------------------------------------------------

def tiers_commitment_hex() -> str:
    """SHA3-256 over the frozen tier nomenclature."""
    payload = json.dumps(
        [{"tier": n, "count": c, "glyph": g} for n, c, g in TIERS],
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha3_256(EGG_DOMAIN + b"|tiers|" + payload).hexdigest()


def egg_commitment(deployment_pk: bytes,
                   *, btc_block_height: int) -> Dict[str, object]:
    """Public pre-launch commitment to the golden-egg parameters."""
    return {
        "schema_version": SCHEMA_VERSION,
        "domain": EGG_DOMAIN.decode(),
        "btc_block_height": btc_block_height,
        "total_eggs": TOTAL_EGGS,
        "egg_window": EGG_WINDOW,
        "tiers_root": tiers_commitment_hex(),
        "deployment_pk_fp_hex": hashlib.sha3_256(deployment_pk).hexdigest(),
    }


def eggs_manifest(btc_block_hash: bytes,
                  btc_block_height: int) -> Dict[str, object]:
    """Full public manifest: the 555 eggs + commitment for a committed block."""
    eggs = derive_eggs(btc_block_hash, btc_block_height)
    return {
        "schema_version": SCHEMA_VERSION,
        "btc_block_hash_hex": btc_block_hash.hex(),
        "btc_block_height": btc_block_height,
        "total_eggs": TOTAL_EGGS,
        "egg_window": EGG_WINDOW,
        "tiers": [{"tier": n, "count": c, "glyph": g} for n, c, g in TIERS],
        "tiers_root": tiers_commitment_hex(),
        "eggs": [e.to_dict() for e in eggs],
    }


__all__ = [
    "SCHEMA_VERSION", "EGG_WINDOW", "TOTAL_EGGS", "TIERS",
    "GoldenEgg", "EggSeal",
    "derive_egg_positions", "derive_eggs", "egg_for_sequence",
    "founder_draw_index", "founder_egg",
    "mint_egg_seal", "verify_egg_seal",
    "tiers_commitment_hex", "egg_commitment", "eggs_manifest",
]

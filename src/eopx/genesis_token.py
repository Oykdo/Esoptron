"""Genesis Token — 88 special vaults distributed in the first third
of the 1,000,000-vault Esoptron deployment.

Design at a glance
==================

* **Randomness source** — the hash of a publicly committed future
  Bitcoin block (default ``900_000``). At launch we announce the block
  number; once mined, anybody can re-derive the 88 positions.
* **Position derivation** — ``HKDF-SHA3-256(salt=btc_block_hash,
  ikm=GENESIS_DOMAIN, info="esoptron.genesis.positions.v1")`` expanded
  to 1,408 bytes (88 positions × 16 bytes of headroom for rejection
  sampling), each interpreted mod ``333_333`` with dedup-then-resample.
* **Detection** — for any anchored vault with sequence number ``N``,
  ``is_genesis(N, positions)`` returns whether it is one of the 88.
* **Sealing** — the genesis token carries a ``Dilithium5`` signature
  over ``(vault_fp || sequence || archetype_id)`` produced by the
  deployment key. The pubkey is published; nobody else can forge a
  seal.
* **Archetypes** — 88 unique archetypes laid out as a 22×4 lattice
  (22 sacred-geometry archetypes × 4 elemental temperaments). Each
  carries a name, an elemental aspect, a glyph and a color hint for
  the rendering layer to materialise.

The module is the SOURCE OF TRUTH that the server-side anchor and the
client-side ceremony both consume. Once committed, the protocol is
frozen at ``SCHEMA_VERSION = 1``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .format.keys import EopxKey

SCHEMA_VERSION = 1
TOTAL_GENESIS = 88
TOTAL_VAULTS = 1_000_000
GENESIS_WINDOW = TOTAL_VAULTS // 3  # first third → 333_333
GENESIS_DOMAIN = b"esoptron.genesis.v1"
GENESIS_POSITIONS_INFO = b"esoptron.genesis.positions.v1"
GENESIS_SEAL_INFO = b"esoptron.genesis.seal.v1"
BTC_BLOCK_TARGET = 900_000  # publicly committed; can be changed pre-launch


# ---------------------------------------------------------------------------
# Archetype catalog — 88 distinct identities laid out as 22 × 4
# ---------------------------------------------------------------------------

# 22 sacred-geometry archetypes (loosely inspired by major arcana naming
# but reframed within the Esoptron mythos). These are the "rows" of the
# lattice — patterns of being.
LATTICE_PATTERNS: List[str] = [
    "Source", "Mirror", "Crown", "Star", "Tower", "Veil", "Bridge",
    "Spiral", "Octave", "Lantern", "Threshold", "Pillar", "Reed",
    "Compass", "Anchor", "Echo", "Loom", "Furnace", "Garden", "Codex",
    "Cipher", "Lotus",
]
assert len(LATTICE_PATTERNS) == 22

# 4 elemental temperaments (the "columns") — how a pattern manifests.
LATTICE_ELEMENTS: List[str] = ["Air", "Fire", "Water", "Earth"]
assert len(LATTICE_ELEMENTS) == 4

assert len(LATTICE_PATTERNS) * len(LATTICE_ELEMENTS) == TOTAL_GENESIS

# Elemental color hints for the rendering layer (HSL center hues).
ELEMENT_HUES: Dict[str, int] = {
    "Air":   200,   # cyan / aether
    "Fire":  15,    # vermillion
    "Water": 240,   # deep indigo
    "Earth": 95,    # moss
}


@dataclass(frozen=True)
class Archetype:
    """A single Genesis archetype within the 22 × 4 lattice."""
    id: int                # 0..87
    pattern: str           # e.g. "Mirror"
    element: str           # e.g. "Fire"
    glyph: str             # e.g. "MIR-FIR"
    color_hue: int         # 0..359

    @property
    def name(self) -> str:
        return f"{self.pattern} of {self.element}"


def all_archetypes() -> List[Archetype]:
    """Deterministic enumeration of the 88 archetypes (id 0..87).

    Lattice index ``id = pattern_index * 4 + element_index`` so that
    archetypes 0..3 are the 4 elementals of "Source", 4..7 of "Mirror",
    and so on.
    """
    out: List[Archetype] = []
    for p_idx, pattern in enumerate(LATTICE_PATTERNS):
        for e_idx, element in enumerate(LATTICE_ELEMENTS):
            archetype_id = p_idx * 4 + e_idx
            glyph = f"{pattern[:3].upper()}-{element[:3].upper()}"
            out.append(Archetype(
                id=archetype_id, pattern=pattern, element=element,
                glyph=glyph, color_hue=ELEMENT_HUES[element],
            ))
    assert len(out) == TOTAL_GENESIS
    return out


def archetype_of(archetype_id: int) -> Archetype:
    if not 0 <= archetype_id < TOTAL_GENESIS:
        raise ValueError(f"archetype_id must be in 0..{TOTAL_GENESIS-1}")
    return all_archetypes()[archetype_id]


# ---------------------------------------------------------------------------
# HKDF-SHA3-256 (single-block expansion, matches `eopx.recovery`)
# ---------------------------------------------------------------------------

from .metatron.field import hkdf_sha3_256 as _hkdf_sha3_256  # noqa: E402


# ---------------------------------------------------------------------------
# Position derivation from a Bitcoin block hash
# ---------------------------------------------------------------------------

def derive_positions(btc_block_hash: bytes,
                       btc_block_height: int = BTC_BLOCK_TARGET,
                       *,
                       total: int = TOTAL_GENESIS,
                       window: int = GENESIS_WINDOW,
                       ) -> List[int]:
    """Derive the ``total`` distinct genesis positions in ``[1, window]``.

    Parameters
    ----------
    btc_block_hash:
        The 32-byte little-endian double-SHA-256 hash of a publicly
        committed Bitcoin block (e.g. block 900,000). The block must
        already be mined; any observer can fetch the same value.
    btc_block_height:
        Optional sanity field — included in the HKDF info to bind the
        positions to the specific block we committed to (defence
        against ambiguous reorg drama).
    total:
        Number of distinct positions to draw (default 88).
    window:
        Range for the positions, ``[1, window]`` (default 333,333).

    Returns
    -------
    list[int]
        ``total`` distinct positions, sorted ascending. Deterministic
        for a given ``btc_block_hash``.

    Notes
    -----
    Uses rejection sampling on 32-bit integers to avoid modulo bias:
    each draw consumes 4 bytes of HKDF output, rejects anything ≥
    ``window * floor(2**32 / window)``, and re-draws until the desired
    count is reached. With ``window = 333_333`` the rejection rate is
    < 0.02%, so 1,408 bytes (352 draws) is far more than enough to
    yield 88 distinct survivors.
    """
    if len(btc_block_hash) != 32:
        raise ValueError("btc_block_hash must be 32 bytes")
    if total <= 0 or window < total:
        raise ValueError(f"need 0 < total <= window; got {total}, {window}")

    # Bind to the height too so a reorg to a sibling block cannot reuse
    # the same derivation accidentally.
    info = GENESIS_POSITIONS_INFO + f"|h={btc_block_height}|w={window}|n={total}".encode()
    okm = _hkdf_sha3_256(
        ikm=GENESIS_DOMAIN,
        salt=btc_block_hash,
        info=info,
        length=total * 16,  # 16 bytes of headroom per position
    )

    # Rejection sampling: read 4 bytes at a time, accept if < bias_limit.
    threshold = (2 ** 32 // window) * window
    positions: List[int] = []
    seen: set[int] = set()
    off = 0
    while len(positions) < total:
        if off + 4 > len(okm):
            # Should never happen with 16-byte headroom × 88 positions,
            # but guard anyway; extend the stream deterministically.
            okm = okm + _hkdf_sha3_256(
                ikm=GENESIS_DOMAIN + b"|extend",
                salt=btc_block_hash,
                info=info + f"|off={off}".encode(),
                length=total * 16,
            )
        x = int.from_bytes(okm[off:off + 4], "big")
        off += 4
        if x >= threshold:
            continue
        pos = (x % window) + 1  # positions are 1-indexed in [1, window]
        if pos in seen:
            continue
        seen.add(pos)
        positions.append(pos)

    return sorted(positions)


def is_genesis(sequence: int, positions: List[int]) -> bool:
    """Constant-time lookup is not required (positions is public)."""
    return sequence in set(positions)


def archetype_for_sequence(sequence: int,
                             positions: List[int]) -> Optional[Archetype]:
    """Return the archetype assigned to ``sequence`` if it is a Genesis.

    Archetypes are assigned in sorted-position order: the smallest
    Genesis position receives ``archetype_id = 0`` ("Source of Air"),
    the next "Source of Fire", and so on, scanning the lattice
    pattern-major / element-minor.
    """
    sorted_positions = sorted(positions)
    try:
        rank = sorted_positions.index(sequence)
    except ValueError:
        return None
    return archetype_of(rank)


# ---------------------------------------------------------------------------
# Genesis seal — Dilithium5 signature linking (vault_fp, sequence, archetype)
# ---------------------------------------------------------------------------

#: Canonical fields covered by the deployment Dilithium signature.
#:
#: Any new field added to :class:`GenesisSeal` MUST be reviewed against this
#: tuple. If the field belongs in the signed payload, extend both the tuple
#: and :func:`_seal_message`. If it is metadata only (e.g. an observer
#: timestamp), add it to :data:`GENESIS_SEAL_UNSIGNED_FIELDS` so the canonical
#: contract test in ``tests/test_genesis_token.py`` notices that you thought
#: about it.
GENESIS_SEAL_SIGNED_FIELDS: tuple[str, ...] = (
    "schema_version",
    "vault_fp_hex",
    "sequence",
    "archetype_id",
    "btc_block_height",
    "btc_block_hash_hex",
)

#: Fields that appear in :meth:`GenesisSeal.to_dict` but are intentionally
#: NOT part of the signed message (signer identity and the signature itself).
GENESIS_SEAL_UNSIGNED_FIELDS: tuple[str, ...] = (
    "signer_pk_fp_hex",
    "signature_hex",
)


@dataclass
class GenesisSeal:
    """A signed certificate that vault X is one of the 88 elected."""
    schema_version: int
    vault_fp_hex: str
    sequence: int
    archetype_id: int
    btc_block_height: int
    btc_block_hash_hex: str
    signer_pk_fp_hex: str
    signature_hex: str

    def to_dict(self) -> Dict[str, object]:
        return dataclasses.asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "GenesisSeal":
        if d.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported schema_version: {d.get('schema_version')}"
            )
        return cls(
            schema_version=int(d["schema_version"]),  # type: ignore[arg-type]
            vault_fp_hex=str(d["vault_fp_hex"]),
            sequence=int(d["sequence"]),  # type: ignore[arg-type]
            archetype_id=int(d["archetype_id"]),  # type: ignore[arg-type]
            btc_block_height=int(d["btc_block_height"]),  # type: ignore[arg-type]
            btc_block_hash_hex=str(d["btc_block_hash_hex"]),
            signer_pk_fp_hex=str(d["signer_pk_fp_hex"]),
            signature_hex=str(d["signature_hex"]),
        )


def _seal_message(*, vault_fp: bytes, sequence: int, archetype_id: int,
                    btc_block_height: int, btc_block_hash: bytes) -> bytes:
    """Canonical message that the deployment key signs."""
    return b"|".join([
        GENESIS_SEAL_INFO,
        str(SCHEMA_VERSION).encode(),
        vault_fp,
        str(sequence).encode(),
        str(archetype_id).encode(),
        str(btc_block_height).encode(),
        btc_block_hash,
    ])


def mint_genesis_seal(*,
                       vault_fp: bytes,
                       sequence: int,
                       btc_block_hash: bytes,
                       btc_block_height: int,
                       positions: List[int],
                       deployment_key: EopxKey,
                       ) -> GenesisSeal:
    """Produce a verifiable Genesis seal for a Genesis vault.

    Raises ``ValueError`` if ``sequence`` is not in ``positions``.
    """
    if not is_genesis(sequence, positions):
        raise ValueError(
            f"sequence {sequence} is not a Genesis position"
        )
    archetype = archetype_for_sequence(sequence, positions)
    assert archetype is not None  # by the check above

    msg = _seal_message(
        vault_fp=vault_fp,
        sequence=sequence,
        archetype_id=archetype.id,
        btc_block_height=btc_block_height,
        btc_block_hash=btc_block_hash,
    )
    sig = deployment_key.sign(msg)
    return GenesisSeal(
        schema_version=SCHEMA_VERSION,
        vault_fp_hex=vault_fp.hex(),
        sequence=sequence,
        archetype_id=archetype.id,
        btc_block_height=btc_block_height,
        btc_block_hash_hex=btc_block_hash.hex(),
        signer_pk_fp_hex=hashlib.sha3_256(
            deployment_key.dilithium_pk).hexdigest(),
        signature_hex=sig.hex(),
    )


def verify_genesis_seal(seal: GenesisSeal,
                          *,
                          deployment_pk: bytes,
                          positions: List[int],
                          ) -> bool:
    """Verify a Genesis seal against the published deployment pubkey.

    All four checks must pass:

    1. ``schema_version`` matches the frozen wire format.
    2. ``signer_pk_fp_hex`` matches ``deployment_pk``'s SHA3-256 fingerprint.
    3. ``sequence`` is one of the published ``positions``.
    4. The Dilithium signature is valid for the canonical message.
    """
    if seal.schema_version != SCHEMA_VERSION:
        return False
    expected_fp = hashlib.sha3_256(deployment_pk).hexdigest()
    if seal.signer_pk_fp_hex != expected_fp:
        return False
    if not is_genesis(seal.sequence, positions):
        return False
    # Also check the archetype matches the assignment rule.
    expected_arch = archetype_for_sequence(seal.sequence, positions)
    if expected_arch is None or expected_arch.id != seal.archetype_id:
        return False
    msg = _seal_message(
        vault_fp=bytes.fromhex(seal.vault_fp_hex),
        sequence=seal.sequence,
        archetype_id=seal.archetype_id,
        btc_block_height=seal.btc_block_height,
        btc_block_hash=bytes.fromhex(seal.btc_block_hash_hex),
    )
    try:
        sig = bytes.fromhex(seal.signature_hex)
    except ValueError:
        return False
    verifier = EopxKey(dilithium_pk=deployment_pk, kyber_pk=b"")
    return verifier.verify(msg, sig)


# ---------------------------------------------------------------------------
# Commitment helpers — published before the launch
# ---------------------------------------------------------------------------

def genesis_commitment(deployment_pk: bytes,
                         *,
                         btc_block_height: int = BTC_BLOCK_TARGET,
                         total: int = TOTAL_GENESIS,
                         window: int = GENESIS_WINDOW,
                         ) -> Dict[str, object]:
    """Public commitment to the Genesis protocol parameters.

    This is what we publish BEFORE the Bitcoin block is mined. After
    publication, anybody can verify that the eventual positions list
    derived from the block hash matches the protocol described here.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "domain": GENESIS_DOMAIN.decode(),
        "info_positions": GENESIS_POSITIONS_INFO.decode(),
        "info_seal": GENESIS_SEAL_INFO.decode(),
        "btc_block_height": btc_block_height,
        "total_genesis": total,
        "genesis_window": window,
        "total_vaults": TOTAL_VAULTS,
        "deployment_pk_fp_hex":
            hashlib.sha3_256(deployment_pk).hexdigest(),
        "archetypes_root": archetypes_commitment_hex(),
    }


def archetypes_commitment_hex() -> str:
    """SHA3-256 over the canonical archetype list — frozen catalog."""
    payload = json.dumps(
        [
            {"id": a.id, "pattern": a.pattern, "element": a.element,
              "glyph": a.glyph, "color_hue": a.color_hue}
            for a in all_archetypes()
        ],
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha3_256(payload).hexdigest()


__all__ = [
    "SCHEMA_VERSION",
    "TOTAL_GENESIS", "TOTAL_VAULTS", "GENESIS_WINDOW", "BTC_BLOCK_TARGET",
    "Archetype", "GenesisSeal",
    "LATTICE_PATTERNS", "LATTICE_ELEMENTS",
    "all_archetypes", "archetype_of", "archetype_for_sequence",
    "derive_positions", "is_genesis",
    "mint_genesis_seal", "verify_genesis_seal",
    "genesis_commitment", "archetypes_commitment_hex",
]

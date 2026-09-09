"""
Explicit, signed attribution of a golden egg — and the ledger that keeps
attributions honest.

Why this module exists
----------------------
``egg_token.EggSeal`` attests that "a vault won a golden egg", but
``verify_egg_seal`` never recomputes ``founder_draw_index``. Two consequences
follow, and this module addresses both:

1. **A seal cannot distinguish a draw from a gift.** Sealing GE-111 to a vault
   whose fair draw yields GE-042 produces a signature that verifies, while
   asserting something the draw does not support. The published promise
   ("verifiable fair draw") and what verification actually proves diverge —
   invisibly to the holder.

2. **Nothing makes double attribution detectable.** Two valid seals for the
   same egg, to two different vaults, both verify. The scarcity of the 555
   rests on issuer discipline alone, not on a checkable property.

An ``EggGrant`` therefore carries ``kind``:

* ``"draw"``         — the egg the fair draw gives this vault. Verification
                       RECOMPUTES the draw and rejects the record if it does
                       not match. A draw grant cannot lie.
* ``"issuer_grant"`` — a deliberate attribution by the issuer. The record
                       always carries ``drawn_egg_id`` / ``drawn_egg_number``,
                       the egg the draw would have given, so the divergence is
                       stated by the record itself instead of hidden. A
                       verifier can render it as "granted by the issuer, not
                       won", which is the honest reading.

``GrantLedger`` is an append-only hash chain: every grant is linked to the
previous one, so an issued grant cannot be silently removed or reordered, and
a second attribution of the same egg is visible to anyone holding the ledger.

Trust boundary this does NOT change: forging a grant still requires the
issuer's Dilithium secret key. If that key leaks, an attacker mints arbitrary
``issuer_grant`` records — the draw check only protects ``kind="draw"``. Keep
the signing key offline; nothing here rescues a compromised issuer.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, TYPE_CHECKING

from .egg_token import (
    GoldenEgg,
    SCHEMA_VERSION,
    derive_eggs,
    founder_draw_index,
)

if TYPE_CHECKING:  # pragma: no cover
    from .format.keys import EopxKey


GRANT_INFO = b"esoptron.golden_egg.grant.v1"
LEDGER_INFO = b"esoptron.golden_egg.grant_ledger.v1"

KIND_DRAW = "draw"
KIND_ISSUER = "issuer_grant"
VALID_KINDS = (KIND_DRAW, KIND_ISSUER)

GENESIS_LINK = "0" * 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# =============================================================================
# Record
# =============================================================================

@dataclass(frozen=True)
class EggGrant:
    """A signed attribution of one golden egg to one vault.

    ``kind`` states how the egg was obtained; ``drawn_egg_*`` always records
    what the fair draw yields for this vault, so an issuer grant never passes
    itself off as a draw result.
    """

    schema_version: int
    kind: str
    egg_id: str
    egg_number: int
    position: int
    tier: str
    egg_hash: str
    vault_fp_hex: str
    # What the fair draw gives this vault — identical to egg_* when kind="draw".
    drawn_egg_id: str
    drawn_egg_number: int
    btc_block_height: int
    btc_block_hash_hex: str
    issued_at: str
    reason: str
    prev_link_hex: str
    signer_pk_fp_hex: str
    signature_hex: str

    @property
    def diverges_from_draw(self) -> bool:
        """True when the granted egg is not the one the draw yields."""
        return self.egg_id != self.drawn_egg_id

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "EggGrant":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def link_hex(self) -> str:
        """This record's position in the chain: H(prev | canonical record)."""
        return hashlib.sha3_256(
            LEDGER_INFO + b"|" + bytes.fromhex(self.prev_link_hex) + b"|"
            + _grant_message(self)
        ).hexdigest()


def _grant_message(grant: "EggGrant") -> bytes:
    """Canonical signed bytes. Every field that carries meaning is covered."""
    return b"|".join([
        GRANT_INFO,
        str(grant.schema_version).encode(),
        grant.kind.encode(),
        grant.egg_id.encode(),
        str(grant.egg_number).encode(),
        str(grant.position).encode(),
        grant.tier.encode(),
        grant.egg_hash.encode(),
        bytes.fromhex(grant.vault_fp_hex),
        grant.drawn_egg_id.encode(),
        str(grant.drawn_egg_number).encode(),
        str(grant.btc_block_height).encode(),
        bytes.fromhex(grant.btc_block_hash_hex),
        grant.issued_at.encode(),
        grant.reason.encode(),
        bytes.fromhex(grant.prev_link_hex),
    ])


# =============================================================================
# Minting
# =============================================================================

def mint_egg_grant(
    *,
    egg: GoldenEgg,
    vault_fp: bytes,
    btc_block_hash: bytes,
    btc_block_height: int,
    eggs: List[GoldenEgg],
    deployment_key: "EopxKey",
    kind: str = KIND_DRAW,
    reason: str = "",
    prev_link_hex: str = GENESIS_LINK,
    issued_at: Optional[str] = None,
) -> EggGrant:
    """Sign an attribution of ``egg`` to ``vault_fp``.

    ``kind="draw"`` is refused when ``egg`` is not what the draw yields: a
    draw grant that lies cannot be produced in the first place.

    ``kind="issuer_grant"`` accepts any egg of the published clutch, and the
    record keeps the drawn egg alongside so the divergence is explicit.
    """
    if kind not in VALID_KINDS:
        raise ValueError(f"kind must be one of {VALID_KINDS}, got {kind!r}")
    if egg.position not in {e.position for e in eggs}:
        raise ValueError("egg is not part of the published clutch")
    if not reason and kind == KIND_ISSUER:
        raise ValueError("an issuer grant must state a reason")

    drawn = eggs[founder_draw_index(vault_fp, btc_block_hash, total=len(eggs))]

    if kind == KIND_DRAW and drawn.egg_id != egg.egg_id:
        raise ValueError(
            f"draw grant mismatch: this vault draws {drawn.egg_id}, not "
            f"{egg.egg_id}. Use kind='issuer_grant' to attribute it deliberately."
        )

    unsigned = EggGrant(
        schema_version=SCHEMA_VERSION,
        kind=kind,
        egg_id=egg.egg_id,
        egg_number=egg.egg_number,
        position=egg.position,
        tier=egg.tier,
        egg_hash=egg.egg_hash,
        vault_fp_hex=vault_fp.hex(),
        drawn_egg_id=drawn.egg_id,
        drawn_egg_number=drawn.egg_number,
        btc_block_height=btc_block_height,
        btc_block_hash_hex=btc_block_hash.hex(),
        issued_at=issued_at or _utc_now(),
        reason=reason,
        prev_link_hex=prev_link_hex,
        signer_pk_fp_hex=hashlib.sha3_256(deployment_key.dilithium_pk).hexdigest(),
        signature_hex="",
    )

    signature = deployment_key.sign(_grant_message(unsigned))
    return EggGrant(**{**unsigned.to_dict(), "signature_hex": signature.hex()})


# =============================================================================
# Verification
# =============================================================================

def verify_egg_grant(
    grant: EggGrant,
    *,
    deployment_pk: bytes,
    eggs: List[GoldenEgg],
    btc_block_hash: bytes,
) -> bool:
    """Verify a grant against the published issuer key and clutch.

    For ``kind="draw"`` the fair draw is recomputed and must match — that is
    the check ``verify_egg_seal`` never performed. For ``kind="issuer_grant"``
    the divergence is allowed, but ``drawn_egg_*`` must still describe the
    real draw, so the record cannot misstate what would have been won.
    """
    from .format.keys import EopxKey

    if grant.schema_version != SCHEMA_VERSION:
        return False
    if grant.kind not in VALID_KINDS:
        return False
    if grant.signer_pk_fp_hex != hashlib.sha3_256(deployment_pk).hexdigest():
        return False

    granted = next((e for e in eggs if e.position == grant.position), None)
    if granted is None:
        return False
    if (granted.egg_id != grant.egg_id
            or granted.egg_hash != grant.egg_hash
            or granted.tier != grant.tier
            or granted.egg_number != grant.egg_number):
        return False

    try:
        vault_fp = bytes.fromhex(grant.vault_fp_hex)
    except ValueError:
        return False

    drawn = eggs[founder_draw_index(vault_fp, btc_block_hash, total=len(eggs))]
    if (drawn.egg_id != grant.drawn_egg_id
            or drawn.egg_number != grant.drawn_egg_number):
        return False

    if grant.kind == KIND_DRAW and grant.egg_id != drawn.egg_id:
        return False

    if grant.kind == KIND_ISSUER and not grant.reason:
        return False

    unsigned = EggGrant(**{**grant.to_dict(), "signature_hex": ""})
    verifier = EopxKey(dilithium_pk=deployment_pk, kyber_pk=b"")
    return verifier.verify(_grant_message(unsigned), bytes.fromhex(grant.signature_hex))


# =============================================================================
# Append-only ledger
# =============================================================================

class GrantLedger:
    """Hash-chained list of grants: removal, reordering and double
    attribution all become detectable.

    The chain proves ordering and completeness to anyone holding the ledger.
    It does not prevent an issuer from maintaining two divergent ledgers —
    only publishing the head hash does that.
    """

    def __init__(self, grants: Optional[List[EggGrant]] = None) -> None:
        self.grants: List[EggGrant] = list(grants or [])

    @property
    def head(self) -> str:
        return self.grants[-1].link_hex() if self.grants else GENESIS_LINK

    def append(self, grant: EggGrant) -> None:
        if grant.prev_link_hex != self.head:
            raise ValueError(
                "grant does not chain onto the current head "
                f"({grant.prev_link_hex[:16]}... != {self.head[:16]}...)"
            )
        self.grants.append(grant)

    def verify_chain(self) -> bool:
        prev = GENESIS_LINK
        for grant in self.grants:
            if grant.prev_link_hex != prev:
                return False
            prev = grant.link_hex()
        return True

    def duplicate_eggs(self) -> Dict[str, List[str]]:
        """Eggs attributed more than once -> the vaults holding them.

        A non-empty result means the 555 scarcity has been broken.
        """
        by_egg: Dict[str, List[str]] = {}
        for grant in self.grants:
            by_egg.setdefault(grant.egg_id, []).append(grant.vault_fp_hex)
        return {egg: vaults for egg, vaults in by_egg.items() if len(vaults) > 1}

    def for_vault(self, vault_fp_hex: str) -> List[EggGrant]:
        return [g for g in self.grants if g.vault_fp_hex == vault_fp_hex]

    # -- persistence ----------------------------------------------------

    def to_json(self) -> str:
        return json.dumps(
            {
                "ledger_info": LEDGER_INFO.decode(),
                "head": self.head,
                "grants": [g.to_dict() for g in self.grants],
            },
            indent=2,
            ensure_ascii=False,
        )

    @classmethod
    def from_json(cls, raw: str) -> "GrantLedger":
        data = json.loads(raw)
        ledger = cls([EggGrant.from_dict(g) for g in data.get("grants", [])])
        head = data.get("head")
        if head and head != ledger.head:
            raise ValueError("ledger head does not match its own grants")
        return ledger


__all__ = [
    "EggGrant",
    "GrantLedger",
    "GENESIS_LINK",
    "KIND_DRAW",
    "KIND_ISSUER",
    "mint_egg_grant",
    "verify_egg_grant",
]

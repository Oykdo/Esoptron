"""EPX-K — Keys of Office: the twelve relic capabilities.

Each Codex relic (``eopx.collection``) is not only a titled artifact and a
badge — it is an **office**. Holding a relic confers exactly one verifiable
**capability** in the ecosystem, and because a relic is an EPX-T titled
artifact, *the office travels with it*: the current controller recorded on
the anchor **is** the current office-holder. Transfer the relic and the
power moves to the new controller, automatically — Corona Cava made literal
(``the crown is worn, never owned``).

Honesty (POSITIONING). The power is **not** in the image and not in the
seal. It is a real, post-quantum, offline-verifiable capability:

1. the canonical map ``capability -> relic -> artifact_id`` is frozen here
   and committed (:func:`capabilities_commitment`);
2. to *exercise* a capability the holder signs a domain-separated
   :func:`office_statement` with the relic's **controller** secret key
   (ML-DSA-87 / Dilithium5);
3. a verifier checks the signature against the controller the anchor
   currently records for that relic's ``artifact_id`` — so a proof is valid
   iff the signer is the office-holder *right now*.

This module is **pure** with respect to the mapping and the statement
bytes (no pqcrypto needed to read the catalog or hash the commitment). Only
:func:`sign_office` / :func:`verify_office` touch the signature primitives,
and they import :class:`eopx.format.keys.EopxKey` lazily so the catalog can
be inspected in environments without the native crypto.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional

from .collection import CODEX_BY_KEY

# Frozen derivation/signing domain. Bumping this invalidates every prior
# office proof — treat as a hard protocol break.
EPX_K_DOMAIN = b"esoptron.epx_k.office.v1"
EPX_K_VERSION = 1


@dataclass(frozen=True)
class Capability:
    """One office: a unique power conferred by holding a specific relic.

    ``cap_id`` and ``relic_key`` are the **frozen** binding (covered by
    :func:`capabilities_commitment`); ``title`` and ``power`` are
    presentation and may be reworded without moving the commitment.
    """

    cap_id: str       # stable slug, e.g. "EPX-K:audit"
    relic_key: str    # the relic that confers it (eopx.collection key)
    title: str        # human title of the office
    power: str        # the concrete capability, one line

    def artifact_id_hex(self) -> str:
        """The relic artifact whose current controller holds this office."""
        return CODEX_BY_KEY[self.relic_key].artifact_id().hex()

    def to_dict(self) -> Dict[str, object]:
        relic = CODEX_BY_KEY[self.relic_key]
        return {
            "cap_id": self.cap_id,
            "relic_key": self.relic_key,
            "relic_name": relic.name,
            "title": self.title,
            "power": self.power,
            "artifact_id_hex": self.artifact_id_hex(),
        }


# ---------------------------------------------------------------------------
# The twelve offices — one per relic, grounded in the mechanism it embodies.
# ---------------------------------------------------------------------------

CAPABILITIES: List[Capability] = [
    Capability(
        "EPX-K:attest", "speculum_primum", "Attestor of Personhood",
        "co-signs privacy-preserving 'this vault proved itself' attestations "
        "(identity reflected, never revealed)",
    ),
    Capability(
        "EPX-K:seal", "clavis", "Seal-Master",
        "blesses a badge as canonically official; keeps the registry of "
        "genuine EPX-H seals",
    ),
    Capability(
        "EPX-K:sovereign", "scintilla", "Keeper of the Ember",
        "authorises operation of independent anchor / registry nodes "
        "(the decentralisation charter)",
    ),
    Capability(
        "EPX-K:recover", "unda", "Recovery Steward",
        "designated witness in k-of-n holographic recovery ceremonies",
    ),
    Capability(
        "EPX-K:multisig", "stamen", "Multisig Weaver",
        "authorises creation of k-of-n group vaults (threshold custody "
        "policies)",
    ),
    Capability(
        "EPX-K:audit", "lucerna", "Auditor",
        "publishes authoritative §10 transparency audits (fork / "
        "equivocation findings)",
    ),
    Capability(
        "EPX-K:registry", "corona_cava", "Registrar of Titles",
        "governs the EPX-T title registry and EPX-M market parameters "
        "(the throne none owns)",
    ),
    Capability(
        "EPX-K:enroll", "persona", "Enroller",
        "conducts per-device enrollment ceremonies for others (Protocol D)",
    ),
    Capability(
        "EPX-K:genesis", "focus", "Host of the Genesis",
        "hosts a Genesis ceremony: one sheet -> N independent vaults "
        "(Protocol E)",
    ),
    Capability(
        "EPX-K:migrate", "limen", "Migration Notary",
        "co-signs cross-machine migrations, hardening Protocol F against "
        "theft",
    ),
    Capability(
        "EPX-K:reclaim", "phoenix", "Guardian of Reclaim",
        "attests that an identity reclaim on new hardware is legitimate "
        "(Protocol G, anti-impersonation)",
    ),
    Capability(
        "EPX-K:challenge", "tessera", "Challenge-Master",
        "operates the card+device strong-authentication gate for sensitive "
        "actions (Protocol C)",
    ),
]

CAPABILITY_BY_ID: Dict[str, Capability] = {c.cap_id: c for c in CAPABILITIES}
CAPABILITY_BY_RELIC: Dict[str, Capability] = {c.relic_key: c for c in CAPABILITIES}


def capability_for_relic(relic_key: str) -> Optional[Capability]:
    return CAPABILITY_BY_RELIC.get(relic_key)


def artifact_id_for_capability(cap_id: str) -> Optional[str]:
    cap = CAPABILITY_BY_ID.get(cap_id)
    return cap.artifact_id_hex() if cap is not None else None


def capabilities_commitment(caps: Optional[List[Capability]] = None) -> str:
    """SHA3-256 over the frozen ``cap_id -> relic -> artifact_id`` binding.

    Presentation (``title`` / ``power``) is excluded so the offices can be
    reworded without moving the commitment, exactly as the Codex lore is
    excluded from :func:`eopx.collection.catalog_commitment_hex`. ``caps``
    defaults to the canonical :data:`CAPABILITIES`; pass a list only to
    exercise the contract in tests.
    """
    caps = CAPABILITIES if caps is None else caps
    h = hashlib.sha3_256()
    h.update(EPX_K_DOMAIN)
    h.update(f"|v={EPX_K_VERSION}|n={len(caps)}".encode("utf-8"))
    for cap in sorted(caps, key=lambda c: c.cap_id):
        h.update(b"|")
        h.update(json.dumps(
            [cap.cap_id, cap.relic_key, cap.artifact_id_hex()],
            sort_keys=True, ensure_ascii=False,
        ).encode("utf-8"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Office proofs — sign an action as the current holder of a capability.
# ---------------------------------------------------------------------------

def office_statement(cap_id: str, action: str, nonce_hex: str, ts: str) -> bytes:
    """Canonical, domain-separated bytes the office-holder signs.

    ``action`` names the operation being authorised (free-form, the
    verifying subsystem defines its vocabulary); ``nonce_hex`` + ``ts`` give
    the verifier the material for replay protection (the verifier is
    responsible for rejecting reused nonces).
    """
    doc = {
        "v": EPX_K_VERSION,
        "cap": cap_id,
        "action": action,
        "nonce": nonce_hex,
        "ts": ts,
    }
    return EPX_K_DOMAIN + b"|" + json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class OfficeProof:
    """A signed claim to exercise a capability.

    The signer's public key is intentionally **absent**: it is whatever
    controller the anchor currently records for the capability's relic, so
    the proof cannot assert its own authority — it is bound to live
    controllership. ``sig`` is an ML-DSA-87 signature over
    :func:`office_statement`.
    """

    cap_id: str
    action: str
    nonce_hex: str
    ts: str
    sig: bytes

    def statement(self) -> bytes:
        return office_statement(self.cap_id, self.action, self.nonce_hex, self.ts)

    def to_dict(self) -> Dict[str, object]:
        return {
            "cap_id": self.cap_id,
            "action": self.action,
            "nonce_hex": self.nonce_hex,
            "ts": self.ts,
            "sig_b64": _b64e(self.sig),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "OfficeProof":
        return cls(
            cap_id=str(d["cap_id"]),
            action=str(d["action"]),
            nonce_hex=str(d["nonce_hex"]),
            ts=str(d["ts"]),
            sig=_b64d(str(d["sig_b64"])),
        )


def sign_office(key, cap_id: str, action: str, *, nonce_hex: str, ts: str) -> OfficeProof:
    """Sign an office statement with the relic controller's secret key.

    ``key`` is an :class:`eopx.format.keys.EopxKey` holding the Dilithium
    secret of the relic's **current controller**. Raises if ``cap_id`` is
    unknown or the key cannot sign.
    """
    if cap_id not in CAPABILITY_BY_ID:
        raise ValueError(f"unknown capability: {cap_id}")
    sig = key.sign(office_statement(cap_id, action, nonce_hex, ts))
    return OfficeProof(cap_id=cap_id, action=action, nonce_hex=nonce_hex,
                       ts=ts, sig=sig)


def verify_office(proof: OfficeProof, controller_pub: bytes) -> bool:
    """Verify an office proof against a controller public key (offline).

    Returns True iff ``controller_pub`` produced ``proof.sig`` over the
    canonical statement **and** ``proof.cap_id`` is a known capability. The
    caller is responsible for supplying the controller the anchor currently
    records for ``cap_id``'s relic (that binding is what makes the proof an
    *office* proof rather than a bare signature).
    """
    if proof.cap_id not in CAPABILITY_BY_ID:
        return False
    from .format.keys import EopxKey  # lazy: keeps the catalog pqcrypto-free

    verifier = EopxKey(dilithium_pk=controller_pub, kyber_pk=b"")
    return verifier.verify(proof.statement(), proof.sig)


# ---------------------------------------------------------------------------
# tiny base64 helpers (kept local so the module has no heavy imports)
# ---------------------------------------------------------------------------

def _b64e(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    import base64
    return base64.b64decode(s.encode("ascii"))


__all__ = [
    "EPX_K_DOMAIN",
    "EPX_K_VERSION",
    "Capability",
    "CAPABILITIES",
    "CAPABILITY_BY_ID",
    "CAPABILITY_BY_RELIC",
    "capability_for_relic",
    "artifact_id_for_capability",
    "capabilities_commitment",
    "office_statement",
    "OfficeProof",
    "sign_office",
    "verify_office",
]

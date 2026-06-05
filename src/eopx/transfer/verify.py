"""EPX-T ownership verification (spec §5.3).

Possession of a ``.eopx`` proves nothing. Ownership is, by definition, the
``controller_pub`` recorded at the latest ``seq`` in the anchor ledger. To
prove you own an artifact *now*, you sign a fresh verifier-chosen nonce
under the controller key the ledger currently records.

This module provides the challenge/response primitives plus a small
:class:`LedgerView` helper so a verifier can run the full §5.3 check
(authenticity of the record + freshness against the ledger + a live
ownership signature) without depending on the server package.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Optional

from ..format.keys import EopxKey
from . import (
    NONCE_LEN,
    TitledArtifact,
    lp,
)
from .mint import verify_artifact

# Ownership challenges reuse a dedicated domain separator so a live
# ownership signature can never be replayed as a transfer PoP or vice versa.
EPXT_OWN = b"epx-t.ownership.v1"


def _ownership_payload(artifact_id: bytes, nonce: bytes) -> bytes:
    return EPXT_OWN + lp(artifact_id, nonce)


def ownership_challenge() -> bytes:
    """Fresh verifier nonce to challenge a claimed owner."""
    return secrets.token_bytes(NONCE_LEN)


def prove_ownership(controller: EopxKey, artifact_id: bytes,
                    nonce: bytes) -> bytes:
    """Owner side: sign the verifier's nonce under the controller key."""
    if not controller.has_secrets:
        raise ValueError("controller must hold a Dilithium secret key")
    return controller.sign(_ownership_payload(artifact_id, nonce))


def verify_ownership_proof(artifact_id: bytes, nonce: bytes,
                           proof: bytes, controller_pub: bytes) -> bool:
    """Verifier side: check an ownership proof under the ledger controller.

    ``controller_pub`` MUST be the value the ledger records at the latest
    ``seq`` — not a key read from the artifact file. Returns ``False`` on
    any mismatch — never raises.
    """
    try:
        pub = EopxKey(dilithium_pk=controller_pub, kyber_pk=b"")
        return pub.verify(_ownership_payload(artifact_id, nonce), proof)
    except Exception:
        return False


@dataclass(frozen=True)
class LedgerView:
    """The authoritative ledger state for an artifact (spec §3.2).

    A verifier obtains this from ``GET /api/v1/artifact/<id>`` (or any other
    anchor transport). It is the *only* source of current ownership.
    """
    artifact_id: bytes
    seq: int
    controller_pub: bytes
    content_commit: bytes
    issuer_fp: bytes


def verify_against_ledger(
    artifact: TitledArtifact,
    ledger: LedgerView,
    *,
    claimed_owner_proof: Optional[bytes] = None,
    challenge_nonce: Optional[bytes] = None,
    content: Optional[bytes] = None,
) -> bool:
    """Run the full §5.3 ownership check.

    Steps:

    1. authenticity — ``issuer_sig`` verifies and (if ``content`` given)
       matches ``content_commit``;
    2. consistency — the artifact's ``artifact_id``, ``content_commit`` and
       issuer fingerprint match what the ledger records;
    3. liveness (optional) — if ``claimed_owner_proof`` + ``challenge_nonce``
       are supplied, they verify under the ledger's current
       ``controller_pub``.

    Returns ``True`` only when every supplied check passes.
    """
    if artifact.artifact_id != ledger.artifact_id:
        return False
    if not verify_artifact(artifact, content=content):
        return False
    if artifact.content_commit != ledger.content_commit:
        return False
    if artifact.issuer_vault_fp != ledger.issuer_fp:
        return False
    if claimed_owner_proof is not None:
        if challenge_nonce is None:
            return False
        if not verify_ownership_proof(
            ledger.artifact_id, challenge_nonce,
            claimed_owner_proof, ledger.controller_pub,
        ):
            return False
    return True


__all__ = [
    "EPXT_OWN",
    "ownership_challenge",
    "prove_ownership",
    "verify_ownership_proof",
    "LedgerView",
    "verify_against_ledger",
]

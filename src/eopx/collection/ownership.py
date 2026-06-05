"""Authentic possession of a titled relic (EPX-T §5.3, applied to EPX-C).

Holding a ``.eopx`` — or even a claim record — is *not* ownership. A vault
**possesses** a relic now iff the controller key the anchor records at the
latest ``seq`` is one the vault can sign with. This module turns that
definition into two checks:

* :func:`possession_status` — the lightweight *self* view: compare the
  controller public key the vault holds against the one the ledger
  currently records. No secrets, no signatures — it simply reflects the
  ledger's truth, which is exactly what a "my relics" screen needs.
* :func:`prove_relic_ownership` / :func:`verify_relic_ownership` — the
  *trustless* view: the owner unseals the controller secret from its
  ``device_secret`` and signs a verifier-chosen nonce; anyone can check the
  signature against the ledger's controller. This is what a third party
  (or the anchor) demands before believing a possession claim.

The distinction matters: the self view answers "do I still hold it?" with a
string comparison; the trustless view answers "can you prove it to me?" with
a post-quantum signature. The empty state ("you hold none") falls out of the
self view directly.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from ..transfer import (
    SealedController,
    prove_ownership,
    unseal_controller,
    verify_ownership_proof,
)


class Possession(str, Enum):
    """Outcome of comparing a vault's controller to the ledger's record."""

    HELD = "held"
    """The vault's controller IS the ledger's current controller — owned now."""

    TRANSFERRED = "transferred"
    """The vault once held a controller, but the ledger has moved past it."""

    NOT_OWNED = "not_owned"
    """The vault has no controller for this artifact (never claimed it)."""

    UNKNOWN = "unknown"
    """The ledger state is unavailable (anchor unreachable / not minted)."""


def possession_status(
    my_controller_pub: Optional[bytes],
    ledger_controller_pub: Optional[bytes],
) -> Possession:
    """Classify possession from the vault's controller vs. the ledger's.

    ``my_controller_pub`` is the public controller the vault retained when
    it claimed the relic (``None`` if it never claimed). ``ledger_controller_pub``
    is the anchor's current record (``None`` if the anchor could not be
    reached or the artifact is unknown).
    """
    if ledger_controller_pub is None:
        return Possession.UNKNOWN
    if my_controller_pub is None:
        return Possession.NOT_OWNED
    return (
        Possession.HELD
        if my_controller_pub == ledger_controller_pub
        else Possession.TRANSFERRED
    )


def prove_relic_ownership(
    sealed_controller: SealedController,
    device_secret: bytes,
    artifact_id: bytes,
    nonce: bytes,
) -> bytes:
    """Unseal the controller and sign a verifier nonce (the trustless path).

    Requires the owning vault's ``device_secret`` (only it can unseal the
    controller). The returned signature is checked by
    :func:`verify_relic_ownership` against the ledger's current controller.
    """
    controller = unseal_controller(sealed_controller, device_secret)
    return prove_ownership(controller, artifact_id, nonce)


def verify_relic_ownership(
    artifact_id: bytes,
    nonce: bytes,
    proof: bytes,
    ledger_controller_pub: bytes,
) -> bool:
    """Verify an ownership proof against the ledger's current controller.

    ``ledger_controller_pub`` MUST come from the anchor (the latest ``seq``),
    never from a file the claimant supplied. Returns ``False`` on any
    mismatch — never raises.
    """
    return verify_ownership_proof(
        artifact_id, nonce, proof, ledger_controller_pub,
    )


__all__ = [
    "Possession",
    "possession_status",
    "prove_relic_ownership",
    "verify_relic_ownership",
]

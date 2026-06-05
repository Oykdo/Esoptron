"""EPX-V — Voucher claim: claim a huntable relic by scanning a physical sheet.

A *huntable* relic is minted unclaimed, with only a **claim commitment**
recorded at the anchor: ``C = SHA3-256(EPXT_VOUCHER ‖ artifact_id ‖ secret)``.
The secret is printed (hidden / scratch-off) on the relic's A4 sheet
alongside its public Metatron card. To claim it, the finder:

1. scans the sheet → learns ``artifact_id`` (public card) and reads the
   hidden ``secret``;
2. generates a fresh controller bound to their vault (EPX-T §8);
3. signs a :class:`ClaimProof` that reveals ``secret`` and binds it to that
   new controller, so the claim cannot be re-pointed at someone else.

The anchor accepts the **first** proof whose ``secret`` matches the stored
commitment, atomically transferring the relic to the finder's controller
(the same compare-and-swap that prevents double-spend). The hunt is fair by
construction: first valid claim wins.

Honesty / limits
----------------
* A photo of the *whole* sheet (including the hidden secret) is enough to
  claim remotely — physical presence is encouraged (hide/scratch the
  secret), not cryptographically enforced. The fun rests partly on the race.
* Revealing ``secret`` to the anchor over the wire means a malicious anchor
  could front-run; that is the usual anchor-trust caveat (detectable via the
  transparency log, preventable under a BFT/chain anchor). A commit-reveal
  upgrade removes the front-run window and is left as a future hardening.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict

from ..format.keys import EopxKey
from . import _h, _u, lp

# Frozen at v1.
EPXT_VOUCHER = b"epx-v.claim.v1"
EPXT_VOUCHER_POP = b"epx-v.claim.pop.v1"


def claim_commitment(artifact_id: bytes, secret: bytes) -> bytes:
    """The 32-byte commitment the anchor stores for a huntable relic."""
    return hashlib.sha3_256(EPXT_VOUCHER + lp(artifact_id, secret)).digest()


def _claim_pop_payload(artifact_id: bytes, new_controller_pub: bytes,
                       secret: bytes) -> bytes:
    """Bytes the claimant signs — binds the secret to the chosen controller."""
    return EPXT_VOUCHER_POP + lp(artifact_id, new_controller_pub, secret)


@dataclass
class ClaimProof:
    """A finder's signed claim for a huntable relic.

    ``secret`` is the voucher secret read off the sheet; ``sig`` (under
    ``new_controller_pub``) binds it to the controller the finder is claiming
    into, so an eavesdropper cannot retarget the claim without re-signing
    under a key they do not hold.
    """
    artifact_id: bytes
    new_controller_pub: bytes
    new_controller_kyber_pub: bytes
    secret: bytes
    sig: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id_hex": _h(self.artifact_id),
            "new_controller_pub_hex": _h(self.new_controller_pub),
            "new_controller_kyber_pub_hex": _h(self.new_controller_kyber_pub),
            "secret_hex": _h(self.secret),
            "sig_hex": _h(self.sig),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ClaimProof":
        return cls(
            artifact_id=_u(d["artifact_id_hex"]),
            new_controller_pub=_u(d["new_controller_pub_hex"]),
            new_controller_kyber_pub=_u(d["new_controller_kyber_pub_hex"]),
            secret=_u(d["secret_hex"]),
            sig=_u(d["sig_hex"]),
        )


def make_claim(new_controller: EopxKey, artifact_id: bytes,
               secret: bytes) -> ClaimProof:
    """Finder side: build a signed claim for ``artifact_id`` using ``secret``.

    ``new_controller`` is the finder's fresh per-relic controller (secret
    half required). Bind it to their vault first with
    :func:`eopx.transfer.bind_new_controller` so the relic can be woken later.
    """
    if not new_controller.has_secrets:
        raise ValueError("new_controller must hold a Dilithium secret key")
    sig = new_controller.sign(
        _claim_pop_payload(artifact_id, new_controller.dilithium_pk, secret)
    )
    return ClaimProof(
        artifact_id=artifact_id,
        new_controller_pub=new_controller.dilithium_pk,
        new_controller_kyber_pub=new_controller.kyber_pk,
        secret=secret,
        sig=sig,
    )


def verify_claim(proof: ClaimProof, artifact_id: bytes,
                 commitment: bytes) -> bool:
    """Anchor/verifier side: does this claim open the stored commitment?

    Checks that ``proof`` is for the right artifact, that the secret matches
    the recorded ``commitment``, and that the binding signature verifies
    under the claimed new controller. Returns ``False`` on any mismatch —
    never raises.
    """
    try:
        if proof.artifact_id != artifact_id:
            return False
        if claim_commitment(artifact_id, proof.secret) != commitment:
            return False
        pub = EopxKey(dilithium_pk=proof.new_controller_pub, kyber_pk=b"")
        return pub.verify(
            _claim_pop_payload(artifact_id, proof.new_controller_pub,
                               proof.secret),
            proof.sig,
        )
    except Exception:
        return False


__all__ = [
    "EPXT_VOUCHER",
    "claim_commitment",
    "ClaimProof",
    "make_claim",
    "verify_claim",
]

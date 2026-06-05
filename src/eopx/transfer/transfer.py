"""EPX-T transfer — build, sign, and verify a forward-secure re-key.

This is the offline-capable half of a transfer A → B (spec §5.2). The
online finalization (the anchor's atomic compare-and-swap on ``seq``)
lives in :mod:`eopx.server.artifact_api`; nothing here touches the
network.

The flow:

* B runs :func:`build_handoff` to generate a fresh controller key A never
  learns, plus a proof-of-possession, and ships the public bundle to A.
* A runs :func:`verify_handoff`, then :func:`build_transfer` to sign the
  hand-off with the *current* controller key and (if there is content)
  re-seal the content key to B's Kyber key.
* Anyone can run :func:`verify_transfer` to check the signed object before
  it is submitted to the anchor.
"""

from __future__ import annotations

import secrets
from typing import Optional, Tuple

from ..format.keys import EopxKey
from . import (
    NONCE_LEN,
    ControllerHandoff,
    SealedContent,
    Transfer,
    pop_payload,
    reseal_content,
    transfer_payload,
)


def build_handoff(new_controller: EopxKey, artifact_id: bytes,
                  *, nonce_b: Optional[bytes] = None) -> ControllerHandoff:
    """Recipient side: produce the hand-off bundle for A (spec §5.2.1–2).

    ``new_controller`` is B's freshly generated per-artifact key (secret
    half required, to sign the PoP). A never sees the secret half.
    """
    if not new_controller.has_secrets:
        raise ValueError("new_controller must hold a Dilithium secret key")
    nonce = nonce_b if nonce_b is not None else secrets.token_bytes(NONCE_LEN)
    pop = new_controller.sign(pop_payload(artifact_id, nonce))
    return ControllerHandoff(
        artifact_id=artifact_id,
        new_controller_pub=new_controller.dilithium_pk,
        new_controller_kyber_pub=new_controller.kyber_pk,
        nonce_b=nonce,
        pop=pop,
    )


def verify_handoff(handoff: ControllerHandoff, artifact_id: bytes) -> bool:
    """Sender side: check B's proof-of-possession (spec §5.2.3, step 3).

    Confirms B actually controls the new key, so control can never be
    transferred to a key nobody holds (an accidental burn). Returns
    ``False`` on any mismatch — never raises.
    """
    try:
        if handoff.artifact_id != artifact_id:
            return False
        pub = EopxKey(dilithium_pk=handoff.new_controller_pub, kyber_pk=b"")
        return pub.verify(
            pop_payload(artifact_id, handoff.nonce_b), handoff.pop,
        )
    except Exception:
        return False


def build_transfer(
    current_controller: EopxKey,
    from_seq: int,
    handoff: ControllerHandoff,
    *,
    sealed_content: Optional[SealedContent] = None,
) -> Tuple[Transfer, Optional[SealedContent]]:
    """Sender side: sign the hand-off and re-seal content (spec §5.2.3).

    Parameters
    ----------
    current_controller:
        A's current controller key, ``C_n`` (secret half required).
    from_seq:
        The sequence A believes is current (``n``). The anchor rejects the
        transfer if the ledger has moved past it (the anti-double-spend
        gate).
    handoff:
        B's verified hand-off bundle.
    sealed_content:
        The artifact's current sealed content, if any. It is re-keyed to
        B's Kyber key here (the delivery step); ``current_controller`` must
        be able to unwrap it (i.e. hold the matching Kyber secret).

    Returns
    -------
    (Transfer, SealedContent | None)
        The signed transfer to submit to the anchor, and the content
        re-sealed to B (``None`` when the artifact carries no content).

    Raises
    ------
    ValueError
        If the hand-off's PoP does not verify.
    """
    if not current_controller.has_secrets:
        raise ValueError("current_controller must hold a Dilithium secret key")
    if not verify_handoff(handoff, handoff.artifact_id):
        raise ValueError("hand-off PoP does not verify; refusing to transfer")

    prev_pub = current_controller.dilithium_pk
    xfer_sig = current_controller.sign(
        transfer_payload(
            handoff.artifact_id, from_seq, prev_pub,
            handoff.new_controller_pub, handoff.nonce_b,
        )
    )

    transfer = Transfer(
        artifact_id=handoff.artifact_id,
        from_seq=from_seq,
        prev_controller=prev_pub,
        new_controller=handoff.new_controller_pub,
        new_controller_kyber_pub=handoff.new_controller_kyber_pub,
        nonce_b=handoff.nonce_b,
        xfer_sig=xfer_sig,
        pop=handoff.pop,
    )

    resealed: Optional[SealedContent] = None
    if sealed_content is not None:
        resealed = reseal_content(
            sealed_content, current_controller,
            handoff.new_controller_kyber_pub,
        )

    return transfer, resealed


def verify_transfer(transfer: Transfer,
                    expected_controller_pub: bytes) -> bool:
    """Verify a signed transfer end-to-end (the checks the anchor replays).

    Confirms, against the controller recorded at the latest ``seq``:

    * ``prev_controller`` equals ``expected_controller_pub`` (the ledger's
      current controller);
    * ``xfer_sig`` verifies under that controller over the canonical
      transfer payload;
    * ``pop`` verifies under ``new_controller`` (B really holds the new key).

    Returns ``False`` on any mismatch — never raises. The *freshness* check
    (``from_seq == ledger.seq``) is the anchor's atomic responsibility and
    is intentionally not done here.
    """
    try:
        if transfer.prev_controller != expected_controller_pub:
            return False
        prev = EopxKey(dilithium_pk=transfer.prev_controller, kyber_pk=b"")
        ok_xfer = prev.verify(
            transfer_payload(
                transfer.artifact_id, transfer.from_seq,
                transfer.prev_controller, transfer.new_controller,
                transfer.nonce_b,
            ),
            transfer.xfer_sig,
        )
        if not ok_xfer:
            return False
        new = EopxKey(dilithium_pk=transfer.new_controller, kyber_pk=b"")
        return new.verify(
            pop_payload(transfer.artifact_id, transfer.nonce_b), transfer.pop,
        )
    except Exception:
        return False

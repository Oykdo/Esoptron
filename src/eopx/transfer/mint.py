"""EPX-T mint — issue a titled artifact and sign its genesis record.

Minting is the *offline* half of issuance (spec §5.1, steps 1–3 and 5):
the issuer chooses a fresh ``artifact_id``, commits to the (optional)
confidential content, and signs the genesis record binding the first
controller. The *online* half — claiming the ``artifact_id`` and recording
``seq=0`` in the ledger (step 4) — is performed by the anchor server.
"""

from __future__ import annotations

import secrets
from typing import Optional, Tuple

from ..format.keys import EopxKey
from . import (
    ARTIFACT_ID_LEN,
    NONCE_LEN,
    SealedContent,
    TitledArtifact,
    content_commitment,
    issue_payload,
    seal_content,
)


def new_artifact_id() -> bytes:
    """16 fresh random bytes — globally unique for the artifact's life."""
    return secrets.token_bytes(ARTIFACT_ID_LEN)


def mint_artifact(
    issuer: EopxKey,
    type_: str,
    first_controller: EopxKey,
    *,
    content: Optional[bytes] = None,
    artifact_id: Optional[bytes] = None,
    issue_nonce: Optional[bytes] = None,
) -> Tuple[TitledArtifact, Optional[SealedContent]]:
    """Mint a titled artifact (the offline issuer steps of spec §5.1).

    Parameters
    ----------
    issuer:
        The minting vault's :class:`EopxKey` (secret half required) — signs
        the genesis record.
    type_:
        Free-form UTF-8 tag, e.g. ``"sphere"``, ``"token"``, ``"credential"``.
    first_controller:
        The first owner's per-artifact controller key. Only the *public*
        halves are read here (Dilithium for control, Kyber for content
        delivery), so a public-only :class:`EopxKey` is fine; the secret
        half stays with the owner.
    content:
        Optional confidential payload. When present it is sealed to
        ``first_controller``'s Kyber key and returned alongside the record;
        its SHA3-512 commitment is bound into ``issuer_sig``.
    artifact_id / issue_nonce:
        Overrides for deterministic testing; random by default.

    Returns
    -------
    (TitledArtifact, SealedContent | None)
        The signed genesis record (``issue_seq`` still ``None`` until the
        anchor assigns it) and the sealed content, if any.
    """
    if not issuer.has_secrets:
        raise ValueError("issuer must hold a Dilithium secret key to mint")
    if not type_:
        raise ValueError("artifact type tag must be non-empty")

    aid = artifact_id if artifact_id is not None else new_artifact_id()
    if len(aid) != ARTIFACT_ID_LEN:
        raise ValueError(f"artifact_id must be {ARTIFACT_ID_LEN} bytes")
    nonce = issue_nonce if issue_nonce is not None else secrets.token_bytes(NONCE_LEN)

    commit = content_commitment(content)
    c0_pub = first_controller.dilithium_pk

    sig = issuer.sign(issue_payload(aid, type_, commit, c0_pub, nonce))

    artifact = TitledArtifact(
        artifact_id=aid,
        type=type_,
        content_commit=commit,
        issuer_pub=issuer.dilithium_pk,
        initial_controller_pub=c0_pub,
        issue_nonce=nonce,
        issuer_sig=sig,
    )

    sealed: Optional[SealedContent] = None
    if content is not None:
        sealed = seal_content(content, first_controller, aid)

    return artifact, sealed


def verify_artifact(artifact: TitledArtifact,
                    *,
                    content: Optional[bytes] = None,
                    expected_issuer_fp: Optional[bytes] = None) -> bool:
    """Verify a titled artifact's issuer signature (and optional bindings).

    Checks ``issuer_sig`` over the canonical ISSUE payload. When ``content``
    is supplied, also checks its SHA3-512 against the bound commitment. When
    ``expected_issuer_fp`` is supplied, also checks the issuer key
    fingerprint. Returns ``False`` on any mismatch — never raises.
    """
    try:
        if expected_issuer_fp is not None and artifact.issuer_vault_fp != expected_issuer_fp:
            return False
        if content is not None:
            if content_commitment(content) != artifact.content_commit:
                return False
        pub = EopxKey(dilithium_pk=artifact.issuer_pub, kyber_pk=b"")
        return pub.verify(
            issue_payload(
                artifact.artifact_id, artifact.type,
                artifact.content_commit, artifact.initial_controller_pub,
                artifact.issue_nonce,
            ),
            artifact.issuer_sig,
        )
    except Exception:
        return False

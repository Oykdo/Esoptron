"""Tests for Protocol E ceremony attestations (P1-8)."""

from __future__ import annotations

import secrets
import time

import pytest

from eopx.format.keys import EopxKey
from eopx.metatron import encode_private
from eopx.vault.genesis import (
    CeremonyAttestation,
    genesis_enroll,
    sign_ceremony_attestation,
    verify_ceremony_attestation,
)
from eopx.vault.verify_card import card_fingerprint


def _make_sheet():
    seed = secrets.token_bytes(32)
    return encode_private(seed)


def test_sign_and_verify_attestation_roundtrip():
    sheet = _make_sheet()
    fp = card_fingerprint(sheet)
    org = EopxKey.generate()

    att = sign_ceremony_attestation(
        fp, org, metadata={"event": "demo", "max_participants": 88},
    )
    assert isinstance(att, CeremonyAttestation)
    assert verify_ceremony_attestation(att, expected_ceremony_fp=fp)


def test_attestation_rejects_wrong_fingerprint():
    sheet = _make_sheet()
    fp = card_fingerprint(sheet)
    org = EopxKey.generate()

    att = sign_ceremony_attestation(fp, org)
    other_fp = secrets.token_bytes(32)
    assert not verify_ceremony_attestation(att, expected_ceremony_fp=other_fp)


def test_attestation_rejects_wrong_organizer():
    sheet = _make_sheet()
    fp = card_fingerprint(sheet)
    org = EopxKey.generate()
    impostor = EopxKey.generate()

    att = sign_ceremony_attestation(fp, org)
    assert not verify_ceremony_attestation(
        att,
        expected_ceremony_fp=fp,
        expected_organizer_pk=impostor.dilithium_pk,
    )


def test_attestation_ttl_enforcement():
    sheet = _make_sheet()
    fp = card_fingerprint(sheet)
    org = EopxKey.generate()

    stale = sign_ceremony_attestation(
        fp, org, issued_at=time.time() - 3600,
    )
    # Within a 7200s window: accepted.
    assert verify_ceremony_attestation(
        stale, expected_ceremony_fp=fp, max_age_seconds=7200
    )
    # Within a 60s window: rejected.
    assert not verify_ceremony_attestation(
        stale, expected_ceremony_fp=fp, max_age_seconds=60
    )


def test_attestation_rejects_tampered_signature():
    sheet = _make_sheet()
    fp = card_fingerprint(sheet)
    org = EopxKey.generate()
    att = sign_ceremony_attestation(fp, org)

    tampered = CeremonyAttestation(
        ceremony_fp=att.ceremony_fp,
        organizer_pk=att.organizer_pk,
        issued_at=att.issued_at,
        nonce=att.nonce,
        metadata=att.metadata,
        signature=b"\x00" * len(att.signature),
    )
    assert not verify_ceremony_attestation(
        tampered, expected_ceremony_fp=fp
    )


def test_attestation_metadata_is_signed():
    sheet = _make_sheet()
    fp = card_fingerprint(sheet)
    org = EopxKey.generate()
    att = sign_ceremony_attestation(fp, org, metadata={"event": "real"})

    forged = CeremonyAttestation(
        ceremony_fp=att.ceremony_fp,
        organizer_pk=att.organizer_pk,
        issued_at=att.issued_at,
        nonce=att.nonce,
        metadata={"event": "fake"},
        signature=att.signature,
    )
    assert not verify_ceremony_attestation(
        forged, expected_ceremony_fp=fp
    )


def test_genesis_enroll_verifies_attestation_when_supplied():
    sheet = _make_sheet()
    fp = card_fingerprint(sheet)
    org = EopxKey.generate()
    att = sign_ceremony_attestation(fp, org)

    vault = genesis_enroll(sheet, attestation=att)
    assert vault.ceremony_fp == fp


def test_genesis_enroll_rejects_bad_attestation():
    sheet = _make_sheet()
    org = EopxKey.generate()
    att = sign_ceremony_attestation(secrets.token_bytes(32), org)

    with pytest.raises(ValueError, match="attestation"):
        genesis_enroll(sheet, attestation=att)


def test_genesis_enroll_works_without_attestation():
    """Backwards compatibility: attestation is opt-in."""
    sheet = _make_sheet()
    vault = genesis_enroll(sheet)
    assert vault.vault_seed != b"\x00" * 32


def test_attestation_dict_roundtrip():
    sheet = _make_sheet()
    fp = card_fingerprint(sheet)
    org = EopxKey.generate()
    att = sign_ceremony_attestation(fp, org, metadata={"k": 1})

    d = att.to_dict()
    restored = CeremonyAttestation.from_dict(d)
    assert restored.ceremony_fp == att.ceremony_fp
    assert restored.signature == att.signature
    assert verify_ceremony_attestation(restored, expected_ceremony_fp=fp)

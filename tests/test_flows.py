"""Smoke tests for the high-level ``eopx.flows`` dispatcher.

These tests don't require a real camera image; they synthesize a canonical
Metatron rendering then feed it through ``scan_and_route`` with each
:class:`Intent`. The goal is to exercise the routing layer, not the
detection pipeline (which has its own dedicated suites).
"""

from __future__ import annotations

import secrets

import pytest
from PIL import Image

from eopx.flows import (
    Intent,
    ScanContext,
    ScanResult,
    scan_and_route,
    scan_only,
)
from eopx.metatron import encode_private, encode_public, render
from eopx.vault import card_fingerprint, new_challenge


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def spinor_hash() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture(scope="module")
def public_card_image(spinor_hash: bytes) -> Image.Image:
    symbols = encode_public(spinor_hash)
    return render(symbols, size=1024)


@pytest.fixture(scope="module")
def private_card_image() -> tuple[Image.Image, bytes]:
    seed = secrets.token_bytes(32)
    symbols = encode_private(seed)
    return render(symbols, size=1024), seed


# ---------------------------------------------------------------------------
# Detection front-end is tested elsewhere; here we patch around it by
# calling the dispatcher with pre-extracted symbols via a monkey patch.
# This isolates the routing logic from camera/ArUco concerns.
# ---------------------------------------------------------------------------

def _patch_detection(monkeypatch, symbols):
    """Make _detect_and_extract return our canned symbols.

    The flows module is imported fresh per test session; we monkey-patch
    the internal helper so handlers see deterministic input.
    """
    import eopx.flows as flows_mod

    def fake(_image, _ctx, result):
        result.symbols = list(symbols)
        result.card_fingerprint_hex = card_fingerprint(symbols).hex()
        result.detection_method = "fake"
        result.markers_used = 0
        return result.symbols

    monkeypatch.setattr(flows_mod, "_detect_and_extract", fake)


# ---------------------------------------------------------------------------
# VERIFY
# ---------------------------------------------------------------------------

def test_verify_ok(monkeypatch, spinor_hash: bytes) -> None:
    symbols = encode_public(spinor_hash)
    _patch_detection(monkeypatch, symbols)
    ctx = ScanContext(intent=Intent.VERIFY, spinor_hash_local=spinor_hash)
    res = scan_and_route("ignored", ctx)
    assert res.success
    assert res.verify_ok is True
    assert res.intent == Intent.VERIFY


def test_verify_wrong_spinor(monkeypatch, spinor_hash: bytes) -> None:
    symbols = encode_public(spinor_hash)
    _patch_detection(monkeypatch, symbols)
    ctx = ScanContext(intent=Intent.VERIFY,
                       spinor_hash_local=secrets.token_bytes(32))
    res = scan_and_route("ignored", ctx)
    assert not res.success
    assert res.verify_ok is False


def test_verify_missing_spinor_errors(monkeypatch, spinor_hash: bytes) -> None:
    symbols = encode_public(spinor_hash)
    _patch_detection(monkeypatch, symbols)
    ctx = ScanContext(intent=Intent.VERIFY)
    res = scan_and_route("ignored", ctx)
    assert not res.success
    assert any("spinor_hash_local" in e for e in res.errors)


# ---------------------------------------------------------------------------
# ENROLL / RECOVER
# ---------------------------------------------------------------------------

def test_enroll_with_explicit_entropy_yields_phrase(
    monkeypatch, spinor_hash: bytes,
) -> None:
    symbols = encode_public(spinor_hash)
    _patch_detection(monkeypatch, symbols)
    entropy = secrets.token_bytes(32)
    ctx = ScanContext(intent=Intent.ENROLL, device_entropy=entropy)
    res = scan_and_route("ignored", ctx)
    assert res.success, res.errors
    assert res.enrollment is not None
    assert res.recovery_phrase is not None
    assert len(res.recovery_phrase) == 24


def test_recover_reproduces_same_enrollment(
    monkeypatch, spinor_hash: bytes,
) -> None:
    symbols = encode_public(spinor_hash)
    _patch_detection(monkeypatch, symbols)
    entropy = secrets.token_bytes(32)

    ctx1 = ScanContext(intent=Intent.ENROLL, device_entropy=entropy)
    res1 = scan_and_route("ignored", ctx1)

    ctx2 = ScanContext(intent=Intent.RECOVER, device_entropy=entropy)
    res2 = scan_and_route("ignored", ctx2)

    assert res1.enrollment.enrollment_fp == res2.enrollment.enrollment_fp
    assert res1.enrollment.public_tag == res2.enrollment.public_tag


def test_recover_missing_entropy_errors(monkeypatch, spinor_hash: bytes) -> None:
    symbols = encode_public(spinor_hash)
    _patch_detection(monkeypatch, symbols)
    ctx = ScanContext(intent=Intent.RECOVER)
    res = scan_and_route("ignored", ctx)
    assert not res.success
    assert any("device_entropy" in e for e in res.errors)


def test_enroll_without_explicit_entropy_skips_phrase(
    monkeypatch, spinor_hash: bytes,
) -> None:
    """The dispatcher does not invent a recovery phrase out of thin air.

    When the caller relies on automatic entropy generation, no phrase is
    surfaced (and an error explains why).
    """
    symbols = encode_public(spinor_hash)
    _patch_detection(monkeypatch, symbols)
    ctx = ScanContext(intent=Intent.ENROLL)  # no device_entropy
    res = scan_and_route("ignored", ctx)
    # Enrollment itself may succeed in the dataclass sense, but the
    # mnemonic step is expected to surface an error.
    assert not res.success
    assert any("device_entropy" in e for e in res.errors)


# ---------------------------------------------------------------------------
# UNLOCK_PRIVATE — round-trip a private inscription
# ---------------------------------------------------------------------------

def test_unlock_private_returns_seed(
    monkeypatch, private_card_image: tuple[Image.Image, bytes],
) -> None:
    _img, seed = private_card_image
    symbols = encode_private(seed)
    _patch_detection(monkeypatch, symbols)
    ctx = ScanContext(intent=Intent.UNLOCK_PRIVATE)
    res = scan_and_route("ignored", ctx)
    assert res.success, res.errors
    assert res.vault_seed == seed
    assert res.vault_master_key is not None
    assert len(res.vault_master_key) == 32


# ---------------------------------------------------------------------------
# UNLOCK / SAS
# ---------------------------------------------------------------------------

def test_unlock_sas_session_key(monkeypatch, spinor_hash: bytes) -> None:
    symbols = encode_public(spinor_hash)
    _patch_detection(monkeypatch, symbols)
    challenge = new_challenge(vault_id=bytes(32))
    ctx = ScanContext(intent=Intent.UNLOCK,
                       spinor_hash_local=spinor_hash,
                       challenge=challenge)
    res = scan_and_route("ignored", ctx)
    assert res.success, res.errors
    assert res.session_key is not None
    assert len(res.session_key) == 32


# ---------------------------------------------------------------------------
# GENESIS
# ---------------------------------------------------------------------------

def test_genesis_two_devices_distinct(monkeypatch) -> None:
    # Use a private sheet so decode_private succeeds (genesis_enroll
    # expects RS-decodable symbols).
    seed = secrets.token_bytes(32)
    symbols = encode_private(seed)
    _patch_detection(monkeypatch, symbols)

    ctx_a = ScanContext(intent=Intent.GENESIS,
                         device_entropy=secrets.token_bytes(32))
    ctx_b = ScanContext(intent=Intent.GENESIS,
                         device_entropy=secrets.token_bytes(32))
    res_a = scan_and_route("ignored", ctx_a)
    res_b = scan_and_route("ignored", ctx_b)

    assert res_a.success and res_b.success
    assert res_a.genesis_vault.ceremony_fp == res_b.genesis_vault.ceremony_fp
    assert res_a.genesis_vault.vault_fp != res_b.genesis_vault.vault_fp
    assert len(res_a.recovery_phrase) == 24


# ---------------------------------------------------------------------------
# scan_only
# ---------------------------------------------------------------------------

def test_scan_only_returns_fingerprint(monkeypatch, spinor_hash: bytes) -> None:
    symbols = encode_public(spinor_hash)
    _patch_detection(monkeypatch, symbols)
    res = scan_only("ignored")
    assert res.success
    assert res.card_fingerprint_hex is not None
    assert len(res.card_fingerprint_hex) == 64

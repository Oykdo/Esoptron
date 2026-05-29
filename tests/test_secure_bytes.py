"""Tests for the best-effort secret-zeroizing helpers."""

from __future__ import annotations

import pytest

from eopx.format import EopxKey, Secret, wipe_bytearrays


# ---------------------------------------------------------------------------
# Secret wrapper
# ---------------------------------------------------------------------------

def test_secret_holds_and_returns_data() -> None:
    s = Secret(b"correct horse battery staple")
    assert len(s) == 28
    assert bytes(s) == b"correct horse battery staple"
    assert s.wiped is False
    s.wipe()
    assert s.wiped is True
    with pytest.raises(RuntimeError):
        bytes(s)


def test_secret_context_manager_wipes() -> None:
    with Secret(b"\xde\xad\xbe\xef" * 8) as s:
        assert bytes(s).startswith(b"\xde\xad")
        assert s.wiped is False
    assert s.wiped is True
    with pytest.raises(RuntimeError):
        bytes(s)


def test_secret_repr_redacts() -> None:
    s = Secret(b"hidden-secret")
    text = repr(s)
    assert "hidden" not in text
    assert "secret" not in text
    assert "<13 bytes redacted>" in text
    s.wipe()
    assert "<wiped>" in repr(s)


def test_secret_view_invalidates_on_wipe() -> None:
    s = Secret(b"abcdefgh")
    v = s.view()
    assert bytes(v) == b"abcdefgh"
    s.wipe()
    # The underlying buffer is gone — re-requesting a view must fail.
    with pytest.raises(RuntimeError):
        s.view()


def test_secret_double_wipe_is_idempotent() -> None:
    s = Secret(b"x")
    s.wipe()
    s.wipe()
    assert s.wiped is True


def test_secret_rejects_non_bytes() -> None:
    with pytest.raises(TypeError):
        Secret("not bytes")
    with pytest.raises(TypeError):
        Secret(12345)


def test_wipe_bytearrays_handles_none() -> None:
    a = bytearray(b"hello")
    b = None
    wipe_bytearrays(a, b)
    assert bytes(a) == b"\x00" * 5


def test_zero_length_secret_safe() -> None:
    s = Secret(b"")
    assert len(s) == 0
    assert bytes(s) == b""
    s.wipe()
    assert s.wiped


# ---------------------------------------------------------------------------
# EopxKey.wipe_secrets
# ---------------------------------------------------------------------------

def test_eopxkey_wipe_secrets_disables_signing() -> None:
    key = EopxKey.generate()
    assert key.has_secrets is True
    sig = key.sign(b"msg")
    assert key.verify(b"msg", sig)

    key.wipe_secrets()
    assert key.has_secrets is False
    assert key.dilithium_sk is None
    assert key.kyber_sk is None
    # Public verify still works
    assert key.verify(b"msg", sig)
    # Signing is impossible
    with pytest.raises(RuntimeError):
        key.sign(b"msg")
    # Decapsulation is impossible
    with pytest.raises(RuntimeError):
        key.kem_decapsulate(b"\x00" * 1568)


def test_eopxkey_wipe_secrets_preserves_pubkeys() -> None:
    key = EopxKey.generate()
    pk_before = bytes(key.dilithium_pk)
    fp_before = key.dilithium_pk_fp
    key.wipe_secrets()
    assert bytes(key.dilithium_pk) == pk_before
    assert key.dilithium_pk_fp == fp_before


def test_eopxkey_wipe_idempotent() -> None:
    key = EopxKey.generate()
    key.wipe_secrets()
    key.wipe_secrets()  # Should not raise.
    assert key.has_secrets is False

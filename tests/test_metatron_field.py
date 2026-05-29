"""F_13 arithmetic and base-13 conversion."""

import pytest

from eopx.metatron import field as F


def test_field_size():
    assert F.Q == 13


def test_alpha_is_primitive():
    """alpha = 2 must generate F_13* (order 12)."""
    seen = set()
    x = 1
    for _ in range(12):
        x = F.mul(x, F.ALPHA)
        seen.add(x)
    # 12 distinct non-zero values + 0 = full F_13*
    assert seen == set(range(1, 13))


def test_inverse_round_trip():
    for a in range(1, 13):
        assert F.mul(a, F.inv(a)) == 1


def test_inverse_of_zero_raises():
    with pytest.raises(ZeroDivisionError):
        F.inv(0)


def test_base13_round_trip_zero():
    assert F.symbols_to_bits(F.bits_to_symbols(b"\x00" * 4, 8), 4) == b"\x00" * 4


def test_base13_round_trip_random_bytes():
    import os
    raw = os.urandom(32)
    # 32 bytes = 256 bits ; 13^70 > 2^259 > 2^256, so 70 digits suffice.
    syms = F.bits_to_symbols(raw, 70)
    assert all(0 <= s < 13 for s in syms)
    assert len(syms) == 70
    recovered = F.symbols_to_bits(syms, 32)
    assert recovered == raw


def test_base13_overflow_raises():
    # Too small a digit count to hold the value
    with pytest.raises(ValueError):
        F.bits_to_symbols(b"\xff" * 32, 10)


def test_hkdf_determinism():
    out1 = F.hkdf_sha3_512(b"ikm", b"salt", b"info", 64)
    out2 = F.hkdf_sha3_512(b"ikm", b"salt", b"info", 64)
    assert out1 == out2
    assert len(out1) == 64


def test_hkdf_distinct_outputs():
    out1 = F.hkdf_sha3_512(b"ikm-A", b"", b"info", 64)
    out2 = F.hkdf_sha3_512(b"ikm-B", b"", b"info", 64)
    assert out1 != out2

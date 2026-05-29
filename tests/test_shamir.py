"""Tests for the GF(2^8) Shamir secret sharing primitive."""

from __future__ import annotations

import itertools
import os
import secrets

import pytest

from eopx.format.shamir import (
    gf_mul, gf_inv, gf_div,
    shamir_split, shamir_combine,
)


# ---------------------------------------------------------------------------
# Field arithmetic
# ---------------------------------------------------------------------------

def test_gf_mul_identity() -> None:
    for a in range(256):
        assert gf_mul(a, 1) == a
        assert gf_mul(1, a) == a
        assert gf_mul(a, 0) == 0
        assert gf_mul(0, a) == 0


def test_gf_inv_roundtrip() -> None:
    for a in range(1, 256):
        ai = gf_inv(a)
        assert gf_mul(a, ai) == 1
        assert gf_div(a, a) == 1


def test_gf_inv_zero_raises() -> None:
    with pytest.raises(ZeroDivisionError):
        gf_inv(0)
    with pytest.raises(ZeroDivisionError):
        gf_div(1, 0)


def test_gf_mul_associative_random() -> None:
    for _ in range(50):
        a = secrets.randbits(8)
        b = secrets.randbits(8)
        c = secrets.randbits(8)
        assert gf_mul(gf_mul(a, b), c) == gf_mul(a, gf_mul(b, c))


# ---------------------------------------------------------------------------
# Split + combine
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("k,n", [(1, 1), (1, 5), (2, 3), (3, 5), (5, 7), (10, 15)])
def test_split_combine_roundtrip(k: int, n: int) -> None:
    secret = secrets.token_bytes(32)
    shares = shamir_split(secret, k=k, n=n)
    assert len(shares) == n
    indices = [s[0] for s in shares]
    assert indices == list(range(1, n + 1))
    # Combine using the first k shares
    recovered = shamir_combine(shares[:k])
    assert recovered == secret


def test_all_subsets_of_k_recover(case_k: int = 3, case_n: int = 5) -> None:
    secret = secrets.token_bytes(48)
    shares = shamir_split(secret, k=case_k, n=case_n)
    for subset in itertools.combinations(shares, case_k):
        assert shamir_combine(subset) == secret


def test_k_minus_one_does_not_reveal() -> None:
    # The standard sanity check: with k-1 shares, you can recover
    # arbitrary "secrets" by guessing the missing share. No correlation
    # between true secret and the value reconstructible from k-1 shares.
    secret = b"super-secret-info-here-123!"
    shares = shamir_split(secret, k=3, n=5)
    # Use only 2 shares (k-1) and inject a third arbitrary value:
    for invented_value in [b"\x00" * len(secret), b"\xff" * len(secret), b"different bytes!!!" + b"\x00" * (len(secret) - 18)]:
        # Pretend that "share at index 3" took the invented value
        spoofed = list(shares[:2]) + [(3, invented_value)]
        recovered = shamir_combine(spoofed)
        # The recovered value is whatever Lagrange interpolation yields;
        # it is NEVER equal to the true secret unless the invented share
        # happens to match the true share at index 3 (probability 2^-256).
        assert recovered != secret


@pytest.mark.parametrize("k,n", [(2, 5), (3, 6)])
def test_combine_with_more_than_k_shares(k: int, n: int) -> None:
    # Lagrange with > k shares should still recover the secret (the
    # extra shares are consistent points of the same polynomial).
    secret = secrets.token_bytes(16)
    shares = shamir_split(secret, k=k, n=n)
    assert shamir_combine(shares) == secret  # use all n


def test_split_rejects_bad_parameters() -> None:
    with pytest.raises(ValueError):
        shamir_split(b"x", k=0, n=2)
    with pytest.raises(ValueError):
        shamir_split(b"x", k=3, n=2)
    with pytest.raises(ValueError):
        shamir_split(b"", k=1, n=2)
    with pytest.raises(ValueError):
        shamir_split(b"x", k=1, n=300)


def test_combine_rejects_duplicate_indices() -> None:
    s = shamir_split(b"abc", k=2, n=3)
    with pytest.raises(ValueError):
        shamir_combine([s[0], s[0]])


def test_combine_rejects_mismatched_lengths() -> None:
    with pytest.raises(ValueError):
        shamir_combine([(1, b"abc"), (2, b"de")])

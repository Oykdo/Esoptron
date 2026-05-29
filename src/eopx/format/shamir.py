"""Shamir secret sharing over GF(2^8) using the AES irreducible polynomial.

The field is :math:`F_{256} = F_2[X] / (X^8 + X^4 + X^3 + X + 1)` (Rijndael
polynomial ``0x11B``). Each byte of the secret is split independently:

* Random polynomial ``p(X) = a_0 + a_1 X + ... + a_{k-1} X^{k-1}`` over
  GF(2^8), with ``a_0`` set to the secret byte and ``a_1..a_{k-1}``
  drawn from :mod:`secrets`.
* The *i*-th share is ``p(i)`` evaluated at ``x = i`` for
  ``i in {1, 2, ..., n}`` (``x = 0`` would leak the secret).
* Reconstruction interpolates ``p(0)`` from any ``k`` shares via the
  Lagrange formula.

Security
--------
* Any ``k-1`` shares reveal NOTHING about the secret beyond its length.
* Shares are **fixed-length** equal to the secret's length: this leaks
  the secret length but no content.
* This implementation does NOT include integrity protection — that is
  the job of the surrounding :mod:`eopx.format.visual_sharding` layer
  (AEAD via ChaCha20-Poly1305).
"""

from __future__ import annotations

import secrets
from typing import Iterable, List, Sequence, Tuple

# Rijndael irreducible polynomial: x^8 + x^4 + x^3 + x + 1
_RIJNDAEL = 0x11B

# Precomputed log/antilog tables for fast GF(2^8) multiply / inverse.
_EXP: List[int] = [0] * 512
_LOG: List[int] = [0] * 256


def _init_tables() -> None:
    """Build log / antilog tables using generator 0x03."""
    g = 0x03
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x = _mul_naive(x, g)
        # _mul_naive is only used here during bootstrap
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


def _mul_naive(a: int, b: int) -> int:
    """Schoolbook GF(2^8) multiplication, used only for table bootstrap."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def gf_mul(a: int, b: int) -> int:
    """Multiply two GF(2^8) elements (returns ``a * b`` in the field)."""
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(2^8). Raises on ``a == 0``."""
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^8)")
    return _EXP[255 - _LOG[a]]


def gf_div(a: int, b: int) -> int:
    """Divide ``a / b`` in GF(2^8)."""
    if a == 0:
        return 0
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(2^8)")
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


_init_tables()


# ---------------------------------------------------------------------------
# Polynomial evaluation
# ---------------------------------------------------------------------------

def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Horner evaluation of a polynomial over GF(2^8) at ``x``."""
    acc = 0
    for c in reversed(coeffs):
        acc = gf_mul(acc, x) ^ c
    return acc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

Share = Tuple[int, bytes]


def shamir_split(secret: bytes, k: int, n: int) -> List[Share]:
    """Split ``secret`` into ``n`` shares; any ``k`` shares reconstruct it.

    Parameters
    ----------
    secret:
        Arbitrary bytes (at least 1 byte).
    k:
        Threshold. Must satisfy ``1 <= k <= n``.
    n:
        Total number of shares. Must satisfy ``k <= n <= 255``.

    Returns
    -------
    list of (index, share_bytes)
        Indices run from 1 to n (never 0). Share bytes have the same
        length as the secret.
    """
    if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
        raise ValueError("secret must be non-empty bytes")
    if not (1 <= k <= n):
        raise ValueError(f"need 1 <= k <= n, got k={k}, n={n}")
    if n > 255:
        raise ValueError("n must be <= 255 for GF(2^8) Shamir")

    secret_bytes = bytes(secret)
    L = len(secret_bytes)
    shares: List[bytearray] = [bytearray(L) for _ in range(n)]

    # For each byte position, build a fresh random polynomial.
    for pos in range(L):
        coeffs = [secret_bytes[pos]]
        # k-1 random coefficients in GF(2^8). secrets.randbits is CSPRNG.
        for _ in range(k - 1):
            coeffs.append(secrets.randbits(8))
        for i in range(1, n + 1):
            shares[i - 1][pos] = _eval_poly(coeffs, i)

    return [(i + 1, bytes(s)) for i, s in enumerate(shares)]


def shamir_combine(shares: Iterable[Share]) -> bytes:
    """Reconstruct the original secret from at least ``k`` shares.

    Parameters
    ----------
    shares:
        Iterable of ``(index, share_bytes)``. Indices must be distinct
        and in ``1..255``. All share byte strings must have the same
        length.

    Returns
    -------
    bytes
        The recovered secret. If fewer than the true threshold are
        provided, this function still returns *something* — Shamir
        cannot detect "too few shares"; only the caller knows the
        threshold ``k``. Pair with an AEAD check upstream to confirm
        success.
    """
    share_list = list(shares)
    if not share_list:
        raise ValueError("at least one share is required")
    L = len(share_list[0][1])
    indices = [i for i, _ in share_list]
    if len(set(indices)) != len(indices):
        raise ValueError("share indices must be distinct")
    if any(i < 1 or i > 255 for i in indices):
        raise ValueError("share indices must lie in 1..255")
    if any(len(s) != L for _, s in share_list):
        raise ValueError("all shares must have equal length")

    out = bytearray(L)
    # Precompute Lagrange basis values at x = 0:
    #   L_i(0) = prod_{j != i} x_j / (x_i XOR x_j)
    coeffs0: List[int] = []
    for i_idx, xi in enumerate(indices):
        num = 1
        den = 1
        for j_idx, xj in enumerate(indices):
            if j_idx == i_idx:
                continue
            num = gf_mul(num, xj)
            den = gf_mul(den, xi ^ xj)
        coeffs0.append(gf_div(num, den))

    for pos in range(L):
        acc = 0
        for (_, share_bytes), c0 in zip(share_list, coeffs0):
            acc ^= gf_mul(share_bytes[pos], c0)
        out[pos] = acc
    return bytes(out)

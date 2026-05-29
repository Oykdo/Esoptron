"""Arithmetic in F_13 and base-13 conversion helpers.

Whitepaper II, sections 2.1, 5.2.

F_13 = Z/13Z. The primitive root alpha = 2 has order 12.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import List

Q = 13
ALPHA = 2  # primitive element of F_13*


def add(a: int, b: int) -> int:
    return (a + b) % Q


def sub(a: int, b: int) -> int:
    return (a - b) % Q


def mul(a: int, b: int) -> int:
    return (a * b) % Q


def inv(a: int) -> int:
    """Multiplicative inverse in F_13 via Fermat's little theorem."""
    if a % Q == 0:
        raise ZeroDivisionError("0 has no multiplicative inverse in F_13")
    return pow(a % Q, Q - 2, Q)


def div(a: int, b: int) -> int:
    return mul(a, inv(b))


def pow_(a: int, k: int) -> int:
    return pow(a % Q, k, Q)


# ----- base-13 packing -----

def bits_to_symbols(payload: bytes, n_symbols: int) -> List[int]:
    """Convert a byte string into n_symbols digits of base 13, big-endian.

    Raises ValueError if the integer value does not fit in n_symbols digits.
    """
    n = int.from_bytes(payload, "big") if payload else 0
    out: List[int] = []
    for _ in range(n_symbols):
        out.append(n % Q)
        n //= Q
    if n != 0:
        raise ValueError(
            f"payload {payload.hex()} does not fit in {n_symbols} base-13 digits"
        )
    return list(reversed(out))


def symbols_to_bits(symbols: List[int], n_bytes: int) -> bytes:
    """Inverse of bits_to_symbols: recover n_bytes big-endian from base-13 digits."""
    n = 0
    for s in symbols:
        if not (0 <= s < Q):
            raise ValueError(f"symbol {s} out of F_13")
        n = n * Q + s
    return n.to_bytes(n_bytes, "big")


# ----- HKDF-SHA3-512 (used by the public render path) -----

def _hkdf(hash_name: str, ikm: bytes, salt: bytes,
           info: bytes, length: int) -> bytes:
    hash_len = hashlib.new(hash_name).digest_size
    if not salt:
        salt = b"\x00" * hash_len
    prk = hmac.new(salt, ikm, hash_name).digest()

    n_blocks = (length + hash_len - 1) // hash_len
    if n_blocks > 255:
        raise ValueError("length too large for HKDF-Expand")
    okm = bytearray()
    t = b""
    for i in range(n_blocks):
        t = hmac.new(prk, t + info + bytes([i + 1]), hash_name).digest()
        okm.extend(t)
    return bytes(okm[:length])


def hkdf_sha3_512(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF (RFC 5869) instantiated with SHA3-512."""
    return _hkdf("sha3_512", ikm, salt, info, length)


def hkdf_sha3_256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF (RFC 5869) instantiated with SHA3-256.

    Centralised here so the format / genesis_token / recovery modules can
    share a single implementation. Previously each module rolled its own.
    """
    return _hkdf("sha3_256", ikm, salt, info, length)

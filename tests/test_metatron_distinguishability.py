"""Theorem 2 (Whitepaper III §4): the public and private encodings are
algebraically distinguishable.

- A private codeword always lies in the linear code C of dimension 70.
- A public render's symbols, derived from HKDF-SHA3-512 (PRF assumption),
  lie in C with negligible probability 13^-21 ~= 2^-77.8.
"""

import os
import random

from eopx.metatron import encode_public, encode_private, is_in_code
from eopx.metatron import reed_solomon as RS


def test_private_always_in_code():
    for _ in range(20):
        seed = os.urandom(32)
        cw = encode_private(seed)
        assert is_in_code(cw)


def test_public_almost_never_in_code():
    """50 distinct vault hashes should yield 0 false-positive memberships."""
    rng = random.Random(31415)
    hits = 0
    for _ in range(50):
        spinor = bytes(rng.randrange(256) for _ in range(64))
        symbols = encode_public(spinor)
        if is_in_code(symbols):
            hits += 1
    # Expected hits ~= 50 * 13^-21 ~= 1.6e-21, so 0 with overwhelming probability
    assert hits == 0


def test_public_is_deterministic():
    spinor = os.urandom(64)
    a = encode_public(spinor)
    b = encode_public(spinor)
    assert a == b


def test_public_avalanche():
    """Flipping one bit of spinor_hash must flip a large fraction of symbols."""
    spinor = bytearray(os.urandom(64))
    a = encode_public(bytes(spinor))
    spinor[0] ^= 0x01
    b = encode_public(bytes(spinor))
    diffs = sum(1 for x, y in zip(a, b) if x != y)
    # Under a PRF, expected diffs ~ 91 * (1 - 1/13) ~= 84. Allow a generous
    # tail for randomness.
    assert diffs >= 70, f"only {diffs}/91 symbols changed"

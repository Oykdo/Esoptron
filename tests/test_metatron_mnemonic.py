"""Private inscription (Metatron Mnemonic) round-trip and robustness."""

import os
import random

import pytest

from eopx.metatron import mnemonic
from eopx.metatron import reed_solomon as RS


def test_constants():
    assert mnemonic.SEED_BYTES == 32
    assert mnemonic.VERSION_BITS + mnemonic.SEED_BITS == 259


def test_round_trip_zero_seed():
    seed = b"\x00" * 32
    cw = mnemonic.encode_private(seed)
    assert len(cw) == 91
    rec_seed, rec_version = mnemonic.decode_private(cw)
    assert rec_seed == seed
    assert rec_version == 1


def test_round_trip_random_seeds():
    rng = random.Random(2026)
    for _ in range(10):
        seed = bytes(rng.randrange(256) for _ in range(32))
        cw = mnemonic.encode_private(seed)
        rec, ver = mnemonic.decode_private(cw)
        assert rec == seed
        assert ver == 1


def test_round_trip_with_erasures():
    """Same as RS recovery test, but at the mnemonic API level."""
    rng = random.Random(1)
    seed = os.urandom(32)
    cw = mnemonic.encode_private(seed)
    # Erase 3 carriers per block = 21 erasures total
    erasures = []
    for b in range(RS.NUM_BLOCKS):
        for i in rng.sample(range(RS.BLOCK_N), 3):
            erasures.append(i * RS.NUM_BLOCKS + b)
    damaged = list(cw)
    for p in erasures:
        damaged[p] = (damaged[p] + 4) % 13
    rec, _ = mnemonic.decode_private(damaged, erasures=erasures)
    assert rec == seed


def test_encoded_lies_in_code():
    seed = os.urandom(32)
    cw = mnemonic.encode_private(seed)
    assert RS.is_in_code(cw)


def test_seed_wrong_length():
    with pytest.raises(ValueError):
        mnemonic.encode_private(b"\x00" * 16)

"""Reed-Solomon RS(13, 10) over F_13, interleaved x7 = (91, 70)."""

import random

import pytest

from eopx.metatron import reed_solomon as RS


def test_constants():
    assert RS.BLOCK_N == 13
    assert RS.BLOCK_K == 10
    assert RS.BLOCK_D == 4
    assert RS.NUM_BLOCKS == 7
    assert RS.TOTAL_N == 91
    assert RS.TOTAL_K == 70


def test_block_round_trip_zero():
    msg = [0] * RS.BLOCK_K
    cw = RS.block_encode(msg)
    assert len(cw) == RS.BLOCK_N
    assert RS.is_block_codeword(cw)
    assert RS.block_decode(cw) == msg


def test_block_round_trip_random():
    rng = random.Random(42)
    for _ in range(20):
        msg = [rng.randrange(13) for _ in range(RS.BLOCK_K)]
        cw = RS.block_encode(msg)
        assert RS.is_block_codeword(cw)
        assert RS.block_decode(cw) == msg


def test_block_systematic_property():
    """block_encode is systematic on positions 0..9."""
    msg = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3]
    cw = RS.block_encode(msg)
    assert cw[:RS.BLOCK_K] == msg


@pytest.mark.parametrize("n_erasures", [1, 2, 3])
def test_block_erasure_recovery(n_erasures):
    rng = random.Random(7)
    for _ in range(20):
        msg = [rng.randrange(13) for _ in range(RS.BLOCK_K)]
        cw = RS.block_encode(msg)
        erased = rng.sample(range(RS.BLOCK_N), n_erasures)
        damaged = list(cw)
        for p in erased:
            damaged[p] = (cw[p] + 7) % 13  # arbitrary wrong value
        assert RS.block_decode(damaged, erasures=erased) == msg


def test_block_too_many_erasures():
    msg = list(range(RS.BLOCK_K))
    cw = RS.block_encode(msg)
    with pytest.raises(ValueError):
        RS.block_decode(cw, erasures=[0, 1, 2, 3])


def test_block_residual_error_detected():
    """If we declare 0 erasures but the codeword has been tampered with,
    the error+erasure decoder should now CORRECT the single error
    (d=4 allows t=1). The old behaviour was to raise; the new PGZ
    decoder recovers the original message."""
    msg = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    cw = RS.block_encode(msg)
    cw[5] = (cw[5] + 1) % 13  # introduce error at position 5
    # With the PGZ error decoder, this should now succeed:
    recovered = RS.block_decode(cw, erasures=None)
    assert recovered == msg


def test_block_error_plus_erasure():
    """1 error + 1 erasure: 2*1 + 1 = 3 <= d-1 = 3, must be correctable."""
    rng = random.Random(77)
    for _ in range(30):
        msg = [rng.randrange(13) for _ in range(RS.BLOCK_K)]
        cw = RS.block_encode(msg)
        # Erase position 0
        erasure_pos = 0
        # Error at a different position
        error_pos = rng.choice([p for p in range(RS.BLOCK_N) if p != erasure_pos])
        damaged = list(cw)
        damaged[erasure_pos] = (cw[erasure_pos] + 7) % 13
        damaged[error_pos] = (cw[error_pos] + 3) % 13
        recovered = RS.block_decode(damaged, erasures=[erasure_pos])
        assert recovered == msg


def test_full_round_trip():
    rng = random.Random(123)
    msg = [rng.randrange(13) for _ in range(RS.TOTAL_K)]
    cw = RS.encode(msg)
    assert len(cw) == RS.TOTAL_N
    assert RS.is_in_code(cw)
    assert RS.decode(cw) == msg


def test_full_erasure_recovery_3_per_block():
    """21 erasures, distributed at most 3 per block, must be recoverable."""
    rng = random.Random(99)
    msg = [rng.randrange(13) for _ in range(RS.TOTAL_K)]
    cw = RS.encode(msg)
    # Pick 3 erasures within each block (= 3 distinct codeword positions per block)
    erasures = []
    for b in range(RS.NUM_BLOCKS):
        for i in rng.sample(range(RS.BLOCK_N), 3):
            erasures.append(i * RS.NUM_BLOCKS + b)
    damaged = list(cw)
    for p in erasures:
        damaged[p] = (damaged[p] + 5) % 13
    assert RS.decode(damaged, erasures=erasures) == msg


def test_random_vector_not_in_code():
    """Theorem 2: a uniformly random F_13^91 vector lies in C with
    probability 13^-21 ~= 2^-78. With 50 trials we expect 0 successes."""
    rng = random.Random(2026)
    hits = 0
    for _ in range(50):
        v = [rng.randrange(13) for _ in range(RS.TOTAL_N)]
        if RS.is_in_code(v):
            hits += 1
    assert hits == 0, f"unexpected hits: {hits}"


def test_encoded_vector_is_in_code():
    rng = random.Random(2027)
    for _ in range(10):
        msg = [rng.randrange(13) for _ in range(RS.TOTAL_K)]
        assert RS.is_in_code(RS.encode(msg))

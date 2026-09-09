"""Decoded is not verified — and the layer must say which one it means.

A private inscription spends 259 of its ~259.2 available bits on version+seed,
so there is no checksum and no room for one. Re-encoding what the decoder
returned proves nothing either: the decoder's output is by construction close
to what was received, so the test would only re-derive the decoder's own
assumption. What *can* be established is whether the read needed correcting at
all, and that is what these tests pin.
"""

import random

import pytest

from eopx.flows import Intent, ScanContext, ScanResult, _record_read_integrity
from eopx.metatron import encode_private, encode_public
from eopx.metatron.reed_solomon import (
    BLOCK_N,
    NUM_BLOCKS,
    TOTAL_N,
    blocks_out_of_code,
    is_in_code,
)


@pytest.fixture(scope="module")
def clean():
    rng = random.Random(7)
    seed = bytes(rng.randrange(256) for _ in range(32))
    return list(encode_private(seed))


# --- the raw-read test -----------------------------------------------------

def test_a_clean_private_read_needs_no_repair(clean):
    assert blocks_out_of_code(clean) == []
    assert is_in_code(clean)


def test_a_single_flipped_symbol_shows_its_block(clean):
    for block in (0, 3, 6):
        damaged = list(clean)
        carrier = 2 * NUM_BLOCKS + block          # third symbol of that block
        damaged[carrier] = (damaged[carrier] + 1) % 13
        assert blocks_out_of_code(damaged) == [block]


def test_damage_in_several_blocks_is_all_reported(clean):
    damaged = list(clean)
    for block in (1, 4):
        carrier = block
        damaged[carrier] = (damaged[carrier] + 5) % 13
    assert blocks_out_of_code(damaged) == [1, 4]


def test_a_wrong_length_read_is_wholly_suspect():
    assert blocks_out_of_code([0] * (TOTAL_N - 1)) == list(range(NUM_BLOCKS))


def test_a_public_card_is_outside_the_code_by_construction():
    """Theorem 2's discriminator — and why membership cannot grade a public read."""
    import os
    public = encode_public(os.urandom(64))
    assert len(public) == TOTAL_N == BLOCK_N * NUM_BLOCKS
    assert not is_in_code(public)


# --- what the caller is told ----------------------------------------------

def _report(symbols, intent):
    result = ScanResult()
    _record_read_integrity(list(symbols), ScanContext(intent=intent), result)
    return result


def test_clean_private_read_is_reported_verified(clean):
    r = _report(clean, Intent.UNLOCK_PRIVATE)
    assert r.symbols_in_code is True
    assert r.blocks_repaired == 0
    assert r.symbols_verified is True
    assert "verified" in r.verification


def test_repaired_private_read_is_reported_unverified(clean):
    """The case that used to be announced as a plain success."""
    damaged = list(clean)
    damaged[5] = (damaged[5] + 1) % 13
    r = _report(damaged, Intent.GENESIS)
    assert r.symbols_in_code is False
    assert r.blocks_repaired == 1
    assert r.symbols_verified is False
    assert "unverified" in r.verification


@pytest.mark.parametrize("intent", [
    Intent.ENROLL, Intent.RECOVER, Intent.VERIFY, Intent.UNLOCK,
])
def test_public_card_intents_claim_nothing(intent):
    """A public card is outside C on purpose; membership grades nothing."""
    import os
    r = _report(encode_public(os.urandom(64)), intent)
    assert r.symbols_in_code is False        # expected, not a defect
    assert r.symbols_verified is None        # no claim either way
    assert "registry" in r.verification


def test_the_field_defaults_to_no_claim():
    """A ScanResult that never went through detection asserts nothing."""
    r = ScanResult()
    assert r.symbols_verified is None
    assert r.verification is None
    assert r.blocks_repaired is None

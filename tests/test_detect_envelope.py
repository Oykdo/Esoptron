"""The camera path's decode envelope, pinned so a regression fails loudly.

Measured with ``scripts/detect_envelope.py`` (canvas 1024, seed 2026). Each
axis is asserted at a level *inside* its measured envelope, so ordinary
resampling differences between platforms have room, while a real regression —
a palette change, a sampling change, a render change — pushes the worst block
past 1 and turns this file red.

The number that decides is ``worst_block``: RS(13,10) interleaved seven ways
corrects one error per block, so seven errors spread one per block decode and
three errors in one block do not.

Nothing here may become a ``pytest.skip``. A skip on the product's core risk
is an angle mort, not a tolerance.
"""

import random

import pytest

from eopx.metatron import encode_private, render
from eopx.metatron.degrade import (
    blur,
    canonical_fiducials,
    chroma_noise,
    illumination,
    jpeg,
    perspective,
    score,
)
from eopx.metatron.detect import erasures_from_confidences
from eopx.metatron.mnemonic import decode_private

CANVAS = 1024
SEED_RNG = 2026

# Measured envelopes (worst block still <= 1), canvas 1024:
#   perspective  2.25   | blur 4.0 px | JPEG q10
#   illumination 0.5    | chroma noise sigma 96
# The levels below sit inside those, with margin.
MUST_SURVIVE = {
    "perspective": 2.0,
    "blur": 3.0,
    "jpeg": 40,
    "illumination": 0.4,
    "noise": 32.0,
}


@pytest.fixture(scope="module")
def card():
    rng = random.Random(SEED_RNG)
    seed = bytes(rng.randrange(256) for _ in range(32))
    codeword = encode_private(seed)
    img = render(codeword, size=CANVAS)
    return seed, codeword, img, canonical_fiducials(CANVAS)


def _decode(sc, seed):
    """End-to-end: does the RS layer actually give the seed back?"""
    recovered, _ = decode_private(
        sc.symbols, erasures=erasures_from_confidences(sc.distances))
    return recovered == seed


# --- the reference point ---------------------------------------------------

def test_pristine_render_is_exact(card):
    seed, codeword, img, fid = card
    sc = score(img, fid, codeword, canvas=CANVAS)
    assert sc.errors == 0, f"a pristine render misread {sc.errors} carriers"
    assert _decode(sc, seed)


# --- one axis at a time ----------------------------------------------------

def test_perspective_within_envelope(card):
    seed, codeword, img, _ = card
    degraded, fid = perspective(img, MUST_SURVIVE["perspective"], canvas=CANVAS)
    sc = score(degraded, fid, codeword, canvas=CANVAS)
    assert sc.worst_block <= 1, f"per-block errors {sc.per_block}"
    assert _decode(sc, seed)


def test_blur_within_envelope(card):
    seed, codeword, img, fid = card
    sc = score(blur(img, MUST_SURVIVE["blur"]), fid, codeword, canvas=CANVAS)
    assert sc.worst_block <= 1, f"per-block errors {sc.per_block}"
    assert _decode(sc, seed)


def test_jpeg_within_envelope(card):
    seed, codeword, img, fid = card
    sc = score(jpeg(img, MUST_SURVIVE["jpeg"]), fid, codeword, canvas=CANVAS)
    assert sc.worst_block <= 1, f"per-block errors {sc.per_block}"
    assert _decode(sc, seed)


def test_illumination_within_envelope(card):
    seed, codeword, img, fid = card
    sc = score(illumination(img, MUST_SURVIVE["illumination"]), fid, codeword,
               canvas=CANVAS)
    assert sc.worst_block <= 1, f"per-block errors {sc.per_block}"
    assert _decode(sc, seed)


def test_chroma_noise_within_envelope(card):
    seed, codeword, img, fid = card
    sc = score(chroma_noise(img, MUST_SURVIVE["noise"], seed=7), fid, codeword,
               canvas=CANVAS)
    assert sc.worst_block <= 1, f"per-block errors {sc.per_block}"
    assert _decode(sc, seed)


# --- the cliff -------------------------------------------------------------

def test_perspective_cliff_is_where_we_think_it_is(card):
    """Geometry is the binding axis: past ~2.5 the block budget collapses.

    Documented, not tolerated — if this ever passes at 3.0 the pipeline got
    substantially better and the envelope above should be re-measured.
    """
    _seed, codeword, img, _ = card
    degraded, fid = perspective(img, 3.0, canvas=CANVAS)
    sc = score(degraded, fid, codeword, canvas=CANVAS)
    assert sc.worst_block > 1


# --- axes compound ---------------------------------------------------------

def test_a_plausible_photo_decodes(card):
    """Every axis at a level a steady handheld shot would plausibly produce."""
    seed, codeword, img, _ = card
    degraded, fid = perspective(img, 1.5, canvas=CANVAS)
    degraded = blur(degraded, 1.5)
    degraded = illumination(degraded, 0.2)
    degraded = chroma_noise(degraded, 8.0, seed=7)
    degraded = jpeg(degraded, 70)
    sc = score(degraded, fid, codeword, canvas=CANVAS)
    assert sc.worst_block <= 1, f"per-block errors {sc.per_block}"
    assert _decode(sc, seed), "a plausible photo must round-trip to the seed"


def test_degradation_compounds_across_axes(card):
    """Each axis alone is inside its envelope; together they are not.

    This is the finding that matters: single-axis envelopes are optimistic,
    because a real photo pays every axis at once. The bound below says how bad
    a *mediocre* shot gets — worst block 2, which pure error correction cannot
    fix but three erasures per block could.
    """
    _seed, codeword, img, _ = card
    degraded, fid = perspective(img, 2.0, canvas=CANVAS)
    degraded = blur(degraded, 2.5)
    degraded = illumination(degraded, 0.35)
    degraded = chroma_noise(degraded, 16.0, seed=7)
    degraded = jpeg(degraded, 50)
    sc = score(degraded, fid, codeword, canvas=CANVAS)
    assert sc.worst_block >= 2, (
        "the mediocre-photo case no longer compounds past the error budget — "
        "re-measure the envelope and re-pin this test")
    assert sc.worst_block <= 3, f"degradation worse than recorded: {sc.per_block}"

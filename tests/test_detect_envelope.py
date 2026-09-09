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
    fiducial_jitter,
    fiducial_radius,
    fiducial_shift,
    illumination,
    jpeg,
    tilt,
    score,
)
from eopx.metatron.detect import erasures_from_confidences
from eopx.metatron.mnemonic import decode_private

CANVAS = 1024
SEED_RNG = 2026

# Measured envelopes (worst block still <= 1), canvas 1024, seeds 2026 and 77:
#   tilt 84 deg          | blur 4.0 px | JPEG q10
#   illumination 0.5    | chroma noise sigma 96
#   fiducial error: 12 px common mode, sigma 6 px differential
# The levels below sit inside those, with margin.
#
# The geometry axis was `perspective(img, strength)` until 2026-09-09, pinned
# at 2.25, and neither the scalar nor the envelope meant anything. It displaced
# the six fiducials by six hand-chosen vectors no homography can realise,
# least-squares-fitted a matrix, warped by the fit and returned the *unfitted*
# targets -- 68 px of injected fiducial error at the pinned level. On top of
# that `detect._compute_homography` advertised a normalised DLT and performed
# none, which was the larger half again.
#
# Both are fixed. `tilt` rotates the card plane and derives the fiducials from
# the homography, so the residual is identically zero, and the scalar is an
# angle. The envelope is 84 degrees -- a card nearly edge-on -- against 2.25
# opaque units. Geometry is not the binding axis and never was; the fitter
# was.
MUST_SURVIVE = {
    "tilt": 60.0,
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

def test_tilt_within_envelope(card):
    seed, codeword, img, _ = card
    degraded, fid = tilt(img, MUST_SURVIVE["tilt"], canvas=CANVAS)
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

def test_geometry_is_not_the_binding_axis(card):
    """Rewritten 2026-09-09. It used to assert the opposite, twice over.

    The old claim was "geometry is the binding axis: past ~2.5 the block budget
    collapses". Two defects made it: `detect._compute_homography` advertised a
    normalised DLT and performed none, and the axis itself displaced the six
    fiducials by vectors no homography can realise, then handed the rectifier
    the unfitted targets. Between them the axis was four parts fiducial error
    to one part geometry.

    With both fixed and the axis a real tilt, a card holds to **84 degrees**
    and fails at 85 -- nearly edge-on. Both bounds hold on seeds 2026 and 77.
    Tilt is not a binding condition at any angle a person would photograph
    from; finding the fiducials is the whole cost.
    """
    _seed, codeword, img, _ = card

    assert score(*tilt(img, 80.0, canvas=CANVAS), codeword,
                 canvas=CANVAS).worst_block <= 1, "the envelope shrank"

    assert score(*tilt(img, 85.0, canvas=CANVAS), codeword,
                 canvas=CANVAS).worst_block > 1, (
        "geometry now survives past 16 — re-measure the envelope and re-pin, "
        "and check the fiducial axes too, since they moved together last time")


# --- axes compound ---------------------------------------------------------

def test_a_plausible_photo_decodes(card):
    """Every axis at a level a steady handheld shot would plausibly produce."""
    seed, codeword, img, _ = card
    degraded, fid = tilt(img, 20.0, canvas=CANVAS)
    degraded = blur(degraded, 1.5)
    degraded = illumination(degraded, 0.2)
    degraded = chroma_noise(degraded, 8.0, seed=7)
    degraded = jpeg(degraded, 70)
    sc = score(degraded, fid, codeword, canvas=CANVAS)
    assert sc.worst_block <= 1, f"per-block errors {sc.per_block}"
    assert _decode(sc, seed), "a plausible photo must round-trip to the seed"


def test_degradation_compounds_but_stays_within_budget(card):
    """Rewritten 2026-09-09: axes still compound, and no longer past the budget.

    The old assertion was `worst_block >= 2` — "a mediocre photo pays every
    axis at once and lands past pure error correction". That was true when it
    was written and is false now, for the same reason as the cliff above: the
    homography fit and the axis itself were contributing most of the damage
    attributed to geometry. With both corrected and a real 30-degree tilt, the
    same stack yields 3 errors on seed 2026 and 2 on seed 77, worst block 1 on
    both.

    Compounding itself is real and still worth pinning — errors do accumulate
    across axes rather than staying at zero. What is no longer true is that
    they accumulate *past the error budget*, and the difference matters: it is
    the premise the erasure ladder in `tests/test_erasure_budget.py` was built
    on.
    """
    _seed, codeword, img, _ = card
    degraded, fid = tilt(img, 30.0, canvas=CANVAS)
    degraded = blur(degraded, 2.5)
    degraded = illumination(degraded, 0.35)
    degraded = chroma_noise(degraded, 16.0, seed=7)
    degraded = jpeg(degraded, 50)
    sc = score(degraded, fid, codeword, canvas=CANVAS)

    assert sc.errors > 0, (
        "the mediocre stack now reads every carrier correctly — the axes no "
        "longer compound at all, which would be a bigger change than a re-pin")
    assert sc.worst_block <= 1, (
        f"the mediocre photo fell past the error budget again: {sc.per_block}")


# --- fiducial localisation: the term the bench used to exclude -------------
#
# Every axis above degrades the image and then hands the rectifier the six
# fiducials exactly. A scanner has to find them. These two tests pin what that
# error costs, and the answer decides where fiducials should be placed --
# which is a live question (audit N-10, `metatron/local_rectify.py`).

def test_common_mode_fiducial_error_is_cheap_but_not_free(card):
    """A uniform mislocation slides the sampling grid; it is not absorbed.

    It is tempting to expect a homography to swallow a translation. It does
    not here, because the *destination* is the fixed canonical frame: shifting
    every source correspondence reads every carrier off-centre by the same
    amount. Measured envelope is 12 px on a 1024 canvas; 8 is asserted.
    """
    _, codeword, img, fid = card
    sc = score(img, fiducial_shift(fid, 8.0, 0.0), codeword, canvas=CANVAS)
    assert sc.worst_block <= 1, sc.per_block

    # And it does break, so the test above is not vacuous.
    broken = score(img, fiducial_shift(fid, 24.0, 0.0), codeword, canvas=CANVAS)
    assert broken.worst_block > 1


def test_differential_fiducial_error_is_dearer_than_common_mode(card):
    """Rewritten 2026-09-09. The direction survived; the factor did not.

    First measured the same day as an order of magnitude — sigma 1 px already
    losing draws against 12 px of uniform slide — and published as a
    requirement of "about one pixel of relative accuracy over a 410 px figure
    radius". That figure was mostly an artefact of the un-normalised
    homography fit: with `detect._compute_homography` conditioned properly the
    differential envelope moved from 0.5 px to 6 px, while the common-mode
    envelope did not move at all.

    The asymmetry is therefore real but modest — roughly 2x, not 24x — and the
    honest requirement is nearer **6 px over a 410 px radius, about 1.5%**.
    Single draws still vary, because one badly-placed fiducial dominates the
    fit, so this asserts on the distribution.
    """
    _, codeword, img, fid = card

    def in_budget(sigma, seeds=5):
        return sum(
            1 for s in range(seeds)
            if score(img, fiducial_jitter(fid, sigma, seed=s),
                     codeword, canvas=CANVAS).worst_block <= 1
        )

    assert in_budget(0.0) == 5, "no jitter must be exact"
    assert in_budget(6.0) == 5, "the differential envelope shrank below 6 px"
    # It does break, so the assertion above is not vacuous: 3/5 at 12 px and
    # 1/5 at 16 px on both seeds measured.
    assert in_budget(16.0) <= 2


def test_fiducial_radius_makes_a_sigma_scale_free(card):
    """A pixel budget is meaningless without the figure it is measured against."""
    r = fiducial_radius(CANVAS)
    assert 0.35 * CANVAS < r < 0.45 * CANVAS
    # Twice the canvas, twice the radius: the ratio is what transfers.
    assert fiducial_radius(2 * CANVAS) == pytest.approx(2 * r, rel=1e-6)

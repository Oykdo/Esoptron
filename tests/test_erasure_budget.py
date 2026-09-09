"""Spending the erasure budget: per block, ranked by margin.

The code is RS(13,10) interleaved seven ways. A block satisfies ``2t + e <= 3``,
so an erasure is worth three times an error — but only in the block it lands
in, and only if it lands on a carrier that was actually wrong. Which carrier
is wrong is a *ranking* problem, and these tests pin the two findings that
decide it:

* absolute Oklab distance barely separates misreads from good reads under a
  mediocre photograph — the two distributions overlap;
* the margin (how much closer to the winner than to the runner-up) does,
  because a shadow or a warm lamp pushes every carrier away from the palette
  at once, and a difference cancels what a magnitude cannot.
"""

import random
import statistics

import pytest

from eopx.metatron import encode_private, render
from eopx.metatron.degrade import (
    blur,
    chroma_noise,
    illumination,
    jpeg,
    tilt,
)
from eopx.metatron.detect import (
    erasures_from_confidences,
    erasures_per_block,
    extract_canonical,
    extract_canonical_full,
    extract_robust,
    rectify,
)
from eopx.metatron.mnemonic import decode_private
from eopx.metatron.palette import classify_margin, srgb_for_symbol
from eopx.metatron.reed_solomon import NUM_BLOCKS

CANVAS = 1024

#: Every axis at a level a mediocre-but-ordinary shot produces.
#:
#: This used to say "together they push the worst block to 2, past pure error
#: correction — the case the margin has to rescue". It no longer does, and the
#: reason is not that the photo got easier: the geometry axis was
#: `perspective(strength=2.0)`, which injected 68 px of fiducial error under
#: the name of tilt, on top of an un-normalised homography fit. With both
#: corrected and a real 30-degree tilt the stack yields 3 errors on seed 2026
#: and worst block 1 — inside the error budget, needing no erasures at all.
MEDIOCRE = dict(tilt=30.0, blur=2.5, illumination=0.35,
                noise=16.0, jpeg=50)


@pytest.fixture(scope="module")
def card():
    rng = random.Random(2026)
    seed = bytes(rng.randrange(256) for _ in range(32))
    codeword = encode_private(seed)
    return seed, codeword, render(codeword, size=CANVAS)


@pytest.fixture(scope="module")
def mediocre(card):
    """(symbols, distances, margins) read off a mediocre photograph."""
    _seed, _cw, img = card
    degraded, fid = tilt(img, MEDIOCRE["tilt"], canvas=CANVAS)
    degraded = blur(degraded, MEDIOCRE["blur"])
    degraded = illumination(degraded, MEDIOCRE["illumination"])
    degraded = chroma_noise(degraded, MEDIOCRE["noise"], seed=7)
    degraded = jpeg(degraded, MEDIOCRE["jpeg"])
    rect = rectify(degraded, fid, dst_size=CANVAS)
    return extract_canonical_full(rect)


# --- the margin itself -----------------------------------------------------

def test_a_palette_colour_is_decided():
    """An exact palette colour sits far from every rival."""
    for symbol in range(13):
        _sym, _d, margin = classify_margin(*srgb_for_symbol(symbol))
        assert margin > 0.05, f"symbol {symbol} has no margin"


def test_a_colour_between_two_entries_is_not_decided():
    """Halfway between two palette entries, the margin collapses."""
    a = srgb_for_symbol(3)
    b = srgb_for_symbol(4)
    mid = tuple((x + y) // 2 for x, y in zip(a, b))
    _sym, _d, margin = classify_margin(*mid)
    _sym_a, _d_a, margin_a = classify_margin(*a)
    assert margin < margin_a


def test_pristine_render_is_decided_everywhere(card):
    _seed, codeword, img = card
    syms, _dists, margins = extract_canonical_full(img)
    assert syms == list(codeword)
    assert min(margins) > 0.05, f"least decided carrier: {min(margins):.4f}"


def test_extract_canonical_kept_its_two_value_shape(card):
    """Callers since the beginning unpack two values; that must not move."""
    _seed, _cw, img = card
    syms, dists = extract_canonical(img)
    full_syms, full_dists, _margins = extract_canonical_full(img)
    assert syms == full_syms
    assert dists == full_dists


# --- the finding that motivates the whole change ---------------------------

def test_margin_separates_where_distance_does_not(card, mediocre):
    _seed, codeword, _img = card
    syms, dists, margins = mediocre
    bad = [i for i, (a, b) in enumerate(zip(syms, codeword)) if a != b]
    good = [i for i in range(len(syms)) if i not in bad]
    assert bad, "the mediocre photo should misread something"

    margin_bad = statistics.median(margins[i] for i in bad)
    margin_good = statistics.median(margins[i] for i in good)
    dist_bad = statistics.median(dists[i] for i in bad)
    dist_good = statistics.median(dists[i] for i in good)

    assert margin_bad < margin_good / 2, (
        f"margin fails to separate: bad {margin_bad:.4f} vs good {margin_good:.4f}")
    # And the reason the old ranking could not work:
    assert abs(dist_bad - dist_good) < 0.02, (
        f"distance unexpectedly separated: {dist_bad:.4f} vs {dist_good:.4f}")


# --- budgeting -------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 3])
def test_never_flags_more_than_n_per_block(mediocre, n):
    _syms, dists, margins = mediocre
    era = erasures_per_block(dists, margins=margins, max_per_block=n)
    per_block = [sum(1 for i in era if i % NUM_BLOCKS == b)
                 for b in range(NUM_BLOCKS)]
    assert max(per_block) <= n
    assert era == sorted(era)


def test_confident_carriers_are_left_alone(card):
    """A pristine render should spend no budget at all."""
    _seed, _cw, img = card
    _syms, dists, margins = extract_canonical_full(img)
    assert erasures_per_block(dists, margins=margins, max_per_block=3) == []


# --- the payoff ------------------------------------------------------------

def test_the_mediocre_photo_no_longer_needs_rescuing(card, mediocre):
    """Rewritten 2026-09-09. This test used to demonstrate the margin ladder,
    and the demonstration is gone.

    It asserted that ``MEDIOCRE`` fails to decode with distance-ranked
    erasures and succeeds with margin-ranked ones -- the finding the whole
    erasure-ranking work rests on. With ``detect._compute_homography``
    normalised (it claimed a normalised DLT and did none), the same photograph
    **decodes with no erasures at all**. The failure it was rescuing was
    largely produced by the fit.

    Searched for a level where the margin still makes the difference:
    perspective 7 to 10, blur 3.0 to 3.5 in steps of 0.1, JPEG q50/q40/q30.
    There is no window -- the transition from "decodes unaided" to "nothing
    decodes" is a single blur step. That is on one card and one degradation
    family, so it does not prove margin ranking useless; it does mean this
    bench no longer demonstrates its benefit, and a test that claimed
    otherwise would be asserting a result nobody can reproduce.

    What is pinned instead is the fact that replaced it: the ladder is not
    needed here, and margin-ranked erasures do not *break* what already works.
    Anyone reviving the original claim needs a case where a photo genuinely
    fails, and should re-derive it rather than re-tune this one until it goes
    red.
    """
    seed, _cw, _img = card
    syms, dists, margins = mediocre

    unaided, _version = decode_private(syms)
    assert unaided == seed, (
        "the mediocre photo needs help again -- the erasure ladder may be "
        "demonstrable once more; re-derive it rather than restoring the old "
        "assertions")

    for era in (erasures_from_confidences(dists),
                erasures_per_block(dists, margins=margins, max_per_block=1)):
        recovered, _version = decode_private(syms, erasures=era)
        assert recovered == seed, "spending erasures broke a working decode"


def test_extract_robust_recovers_the_mediocre_photo(card):
    """End to end through the retry ladder, not by calling the pieces."""
    seed, _cw, img = card
    degraded, fid = tilt(img, MEDIOCRE["tilt"], canvas=CANVAS)
    degraded = blur(degraded, MEDIOCRE["blur"])
    degraded = illumination(degraded, MEDIOCRE["illumination"])
    degraded = chroma_noise(degraded, MEDIOCRE["noise"], seed=7)
    degraded = jpeg(degraded, MEDIOCRE["jpeg"])
    rect = rectify(degraded, fid, dst_size=CANVAS)

    reached = []

    def decode_fn(symbols, erasures=None):
        try:
            recovered, _version = decode_private(symbols, erasures=erasures)
        except ValueError:
            return None
        if recovered == seed:
            reached.append(list(erasures or []))
            return recovered
        return None

    extract_robust(rect, decode_fn=decode_fn)
    assert reached, "the retry ladder never reached a successful decode"
    per_block = [sum(1 for i in reached[0] if i % NUM_BLOCKS == b)
                 for b in range(NUM_BLOCKS)]
    assert max(per_block) <= 1, (
        f"the ladder should have succeeded frugally, spent {per_block}")

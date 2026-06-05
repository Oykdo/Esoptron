"""Golden-egg emblem rendering (EPX-E brand asset)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from eopx.egg_token import TIERS
from eopx.metatron.egg_emblem import TIER_PALETTE, render_egg_emblem, tier_palette


def _fake_egg(tier: str, glyph: str):
    return SimpleNamespace(tier=tier, glyph=glyph, egg_id="GE-042",
                           name=f"Golden Egg 042 {glyph} — {tier} Clutch")


@pytest.mark.parametrize("name,glyph", [(n, g) for n, _, g in TIERS])
def test_renders_each_tier(name, glyph):
    img = render_egg_emblem(_fake_egg(name, glyph), size=160)
    assert img.size == (160, 160)
    assert img.mode == "RGBA"
    # Something was drawn (non-transparent pixels exist).
    assert img.getbbox() is not None


def test_every_tier_has_a_palette():
    assert {n for n, _, _ in TIERS} <= set(TIER_PALETTE)


def test_unknown_tier_falls_back():
    # No exception, and a stable fallback palette.
    img = render_egg_emblem(_fake_egg("Mythic", "✷"), size=120)
    assert img.size == (120, 120)
    assert tier_palette("Mythic") == tier_palette("definitely-not-a-tier")


def test_caption_toggle_changes_drawing():
    with_cap = render_egg_emblem(_fake_egg("Lunar", "☾"), size=200)
    no_cap = render_egg_emblem(_fake_egg("Lunar", "☾"), size=200,
                               with_caption=False)
    # The captioned version paints lower into the canvas than the bare egg.
    bb_cap = with_cap.getbbox()
    bb_bare = no_cap.getbbox()
    assert bb_cap is not None and bb_bare is not None
    assert bb_cap[3] >= bb_bare[3]

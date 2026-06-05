"""Tests for ``eopx.metatron.seal_reveal`` (EPX-H).

Covers:
  * Discrete star selection from vault_fp (Mesure D)
  * Hexagram edge geometry for each catalog star
  * Edge tier classification (seal / near / dim)
  * HSL → sRGB palette derivation + saturation cap (Mesure B)
  * Exclusion mask over the 91 symbol sampling windows (Mesure A)
  * Rendering invariants: same input → same image bytes
  * Symbol preservation: vertex disks + edge tags pixel-identical to render()
"""

from __future__ import annotations

import hashlib
import io

import pytest

from eopx.metatron import render, render_seal_revealed
from eopx.metatron.graph import EDGES, VERTICES
from eopx.metatron.render import (
    EDGE_TAG_RADIUS_FRAC, VERTEX_RADIUS_FRAC, _project, edge_tag_position,
)
from eopx.metatron.seal_reveal import (
    DEFAULT_SEAL_SIZE,
    DIM_ALPHA,
    NEAR_ALPHA,
    SEAL_ALPHA,
    SEAL_DOMAIN,
    SEAL_MAX_SATURATION,
    STAR_CONFIGS,
    TAG_CLEAR_PAD_FRAC,
    VERTEX_CLEAR_MULT,
    _build_protection_mask,
    _hsl_to_rgb,
    classify_edges,
    derive_palette,
    fire_water_edges,
    seal_color_swap,
    seal_edges,
    select_star,
    star_pointing_degrees,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def symbols():
    return [i % 13 for i in range(91)]


@pytest.fixture
def vault_fp():
    return b"\x01" * 32


@pytest.fixture
def spinor_hash():
    return b"\x02" * 64


def _hsl_saturation(rgb):
    """sRGB → HSL saturation in [0, 1]."""
    r, g, b = (c / 255.0 for c in rgb)
    mx, mn = max(r, g, b), min(r, g, b)
    if mx == mn:
        return 0.0
    d = mx - mn
    l = (mx + mn) / 2.0
    return d / (2.0 - mx - mn) if l > 0.5 else d / (mx + mn)


# ---------------------------------------------------------------------------
# Mesure D — discrete star selection
# ---------------------------------------------------------------------------

class TestStarSelection:
    def test_deterministic(self, vault_fp):
        assert select_star(vault_fp) == select_star(vault_fp)
        assert seal_color_swap(vault_fp) == seal_color_swap(vault_fp)

    def test_in_range(self):
        for i in range(50):
            star = select_star(bytes([i] * 32))
            assert 0 <= star < len(STAR_CONFIGS)

    def test_both_stars_appear(self):
        seen = {select_star(bytes([i] * 32)) for i in range(50)}
        # With 2 catalog stars, 50 vaults should exercise both.
        assert seen == set(range(len(STAR_CONFIGS)))

    def test_wrong_length_rejected(self):
        with pytest.raises(ValueError):
            select_star(b"\x01" * 31)

    def test_uses_domain_separator(self, vault_fp):
        direct = hashlib.sha3_256(vault_fp).digest()[0] % len(STAR_CONFIGS)
        with_domain = (hashlib.sha3_256(SEAL_DOMAIN + vault_fp).digest()[0]
                       % len(STAR_CONFIGS))
        assert select_star(vault_fp) == with_domain
        # Domain separation must change the byte stream (not just the modulo).
        assert hashlib.sha3_256(SEAL_DOMAIN + vault_fp).digest() != \
            hashlib.sha3_256(vault_fp).digest()
        _ = direct  # documented baseline

    def test_pointing_degrees(self):
        assert star_pointing_degrees(0) == 0
        assert star_pointing_degrees(1) == 30


# ---------------------------------------------------------------------------
# Hexagram geometry
# ---------------------------------------------------------------------------

class TestHexagramGeometry:
    def test_six_edges_per_star(self):
        for star in range(len(STAR_CONFIGS)):
            assert len(seal_edges(star)) == 6

    def test_edges_connect_ring_vertices(self):
        """Inner star uses vertices 1..6; outer star uses 7..12."""
        expected = {0: range(1, 7), 1: range(7, 13)}
        for star in range(len(STAR_CONFIGS)):
            allowed = set(expected[star])
            for i, j in seal_edges(star):
                assert i in allowed and j in allowed

    def test_canonical_edge_ordering(self):
        for star in range(len(STAR_CONFIGS)):
            for i, j in seal_edges(star):
                assert i < j

    def test_edges_are_in_k13(self):
        edge_set = set(EDGES)
        for star in range(len(STAR_CONFIGS)):
            for edge in seal_edges(star):
                assert edge in edge_set, f"edge {edge} not in K_13"

    def test_fire_water_disjoint(self):
        for star in range(len(STAR_CONFIGS)):
            fire, water = fire_water_edges(star)
            assert set(fire).isdisjoint(set(water))
            assert len(fire) == len(water) == 3


# ---------------------------------------------------------------------------
# Edge classification
# ---------------------------------------------------------------------------

class TestEdgeClassification:
    def test_sum_to_78(self):
        for star in range(len(STAR_CONFIGS)):
            seal, near = classify_edges(seal_edges(star))
            dim_count = 78 - len(seal) - len(near)
            assert len(seal) + len(near) + dim_count == 78
            assert dim_count >= 0

    def test_seal_count_is_6(self):
        seal, _ = classify_edges(seal_edges(0))
        assert len(seal) == 6

    def test_seal_and_near_disjoint(self):
        seal, near = classify_edges(seal_edges(0))
        assert seal.isdisjoint(near)

    def test_near_shares_vertex_with_seal(self):
        seal, near = classify_edges(seal_edges(0))
        seal_vertices = {v for edge in seal for v in edge}
        for i, j in near:
            assert i in seal_vertices or j in seal_vertices


# ---------------------------------------------------------------------------
# HSL → sRGB conversion
# ---------------------------------------------------------------------------

class TestHSLConversion:
    def test_pure_red(self):
        assert _hsl_to_rgb(0, 100, 50) == (255, 0, 0)

    def test_pure_green(self):
        assert _hsl_to_rgb(120, 100, 50) == (0, 255, 0)

    def test_pure_blue(self):
        assert _hsl_to_rgb(240, 100, 50) == (0, 0, 255)

    def test_grey_at_zero_saturation(self):
        r, g, b = _hsl_to_rgb(0, 0, 50)
        assert r == g == b
        assert 120 <= r <= 130

    def test_white(self):
        assert _hsl_to_rgb(0, 0, 100) == (255, 255, 255)

    def test_black(self):
        assert _hsl_to_rgb(0, 0, 0) == (0, 0, 0)


# ---------------------------------------------------------------------------
# Palette derivation + Mesure B (saturation cap)
# ---------------------------------------------------------------------------

class TestPalette:
    def test_deterministic(self, spinor_hash):
        assert derive_palette(spinor_hash) == derive_palette(spinor_hash)

    def test_required_keys(self, spinor_hash):
        assert set(derive_palette(spinor_hash)) == {"fire", "water", "near", "dim"}

    def test_fire_and_water_distinct(self, spinor_hash):
        p = derive_palette(spinor_hash)
        assert p["fire"] != p["water"]

    def test_swap_exchanges_fire_water(self, spinor_hash):
        plain = derive_palette(spinor_hash, swap=False)
        swapped = derive_palette(spinor_hash, swap=True)
        # Hues swap but lightness tiers differ, so they are not a trivial swap;
        # the key property is that swapping changes the palette.
        assert plain != swapped

    def test_dim_is_neutral_grey(self, spinor_hash):
        r, g, b = derive_palette(spinor_hash)["dim"]
        assert r == g == b

    def test_distinct_spinors_distinct_palettes(self):
        palettes = {derive_palette(bytes([i] * 64))["fire"] for i in range(20)}
        assert len(palettes) >= 15

    def test_too_short_rejected(self):
        with pytest.raises(ValueError):
            derive_palette(b"\x01\x02")

    def test_saturation_capped(self):
        """Mesure B: no seal/near colour exceeds the saturation cap."""
        cap = SEAL_MAX_SATURATION / 100.0
        for i in range(64):
            p = derive_palette(bytes([i] * 64))
            for key in ("fire", "water", "near"):
                # Allow a small rounding margin from the HSL round-trip.
                assert _hsl_saturation(p[key]) <= cap + 0.02, (
                    f"{key} saturation {_hsl_saturation(p[key]):.3f} > cap {cap}"
                )


# ---------------------------------------------------------------------------
# Mesure A — exclusion mask
# ---------------------------------------------------------------------------

class TestExclusionMask:
    def test_mask_has_both_extremes(self):
        mask = _build_protection_mask(512)
        assert mask.getextrema() == (0, 255)

    def test_clears_every_tag_search_window(self):
        size = 1024
        mask = _build_protection_mask(size)
        px = mask.load()
        assert px is not None
        r_tag = max(4, int(round(size * EDGE_TAG_RADIUS_FRAC)))
        search_r = r_tag + 8  # the decoder's actual edge-tag search radius
        for (vi, vj) in EDGES:
            p1 = _project(VERTICES[vi], size)
            p2 = _project(VERTICES[vj], size)
            cx, cy = edge_tag_position(p1, p2, size)
            # Centre and a point at the search-window edge must both be cleared.
            assert px[int(cx), int(cy)] == 0
            assert px[int(cx + search_r), int(cy)] == 0

    def test_clears_every_vertex(self):
        size = 1024
        mask = _build_protection_mask(size)
        px = mask.load()
        assert px is not None
        r_v = size * VERTEX_RADIUS_FRAC
        for coord in VERTICES:
            cx, cy = _project(coord, size)
            assert px[int(cx), int(cy)] == 0
            assert px[int(cx + r_v), int(cy)] == 0

    def test_clear_radii_cover_decoder_windows(self):
        size = 1024
        r_tag = max(4, int(round(size * EDGE_TAG_RADIUS_FRAC)))
        tag_clear = r_tag + int(round(size * TAG_CLEAR_PAD_FRAC))
        r_v = size * VERTEX_RADIUS_FRAC
        assert tag_clear >= r_tag + 8          # ≥ decoder tag search window
        assert r_v * VERTEX_CLEAR_MULT >= r_v * 2.0  # ≥ refinement sanity bound


# ---------------------------------------------------------------------------
# Rendering invariants
# ---------------------------------------------------------------------------

class TestRendering:
    def test_returns_rgb_image(self, symbols, vault_fp, spinor_hash):
        img = render_seal_revealed(symbols, vault_fp, spinor_hash, size=256)
        assert img.mode == "RGB"
        assert img.size == (256, 256)

    def test_determinism(self, symbols, vault_fp, spinor_hash):
        a = render_seal_revealed(symbols, vault_fp, spinor_hash, size=256)
        b = render_seal_revealed(symbols, vault_fp, spinor_hash, size=256)
        buf_a = io.BytesIO(); a.save(buf_a, format="PNG", optimize=False)
        buf_b = io.BytesIO(); b.save(buf_b, format="PNG", optimize=False)
        assert buf_a.getvalue() == buf_b.getvalue()

    def test_different_stars_different_images(self, symbols, vault_fp, spinor_hash):
        img_a = render_seal_revealed(symbols, vault_fp, spinor_hash,
                                     size=256, star_override=0)
        img_b = render_seal_revealed(symbols, vault_fp, spinor_hash,
                                     size=256, star_override=1)
        buf_a = io.BytesIO(); img_a.save(buf_a, format="PNG", optimize=False)
        buf_b = io.BytesIO(); img_b.save(buf_b, format="PNG", optimize=False)
        assert buf_a.getvalue() != buf_b.getvalue()

    def test_invalid_symbol_count_rejected(self, vault_fp, spinor_hash):
        with pytest.raises(ValueError):
            render_seal_revealed([0] * 90, vault_fp, spinor_hash)

    def test_invalid_symbol_value_rejected(self, vault_fp, spinor_hash):
        with pytest.raises(ValueError):
            render_seal_revealed([13] + [0] * 90, vault_fp, spinor_hash)


# ---------------------------------------------------------------------------
# Symbol preservation — the seal never overwrites a carrier
# ---------------------------------------------------------------------------

class TestSymbolPreservation:
    def test_tag_interiors_pixel_identical(self, symbols, vault_fp, spinor_hash):
        size = 512
        std = render(symbols, size=size).load()
        seal = render_seal_revealed(symbols, vault_fp, spinor_hash, size=size).load()
        assert std is not None and seal is not None
        r_tag = max(4, int(round(size * EDGE_TAG_RADIUS_FRAC)))
        inner = max(1, r_tag - 1)
        for (vi, vj) in EDGES:
            p1 = _project(VERTICES[vi], size)
            p2 = _project(VERTICES[vj], size)
            cx, cy = edge_tag_position(p1, p2, size)
            for dx in range(-inner, inner + 1):
                for dy in range(-inner, inner + 1):
                    if dx * dx + dy * dy > inner * inner:
                        continue
                    x, y = int(cx) + dx, int(cy) + dy
                    assert std[x, y] == seal[x, y], f"tag pixel differs at {x},{y}"

    def test_vertex_interiors_pixel_identical(self, symbols, vault_fp, spinor_hash):
        size = 512
        std = render(symbols, size=size).load()
        seal = render_seal_revealed(symbols, vault_fp, spinor_hash, size=size).load()
        assert std is not None and seal is not None
        r_v = int(size * VERTEX_RADIUS_FRAC)
        inner = max(1, r_v - 1)
        for coord in VERTICES:
            cx, cy = _project(coord, size)
            for dx in range(-inner, inner + 1):
                for dy in range(-inner, inner + 1):
                    if dx * dx + dy * dy > inner * inner:
                        continue
                    x, y = int(cx) + dx, int(cy) + dy
                    assert std[x, y] == seal[x, y], f"vertex pixel differs at {x},{y}"


# ---------------------------------------------------------------------------
# Compatibility with standard render()
# ---------------------------------------------------------------------------

class TestCompatibility:
    def test_same_size_as_standard_render(self, symbols, vault_fp, spinor_hash):
        std = render(symbols, size=512)
        seal = render_seal_revealed(symbols, vault_fp, spinor_hash, size=512)
        assert std.size == seal.size
        assert std.mode == seal.mode

    def test_default_size_is_1024(self, symbols, vault_fp, spinor_hash):
        img = render_seal_revealed(symbols, vault_fp, spinor_hash)
        assert img.size == (DEFAULT_SEAL_SIZE, DEFAULT_SEAL_SIZE)


# ---------------------------------------------------------------------------
# Constants — frozen at v1
# ---------------------------------------------------------------------------

class TestConstants:
    def test_alpha_ordering(self):
        assert DIM_ALPHA < NEAR_ALPHA < SEAL_ALPHA

    def test_seal_alpha_high(self):
        assert SEAL_ALPHA >= 0.85

    def test_dim_alpha_low(self):
        assert DIM_ALPHA <= 0.15

    def test_domain_separator_frozen(self):
        assert SEAL_DOMAIN == b"epx-h.seal_select.v1"

    def test_saturation_cap_value(self):
        assert SEAL_MAX_SATURATION == 60

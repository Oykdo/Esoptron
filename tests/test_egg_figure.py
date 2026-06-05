"""Figurative ASCII Golden Egg figure (frozen, brand asset)."""

from __future__ import annotations

from eopx.egg_figure import (
    EGG_SILHOUETTE,
    FILL_CELL,
    egg_figure_rows,
    render_egg_figure,
)

_H = "7e" * 32  # a stand-in egg_hash


def test_silhouette_rectangular_with_interior():
    w = max(len(r) for r in EGG_SILHOUETTE)
    t = [r.ljust(w) for r in EGG_SILHOUETTE]
    assert len({len(r) for r in t}) == 1
    interior = sum(row.count(FILL_CELL) for row in t)
    assert interior >= 12


def test_deterministic_and_pure_ascii():
    a = egg_figure_rows(_H)
    b = egg_figure_rows(_H)
    assert a == b
    assert all(ord(c) < 128 for row in a for c in row)


def test_hash_changes_the_interior():
    assert egg_figure_rows("00" * 32) != egg_figure_rows("ff" * 32)


def test_silhouette_is_preserved():
    # Every non-@ structural glyph is fixed; only the interior carries the hash.
    w = max(len(r) for r in EGG_SILHOUETTE)
    t = [r.ljust(w) for r in EGG_SILHOUETTE]
    out = egg_figure_rows(_H)
    for j, row in enumerate(t):
        for i, c in enumerate(row):
            if c != FILL_CELL:
                assert out[j][i] == c


def test_render_has_figure_and_caption():
    egg = {"egg_hash": _H, "egg_id": "GE-254", "tier": "Stone",
           "egg_number": 254}
    lines = render_egg_figure(egg).splitlines()
    assert any("GE-254" in ln for ln in lines)
    assert any("Stone" in ln for ln in lines)
    assert all(ord(c) < 128 for ln in lines for c in ln)

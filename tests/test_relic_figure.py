"""Figurative ASCII relic figure (brand asset) — looks like the object."""

from __future__ import annotations

from eopx.collection import (
    CODEX,
    LIVING_INTERIOR_CAP,
    SILHOUETTES,
    figure_drift,
    figure_rows,
    render_living_relic_figure,
    render_relic_figure,
)
from eopx.collection.figure import FILL_CELL, _interior_cells, _template

_FP = "c3" * 32  # a stand-in card fingerprint


def test_every_relic_has_a_bespoke_silhouette():
    keys = {r.key for r in CODEX}
    assert keys <= set(SILHOUETTES), keys - set(SILHOUETTES)
    assert len(SILHOUETTES) == len(CODEX) == 12


def test_silhouettes_are_rectangular_with_interior():
    for key in SILHOUETTES:
        t = _template(key)
        assert len({len(r) for r in t}) == 1, f"{key} not rectangular"
        assert len(_interior_cells(t)) >= 6, f"{key} too few interior cells"


def test_figure_deterministic_and_pure_ascii():
    for r in CODEX:
        a = figure_rows(r.key, _FP)
        b = figure_rows(r.key, _FP)
        assert a == b
        assert all(ord(c) < 128 for row in a for c in row)


def test_figures_distinct_across_relics():
    faces = {tuple(figure_rows(r.key, r.card_fingerprint_hex())) for r in CODEX}
    assert len(faces) == len(CODEX)  # every relic gets its own face


def test_fingerprint_changes_the_interior():
    key = CODEX[0].key
    assert figure_rows(key, "00" * 32) != figure_rows(key, "ff" * 32)


def test_living_no_activity_equals_frozen():
    key = CODEX[0].key
    assert figure_rows(key, _FP, state_bytes=b"x", activity=0) == \
        figure_rows(key, _FP)
    assert figure_drift(key, _FP, b"x", 0) == 0


def test_living_preserves_the_silhouette():
    # Only interior (@) cells may ever change; every structural glyph is fixed.
    key = CODEX[0].key
    t = _template(key)
    frozen = figure_rows(key, _FP)
    living = figure_rows(key, _FP, state_bytes=b"held|abcd|9", activity=9)
    for j, row in enumerate(t):
        for i, c in enumerate(row):
            if c != FILL_CELL:
                assert frozen[j][i] == c
                assert living[j][i] == c  # structure never moves


def test_living_drift_is_bounded():
    key = CODEX[0].key
    worst = max(figure_drift(key, _FP, f"s-{k}".encode(), activity=999)
                for k in range(40))
    assert 0 < worst <= LIVING_INTERIOR_CAP  # bounded by the cap


def test_living_state_changes_the_face():
    key = CODEX[0].key
    a = figure_rows(key, _FP, state_bytes=b"controller-A", activity=3)
    b = figure_rows(key, _FP, state_bytes=b"controller-B", activity=3)
    assert a != b


def test_render_relic_figure_has_art_and_caption():
    r = CODEX[0]
    frozen = render_relic_figure(r).splitlines()
    living = render_living_relic_figure(
        r, state_bytes=b"held|seq=1", activity=1).splitlines()
    assert any(r.name in line for line in frozen)      # caption present
    assert any(r.name in line for line in living)
    assert all(ord(c) < 128 for line in frozen for c in line)
    assert len(frozen) == len(living)

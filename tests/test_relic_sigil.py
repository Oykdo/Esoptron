"""Deterministic ASCII relic sigil (brand asset)."""

from __future__ import annotations

from eopx.collection import (
    CODEX,
    LIVING_DRIFT_CAP_BYTES,
    living_relic_rows,
    randomart,
    render_living_sigil,
    render_relic_sigil,
    sigil_drift,
)


def test_randomart_deterministic_and_dims():
    a = randomart(bytes(range(32)))
    b = randomart(bytes(range(32)))
    assert a == b
    assert len(a) == 9
    assert all(len(row) == 19 for row in a)


def test_sigil_deterministic():
    r = CODEX[0]
    assert render_relic_sigil(r) == render_relic_sigil(r)


def test_sigils_distinct_across_relics():
    sigs = {render_relic_sigil(r) for r in CODEX}
    assert len(sigs) == len(CODEX)  # every relic gets its own face


def test_sigil_shape_and_pure_ascii():
    lines = render_relic_sigil(CODEX[0]).splitlines()
    assert len(lines) == 11  # 9 body rows + 2 border lines
    assert all(len(line) == 21 for line in lines)  # field 19 + 2 borders
    assert all(ord(c) < 128 for line in lines for c in line)


def test_fingerprint_override_changes_the_face():
    r = CODEX[0]
    assert (render_relic_sigil(r, fingerprint_hex="00" * 32)
            != render_relic_sigil(r, fingerprint_hex="ff" * 32))


# --------------------------------------------------------------------------- #
# Living sigil — frozen core + bounded state-driven tail.
# --------------------------------------------------------------------------- #

_FP = "a1" * 32  # a stand-in card fingerprint


def test_living_no_activity_equals_frozen_badge():
    # activity == 0 -> nothing happened since the mint -> identical to badge.
    badge = randomart(bytes.fromhex(_FP))
    live = living_relic_rows(_FP, b"any-state", activity=0)
    assert live == badge
    assert sigil_drift(_FP, b"any-state", 0) == 0


def test_living_shares_the_badge_core_prefix():
    # The walk reuses the frozen fingerprint bytes first, then a tail: the
    # field START cell (S) is identical and the face is recognisably the same.
    badge = randomart(bytes.fromhex(_FP))
    live = living_relic_rows(_FP, b"controller-x|seq=3|held", activity=3)
    badge_s = next((i, j) for j, row in enumerate(badge)
                   for i, c in enumerate(row) if c == "S")
    live_s = next((i, j) for j, row in enumerate(live)
                  for i, c in enumerate(row) if c == "S")
    assert badge_s == live_s


def test_living_drift_is_bounded():
    # However much state we throw at it, the cap keeps the core dominant:
    # the drift can never approach the full 9x19 field.
    total_cells = 9 * 19
    worst = max(sigil_drift(_FP, f"state-{k}".encode(), activity=999)
                for k in range(32))
    assert 0 < worst < total_cells // 2  # bounded well under half the field


def test_living_tail_saturates_at_cap():
    # Past the cap, growing activity no longer lengthens the walk.
    at_cap = living_relic_rows(_FP, b"s", activity=LIVING_DRIFT_CAP_BYTES)
    way_over = living_relic_rows(_FP, b"s", activity=LIVING_DRIFT_CAP_BYTES * 100)
    assert at_cap == way_over


def test_living_state_changes_the_face():
    # Same relic, different live state -> the face mutates (the tail content
    # is a hash of the state).
    a = living_relic_rows(_FP, b"controller-A|seq=2", activity=2)
    b = living_relic_rows(_FP, b"controller-B|seq=2", activity=2)
    assert a != b


def test_render_living_sigil_shape_matches_badge():
    r = CODEX[0]
    fp = r.card_fingerprint_hex()
    framed = render_living_sigil(r.name, r.element, r.artifact_id().hex(), fp,
                                 state_bytes=b"held|seq=1", activity=1)
    lines = framed.splitlines()
    assert len(lines) == 11
    assert all(len(line) == 21 for line in lines)
    assert all(ord(c) < 128 for line in lines for c in line)

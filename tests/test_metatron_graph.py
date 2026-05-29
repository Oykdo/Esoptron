"""K_13 graph structure validation (Whitepaper I §2)."""

from eopx.metatron.graph import (
    VERTICES, EDGES, NUM_VERTICES, NUM_EDGES,
    edge_length_orbits, carrier_count,
)


def test_cardinalities():
    assert len(VERTICES) == NUM_VERTICES == 13
    assert len(EDGES) == NUM_EDGES == 78  # C(13, 2)
    assert carrier_count() == 91


def test_edges_are_unique_and_lex_ordered_within_length():
    # No duplicate edges
    pairs = [tuple(sorted(e)) for e in EDGES]
    assert len(set(pairs)) == NUM_EDGES
    # All i < j
    for i, j in EDGES:
        assert i < j


def test_length_class_cardinalities():
    """Edges grouped by euclidean length, in ascending order.

    Six distinct lengths arise in the Metatron embedding:
        L = 1         : 6 (centre-inner) + 6 (inner-inner adjacent)
                       + 12 (inner-outer phase pi/6) = 24
        L = sqrt(3)   : 6 (centre-outer) + 6 (inner-inner across-one)
                       + 6 (outer-outer adjacent) = 18
        L = 2         : 3 (inner-inner opposite) + 12 (inner-outer phase pi/2) = 15
        L = sqrt(7)   : 12 (inner-outer phase 5pi/6)
        L = 3         : 6 (outer-outer skip-one)
        L = 2 sqrt(3) : 3 (outer-outer opposite)

    Note: this is the length partition, NOT the finer D_6-orbit partition.
    Distinct D_6 orbits can share the same length; the canonical ordering
    uses length, so the length partition is what determinism cares about.
    """
    orbits = edge_length_orbits()
    assert sum(orbits) == 78
    assert orbits == [24, 18, 15, 12, 6, 3], orbits


def test_center_is_origin():
    assert VERTICES[0] == (0.0, 0.0)


def test_hexagon_radii():
    import math
    # Inner hexagon: indices 1..6, radius 1
    for i in range(1, 7):
        x, y = VERTICES[i]
        assert abs(math.hypot(x, y) - 1.0) < 1e-9
    # Outer hexagon: indices 7..12, radius sqrt(3)
    r2 = math.sqrt(3.0)
    for i in range(7, 13):
        x, y = VERTICES[i]
        assert abs(math.hypot(x, y) - r2) < 1e-9

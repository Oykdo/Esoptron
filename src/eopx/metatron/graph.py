"""K_13 with the canonical Metatron's Cube embedding in R^2.

Whitepaper I, sections 2.1 to 2.3.

Vertices: 1 center + 6 inner hexagon (radius 1) + 6 outer hexagon (radius sqrt(3)).
Edges:    K_13 = C(13, 2) = 78 unordered pairs.
Canonical edge order: tuple (rounded_length, i, j), then lex.
"""

from __future__ import annotations

import math
from typing import List, Tuple

NUM_VERTICES = 13
NUM_EDGES = 78  # = C(13, 2)

# Quantum used to bucket euclidean lengths into stable equivalence classes
# (defends against floating-point noise when sorting). 1e-6 is well below the
# spacing between the eight orbit lengths in §2.3.
LENGTH_QUANTUM = 1_000_000


def _vertex_coords() -> List[Tuple[float, float]]:
    """Return the 13 vertex coordinates in canonical index order.

    v[0]       = center
    v[1..6]    = inner hexagon, arg = 0, pi/3, 2pi/3, ..., 5pi/3, radius 1
    v[7..12]   = outer hexagon, arg = pi/6, pi/2, ..., 11pi/6, radius sqrt(3)
    """
    coords: List[Tuple[float, float]] = [(0.0, 0.0)]
    for k in range(6):
        ang = k * math.pi / 3.0
        coords.append((math.cos(ang), math.sin(ang)))
    r2 = math.sqrt(3.0)
    for k in range(6):
        ang = (2 * k + 1) * math.pi / 6.0
        coords.append((r2 * math.cos(ang), r2 * math.sin(ang)))
    return coords


VERTICES: List[Tuple[float, float]] = _vertex_coords()


def _euclid(p: Tuple[float, float], q: Tuple[float, float]) -> float:
    return math.hypot(p[0] - q[0], p[1] - q[1])


def _canonical_edges() -> List[Tuple[int, int]]:
    """Return the 78 edges of K_13 sorted by (length, i, j).

    Length is bucketed via LENGTH_QUANTUM so that arithmetically equal lengths
    in the same orbit sort together regardless of float jitter.
    """
    triples = []
    for i in range(NUM_VERTICES):
        for j in range(i + 1, NUM_VERTICES):
            length = _euclid(VERTICES[i], VERTICES[j])
            bucket = round(length * LENGTH_QUANTUM)
            triples.append((bucket, i, j))
    triples.sort()
    return [(i, j) for _, i, j in triples]


EDGES: List[Tuple[int, int]] = _canonical_edges()


def edge_length_orbits() -> List[int]:
    """Return a list of orbit cardinalities, ordered by length.

    Expected (Whitepaper I §2.3): [6, 6, 6, 6, 3, 12, 24, 15] summing to 78.
    """
    triples = []
    for i in range(NUM_VERTICES):
        for j in range(i + 1, NUM_VERTICES):
            length = _euclid(VERTICES[i], VERTICES[j])
            triples.append(round(length * LENGTH_QUANTUM))
    orbits: dict[int, int] = {}
    for b in sorted(triples):
        orbits[b] = orbits.get(b, 0) + 1
    return list(orbits.values())


def carrier_count() -> int:
    """Number of F_13 carriers = vertices + edges = 91."""
    return NUM_VERTICES + NUM_EDGES

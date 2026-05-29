"""Diagnose where canonical detection diverges from the encoded symbols."""

from __future__ import annotations

from collections import Counter

from PIL import Image
import numpy as np

from eopx.metatron import encode_private, render
from eopx.metatron.detect import (
    extract_canonical, _classify_edge_by_mode, _sample_ring_color,
)
from eopx.metatron.graph import VERTICES, EDGES, NUM_VERTICES
from eopx.metatron.render import _project, VERTEX_RADIUS_FRAC, EDGE_WIDTH_BASE
from eopx.metatron.palette import (
    classify_color, srgb_for_symbol, SYMBOL_NAMES,
)


def main() -> None:
    seed = bytes(range(32))
    cw = encode_private(seed)
    canvas = 1024
    img = render(cw, size=canvas)
    arr = np.asarray(img.convert("RGB"))
    print(f"render: {canvas}x{canvas}, edge_width_base={EDGE_WIDTH_BASE}")

    syms, dists = extract_canonical(img)

    # Vertex mismatches
    v_diffs = [(i, cw[i], syms[i], dists[i])
               for i in range(NUM_VERTICES) if cw[i] != syms[i]]
    print(f"\nvertex mismatches: {len(v_diffs)}/{NUM_VERTICES}")
    for i, expected, got, d in v_diffs[:5]:
        print(f"  v[{i}]  expected={expected:2d} ({SYMBOL_NAMES[expected]:<10s})"
              f"  got={got:2d} ({SYMBOL_NAMES[got]:<10s})  dist={d:.3f}")

    # Edge mismatches
    e_diffs = [(j, cw[NUM_VERTICES + j], syms[NUM_VERTICES + j],
                dists[NUM_VERTICES + j])
               for j in range(78) if cw[NUM_VERTICES + j] != syms[NUM_VERTICES + j]]
    print(f"\nedge mismatches: {len(e_diffs)}/78")
    for j, expected, got, d in e_diffs[:10]:
        vi, vj = EDGES[j]
        p1 = _project(VERTICES[vi], canvas)
        p2 = _project(VERTICES[vj], canvas)
        length = ((p1[0] - p2[0]) ** 2 + (p1[1] - p2[1]) ** 2) ** 0.5
        print(f"  e[{j:2d}] ({vi:2d}-{vj:2d})  exp={expected:2d} "
              f"({SYMBOL_NAMES[expected]:<10s})  got={got:2d} "
              f"({SYMBOL_NAMES[got]:<10s})  len={length:.0f}px  dist={d:.3f}")

    # Distribution of edge distances
    edge_dists = [dists[NUM_VERTICES + j] for j in range(78)]
    print(f"\nedge confidence (Oklab distance) summary:")
    print(f"  min/median/max = {min(edge_dists):.3f} / "
          f"{sorted(edge_dists)[39]:.3f} / {max(edge_dists):.3f}")

    # Confidence breakdown for mismatched edges
    mism_conf = [d for _, _, _, d in e_diffs]
    if mism_conf:
        print(f"\nmismatched edge distances: "
              f"min={min(mism_conf):.3f} max={max(mism_conf):.3f}")


if __name__ == "__main__":
    main()

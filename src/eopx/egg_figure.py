"""Figurative ASCII *figure* for a Golden Egg (EPX-E) — it looks like an egg.

The parallel to :mod:`eopx.collection.figure` (the relic figures), with one
deliberate difference: a relic **lives** (it changes hands, so its face
shimmers), but a Golden Egg is **sealed and immutable** — so its figure is
**frozen**. The egg silhouette is fixed; its interior is filled
*deterministically* from the egg's ``egg_hash`` (the egg's unique crystalline
texture). No living shimmer: the whole pitch of an egg is its final, immutable
seal, and the figure honours that.

Tier colour and the tier glyph are the caller's business (the menu already
maps Cosmic→magenta, Stellar→yellow … and carries the ✸✦☾◈▣ glyphs); this
module stays pure ASCII and pure stdlib. Brand only, never security — the
interior is a hash visualisation, not a secret (POSITIONING).
"""

from __future__ import annotations

from typing import Any, Dict, List

#: Interior texture ramp, light → dense (index 0 = space).
FILL_RAMP = " .:-=+*#"

#: Sentinel marking an interior (fillable) cell in the silhouette.
FILL_CELL = "@"

#: The egg silhouette — ``@`` interior, everything else fixed structure.
EGG_SILHOUETTE: List[str] = [
    "   .-.   ",
    "  /@@@\\  ",
    " /@@@@@\\ ",
    "|@@@@@@@|",
    "|@@@@@@@|",
    "|@@@@@@@|",
    " \\@@@@@/ ",
    "  '---'  ",
]


def _template() -> List[str]:
    w = max(len(r) for r in EGG_SILHOUETTE)
    return [r.ljust(w) for r in EGG_SILHOUETTE]


def egg_figure_rows(egg_hash_hex: str) -> List[str]:
    """The egg's frozen figurative ASCII rows.

    The silhouette is fixed; the ``@`` interior is filled deterministically
    from ``egg_hash_hex`` (the sealed egg's crystalline texture). No living
    variant — the egg is immutable by design.
    """
    template = _template()
    cells = [(j, i)
             for j, row in enumerate(template)
             for i, c in enumerate(row) if c == FILL_CELL]
    bits = [(b >> s) & 3
            for b in bytes.fromhex(egg_hash_hex) for s in (0, 2, 4, 6)]
    glyph: Dict[tuple, str] = {}
    if cells and bits:
        for idx, pos in enumerate(cells):
            v = bits[idx % len(bits)] + bits[(idx * 5 + 2) % len(bits)]
            glyph[pos] = FILL_RAMP[min(v, len(FILL_RAMP) - 1)]
    return ["".join(glyph.get((j, i), c) if c == FILL_CELL else c
                    for i, c in enumerate(row))
            for j, row in enumerate(template)]


def render_egg_figure(egg: Dict[str, Any]) -> str:
    """Frozen egg figure + a centred caption (id, tier, number).

    Accepts an egg ``dict`` (``GoldenEgg.to_dict()`` shape): needs
    ``egg_hash``, ``egg_id``, ``tier``, ``egg_number``.
    """
    rows = egg_figure_rows(egg["egg_hash"])
    width = max(len(r) for r in rows)
    cap1 = str(egg.get("egg_id", "")).center(width).rstrip()
    cap2 = (f"{egg.get('tier', '')} #{egg.get('egg_number', '')}/555"
            ).center(width).rstrip()
    return "\n".join([*rows, cap1, cap2])


__all__ = [
    "FILL_RAMP",
    "FILL_CELL",
    "EGG_SILHOUETTE",
    "egg_figure_rows",
    "render_egg_figure",
]

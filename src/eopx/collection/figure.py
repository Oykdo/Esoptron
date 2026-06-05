"""Figurative ASCII *figure* for a Codex relic — it looks like the object.

Where :mod:`eopx.collection.sigil` draws an abstract hash-visualisation
(the OpenSSH drunken-bishop randomart), a **figure** draws the relic as the
*thing it is*: a mirror, a key, an ember, a lantern… Still pure ASCII, still
fully deterministic and unique per relic, and still **brand only, never
security** (POSITIONING) — but recognisable.

Three layers, mirroring the living-sigil design:

* **Silhouette** — a hand-authored, fixed outline per relic (the mirror's
  frame, the key's teeth). This is what makes the object recognisable; it
  never changes. Interior cells are marked with the sentinel ``@``.
* **Interior** — the ``@`` cells are filled **deterministically** from the
  relic's card fingerprint, so the inside is the relic's unique texture (the
  mirror's reflection, the ember's glow). This is the real per-relic face.
* **Living** — a **bounded** number of interior cells (``LIVING_INTERIOR_CAP``)
  are perturbed from the relic's current ledger state (controller + seq), so
  the menu face *breathes* — the reflection shimmers, the ember rekindles —
  while the silhouette and most of the interior stay put. The drift is a hint
  for the eye, not a proof.

The frozen figure is the relic "at the mint" (what would be engraved on a
printed badge); the living figure is the relic "now". Lay one beside the other
and the silhouette + most of the interior coincide — the correspondence is
visible. Pure stdlib, pure ASCII.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

#: Interior texture ramp, light → dense (index 0 = space).
FILL_RAMP = " .:-=+*#"

#: Sentinel marking an interior (fillable) cell in a silhouette template.
FILL_CELL = "@"

#: Max interior cells the *living* figure may perturb. The silhouette and the
#: bulk of the interior are never touched, so the relic stays recognisable —
#: the liveness is **bounded** by construction.
LIVING_INTERIOR_CAP = 5

#: Canvas width every silhouette is padded to (for tidy side-by-side galleries).
FIGURE_WIDTH = 11

# --------------------------------------------------------------------------- #
# Silhouettes — keyed by relic.key. ``@`` = interior fill; everything else is
# fixed structure. Each is FIGURE_WIDTH wide; rows are padded on load.
# --------------------------------------------------------------------------- #
SILHOUETTES: Dict[str, List[str]] = {
    "speculum_primum": [  # the first mirror
        "  .-=^=-.  ",
        " /@@@@@@@\\ ",
        "|@@@@@@@@@|",
        "|@@@@@@@@@|",
        " \\@@@@@@@/ ",
        "  '-._.-'  ",
        "    |_|    ",
        " __=====__ ",
    ],
    "clavis": [  # the keystone / key
        "   _---_   ",
        "  /@@@@@\\  ",
        " |@@@@@@@| ",
        "  \\@@@@@/  ",
        "    |@|    ",
        "    |@|    ",
        "    |@|_   ",
        "    |__|]  ",
    ],
    "scintilla": [  # the stolen ember
        "     .     ",
        "    .'.    ",
        "   /@@@\\   ",
        "  |@@@@@|  ",
        "  |@@@@@|  ",
        "   \\@@@/   ",
        "    \\@/    ",
        "   ~~~~~   ",
    ],
    "unda": [  # the tide
        "   .-~~-.  ",
        "  /@@@@@@\\ ",
        " |@@@@@@@@\\",
        " \\@@@@@@@/'",
        "~^\\@@@@/^~^",
        "^~^~^~^~^~^",
        "~^~^~^~^~^~",
        "^~^~^~^~^~^",
    ],
    "stamen": [  # the loom
        " ._______. ",
        " |@:@:@:@| ",
        " |@:@:@:@| ",
        " |=======| ",
        " |@:@:@:@| ",
        " |@:@:@:@| ",
        " |_______| ",
        "  |     |  ",
    ],
    "lucerna": [  # the lantern
        "   _===_   ",
        "  /.---.\\  ",
        " /@@@@@@@\\ ",
        " |@@@@@@@| ",
        " |@@@@@@@| ",
        " \\@@@@@@@/ ",
        "  '-----'  ",
        "   |   |   ",
    ],
    "corona_cava": [  # the hollow crown
        " .   .   . ",
        "  \\  |  /  ",
        " .-+-+-+-. ",
        " |@@@@@@@| ",
        " |@@o@o@@| ",
        " |@@@@@@@| ",
        " '-------' ",
        "  ~~~~~~~  ",
    ],
    "persona": [  # the mask
        "  .-----.  ",
        " /@@@@@@@\\ ",
        "|@(o)@(o)@|",
        "|@@@@@@@@@|",
        "|@@'---'@@|",
        " \\@@@@@@@/ ",
        "  \\@@@@@/  ",
        "   '---'   ",
    ],
    "focus": [  # the hearth
        " _________ ",
        "|  .-^-.  |",
        "| (@@@@@) |",
        "| (@@@@@) |",
        "|  \\@@@/  |",
        "|___|_|___|",
        "|||||||||||",
        "'---------'",
    ],
    "limen": [  # the threshold
        " .-------. ",
        " |@@@@@@@| ",
        " |@.---.@| ",
        " |@|@@@|@| ",
        " |@|@@o|@| ",
        " |@|@@@|@| ",
        " |_|___|_| ",
        " '~~~~~~~' ",
    ],
    "phoenix": [  # the phoenix
        "   .-^-.   ",
        " /\\@@@@@/\\ ",
        "<@@@@@@@@@>",
        " \\@@@@@@@/ ",
        "  \\@@@@@/  ",
        "   \\@@@/   ",
        "   )@@@(   ",
        "  ~~^~^~~  ",
    ],
    "tessera": [  # the watchword (mosaic tile / token)
        " +-------+ ",
        " |@@@@@@@| ",
        " |@/^^^\\@| ",
        " |@|@X@|@| ",
        " |@\\___/@| ",
        " |@@@@@@@| ",
        " +-------+ ",
        "  '.___.'  ",
    ],
}

#: Fallback for any relic without a bespoke silhouette (defensive only).
_GENERIC: List[str] = [
    " .-------. ",
    " |@@@@@@@| ",
    " |@@@@@@@| ",
    " |@@@@@@@| ",
    " |@@@@@@@| ",
    " |@@@@@@@| ",
    " |@@@@@@@| ",
    " '-------' ",
]


def _template(relic_key: str) -> List[str]:
    rows = SILHOUETTES.get(relic_key, _GENERIC)
    w = max(len(r) for r in rows)
    return [r.ljust(w) for r in rows]


def _interior_cells(template: List[str]) -> List[tuple]:
    return [(j, i)
            for j, row in enumerate(template)
            for i, c in enumerate(row) if c == FILL_CELL]


def figure_rows(relic_key: str, fingerprint_hex: str, *,
                state_bytes: Optional[bytes] = None,
                activity: int = 0) -> List[str]:
    """The relic's figurative ASCII rows.

    The silhouette is fixed; the ``@`` interior is filled deterministically
    from ``fingerprint_hex``. When ``state_bytes`` is given and ``activity``
    > 0, up to ``min(activity, LIVING_INTERIOR_CAP)`` interior cells are
    perturbed from ``SHA3-256(state_bytes)`` — the *living* face. With no state
    (or ``activity == 0``) the result is the frozen "at the mint" figure.
    """
    template = _template(relic_key)
    cells = _interior_cells(template)
    bits = [(b >> s) & 3
            for b in bytes.fromhex(fingerprint_hex) for s in (0, 2, 4, 6)]
    glyph: Dict[tuple, str] = {}
    if cells and bits:
        for idx, pos in enumerate(cells):
            v = bits[idx % len(bits)] + bits[(idx * 5 + 2) % len(bits)]
            glyph[pos] = FILL_RAMP[min(v, len(FILL_RAMP) - 1)]
    if cells and state_bytes is not None and activity > 0:
        n = min(LIVING_INTERIOR_CAP, activity)
        tail = hashlib.sha3_256(state_bytes).digest()
        for k in range(n):
            glyph[cells[tail[k] % len(cells)]] = FILL_RAMP[tail[k + 8]
                                                           % len(FILL_RAMP)]
    return ["".join(glyph.get((j, i), c) if c == FILL_CELL else c
                    for i, c in enumerate(row))
            for j, row in enumerate(template)]


def _caption(name: str, artifact_id_hex: str, element: str,
             width: int) -> List[str]:
    line1 = name.center(width)
    tag = f"{artifact_id_hex[:8]} - {element}".strip(" -")
    line2 = tag.center(width)
    return [line1.rstrip(), line2.rstrip()]


def render_relic_figure(relic, *, fingerprint_hex: Optional[str] = None) -> str:
    """Frozen figurative figure for ``relic`` + a centred name/id caption.

    The relic "at the mint" — the canonical face (what a printed badge would
    carry). Pass ``fingerprint_hex`` to override the seed (tests).
    """
    fp = fingerprint_hex or relic.card_fingerprint_hex()
    rows = figure_rows(relic.key, fp)
    width = max(len(r) for r in rows)
    cap = _caption(relic.name, relic.artifact_id().hex(), relic.element, width)
    return "\n".join([*rows, *cap])


def render_living_relic_figure(relic, *, state_bytes: bytes, activity: int,
                               fingerprint_hex: Optional[str] = None) -> str:
    """Living figurative figure for ``relic`` (frozen silhouette + bounded,
    state-driven interior shimmer) + caption. The relic "now"."""
    fp = fingerprint_hex or relic.card_fingerprint_hex()
    rows = figure_rows(relic.key, fp, state_bytes=state_bytes, activity=activity)
    width = max(len(r) for r in rows)
    cap = _caption(relic.name, relic.artifact_id().hex(), relic.element, width)
    return "\n".join([*rows, *cap])


def figure_drift(relic_key: str, fingerprint_hex: str, state_bytes: bytes,
                 activity: int) -> int:
    """How many interior cells the living figure differs from the frozen one.

    Bounded by ``LIVING_INTERIOR_CAP``. A visual "this relic has lived" cue —
    a hint for the eye, not a proof.
    """
    base = figure_rows(relic_key, fingerprint_hex)
    live = figure_rows(relic_key, fingerprint_hex,
                       state_bytes=state_bytes, activity=activity)
    return sum(bc != lc
               for br, lr in zip(base, live)
               for bc, lc in zip(br, lr))


__all__ = [
    "FILL_RAMP",
    "FILL_CELL",
    "FIGURE_WIDTH",
    "LIVING_INTERIOR_CAP",
    "SILHOUETTES",
    "figure_rows",
    "render_relic_figure",
    "render_living_relic_figure",
    "figure_drift",
]

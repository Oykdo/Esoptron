"""Deterministic ASCII *sigil* for a Codex relic — a recognisable text face.

A relic's sigil is a "randomart" (the SSH drunken-bishop walk) over its
**card fingerprint** — so it is fully deterministic (same relic → same
sigil, everywhere: terminal, Eidolon menu, printed sheet) and unique per
relic, yet reveals nothing: it is a hash visualisation, **brand only, never
security** (exactly like the seal — POSITIONING).

Pure ASCII (safe on any console), pure stdlib. The walk is the classic
OpenSSH `bubblebabble`/drunken-bishop field so the result is stable and
familiar.
"""

from __future__ import annotations

import hashlib
from typing import List

# OpenSSH randomart density ramp (value -> glyph); start/end overlaid after.
_RAMP = " .o+=*BOX@%&#/^"
_FIELD_W = 19  # fits "[ Speculum Primum ]" (the longest relic name) in the border
_FIELD_H = 9


def randomart(data: bytes, *, width: int = _FIELD_W, height: int = _FIELD_H) -> List[str]:
    """Drunken-bishop walk over ``data`` → list of ``height`` rows of length ``width``.

    Each input byte contributes 4 diagonal steps (2 bits each, LSB first);
    visited cells are tallied and mapped through :data:`_RAMP`. The start
    cell is marked ``S`` and the final cell ``E`` (OpenSSH convention).
    """
    field = [[0] * width for _ in range(height)]
    x, y = width // 2, height // 2
    sx, sy = x, y
    for byte in data:
        b = byte
        for _ in range(4):
            dx = 1 if (b & 0x1) else -1
            dy = 1 if (b & 0x2) else -1
            x = min(width - 1, max(0, x + dx))
            y = min(height - 1, max(0, y + dy))
            field[y][x] += 1
            b >>= 2

    rows: List[str] = []
    for j in range(height):
        line = []
        for i in range(width):
            if (i, j) == (sx, sy):
                line.append("S")
            elif (i, j) == (x, y):
                line.append("E")
            else:
                v = field[j][i]
                line.append(_RAMP[v] if v < len(_RAMP) else _RAMP[-1])
        rows.append("".join(line))
    return rows


def _bordered_label(text: str, width: int) -> str:
    """A ``+---[ text ]---+`` border line of total length ``width + 2``."""
    tag = f"[ {text} ]"
    if len(tag) > width:
        tag = tag[:width]
    pad = width - len(tag)
    left = pad // 2
    right = pad - left
    return "+" + "-" * left + tag + "-" * right + "+"


def render_sigil(name: str, element: str, artifact_id_hex: str,
                 fingerprint_hex: str) -> str:
    """Framed ASCII sigil from primitives (usable from a manifest dict too).

    ``name`` tops the frame; ``artifact_id_hex[:8]`` + ``element`` label the
    bottom; ``fingerprint_hex`` is the randomart walk seed.
    """
    rows = randomart(bytes.fromhex(fingerprint_hex))
    top = _bordered_label(name, _FIELD_W)
    bottom = _bordered_label(f"{artifact_id_hex[:8]} {element}", _FIELD_W)
    body = [f"|{r}|" for r in rows]
    return "\n".join([top, *body, bottom])


def render_relic_sigil(relic, *, fingerprint_hex: str | None = None) -> str:
    """The framed ASCII sigil for a relic object (delegates to :func:`render_sigil`).

    Uses the relic's public **card fingerprint** as the walk seed by default
    (pass ``fingerprint_hex`` to override, e.g. in tests).
    """
    fp = fingerprint_hex or relic.card_fingerprint_hex()
    return render_sigil(relic.name, relic.element,
                        relic.artifact_id().hex(), fp)


# --------------------------------------------------------------------------- #
# Living sigil (EPX-C) — the badge face *prolonged* by the relic's real state.
#
# The badge sigil (above) is frozen: it is the relic's face **at the mint**,
# printed once. The *living* sigil shares that exact opening, then continues
# the same drunken-bishop walk with a BOUNDED, state-derived tail — so the menu
# face "breathes" with the relic's real ledger history (controller, seq), yet
# the frozen core always stays clearly recognisable. You can lay the printed
# badge next to the screen and see the same core. Brand only, never security:
# the seed is a hash of REAL public state, the drift is a hint for the eye, not
# a proof (POSITIONING — like the seal).
# --------------------------------------------------------------------------- #

LIVING_DRIFT_CAP_BYTES = 6
"""Max extra walk bytes (24 steps) appended for the living face.

The frozen fingerprint walk (typically 16–32 bytes = 64–128 steps) always
dominates this cap, so the core stays recognisable — the drift is **bounded**
by construction. The tail's *length* grows with how much the relic has lived
(``activity`` = ledger seq) but saturates here; its *content* is a hash of the
current state, so a state change visibly mutates the tail.
"""


def _living_walk_bytes(fingerprint_hex: str, state_bytes: bytes,
                       activity: int) -> bytes:
    """Walk bytes for the living face: frozen badge walk + bounded state tail.

    Tail length is ``min(activity, LIVING_DRIFT_CAP_BYTES)`` bytes drawn from
    ``SHA3-256(state_bytes)``. ``activity == 0`` → no tail → identical to the
    badge (nothing has happened since the mint, so the face is unchanged).
    """
    core = bytes.fromhex(fingerprint_hex)
    n = max(0, min(LIVING_DRIFT_CAP_BYTES, activity))
    if n == 0:
        return core
    return core + hashlib.sha3_256(state_bytes).digest()[:n]


def living_relic_rows(fingerprint_hex: str, state_bytes: bytes,
                      activity: int) -> List[str]:
    """The living randomart rows (frozen core + bounded state-driven tail)."""
    return randomart(_living_walk_bytes(fingerprint_hex, state_bytes, activity))


def render_living_sigil(name: str, element: str, artifact_id_hex: str,
                        fingerprint_hex: str, *, state_bytes: bytes,
                        activity: int) -> str:
    """Framed *living* sigil — same frame as :func:`render_sigil`, but the face
    is prolonged by the relic's real, current ledger state (bounded — see
    :data:`LIVING_DRIFT_CAP_BYTES`)."""
    rows = living_relic_rows(fingerprint_hex, state_bytes, activity)
    top = _bordered_label(name, _FIELD_W)
    bottom = _bordered_label(f"{artifact_id_hex[:8]} {element}", _FIELD_W)
    body = [f"|{r}|" for r in rows]
    return "\n".join([top, *body, bottom])


def sigil_drift(fingerprint_hex: str, state_bytes: bytes, activity: int) -> int:
    """How many cells the living face differs from the frozen badge face.

    A small, bounded integer — the visual distance "since the mint", for an
    at-a-glance "this relic has lived" cue. A hint for the eye, not a proof.
    """
    base = randomart(bytes.fromhex(fingerprint_hex))
    live = living_relic_rows(fingerprint_hex, state_bytes, activity)
    return sum(bc != lc
               for br, lr in zip(base, live)
               for bc, lc in zip(br, lr))


__all__ = [
    "randomart",
    "render_sigil",
    "render_relic_sigil",
    # living sigil (state-reactive, bounded)
    "LIVING_DRIFT_CAP_BYTES",
    "living_relic_rows",
    "render_living_sigil",
    "sigil_drift",
]

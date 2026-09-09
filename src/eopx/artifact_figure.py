"""EPX-F — the artifact figure: a frozen, recomputable face for a `.eopx`.

The figure is a **cell grid**, not a picture. Each cell carries an integer
*level*; glyphs are a presentation choice layered on top. This is what lets the
same figure appear as ASCII in a terminal, as Unicode blocks in a rich console,
or engraved on a badge, while remaining *one* object with *one* digest.

Two properties make it worth freezing (see ``docs/specs/EPX-F_artifact_figure.md``):

**It is recomputable, never attestable by eye.** The grid derives from the
*pre-image* half of the signed manifest — the fields fixed before the image
exists. A verifier recomputes the grid from a `.eopx` and compares; looking at
a pretty picture proves nothing (POSITIONING).

**It survives key rotation.** The grid has two bands. The **content band**
(rows 0..5) depends on ``merkle_root`` alone, so an artifact keeps its face for
life. The **epoch band** (rows 6..7) also takes ``dilithium_pk_fp``, so when the
issuing key rotates the artifact visibly moves to a new epoch while staying
recognisably itself. A badge minted under epoch N does not become a stranger
under epoch N+1.

Why not ``payload_hash`` or ``image_sha3_512``
----------------------------------------------
Both are downstream of the pixels (``EopxManifest.canonical_payload`` covers
``image_sha3_512``). A figure drawn *into* the image and derived *from* the
image hash is a fixed point with no solution. Only pre-image fields are
admissible inputs, and the freeze is enforced by :data:`FIGURE_VERSION` inside
the domain-separation strings: changing the derivation means a new version, and
figures already printed keep verifying under the old one.

The single ML-DSA-87 signature already covers both ends: the inputs live in
``canonical_payload()``, and the rendering reaches it through
``image_sha3_512``. No new primitive, no new trust root.
"""

from __future__ import annotations

import hashlib
from typing import List, Sequence

from .metatron.field import hkdf_sha3_512

#: Derivation version. Baked into the domain strings — bump it and every
#: figure changes, which is why printed artifacts pin the version they were
#: minted under. FROZEN: v1 must keep producing v1 grids forever.
FIGURE_VERSION = 1

INFO_CONTENT = b"esoptron.figure.content.v1"
INFO_EPOCH = b"esoptron.figure.epoch.v1"

#: Grid geometry. 16 x 8 = 128 cells of 4 bits = 512 bits, i.e. exactly the
#: width of the SHA3-512 the KDF is built on — no counter mode, no truncation
#: bias, one output one grid.
GRID_W = 16
GRID_H = 8
CONTENT_ROWS = 6
EPOCH_ROWS = GRID_H - CONTENT_ROWS

#: Cell levels. One hex nibble per cell.
LEVELS = 16

#: Reference presentation, light -> dense. Normative *as a rendering*: two
#: implementations printing the same grid must agree. The digest is computed
#: over the levels (:func:`canonical_text`), never over these glyphs, so a
#: Unicode or block-element ramp is a free substitution.
ASCII_RAMP = " .`',:;!~+=*%#@$"

_FP_LEN = 32


def _check(name: str, value: bytes) -> bytes:
    if len(value) != _FP_LEN:
        raise ValueError(f"{name} must be {_FP_LEN} bytes, got {len(value)}")
    return value


def _nibbles(data: bytes) -> List[int]:
    out: List[int] = []
    for b in data:
        out.append(b >> 4)
        out.append(b & 0x0F)
    return out


def figure_grid(merkle_root: bytes, dilithium_pk_fp: bytes) -> List[List[int]]:
    """The artifact's cell grid: ``GRID_H`` rows of ``GRID_W`` levels.

    ``merkle_root`` and ``dilithium_pk_fp`` are the raw 32-byte values carried
    (hex-encoded) by the ``.eopx`` manifest. Rows ``0..CONTENT_ROWS-1`` are the
    content band; the remaining rows are the epoch band.
    """
    _check("merkle_root", merkle_root)
    _check("dilithium_pk_fp", dilithium_pk_fp)

    content_cells = CONTENT_ROWS * GRID_W
    epoch_cells = EPOCH_ROWS * GRID_W

    content = hkdf_sha3_512(ikm=merkle_root, salt=b"", info=INFO_CONTENT,
                            length=content_cells // 2)
    epoch = hkdf_sha3_512(ikm=merkle_root + dilithium_pk_fp, salt=b"",
                          info=INFO_EPOCH, length=epoch_cells // 2)

    cells = _nibbles(content) + _nibbles(epoch)
    return [cells[r * GRID_W:(r + 1) * GRID_W] for r in range(GRID_H)]


def canonical_text(grid: Sequence[Sequence[int]]) -> str:
    """The hashed form: one lowercase hex digit per cell, one line per row.

    Glyph-independent by construction — this, and not any rendering, is what
    :func:`figure_digest` covers.
    """
    if len(grid) != GRID_H or any(len(row) != GRID_W for row in grid):
        raise ValueError(f"grid must be {GRID_H}x{GRID_W}")
    if any(not 0 <= c < LEVELS for row in grid for c in row):
        raise ValueError(f"cell levels must be in [0, {LEVELS})")
    return "\n".join("".join(f"{c:x}" for c in row) for row in grid)


def figure_digest(grid: Sequence[Sequence[int]]) -> bytes:
    """SHA3-256 over :func:`canonical_text` — the figure's own fingerprint."""
    return hashlib.sha3_256(canonical_text(grid).encode("utf-8")).digest()


def figure_tag(grid: Sequence[Sequence[int]]) -> str:
    """Short human-comparable form of :func:`figure_digest` (8 hex chars).

    Small enough to print under a badge, large enough that two artifacts
    colliding by accident is not a practical concern. It is a *comparison*
    aid, not evidence: only recomputation from the `.eopx` decides.
    """
    return figure_digest(grid)[:4].hex()


def epoch_id(dilithium_pk_fp: bytes) -> str:
    """The issuing key's epoch tag (first 4 bytes of its fingerprint, hex).

    Two artifacts sharing an ``epoch_id`` were signed under the same key. The
    tag is a legible signal, never a proof of authority — that is the cosigned
    attestation chain's job (EPX-F §5).
    """
    return _check("dilithium_pk_fp", dilithium_pk_fp)[:4].hex()


def render_rows(grid: Sequence[Sequence[int]],
                ramp: str = ASCII_RAMP) -> List[str]:
    """Present ``grid`` with a glyph ramp (default :data:`ASCII_RAMP`).

    ``ramp`` must have exactly :data:`LEVELS` glyphs. Substituting a Unicode
    ramp changes what a reader sees and nothing else: the grid, the digest and
    the tag are untouched.
    """
    if len(ramp) != LEVELS:
        raise ValueError(f"ramp must have exactly {LEVELS} glyphs")
    return ["".join(ramp[c] for c in row) for row in grid]


__all__ = [
    "FIGURE_VERSION", "INFO_CONTENT", "INFO_EPOCH",
    "GRID_W", "GRID_H", "CONTENT_ROWS", "EPOCH_ROWS", "LEVELS", "ASCII_RAMP",
    "figure_grid", "canonical_text", "figure_digest", "figure_tag",
    "epoch_id", "render_rows",
]

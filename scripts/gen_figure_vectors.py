"""Generate the EPX-F cross-language parity vectors for the TypeScript ports.

    py scripts/gen_figure_vectors.py
    py scripts/gen_figure_vectors.py --out pwa/src/lib/__tests__/figure_vectors.json

Why this is separate from ``gen_test_vectors.py``
-------------------------------------------------
EPX-F depends on the standard library plus ``hkdf_sha3_512`` and nothing else
(spec header, *Dependencies*). Keeping its generator to that same surface means
the vectors can be regenerated on any machine — including one without the
post-quantum stack, where ``gen_test_vectors.py`` cannot even be imported. A
figure is meant to be recomputable by anyone; its vectors should be too.

What is and is not authoritative here
-------------------------------------
The **grids, tags and epoch ids are not defined by this file** — they are
normative in ``docs/specs/EPX-F_artifact_figure.md`` §9, and the TypeScript
tests assert against the spec text directly. What this file adds is the part
the spec does not tabulate: the §6 *presentation* — framed plates, living
plates, galleries — where two ports could drift on centring, padding or the
caption separator without either one being obviously wrong.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from eopx.artifact_figure import (  # noqa: E402
    ASCII_RAMP, canonical_text, epoch_id, figure_grid, figure_tag, render_rows,
)
from eopx.figure_plate import (  # noqa: E402
    UNICODE_RAMP, frames, gallery, living_plate, living_rows, plate, plate_size,
)

# EPX-F §9 inputs, retyped from the spec.
MR_A = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
FP_A = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
FP_B = bytes.fromhex(
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
MR_B = hashlib.sha3_256(b"esoptron.epxf.testvector.B").digest()

CASES = [("A_A", MR_A, FP_A), ("A_B", MR_A, FP_B), ("B_A", MR_B, FP_A)]

#: Ledger states for the living cases. Fixed strings, not random: a living
#: rendering is deterministic in the state, and the vector has to prove it.
STATES = [(b"", 0), (b"block-900001", 3), (b"block-900001", 99)]


def _derivation() -> List[Dict[str, Any]]:
    out = []
    for name, mr, fp in CASES:
        grid = figure_grid(mr, fp)
        out.append({
            "name": name,
            "merkle_root_hex": mr.hex(),
            "dilithium_pk_fp_hex": fp.hex(),
            "grid": grid,
            "canonical_text": canonical_text(grid),
            "figure_tag": figure_tag(grid),
            "epoch_id": epoch_id(fp),
            "ascii_rows": render_rows(grid, ASCII_RAMP),
            "unicode_rows": render_rows(grid, UNICODE_RAMP),
        })
    return out


def _presentation() -> List[Dict[str, Any]]:
    out = []
    for name, mr, fp in CASES:
        grid = figure_grid(mr, fp)
        eid = epoch_id(fp)
        out.append({
            "name": name,
            # A caption longer than the grid widens the frame; include one
            # short and one long title so the centring rule is pinned.
            "plate_plain": plate(grid),
            "plate_titled": plate(grid, title="Relic", epoch=eid),
            "plate_long_title": plate(
                grid, title="a title far wider than sixteen cells", epoch=eid),
            "plate_ascii": plate(grid, title="Relic", epoch=eid,
                                 ramp=ASCII_RAMP, ascii_frame=True),
            "plate_size_titled": list(plate_size(
                title="Relic", epoch=eid, tag=figure_tag(grid))),
        })
    return out


def _living() -> List[Dict[str, Any]]:
    out = []
    grid = figure_grid(MR_A, FP_A)
    eid = epoch_id(FP_A)
    for state, activity in STATES:
        out.append({
            "state_utf8": state.decode("utf-8"),
            "activity": activity,
            "rows": living_rows(grid, state, activity),
            "plate": living_plate(grid, state_bytes=state, activity=activity,
                                  epoch=eid),
        })
    out.append({
        "state_utf8": "animate",
        "activity": 5,
        "frames": frames(grid, b"animate", count=4, activity=5),
    })
    return out


def _gallery() -> Dict[str, Any]:
    plates = [plate(figure_grid(mr, fp), title=name, epoch=epoch_id(fp),
                    ramp=ASCII_RAMP, ascii_frame=True)
              for name, mr, fp in CASES]
    return {"plates": plates, "rendered": gallery(plates)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--out", type=Path,
        default=_REPO_ROOT / "pwa" / "src" / "lib" / "__tests__"
        / "figure_vectors.json",
        help="output path for the JSON parity vectors",
    )
    args = ap.parse_args()

    vectors = {
        "schema_version": 1,
        "spec": "EPX-F v1",
        "ascii_ramp": ASCII_RAMP,
        "unicode_ramp": UNICODE_RAMP,
        "derivation": _derivation(),
        "presentation": _presentation(),
        "living": _living(),
        "gallery": _gallery(),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8", newline="\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

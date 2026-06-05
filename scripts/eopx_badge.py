"""Generate an EPX-H "Seal Revealed" badge sheet (print/scan ready).

The badge is an ordinary Metatron canvas in which the Seal of Solomon is
*revealed* from the cube's own geometry (EPX-H): the vault fingerprint selects
which genuine K_13 hexagram to light up and the spinor hash colours it. The
91 F_13 symbols and the page-corner ArUco fiducials are untouched, so the badge
decodes through the exact same camera pipeline as a standard sheet.

Examples
--------
  # Public badge from an Eidolon Phase-6 spinor_hash (64-byte hex)
  py scripts/eopx_badge.py --spinor 9af3...e1 --out out\\badge.png

  # From a passphrase (SHA3-512 → spinor, SHA3-256 → vault fingerprint)
  py scripts/eopx_badge.py --passphrase "metatron.test_vault.v1" --out out\\badge.png

  # Pin an explicit vault fingerprint (32-byte hex) instead of deriving it
  py scripts/eopx_badge.py --spinor 9af3...e1 --vault-fp 1122...ff --out out\\badge.png

The pointing angle of the revealed seal (0° or 30°) and its two triangle hues
are printed so a holder can recognise their badge at a glance.
"""

from __future__ import annotations

import argparse
import hashlib
import secrets
import sys
from pathlib import Path

from eopx.metatron import encode_public, render_seal_revealed
from eopx.metatron.seal_reveal import (
    select_star, seal_color_swap, star_pointing_degrees,
)

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from print_sheet import make_sheet  # type: ignore  # noqa: E402

VAULT_FP_DOMAIN = b"epx-h.badge.vault_fp.v1"


def _derive_vault_fp(spinor: bytes) -> bytes:
    """Deterministic 32-byte vault fingerprint from a public spinor hash."""
    return hashlib.sha3_256(VAULT_FP_DOMAIN + spinor).digest()


def _resolve(args) -> tuple[bytes, bytes]:
    """Return (spinor_hash, vault_fp) from the CLI arguments."""
    if args.passphrase is not None:
        spinor = hashlib.sha3_512(args.passphrase.encode("utf-8") + b".public").digest()
    elif args.spinor is not None:
        spinor = bytes.fromhex(args.spinor.strip())
        if len(spinor) not in (32, 48, 64):
            raise SystemExit("--spinor must be 32, 48 or 64 bytes (64/96/128 hex chars)")
    elif args.random:
        spinor = secrets.token_bytes(64)
    else:
        raise SystemExit("provide one of --spinor / --passphrase / --random")

    if args.vault_fp is not None:
        vault_fp = bytes.fromhex(args.vault_fp.strip())
        if len(vault_fp) != 32:
            raise SystemExit("--vault-fp must be exactly 32 bytes (64 hex chars)")
    else:
        vault_fp = _derive_vault_fp(spinor)
    return spinor, vault_fp


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="eopx_badge",
        description="Generate an EPX-H Seal Revealed badge sheet.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--spinor", help="32/48/64-byte spinor_hash in hex")
    src.add_argument("--passphrase", help="UTF-8 passphrase → SHA3-512 spinor")
    src.add_argument("--random", action="store_true",
                     help="Generate a fresh random spinor (testing only)")
    p.add_argument("--vault-fp", help="32-byte vault fingerprint in hex "
                                      "(default: derived from the spinor)")
    p.add_argument("--out", required=True, help="Output PNG path (A4 @ 300 DPI).")
    args = p.parse_args(argv[1:])

    spinor, vault_fp = _resolve(args)
    symbols = encode_public(spinor)

    def _cube(syms, size):
        return render_seal_revealed(syms, vault_fp, spinor, size=size)

    sheet = make_sheet(
        symbols, role="public", label="EPX-H seal badge",
        hash_hex=spinor.hex(), cube_renderer=_cube,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    sheet.save(out_path, format="PNG", dpi=(300, 300), optimize=False)

    star = select_star(vault_fp)
    swap = seal_color_swap(vault_fp)
    print(f"wrote {out_path}  ({out_path.stat().st_size} bytes)")
    print()
    print(f"spinor_hash : {spinor.hex()}")
    print(f"vault_fp    : {vault_fp.hex()}")
    print(f"seal star   : #{star} (points at {star_pointing_degrees(star)}°)")
    print(f"colour roles: {'swapped' if swap else 'normal'} (fire/water)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

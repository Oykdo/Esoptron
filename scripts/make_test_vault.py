"""Generate a deterministic "test vault" cube to photograph with your phone.

This produces both the raw 1024x1024 cubes AND print-ready A4 sheets:

  out/test_vault_public.png         -- raw 512x512 public cube
  out/test_vault_private.png        -- raw 1024x1024 private cube
  out/test_vault_private_A4.png     -- A4 @ 300 DPI ready to print (PRIVATE)
  out/test_vault_public_A4.png      -- A4 @ 300 DPI ready to print (PUBLIC)

Print the A4 sheet on white paper (or display it full-screen on a monitor),
photograph it with your phone, transfer the photo to this machine, and run
`decode_from_photo.py <photo>` -- you should recover the same seed shown below.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from eopx.metatron import encode_public, encode_private, render
# Reuse the layout from print_sheet.py so we have a single source of truth.
import sys as _sys
_SCRIPTS_DIR = Path(__file__).parent
if str(_SCRIPTS_DIR) not in _sys.path:
    _sys.path.insert(0, str(_SCRIPTS_DIR))
from print_sheet import make_sheet, DPI  # type: ignore  # noqa: E402


KNOWN_PASSPHRASE = b"metatron.test_vault.v1"


def _print_hash(label: str, hex_str: str) -> None:
    """Print a long hex string in 16-char groups, 4 per line."""
    print(f"  {label:<14s}: {len(hex_str)*4} bits / {len(hex_str)} hex chars")
    groups = [hex_str[i:i + 16] for i in range(0, len(hex_str), 16)]
    for i in range(0, len(groups), 4):
        print("                  " + "  ".join(groups[i:i + 4]))


def main() -> int:
    out = Path("out")
    out.mkdir(parents=True, exist_ok=True)

    seed = hashlib.sha3_256(KNOWN_PASSPHRASE).digest()
    spinor = hashlib.sha3_512(KNOWN_PASSPHRASE + b".public").digest()

    print("=" * 72)
    print("  KNOWN TEST VAULT  (deterministic, reproducible from passphrase)")
    print("=" * 72)
    print(f"  passphrase    : {KNOWN_PASSPHRASE.decode()}")
    print()
    _print_hash("seed (256b)", seed.hex())
    print(f"  sha3-256(seed)[:16] = {hashlib.sha3_256(seed).hexdigest()[:16]}")
    print()
    _print_hash("spinor (512b)", spinor.hex())
    print(f"  sha3-256(spinor)[:16] = {hashlib.sha3_256(spinor).hexdigest()[:16]}")
    print()

    cw_priv = encode_private(seed)
    img_priv = render(cw_priv, size=1024)
    out_priv = out / "test_vault_private.png"
    img_priv.save(out_priv, format="PNG", optimize=False)
    print(f"  wrote {out_priv}  ({out_priv.stat().st_size} bytes, 1024x1024)")

    cw_pub = encode_public(spinor)
    img_pub = render(cw_pub, size=512)
    out_pub = out / "test_vault_public.png"
    img_pub.save(out_pub, format="PNG", optimize=False)
    print(f"  wrote {out_pub}  ({out_pub.stat().st_size} bytes, 512x512)")

    # Print-ready A4 sheets (300 DPI, fiducials + scale bar + full hash printed).
    sheet_priv = make_sheet(
        cw_priv, role="private",
        label=f"passphrase = {KNOWN_PASSPHRASE.decode()!r}",
        hash_hex=seed.hex(),
    )
    out_sheet_priv = out / "test_vault_private_A4.png"
    sheet_priv.save(out_sheet_priv, format="PNG", dpi=(DPI, DPI), optimize=False)
    print(f"  wrote {out_sheet_priv}  ({out_sheet_priv.stat().st_size} bytes, A4 @ {DPI} DPI)")

    sheet_pub = make_sheet(
        cw_pub, role="public",
        label=f"passphrase = {KNOWN_PASSPHRASE.decode()!r}",
        hash_hex=spinor.hex(),
    )
    out_sheet_pub = out / "test_vault_public_A4.png"
    sheet_pub.save(out_sheet_pub, format="PNG", dpi=(DPI, DPI), optimize=False)
    print(f"  wrote {out_sheet_pub}  ({out_sheet_pub.stat().st_size} bytes, A4 @ {DPI} DPI)")

    print()
    print("Next steps:")
    print("  1. Print test_vault_private_A4.png on white A4 paper (Fit to page OFF,")
    print("     scale 100 %), OR display it full-screen.")
    print("  2. Photograph it with your phone (steady, no flash, diffuse light).")
    print("  3. Transfer the photo here.")
    print("  4. Run:")
    print("     py scripts/decode_from_photo.py <photo>")
    print("     and compare the recovered seed to the hex printed above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

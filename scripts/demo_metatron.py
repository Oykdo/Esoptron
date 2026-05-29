"""Demo: generate sample public and private Metatron renders side by side.

Usage:
    python scripts/demo_metatron.py [out_dir]

Default out_dir = ./out
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

from PIL import Image

from eopx.metatron import (
    encode_public, encode_private, decode_private,
    is_in_code, render,
)
from eopx.metatron.palette import palette_srgb, SYMBOL_NAMES


def write(img: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, format="PNG", optimize=False)
    print(f"  wrote {path}  ({path.stat().st_size} bytes)")


def make_palette_strip(size: int = 64) -> Image.Image:
    """Render the 13-color palette as a horizontal strip for visual reference."""
    pal = palette_srgb()
    img = Image.new("RGB", (size * 13, size), (16, 16, 22))
    for i, color in enumerate(pal):
        cell = Image.new("RGB", (size, size), color)
        img.paste(cell, (i * size, 0))
    return img


def hex_id(symbols, length: int = 12) -> str:
    """Return a short hex fingerprint of a 91-symbol vector for logging."""
    h = hashlib.sha3_256(bytes(s for s in symbols)).hexdigest()
    return h[:length]


def main(argv: list[str]) -> int:
    out_dir = Path(argv[1] if len(argv) > 1 else "out")
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"output directory: {out_dir.resolve()}")

    # ---- palette strip
    print("\n[1/4] palette strip (13 OKLCH symbols)")
    write(make_palette_strip(), out_dir / "palette.png")
    for i, name in enumerate(SYMBOL_NAMES):
        r, g, b = palette_srgb()[i]
        print(f"   {i:2d}  {name:<12s}  rgb({r:3d}, {g:3d}, {b:3d})")

    # ---- public renders (3 distinct fake spinor_hash values)
    print("\n[2/4] public renders (.eopx Metatron) -- 3 fake vault hashes")
    fake_vaults = [
        ("vault-alpha", b"vault-alpha" * 8),
        ("vault-beta",  b"vault-beta"  * 8),
        ("vault-gamma", b"vault-gamma" * 8),
    ]
    for name, spinor in fake_vaults:
        syms = encode_public(spinor)
        in_C = is_in_code(syms)
        print(f"   {name:<12s}  fingerprint={hex_id(syms)}  in_C={in_C}")
        assert not in_C, "public render must NOT lie in C (Theorem 2)"
        img = render(syms, size=512)
        write(img, out_dir / f"public_{name}.png")

    # ---- private renders (Metatron Mnemonic) for 3 fixed test seeds
    print("\n[3/4] private inscriptions (Metatron Mnemonic) -- 3 fixed seeds")
    test_seeds = [
        ("zero",    b"\x00" * 32),
        ("ramp",    bytes(range(32))),
        ("rfc-ish", hashlib.sha3_256(b"metatron.mnemonic.v1.testvector").digest()),
    ]
    for name, seed in test_seeds:
        syms = encode_private(seed)
        in_C = is_in_code(syms)
        print(f"   {name:<10s}  fingerprint={hex_id(syms)}  in_C={in_C}")
        assert in_C, "private inscription must lie in C"
        # Round trip
        rec, ver = decode_private(syms)
        assert rec == seed, "round-trip failed"
        img = render(syms, size=1024)
        write(img, out_dir / f"private_{name}.png")

    # ---- robustness demo: 21 erasures on a private cube
    print("\n[4/4] robustness: erase 21 of 91 carriers (3 per RS block)")
    import random
    from eopx.metatron import reed_solomon as RS
    seed = hashlib.sha3_256(b"robustness-demo").digest()
    cw = encode_private(seed)
    rng = random.Random(42)
    erasures = []
    for b in range(RS.NUM_BLOCKS):
        for i in rng.sample(range(RS.BLOCK_N), 3):
            erasures.append(i * RS.NUM_BLOCKS + b)
    damaged = list(cw)
    for p in erasures:
        damaged[p] = (damaged[p] + 4) % 13
    rec, _ = decode_private(damaged, erasures=erasures)
    assert rec == seed, "erasure recovery failed"
    print(f"   recovered {len(rec)} bytes after 21 erasures.")
    # Render the damaged cube to visualize
    img_damaged = render(damaged, size=1024)
    write(img_damaged, out_dir / "private_with_erasures.png")

    print("\nOK. All assertions held.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

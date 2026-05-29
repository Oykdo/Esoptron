"""Loopback self-test: encode -> render -> detect -> decode all on the
canonical PNG (no camera). If this fails, the math chain is broken.

Run before attempting any photographic test."""

from __future__ import annotations

import hashlib
import sys

from eopx.metatron import (
    encode_public, encode_private, decode_private, render,
    is_in_code, extract_canonical, erasures_from_confidences,
)


def main() -> int:
    print("=== LOOPBACK CANONICAL: encode -> render -> detect -> decode ===\n")

    failures = 0

    # --- private path
    seed = hashlib.sha3_256(b"metatron.loopback.private").digest()
    print(f"PRIVATE  seed     = {seed.hex()}")
    cw = encode_private(seed)
    img = render(cw, size=1024)
    syms, dists = extract_canonical(img)
    n_diff = sum(1 for a, b in zip(syms, cw) if a != b)
    in_C = is_in_code(syms)
    print(f"         symbols rendered then re-detected: "
          f"{91 - n_diff}/91 match, in_C={in_C}, max_dist={max(dists):.4f}")
    erasures = erasures_from_confidences(dists)
    try:
        recovered, ver = decode_private(syms, erasures=erasures)
        ok = recovered == seed
    except Exception as exc:
        recovered, ver, ok = None, None, False
        print(f"         decode raised: {exc}")
    print(f"         seed recovered : {ok}\n")
    if not ok:
        failures += 1

    # --- public path
    spinor = hashlib.sha3_512(b"metatron.loopback.public").digest()
    print(f"PUBLIC   spinor   = {spinor.hex()[:32]}...")
    syms_pub = encode_public(spinor)
    img_pub = render(syms_pub, size=512)
    syms_det, dists_pub = extract_canonical(img_pub)
    n_diff_pub = sum(1 for a, b in zip(syms_det, syms_pub) if a != b)
    in_C_pub = is_in_code(syms_det)
    print(f"         symbols rendered then re-detected: "
          f"{91 - n_diff_pub}/91 match, in_C={in_C_pub}, "
          f"max_dist={max(dists_pub):.4f}")
    print(f"         (Theorem 2: in_C should be False for a public render)\n")
    if n_diff_pub > 0 or in_C_pub:
        failures += 1

    if failures == 0:
        print("OK -- loopback succeeds on both private and public paths.")
        return 0
    else:
        print(f"FAILED -- {failures} loopback path(s) broken.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

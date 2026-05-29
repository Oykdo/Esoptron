"""Generate a fresh Dilithium5 + Kyber1024 keypair for Esoptron.

Usage
-----
  py scripts/eopx_keygen.py --out ~/.esoptron/keys/default.json
  py scripts/eopx_keygen.py --out keys/dev.json --force

The generated JSON envelope contains BOTH the public and the secret
keys. Protect it accordingly (filesystem permissions, encrypted volume,
hardware token, ...). Use ``--public-only`` to derive a verifier-safe
copy without secret material.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from eopx.format import EopxKey


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True, help="Path to write the keypair JSON")
    p.add_argument("--force", action="store_true",
                   help="Overwrite if the file already exists")
    p.add_argument("--public-only", action="store_true",
                   help="Write only the public keys (verifier role)")
    p.add_argument("--from", dest="src",
                   help="Path to an existing keypair JSON; "
                        "use with --public-only to derive a public copy")
    args = p.parse_args(argv[1:])

    out = Path(args.out).expanduser()
    if out.exists() and not args.force:
        print(f"refusing to overwrite {out} (pass --force)", file=sys.stderr)
        return 2

    if args.src:
        key = EopxKey.load(Path(args.src).expanduser())
        if args.public_only:
            key = key.public_only()
    else:
        if args.public_only:
            print("--public-only requires --from <signer.json>", file=sys.stderr)
            return 2
        key = EopxKey.generate()

    key.save(out)
    print(f"wrote {out}")
    print(f"  dilithium_pk_fp = {key.dilithium_pk_fp.hex()}")
    print(f"  kyber_pk_fp     = {key.kyber_pk_fp.hex()}")
    print(f"  has_secrets     = {key.has_secrets}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

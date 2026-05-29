"""``eopx-verify`` console entry point.

Installed by ``pyproject.toml`` so ``pip install esoptron`` ships a
``eopx-verify`` command that does not require cloning the full repo.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .eopx_verify import verify


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="eopx-verify",
                                 description="Verify a .eopx artefact.")
    p.add_argument("path", help="Path to the .eopx file")
    p.add_argument("--expect-pk-fp",
                   help="64-char hex SHA3-256 fingerprint that the signer "
                        "must match (optional)")
    p.add_argument("--quiet", action="store_true",
                   help="Print only OK/FAIL")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    path = Path(args.path)
    if not path.is_file():
        print(f"file not found: {path}", file=sys.stderr)
        return 2

    res = verify(path, expected_dilithium_pk_fp=args.expect_pk_fp)
    if args.quiet:
        print("OK" if res.ok else "FAIL")
        return 0 if res.ok else 1

    if res.manifest:
        m = res.manifest
        print(f"vault_id        : {m.vault_id}")
        print(f"timestamp_utc   : {m.timestamp_utc}")
        print(f"dilithium_pk_fp : {m.dilithium_pk_fp}")
        print(f"kyber_pk_fp     : {m.kyber_pk_fp}")
        print(f"merkle_root     : {m.merkle_root}")
    print()
    print(f"chunks_ok       : {res.chunks_ok}")
    print(f"image_hash_ok   : {res.image_hash_ok}")
    print(f"payload_hash_ok : {res.payload_hash_ok}")
    print(f"signature_ok    : {res.signature_ok}")
    for e in res.errors:
        print(f"  ! {e}")
    print()
    print("RESULT:", "OK" if res.ok else "FAIL")
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

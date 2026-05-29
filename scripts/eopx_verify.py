"""Verify a .eopx container offline.

Usage
-----
  py scripts/eopx_verify.py out/test_vault_public.eopx
  py scripts/eopx_verify.py file.eopx --expect-pk-fp <64 hex chars>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from eopx.format import verify


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", help="Path to the .eopx file")
    p.add_argument("--expect-pk-fp",
                   help="Hex-encoded SHA3-256 fingerprint that the signer's "
                        "Dilithium public key must match.")
    p.add_argument("--quiet", action="store_true",
                   help="Print only OK/FAIL and exit with status code.")
    args = p.parse_args(argv[1:])

    path = Path(args.path)
    if not path.is_file():
        print(f"file not found: {path}", file=sys.stderr)
        return 2

    res = verify(path, expected_dilithium_pk_fp=args.expect_pk_fp)
    if args.quiet:
        print("OK" if res.ok else "FAIL")
        return 0 if res.ok else 1

    print(f"== {path} ==")
    if res.manifest:
        m = res.manifest
        print(f"  format_version   : {m.format_version}")
        print(f"  vault_id         : {m.vault_id}")
        print(f"  timestamp_utc    : {m.timestamp_utc}")
        print(f"  dilithium_pk_fp  : {m.dilithium_pk_fp}")
        print(f"  kyber_pk_fp      : {m.kyber_pk_fp}")
        print(f"  merkle_root      : {m.merkle_root}")
        print(f"  image_sha3_512   : {m.image_sha3_512[:32]}...")
        print(f"  payload_hash     : {m.payload_hash[:32]}...")
    print()
    print("Checks:")
    print(f"  chunks_ok        : {res.chunks_ok}")
    print(f"  image_hash_ok    : {res.image_hash_ok}")
    print(f"  payload_hash_ok  : {res.payload_hash_ok}")
    print(f"  signature_ok     : {res.signature_ok}")
    print()
    if res.errors:
        print("Errors:")
        for e in res.errors:
            print(f"  - {e}")
    print()
    print("RESULT:", "OK (signed and intact)" if res.ok else "FAIL (do not trust)")
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

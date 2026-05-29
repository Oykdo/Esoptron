"""Reconstruct a secret from at least k .eopx shards.

Usage
-----
  py scripts/eopx_reconstruct.py \
      --shard out/shards/shard_xxxxx_01.eopx \
      --shard out/shards/shard_xxxxx_03.eopx \
      --shard out/shards/shard_xxxxx_05.eopx \
      --recipient out/recipients/alice.json \
      --recipient out/recipients/carol.json \
      --recipient out/recipients/eve.json

Recipient JSON files must contain Kyber secret keys. Order of
``--shard`` / ``--recipient`` does not matter; the reconstructor tries
every key against every shard.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from eopx.format import EopxKey, reconstruct_secret


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--shard", action="append", required=True,
                   help="Path to a shard .eopx file. Repeat (>=k times).")
    p.add_argument("--recipient", action="append", required=True,
                   help="Recipient keypair JSON (with Kyber secret). Repeat.")
    p.add_argument("--out", help="Write recovered secret bytes to this file")
    p.add_argument("--hex", action="store_true",
                   help="Print recovered secret as hex on stdout")
    args = p.parse_args(argv[1:])

    shard_paths = [Path(s) for s in args.shard]
    recipients = [EopxKey.load(Path(r).expanduser()) for r in args.recipient]
    if not any(r.kyber_sk for r in recipients):
        print("no recipient provides a Kyber secret key", file=sys.stderr)
        return 2

    try:
        secret = reconstruct_secret(shard_paths, recipients)
    except ValueError as exc:
        print(f"reconstruction failed: {exc}", file=sys.stderr)
        return 1

    print(f"recovered {len(secret)} bytes")
    if args.out:
        Path(args.out).write_bytes(secret)
        print(f"  wrote {args.out}")
    if args.hex or not args.out:
        print(f"  hex: {secret.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

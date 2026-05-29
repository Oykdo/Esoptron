"""Split a secret into k/n signed .eopx shards encrypted to recipients.

Usage
-----
  py scripts/eopx_shard.py --secret-hex <hex> --k 3 \
      --recipient out/recipients/alice.json out/recipients/bob.json \
      --recipient out/recipients/carol.json out/recipients/dave.json \
      --recipient out/recipients/eve.json \
      --signer out/demo_key.json \
      --out-dir out/shards

Each recipient JSON must be an EopxKey envelope produced by
``eopx_keygen.py`` (public or private — only the Kyber public key is
used for encryption). The signer JSON must contain Dilithium secret
material.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from eopx.format import EopxKey, shard_secret


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--secret-hex", help="Hex-encoded secret (32 chars per 16 bytes)")
    p.add_argument("--secret-file", help="Path to a binary file containing the secret")
    p.add_argument("--k", type=int, required=True, help="Reconstruction threshold")
    p.add_argument("--recipient", action="append", required=True,
                   help="Recipient keypair JSON (one --recipient per shard). "
                        "Repeat to add more.")
    p.add_argument("--signer", required=True, help="Signer keypair JSON (with secret)")
    p.add_argument("--out-dir", required=True, help="Where to write shard .eopx files")
    p.add_argument("--vault-id", help="Optional 32-char hex vault_id")
    args = p.parse_args(argv[1:])

    if args.secret_hex and args.secret_file:
        print("provide --secret-hex OR --secret-file, not both", file=sys.stderr)
        return 2
    if args.secret_hex:
        secret = bytes.fromhex(args.secret_hex)
    elif args.secret_file:
        secret = Path(args.secret_file).read_bytes()
    else:
        print("must provide --secret-hex or --secret-file", file=sys.stderr)
        return 2

    signer = EopxKey.load(Path(args.signer).expanduser())
    if not signer.has_secrets:
        print("signer key is public-only; cannot sign shards", file=sys.stderr)
        return 2

    recipients = [EopxKey.load(Path(r).expanduser()) for r in args.recipient]
    recipient_pks = [r.kyber_pk for r in recipients]

    pack = shard_secret(
        secret=secret, k=args.k,
        recipient_kyber_pks=recipient_pks,
        signer=signer, out_dir=Path(args.out_dir),
        vault_id=args.vault_id,
    )
    print(f"group_id   : {pack.group_id}")
    print(f"k / n      : {args.k} / {len(recipients)}")
    print(f"secret len : {len(secret)} bytes")
    print(f"shards     :")
    for p in pack.paths:
        print(f"  - {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

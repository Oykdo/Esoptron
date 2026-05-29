"""Wrap a PNG, or generate a Metatron cube, into a signed .eopx container.

Usage
-----
  py scripts/eopx_pack.py out/test_vault_public.png \
      --key ~/.esoptron/keys/default.json \
      --out out/test_vault_public.eopx

  # With explicit vault_id / merkle_root commitment
  py scripts/eopx_pack.py cube.png --key key.json --out cube.eopx \
      --vault-id deadbeefdeadbeefdeadbeefdeadbeef \
      --merkle-root <64 hex chars>

  # One-shot private Metatron cube -> signed .eopx
  py scripts/eopx_pack.py --seed <64 hex chars> --role private \
      --key key.json --out private_cube.eopx
"""

from __future__ import annotations

import argparse
import hashlib
import secrets
import sys
from pathlib import Path

from eopx.format import EopxKey, pack
from eopx.metatron import encode_private, encode_public, render


def _generated_metatron(args):
    if args.role is None:
        raise ValueError("--role is required when generating a Metatron cube")

    if args.seed is not None:
        if args.role != "private":
            raise ValueError("--seed can only be used with --role private")
        seed = bytes.fromhex(args.seed.strip())
        if len(seed) != 32:
            raise ValueError("--seed must be exactly 32 bytes / 64 hex chars")
        symbols = encode_private(seed)
        label = "generated private Metatron cube from seed"
    elif args.spinor is not None:
        if args.role != "public":
            raise ValueError("--spinor can only be used with --role public")
        spinor = bytes.fromhex(args.spinor.strip())
        if len(spinor) not in (32, 48, 64):
            raise ValueError("--spinor must be 32, 48 or 64 bytes")
        symbols = encode_public(spinor)
        label = "generated public Metatron cube from spinor"
    elif args.passphrase is not None:
        raw = args.passphrase.encode("utf-8")
        if args.role == "private":
            symbols = encode_private(hashlib.sha3_256(raw).digest())
            label = "generated private Metatron cube from passphrase"
        else:
            spinor = hashlib.sha3_512(raw + b".public").digest()
            symbols = encode_public(spinor)
            label = "generated public Metatron cube from passphrase"
    elif args.random:
        if args.role == "private":
            symbols = encode_private(secrets.token_bytes(32))
            label = "generated private Metatron cube from random seed"
        else:
            symbols = encode_public(secrets.token_bytes(64))
            label = "generated public Metatron cube from random spinor"
    else:
        raise ValueError("no Metatron generation source selected")

    if args.size <= 0:
        raise ValueError("--size must be positive")
    return render(symbols, size=args.size), label


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", nargs="?",
                   help="Source PNG to wrap. Omit to generate a Metatron cube.")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--seed",
                     help="Generate a private Metatron cube from a 32-byte seed hex")
    src.add_argument("--spinor",
                     help="Generate a public Metatron cube from a 32/48/64-byte spinor hex")
    src.add_argument("--passphrase",
                     help="Generate from a passphrase: SHA3-256 private seed or SHA3-512 public spinor")
    src.add_argument("--random", action="store_true",
                     help="Generate a random seed/spinor for testing")
    p.add_argument("--role", choices=("private", "public"),
                   help="Role for generated Metatron cubes")
    p.add_argument("--size", type=int, default=1024,
                   help="Generated cube size in pixels (default 1024)")
    p.add_argument("--key", required=True, help="Path to the signer keypair JSON")
    p.add_argument("--out", required=True, help="Destination .eopx path")
    p.add_argument("--vault-id",
                   help="16-byte hex (32 chars). Defaults to a random UUID.")
    p.add_argument("--merkle-root",
                   help="32-byte hex (64 chars). Defaults to zeros.")
    p.add_argument("--timestamp",
                   help="ISO-8601 UTC timestamp. Defaults to now.")
    args = p.parse_args(argv[1:])

    generation_selected = any(
        value is not None and value is not False
        for value in (args.seed, args.spinor, args.passphrase, args.random)
    )
    if args.image and generation_selected:
        print("choose either an existing image or a generated Metatron source",
              file=sys.stderr)
        return 2
    if not args.image and not generation_selected:
        print("provide IMAGE, or one of --seed/--spinor/--passphrase/--random",
              file=sys.stderr)
        return 2

    try:
        if generation_selected:
            image, source_label = _generated_metatron(args)
        else:
            img_path = Path(args.image)
            if not img_path.is_file():
                print(f"image not found: {img_path}", file=sys.stderr)
                return 2
            image = img_path
            source_label = f"wrapped existing image {img_path}"
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    key = EopxKey.load(Path(args.key).expanduser())
    if not key.has_secrets:
        print("key file is public-only; cannot sign", file=sys.stderr)
        return 2

    manifest = pack(
        image,
        Path(args.out),
        key,
        vault_id=args.vault_id,
        merkle_root=args.merkle_root,
        timestamp_utc=args.timestamp,
    )
    print(f"wrote {args.out}")
    print(f"  source          = {source_label}")
    print(f"  vault_id        = {manifest.vault_id}")
    print(f"  timestamp_utc   = {manifest.timestamp_utc}")
    print(f"  dilithium_pk_fp = {manifest.dilithium_pk_fp}")
    print(f"  kyber_pk_fp     = {manifest.kyber_pk_fp}")
    print(f"  merkle_root     = {manifest.merkle_root}")
    print(f"  image_sha3_512  = {manifest.image_sha3_512[:32]}...")
    print(f"  payload_hash    = {manifest.payload_hash[:32]}...")
    print(f"  signature size  = {len(manifest.signature)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

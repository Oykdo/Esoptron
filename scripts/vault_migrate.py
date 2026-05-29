"""Cross-machine vault migration CLI (Protocol F).

Usage
-----
Generate migration proof on source device:
  py scripts/vault_migrate.py prove \
      --master-key <hex> \
      --vault-id <hex> \
      --source-lock <hex> \
      --target-lock <hex> \
      --out proof.json

Verify and complete migration on target device:
  py scripts/vault_migrate.py verify \
      --proof proof.json \
      --master-key <hex> \
      --machine-lock <hex>

Generate a QR-displayable target lock for the new device:
  py scripts/vault_migrate.py show-lock --machine-lock <hex>

The migration flow:
  1. Target device displays its machine_lock as QR (show-lock)
  2. Source scans QR, generates proof (prove)
  3. Proof is transferred to target (e.g., QR, NFC, encrypted channel)
  4. Target verifies and derives new machine-bound key (verify)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from eopx.vault.migrate import (
    MigrationProof,
    new_migration_challenge,
    prove_migration,
    verify_migration,
    compute_verify_tag,
)


def cmd_prove(args: argparse.Namespace) -> int:
    master_key = bytes.fromhex(args.master_key)
    vault_id = bytes.fromhex(args.vault_id)
    source_lock = bytes.fromhex(args.source_lock)
    target_lock = bytes.fromhex(args.target_lock)

    if len(master_key) != 32:
        print("master_key must be 32 bytes (64 hex chars)", file=sys.stderr)
        return 2
    if len(vault_id) != 32:
        print("vault_id must be 32 bytes (64 hex chars)", file=sys.stderr)
        return 2
    if len(source_lock) != 32:
        print("source_lock must be 32 bytes (64 hex chars)", file=sys.stderr)
        return 2
    if len(target_lock) != 32:
        print("target_lock must be 32 bytes (64 hex chars)", file=sys.stderr)
        return 2

    challenge = new_migration_challenge(vault_id, source_lock, target_lock)
    proof = prove_migration(master_key, challenge)

    out_path = Path(args.out).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(proof.to_dict(), indent=2))

    print(f"wrote migration proof to {out_path}")
    print(f"  vault_id:   {proof.vault_id.hex()}")
    print(f"  source:     {proof.source_lock.hex()[:16]}...")
    print(f"  target:     {proof.target_lock.hex()[:16]}...")
    print(f"  commitment: {proof.commitment.hex()[:16]}...")

    if args.verify_tag:
        tag = compute_verify_tag(master_key, vault_id)
        print(f"  verify_tag: {tag.hex()}")

    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    proof_path = Path(args.proof).expanduser()
    if not proof_path.exists():
        print(f"proof file not found: {proof_path}", file=sys.stderr)
        return 2

    proof = MigrationProof.from_dict(json.loads(proof_path.read_text()))
    master_key = bytes.fromhex(args.master_key)
    machine_lock = bytes.fromhex(args.machine_lock)

    if len(master_key) != 32:
        print("master_key must be 32 bytes (64 hex chars)", file=sys.stderr)
        return 2
    if len(machine_lock) != 32:
        print("machine_lock must be 32 bytes (64 hex chars)", file=sys.stderr)
        return 2

    check_ttl = not args.no_ttl
    result = verify_migration(proof, master_key, machine_lock, check_ttl=check_ttl)

    if result is None:
        print("MIGRATION FAILED: proof verification failed", file=sys.stderr)
        print("Possible causes:", file=sys.stderr)
        print("  - Wrong master_key", file=sys.stderr)
        print("  - This device is not the intended target", file=sys.stderr)
        print("  - Challenge expired (TTL)", file=sys.stderr)
        print("  - Proof was tampered", file=sys.stderr)
        return 1

    print("MIGRATION SUCCESSFUL")
    print(f"  vault_id:          {result.vault_id.hex()}")
    print(f"  machine_bound_key: {result.machine_bound_key.hex()}")
    print(f"  session_key:       {result.session_key.hex()}")

    if args.out:
        out_path = Path(args.out).expanduser()
        out_data = {
            "vault_id_hex": result.vault_id.hex(),
            "machine_bound_key_hex": result.machine_bound_key.hex(),
            "session_key_hex": result.session_key.hex(),
        }
        out_path.write_text(json.dumps(out_data, indent=2))
        print(f"wrote keys to {out_path}")

    return 0


def cmd_show_lock(args: argparse.Namespace) -> int:
    machine_lock = bytes.fromhex(args.machine_lock)
    if len(machine_lock) != 32:
        print("machine_lock must be 32 bytes (64 hex chars)", file=sys.stderr)
        return 2

    print("Target machine lock (share via QR with source device):")
    print(f"  {machine_lock.hex()}")

    if args.qr:
        try:
            import qrcode
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
            qr.add_data(machine_lock.hex())
            qr.make(fit=True)
            qr.print_ascii(invert=True)
        except ImportError:
            print("(install qrcode for QR display: pip install qrcode)", file=sys.stderr)

    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Cross-machine vault migration (Protocol F)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # prove
    prove_p = sub.add_parser("prove", help="Generate migration proof (source device)")
    prove_p.add_argument("--master-key", required=True, help="64-char hex master key")
    prove_p.add_argument("--vault-id", required=True, help="64-char hex vault ID")
    prove_p.add_argument("--source-lock", required=True, help="64-char hex source machine lock")
    prove_p.add_argument("--target-lock", required=True, help="64-char hex target machine lock")
    prove_p.add_argument("--out", required=True, help="Output path for proof JSON")
    prove_p.add_argument("--verify-tag", action="store_true",
                         help="Also print the verify_tag for embedding in .eopx")

    # verify
    verify_p = sub.add_parser("verify", help="Verify proof and complete migration (target device)")
    verify_p.add_argument("--proof", required=True, help="Path to proof JSON")
    verify_p.add_argument("--master-key", required=True, help="64-char hex master key")
    verify_p.add_argument("--machine-lock", required=True, help="64-char hex THIS device's lock")
    verify_p.add_argument("--no-ttl", action="store_true", help="Disable TTL check (testing)")
    verify_p.add_argument("--out", help="Output path for derived keys JSON")

    # show-lock
    lock_p = sub.add_parser("show-lock", help="Display machine lock for QR sharing")
    lock_p.add_argument("--machine-lock", required=True, help="64-char hex machine lock")
    lock_p.add_argument("--qr", action="store_true", help="Print ASCII QR code")

    args = p.parse_args(argv[1:])

    if args.cmd == "prove":
        return cmd_prove(args)
    elif args.cmd == "verify":
        return cmd_verify(args)
    elif args.cmd == "show-lock":
        return cmd_show_lock(args)
    else:
        p.print_help()
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

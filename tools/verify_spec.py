"""Verify a tracked document against ``SPECS.SHA3-256``.

Recomputes the **normalised** SHA3-256 of the document and compares it
to the manifest record. Normalisation matches ``tools/sign_spec.py``
exactly (see ``normalise_bytes`` there).

If ``--pk-hex`` is provided AND the record carries a ``signature:``
field, also verifies the Dilithium-5 signature.

Use ``--all`` to verify every record in the manifest.

Exits 0 on success, 1 on any failure.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from eopx.format.keys import EopxKey  # noqa: E402

# Re-use the canonical normalisation from sign_spec.
sys.path.insert(0, str(ROOT / "tools"))
from sign_spec import normalise_bytes, NORMALISATION_ID  # noqa: E402


MANIFEST = ROOT / "SPECS.SHA3-256"


def _parse(text: str) -> List[Dict[str, str]]:
    blocks: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            if current:
                blocks.append(current)
                current = {}
            continue
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        current[k.strip().lower()] = v.strip()
    if current:
        blocks.append(current)
    return blocks


def _check(record: Dict[str, str], *, pk_hex: str | None) -> tuple[bool, str]:
    rel = record["spec"]
    path = ROOT / rel
    if not path.is_file():
        return False, f"file not found: {rel}"

    raw = path.read_bytes()
    try:
        normalised = normalise_bytes(raw)
    except UnicodeDecodeError as exc:
        return False, f"{rel}: not valid UTF-8 ({exc.reason} @ {exc.start})"

    expected_norm = record.get("normalisation", "")
    if expected_norm and expected_norm != NORMALISATION_ID:
        return False, (
            f"{rel}: manifest declares normalisation {expected_norm!r} "
            f"but tool implements {NORMALISATION_ID!r}"
        )

    actual = hashlib.sha3_256(normalised).hexdigest()
    expected_field = record.get("hash", "")
    if not expected_field.startswith("sha3-256:"):
        return False, f"{rel}: unsupported hash field {expected_field!r}"
    expected = expected_field.split(":", 1)[1]
    if actual != expected:
        return False, (
            f"{rel}: hash mismatch\n"
            f"    expected: sha3-256:{expected}\n"
            f"    actual  : sha3-256:{actual}"
        )

    if "signature" not in record:
        return True, (
            f"{rel}: OK (hash) sha3-256:{actual[:16]}\u2026 "
            f"author={record.get('author', '?')!r}"
        )

    if not pk_hex:
        return True, (
            f"{rel}: OK (hash only — provide --pk-hex to verify signature)"
        )

    sig_field = record["signature"]
    if not sig_field.startswith("dilithium5:"):
        return False, f"{rel}: unsupported signature {sig_field!r}"
    signature = bytes.fromhex(sig_field.split(":", 1)[1])

    pk = bytes.fromhex(pk_hex)
    pk_fp_actual = hashlib.sha3_256(pk).hexdigest()
    pk_fp_expected = record.get("signer-pk-fp", "")
    if pk_fp_expected.startswith("sha3-256:"):
        pk_fp_expected = pk_fp_expected.split(":", 1)[1]
    if pk_fp_actual != pk_fp_expected:
        return False, (
            f"{rel}: provided public-key fingerprint mismatch\n"
            f"    expected: {pk_fp_expected}\n"
            f"    actual  : {pk_fp_actual}"
        )

    verifier = EopxKey(dilithium_pk=pk, kyber_pk=b"")
    digest = hashlib.sha3_256(normalised).digest()
    if not verifier.verify(digest, signature):
        return False, f"{rel}: Dilithium-5 signature does not verify"
    return True, f"{rel}: OK (hash + Dilithium-5 signature) sha3-256:{actual[:16]}\u2026"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", nargs="?", type=Path)
    ap.add_argument("--pk-hex")
    ap.add_argument("--all", action="store_true",
                    help="Verify every record in the manifest.")
    args = ap.parse_args()

    if not MANIFEST.exists():
        print(f"ERR: {MANIFEST.name} not found at repo root", file=sys.stderr)
        return 1

    blocks = _parse(MANIFEST.read_text(encoding="utf-8"))

    if args.path is None and not args.all:
        ap.error("provide a path, or use --all")

    if args.all:
        records = blocks
    else:
        rel = args.path.resolve().relative_to(ROOT).as_posix()
        records = [b for b in blocks if b.get("spec") == rel]
        if not records:
            print(f"ERR: no record for {rel} in {MANIFEST.name}",
                  file=sys.stderr)
            return 1

    fail = 0
    for rec in records:
        ok, msg = _check(rec, pk_hex=args.pk_hex)
        prefix = "  ok " if ok else "  XX "
        stream = sys.stdout if ok else sys.stderr
        print(prefix + msg, file=stream)
        if not ok:
            fail += 1

    if fail:
        print(f"\n{fail}/{len(records)} record(s) failed.", file=sys.stderr)
        return 1
    print(f"\nall {len(records)} record(s) verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

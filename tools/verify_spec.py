"""Verify a tracked document against ``SPECS.SHA3-256``.

Recomputes the **normalised** SHA3-256 of the document and compares it
to the manifest record. Normalisation matches ``tools/sign_spec.py``
exactly (see ``normalise_bytes`` there).

If a public key is provided (``--pk-hex`` / ``--pk-file``) AND the
record carries a ``signature:`` field, the Dilithium-5 signature is
verified too. A record may also carry a ``cosignature:`` (second
signer); pass ``--cosign-pk-hex`` / ``--cosign-pk-file`` to verify it.
Public keys can be loaded straight from a key or ``*.pub.json`` file.

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


# Re-use the canonical normalisation from sign_spec.
sys.path.insert(0, str(ROOT / "tools"))
from sign_spec import normalise_bytes, NORMALISATION_ID  # noqa: E402


MANIFEST = ROOT / "SPECS.SHA3-256"


def _resolve_pk(pk_hex: str | None, pk_file: Path | None) -> bytes | None:
    """Resolve a Dilithium public key from raw hex or a key/pub JSON file."""
    if pk_file is not None:
        from eopx.format.keys import EopxKey  # deferred: hash-only needs no PQ stack
        return EopxKey.load(pk_file).dilithium_pk
    if pk_hex:
        return bytes.fromhex(pk_hex)
    return None


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


def _verify_sig(kind: str, sig_field: str, fp_field: str,
                pk: bytes | None, digest: bytes) -> tuple[bool, str]:
    """Verify one Dilithium-5 signature line. Hash-only when ``pk`` is None."""
    if not sig_field.startswith("dilithium5:"):
        return False, f"{kind}: unsupported signature {sig_field!r}"
    signature = bytes.fromhex(sig_field.split(":", 1)[1])
    if pk is None:
        return True, f"{kind} present (no key given — hash only)"
    fp_actual = hashlib.sha3_256(pk).hexdigest()
    fp_expected = fp_field.split(":", 1)[1] if fp_field.startswith("sha3-256:") \
        else fp_field
    if fp_actual != fp_expected:
        return False, (
            f"{kind}: pk fingerprint mismatch "
            f"(expected {fp_expected[:16]}…, key is {fp_actual[:16]}…)"
        )
    from eopx.format.keys import EopxKey  # deferred: hash-only needs no PQ stack

    verifier = EopxKey(dilithium_pk=pk, kyber_pk=b"")
    if not verifier.verify(digest, signature):
        return False, f"{kind}: Dilithium-5 signature does not verify"
    return True, f"{kind} OK"


def _check(record: Dict[str, str], *, pk: bytes | None = None,
           cosign_pk: bytes | None = None) -> tuple[bool, str]:
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

    if "signature" not in record and "cosignature" not in record:
        return True, (
            f"{rel}: OK (hash) sha3-256:{actual[:16]}\u2026 "
            f"author={record.get('author', '?')!r}"
        )

    digest = hashlib.sha3_256(normalised).digest()
    overall = True
    notes: List[str] = []
    if "signature" in record:
        ok, note = _verify_sig(
            "sig", record["signature"], record.get("signer-pk-fp", ""),
            pk, digest)
        overall &= ok
        notes.append(note)
    if "cosignature" in record:
        ok, note = _verify_sig(
            "cosig", record["cosignature"], record.get("cosigner-pk-fp", ""),
            cosign_pk, digest)
        overall &= ok
        notes.append(note)
    return overall, (
        f"{rel}: hash OK sha3-256:{actual[:16]}… ["
        + "; ".join(notes) + "]"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", nargs="?", type=Path)
    ap.add_argument("--pk-hex", help="Primary signer public key (hex).")
    ap.add_argument("--pk-file", type=Path,
                    help="Primary signer key/pub JSON (dilithium_pk_b64).")
    ap.add_argument("--cosign-pk-hex", help="Cosigner public key (hex).")
    ap.add_argument("--cosign-pk-file", type=Path,
                    help="Cosigner key/pub JSON (dilithium_pk_b64).")
    ap.add_argument("--all", action="store_true",
                    help="Verify every record in the manifest.")
    args = ap.parse_args()

    pk = _resolve_pk(args.pk_hex, args.pk_file)
    cosign_pk = _resolve_pk(args.cosign_pk_hex, args.cosign_pk_file)

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
        ok, msg = _check(rec, pk=pk, cosign_pk=cosign_pk)
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

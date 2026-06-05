"""License-boundary guard — keep the MIT `eopx` package free of proprietary code.

The MIT licence of Esoptron only holds if the package never imports the
proprietary Eidolon tree. This tool pins `eopx`'s **external import surface**
into a tamper-evident ASCII lock so any drift — above all a sneaked-in
proprietary import — fails CI until it is consciously re-pinned and reviewed.

Layers of defence (maximum, but dependency-free):

1. **Static** — the surface is read by parsing the AST, never by importing, so
   no code runs during the check.
2. **Deny list** — `eidolon`, `eidolon_crypto`, `src` must never appear. A hard,
   independent failure (not just a fingerprint change).
3. **Pinned fingerprint** — a SHA3-256 over the sorted external imports, with a
   randomart **sigil** (a pre-registered ASCII cluster) for human recognition.
4. **Self-hash** — the lock carries a hash over its own body; the verifier
   checks *that* first (authenticity of the fingerprint before trusting it),
   refusing a tampered lock.

    py tools/license_boundary.py            # verify (exit 0 / 1)
    py tools/license_boundary.py --write    # (re)pin the lock — after review
"""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "eopx"
LOCK = ROOT / "tools" / "license_boundary.lock"

#: Roots the MIT package must NEVER import (the proprietary / app tree).
DENY = frozenset({"eidolon", "eidolon_crypto", "src"})

_SELF_MARK = "\nself: sha3-256:"


def scan() -> tuple[set[str], set[str]]:
    """Static AST scan of `eopx` → (external_surface, denied_hits)."""
    surface: set[str] = set()
    denied: set[str] = set()
    stdlib = getattr(sys, "stdlib_module_names", frozenset())
    for path in sorted(PKG.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            roots: list[str] = []
            if isinstance(node, ast.Import):
                roots = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:  # relative import -> internal to eopx
                    continue
                if node.module:
                    roots = [node.module.split(".")[0]]
            for r in roots:
                if r in ("eopx", "esoptron", "__future__"):
                    continue
                if r in DENY:
                    denied.add(r)
                elif r not in stdlib:
                    surface.add(r)
    return surface, denied


def _fingerprint(surface: set[str]) -> str:
    blob = "\n".join(sorted(surface)).encode("utf-8")
    return hashlib.sha3_256(blob).hexdigest()


def _sigil(fp_hex: str) -> list[str]:
    from eopx.collection.sigil import randomart

    return randomart(bytes.fromhex(fp_hex))


def build_body() -> str:
    """The lock body (everything but the trailing self-hash line)."""
    surface, _ = scan()
    fp = _fingerprint(surface)
    lines = [
        "# Esoptron license-boundary lock — generated; do not hand-edit.",
        "# Re-pin only after review: py tools/license_boundary.py --write",
        f"# Denied roots (must never import): {', '.join(sorted(DENY))}",
        "",
        f"fingerprint: sha3-256:{fp}",
        "imports:",
    ]
    lines += [f"  - {mod}" for mod in sorted(surface)]
    lines.append("sigil:")
    lines += [f"  {row}" for row in _sigil(fp)]
    return "\n".join(lines)


def build_manifest() -> str:
    body = build_body()
    self_hash = hashlib.sha3_256(body.encode("utf-8")).hexdigest()
    return f"{body}{_SELF_MARK}{self_hash}\n"


def verify(text: str) -> list[str]:
    """Return a list of problems (empty == intact)."""
    errors: list[str] = []

    # (2) Deny rule — independent of the fingerprint (a denied import is
    #     excluded from the surface, so the pin alone would not catch it).
    _, denied = scan()
    if denied:
        errors.append(
            f"DENIED proprietary import in eopx: {sorted(denied)} — "
            f"the MIT boundary is broken."
        )

    # (4) Authenticity — verify the lock's self-hash BEFORE trusting it.
    if _SELF_MARK not in text:
        errors.append("lock has no self-hash line")
        return errors
    body, _, tail = text.rpartition(_SELF_MARK)
    if hashlib.sha3_256(body.encode("utf-8")).hexdigest() != tail.strip():
        errors.append("lock self-hash mismatch — the lock was tampered with")
        return errors  # do not trust a tampered lock

    # (3) Drift — the live surface must match the authenticated pin.
    if build_body() != body:
        errors.append(
            "eopx import surface drifted from the pinned lock — review the "
            "new dependency, then re-pin: py tools/license_boundary.py --write"
        )
    return errors


def main(argv: list[str]) -> int:
    if "--write" in argv:
        _, denied = scan()
        if denied:
            print(f"refusing to pin: DENIED imports present: {sorted(denied)}",
                  file=sys.stderr)
            return 1
        LOCK.write_text(build_manifest(), encoding="utf-8", newline="\n")
        print(f"pinned {LOCK.relative_to(ROOT)}")
        return 0
    if not LOCK.exists():
        print("no lock — pin it first: py tools/license_boundary.py --write",
              file=sys.stderr)
        return 1
    errors = verify(LOCK.read_text(encoding="utf-8"))
    for e in errors:
        print("FAIL:", e, file=sys.stderr)
    if not errors:
        print("OK: eopx MIT license boundary intact")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

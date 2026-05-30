"""Verify that text files in the repo are valid UTF-8 (no BOM, no CRLF
sneaking in on files declared LF by .gitattributes).

Run on a set of files (e.g. from a pre-commit hook) or with no
arguments to scan the entire repo. Exits 1 if any file fails.

Usage::

    py tools/check_encoding.py                 # scan everything
    py tools/check_encoding.py file1 file2 ... # scan listed files
    py tools/check_encoding.py --fix           # auto-strip BOM + CRLF
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parent.parent

# Suffixes considered "text" (matches .gitattributes scope).
TEXT_SUFFIXES = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".md",
    ".yml", ".yaml", ".toml", ".cfg", ".ini", ".txt", ".sh",
}
# Suffixes where CRLF is OK (Windows shell scripts).
ALLOW_CRLF = {".ps1", ".bat", ".cmd"}
# Filenames we always treat as LF text regardless of extension.
ALWAYS_TEXT = {"SPECS.SHA3-256", ".gitattributes", ".editorconfig"}
# Directories we skip entirely.
SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "out",
    "venv", ".venv", "site-packages",
}


def _iter_text_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.name in ALWAYS_TEXT or p.suffix in TEXT_SUFFIXES:
            yield p


def _check_file(path: Path, *, fix: bool) -> list[str]:
    """Return a list of human-readable issues. Empty list = clean."""
    issues: list[str] = []
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return [f"unreadable: {exc}"]

    changed = False
    new_raw = raw

    # BOM check.
    if new_raw.startswith(b"\xef\xbb\xbf"):
        if fix:
            new_raw = new_raw[3:]
            changed = True
        else:
            issues.append("starts with UTF-8 BOM (EF BB BF)")

    # UTF-8 decode check.
    try:
        new_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        # Cannot auto-fix encoding without knowing the source encoding.
        issues.append(
            f"not valid UTF-8: {exc.reason} at byte {exc.start}"
        )

    # CRLF check (skip files that explicitly allow CRLF).
    if path.suffix not in ALLOW_CRLF and b"\r\n" in new_raw:
        if fix:
            new_raw = new_raw.replace(b"\r\n", b"\n")
            changed = True
        else:
            issues.append("contains CRLF line endings (must be LF)")

    if fix and changed:
        path.write_bytes(new_raw)
        issues.append("[FIXED]")
    return issues


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="*", type=Path,
                    help="Files to check. Default: scan the whole repo.")
    ap.add_argument("--fix", action="store_true",
                    help="Auto-strip BOM and CRLF where safe.")
    args = ap.parse_args()

    targets: Iterable[Path]
    if args.paths:
        targets = [p for p in args.paths if p.is_file()]
    else:
        targets = _iter_text_files(ROOT)

    total = 0
    failed = 0
    for path in targets:
        total += 1
        rel = path.relative_to(ROOT).as_posix() if path.is_absolute() and \
            ROOT in path.parents else str(path)
        issues = _check_file(path, fix=args.fix)
        if not issues:
            continue
        if "[FIXED]" in issues:
            print(f"  fixed: {rel}: " + ", ".join(i for i in issues if i != "[FIXED]"))
            continue
        failed += 1
        print(f"  FAIL: {rel}: " + ", ".join(issues), file=sys.stderr)

    if failed:
        print(f"\n{failed}/{total} files failed UTF-8/LF checks. "
              f"Re-run with --fix to auto-correct safe cases.", file=sys.stderr)
        return 1
    print(f"OK: {total} files clean (UTF-8, no BOM, LF endings).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

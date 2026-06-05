"""License boundary: the MIT `eopx` package must never import the proprietary
Eidolon tree. Enforced statically (AST) and pinned in a tamper-evident lock —
see tools/license_boundary.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import license_boundary as lb  # noqa: E402


def test_no_proprietary_import_in_eopx():
    """Hard deny rule: zero imports of eidolon / eidolon_crypto / src."""
    _, denied = lb.scan()
    assert not denied, (
        f"eopx imports proprietary modules {sorted(denied)} — this breaks the "
        f"MIT licence boundary."
    )


def test_boundary_lock_intact():
    """The pinned lock must be authentic (self-hash) and match the live surface."""
    assert lb.LOCK.exists(), "missing tools/license_boundary.lock — pin it first"
    errors = lb.verify(lb.LOCK.read_text(encoding="utf-8"))
    assert not errors, errors

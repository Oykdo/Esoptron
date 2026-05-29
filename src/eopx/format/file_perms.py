"""Cross-platform restrictive file permissions for secret-key files.

POSIX implementations rely on ``os.chmod(0o600)``. Windows requires DACL
manipulation via ``icacls`` (which ships with every modern Windows) because
``os.chmod`` on Windows only toggles the read-only bit and leaves the file
world-readable by every user on the machine.

This module is best-effort:

* On POSIX, we call ``os.chmod(0o600)`` and emit a warning if it fails.
* On Windows, we invoke ``icacls`` to strip inheritance and grant only the
  current user. If ``icacls`` is missing or returns non-zero we emit a loud
  warning so the operator knows the file is not protected.

The warning text always includes the absolute path so it shows up in the
ops log even when the caller swallows the return value.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Optional

_log = logging.getLogger("eopx.format.file_perms")

_IS_WINDOWS = platform.system() == "Windows"


def _windows_lock_down(path: Path) -> bool:
    """Strip inheritance and grant only the current user. Returns True on success."""
    icacls = shutil.which("icacls")
    if icacls is None:
        _log.warning(
            "icacls not found on PATH; cannot restrict ACL on %s. "
            "The file may be readable by other users on this machine.",
            path,
        )
        return False
    try:
        user = os.environ.get("USERNAME") or os.environ.get("USER")
        if not user:
            _log.warning(
                "Could not determine current Windows user; leaving %s "
                "with default ACLs.", path,
            )
            return False
        # /inheritance:r removes inherited ACEs, then /grant:r grants the
        # current user full control. Run silently; check returncode.
        for args in (
            [icacls, str(path), "/inheritance:r"],
            [icacls, str(path), "/grant:r", f"{user}:(F)"],
        ):
            res = subprocess.run(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
            )
            if res.returncode != 0:
                _log.warning(
                    "icacls %s returned %d: %s",
                    " ".join(args[1:]),
                    res.returncode,
                    res.stderr.decode("utf-8", errors="replace").strip(),
                )
                return False
        return True
    except Exception as exc:  # pragma: no cover - defensive
        _log.warning("Failed to lock down %s on Windows: %s", path, exc)
        return False


def restrict_secret_file(path: str | Path) -> bool:
    """Restrict permissions on a file containing secret-key material.

    Returns ``True`` if the operation succeeded (or was a best-effort no-op
    on a platform where it would not help), ``False`` if the file remains
    insecurely permissive.
    """
    p = Path(path)
    if not p.exists():
        return False
    if _IS_WINDOWS:
        return _windows_lock_down(p)
    try:
        os.chmod(p, 0o600)
        return True
    except OSError as exc:
        _log.warning(
            "Could not chmod %s to 0600 (%s); secret-key file may be "
            "world-readable.", p, exc,
        )
        return False


__all__ = ["restrict_secret_file"]

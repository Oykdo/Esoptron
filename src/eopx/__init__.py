"""Esoptron — Visual Vault Identity for Eidolon.

The high-level scan dispatcher lives in :mod:`eopx.flows` and is imported
lazily on first access so that the lighter sub-packages
(:mod:`eopx.format`, :mod:`eopx.metatron`) can be used without forcing
OpenCV import costs on consumers that don't need the camera pipeline.

    >>> from eopx import scan_and_route, Intent, ScanContext
    >>> result = scan_and_route("photo.jpg",
    ...                         ScanContext(intent=Intent.VERIFY,
    ...                                     spinor_hash_local=h))
"""

from __future__ import annotations

__version__ = "0.0.1"

__all__ = [
    "__version__",
    "Intent",
    "ScanContext",
    "ScanResult",
    "scan_and_route",
    "scan_only",
]


def __getattr__(name: str):
    if name in {"Intent", "ScanContext", "ScanResult",
                "scan_and_route", "scan_only"}:
        from . import flows as _flows
        return getattr(_flows, name)
    raise AttributeError(f"module 'eopx' has no attribute {name!r}")

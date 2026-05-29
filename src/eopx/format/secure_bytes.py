"""Best-effort zeroizing buffer for short-lived secrets.

Python is a managed language and provides **no guarantee** that secret
bytes will be erased from memory: the garbage collector, string interning,
copy-on-write fork(), and CPython's small-int cache all conspire to leak
buffers. The wrapper in this module nonetheless reduces the window of
exposure by:

* storing the secret in a mutable :class:`bytearray` (never an immutable
  :class:`bytes` object, which the runtime is free to copy);
* exposing it through a context manager that calls :func:`wipe` on exit;
* refusing implicit ``str()`` and ``repr()`` conversions that could leak
  bytes into logs.

This is a tactical mitigation, not a substitute for an HSM, kernel
keyring, or Eidolon ``machine_lock``.
"""

from __future__ import annotations

import ctypes
from typing import Iterator, Optional


def _ctypes_memset(buf: bytearray, fill: int) -> None:
    """Fast memset via ctypes; falls back to Python loop on exotic platforms."""
    try:
        n = len(buf)
        if n == 0:
            return
        addr = (ctypes.c_char * n).from_buffer(buf)
        ctypes.memset(addr, fill, n)
    except Exception:  # pragma: no cover - platforms without ctypes buffers
        for i in range(len(buf)):
            buf[i] = fill


def _zeroize(buf: bytearray) -> None:
    """Overwrite ``buf`` with 0x00, then 0xFF, then 0x00 using ``memset``.

    Three passes provide a small amount of defence against compiler /
    runtime tricks that might detect a single zero-fill as dead-store and
    elide it. CPython's bytearray does not optimise this away (the buffer
    is shared with C extensions via the buffer protocol), but the extra
    passes are cheap thanks to ``ctypes.memset`` and align with common
    crypto-library zeroization practice.
    """
    for fill in (0x00, 0xFF, 0x00):
        _ctypes_memset(buf, fill)


class Secret:
    """Container for secret bytes with best-effort wipe on disposal.

    Examples
    --------
    >>> with Secret(b"my-32-byte-vault-seed-........") as s:
    ...     use(bytes(s))
    >>> # s.wipe() was called by the context manager
    """

    __slots__ = ("_buf", "_wiped")

    def __init__(self, data: bytes | bytearray) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Secret expects bytes or bytearray")
        # ALWAYS copy into a fresh bytearray we own, so we can zero it.
        self._buf: Optional[bytearray] = bytearray(data)
        self._wiped: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def wipe(self) -> None:
        """Zero the underlying buffer. Idempotent."""
        if self._wiped:
            return
        buf = self._buf
        if buf is not None:
            _zeroize(buf)
        self._buf = None
        self._wiped = True

    def __del__(self) -> None:  # pragma: no cover - GC-dependent
        try:
            self.wipe()
        except Exception:
            pass

    def __enter__(self) -> "Secret":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.wipe()

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    @property
    def wiped(self) -> bool:
        return self._wiped

    def __len__(self) -> int:
        if self._buf is None:
            return 0
        return len(self._buf)

    def __bytes__(self) -> bytes:
        if self._buf is None:
            raise RuntimeError("Secret already wiped")
        # NB: bytes() copies into a new immutable buffer; callers should
        # avoid keeping that copy around longer than necessary.
        return bytes(self._buf)

    def view(self) -> memoryview:
        """Return a read-only ``memoryview`` of the underlying buffer.

        Useful for hashing / signing without an extra copy. The view
        becomes invalid once :meth:`wipe` is called.
        """
        if self._buf is None:
            raise RuntimeError("Secret already wiped")
        return memoryview(self._buf).toreadonly()

    # ------------------------------------------------------------------
    # Safety: refuse implicit string conversions
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        if self._buf is None:
            return "Secret(<wiped>)"
        return f"Secret(<{len(self._buf)} bytes redacted>)"

    __str__ = __repr__


def wipe_bytearrays(*buffers: Optional[bytearray]) -> None:
    """Zero one or more bytearrays in place. ``None`` arguments are skipped."""
    for b in buffers:
        if b is not None:
            _zeroize(b)

"""In-memory token-bucket rate limiter for Esoptron Flask blueprints.

This is a defense-in-depth measure intended for development / single-instance
deployments. Production deployments SHOULD front the service with a reverse
proxy (nginx, Cloudflare, AWS WAF) that handles rate limiting globally, and
SHOULD replace this module with ``Flask-Limiter`` + a Redis backend so the
counters survive process restarts and are shared across workers.

Defaults are conservative and overridable via env vars:

    ESOPTRON_RATE_LIMIT_DEFAULT   per-IP rate, e.g. "60/minute" (default)
    ESOPTRON_RATE_LIMIT_HEAVY     per-IP rate for crypto/anchor endpoints
                                  (default "10/minute")
    ESOPTRON_RATE_LIMIT_DISABLE   "1" to disable entirely (tests only)

Usage::

    from .rate_limit import rate_limit

    @blueprint.route("/api/v1/scan", methods=["POST"])
    @rate_limit("heavy")
    def scan():
        ...

The limiter keys by ``request.remote_addr``; when behind a trusted reverse
proxy set ``ProxyFix`` so ``X-Forwarded-For`` becomes the effective IP.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from typing import Callable, Deque, Dict, Optional, Tuple

from flask import jsonify, request

# ---------------------------------------------------------------------------
# Rate definitions
# ---------------------------------------------------------------------------

_DEFAULTS = {
    "default": "60/minute",
    "heavy":   "10/minute",
    "anchor":  "30/minute",
}

_UNIT_TO_SECONDS = {
    "second": 1,
    "minute": 60,
    "hour":   3600,
    "day":    86400,
}


def _parse_rate(spec: str) -> Tuple[int, int]:
    """Parse ``"60/minute"`` → ``(60, 60)`` (count, window_seconds)."""
    count_str, _, unit = spec.strip().partition("/")
    count = int(count_str.strip())
    unit = unit.strip().rstrip("s").lower()  # accept "minutes" → "minute"
    window = _UNIT_TO_SECONDS.get(unit)
    if window is None or count <= 0:
        raise ValueError(f"invalid rate spec: {spec!r}")
    return count, window


def _rate_for(bucket: str) -> Tuple[int, int]:
    env_key = f"ESOPTRON_RATE_LIMIT_{bucket.upper()}"
    spec = os.environ.get(env_key, _DEFAULTS.get(bucket, _DEFAULTS["default"]))
    return _parse_rate(spec)


def _is_disabled() -> bool:
    return os.environ.get("ESOPTRON_RATE_LIMIT_DISABLE", "0") == "1"


# ---------------------------------------------------------------------------
# Sliding-window store
# ---------------------------------------------------------------------------

class _SlidingWindow:
    """Per-key deque of request timestamps; O(1) amortised per check."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)

    def check(self, bucket: str, key: str, limit: int, window: int) -> Optional[float]:
        """Return None if allowed; otherwise the retry-after delay in seconds."""
        now = time.monotonic()
        cutoff = now - window
        with self._lock:
            dq = self._buckets[(bucket, key)]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= limit:
                return max(0.0, dq[0] + window - now)
            dq.append(now)
            return None


_STORE = _SlidingWindow()


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------

def _client_ip() -> str:
    # ProxyFix-aware: remote_addr already reflects X-Forwarded-For when the
    # WSGI middleware is configured. Fall back to a sentinel so missing IP
    # never bypasses the limiter.
    return request.remote_addr or "unknown"


def rate_limit(bucket: str = "default") -> Callable:
    """Apply a rate limit to a Flask view function.

    Returns 429 Too Many Requests with ``Retry-After`` (seconds) when the
    caller exceeds the configured rate. No-op when
    ``ESOPTRON_RATE_LIMIT_DISABLE=1`` (intended for tests).
    """
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if _is_disabled():
                return view(*args, **kwargs)
            try:
                limit, window = _rate_for(bucket)
            except ValueError:
                # Misconfigured env: fail open with a server warning rather
                # than 500'ing every request.
                return view(*args, **kwargs)
            retry_after = _STORE.check(
                bucket, _client_ip(), limit, window
            )
            if retry_after is not None:
                resp = jsonify({
                    "error": "rate_limit_exceeded",
                    "bucket": bucket,
                    "limit": f"{limit}/{window}s",
                    "retry_after": round(retry_after, 2),
                })
                resp.status_code = 429
                resp.headers["Retry-After"] = str(int(retry_after) + 1)
                return resp
            return view(*args, **kwargs)
        return wrapper
    return decorator


__all__ = ["rate_limit"]

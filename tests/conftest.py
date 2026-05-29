"""Test session configuration.

Disables the in-process rate limiter so HTTP tests can hammer the same
endpoint from a single fixture without tripping a 429.
"""

from __future__ import annotations

import os

os.environ.setdefault("ESOPTRON_RATE_LIMIT_DISABLE", "1")

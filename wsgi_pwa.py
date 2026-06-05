"""Production WSGI entrypoint for the Esoptron PWA API.

Serves the public, stateless surface — `/api/v1/{health,info,scan,codex,egg,
extract}` — used by the phone-as-scanner PWA and for public Codex / golden-egg
lookups. No database: the Codex and eggs are derived deterministically from the
committed Genesis block (`ESOPTRON_BTC_BLOCK_HASH` / `_HEIGHT`).

Run with gunicorn (bind set by the service env, default :8789):

    ESOPTRON_ANCHOR_BIND=127.0.0.1:8789 \
        gunicorn -c deploy/gunicorn.conf.py wsgi_pwa:app
"""

from __future__ import annotations

import os

from eopx.server.pwa_api import create_app

# Same-origin behind nginx → no CORS needed. Set ESOPTRON_PWA_CORS (comma list)
# only if a separate front-end origin must call it directly.
_cors = os.environ.get("ESOPTRON_PWA_CORS", "").strip()
_origins = [o.strip() for o in _cors.split(",") if o.strip()] or None

app = create_app(allow_origins=_origins)

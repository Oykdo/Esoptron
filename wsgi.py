"""Production WSGI entrypoint for the EPX-T artifact anchor.

Run with gunicorn (from the repo root):

    gunicorn -c deploy/gunicorn.conf.py wsgi:app

Configuration is read from the environment (see ``deploy/anchor.env.example``):

    ESOPTRON_ANCHOR_DSN    PostgreSQL DSN — REQUIRED in production. Use the
                           DIRECT Neon endpoint (no ``-pooler``).
    ESOPTRON_ANCHOR_KEY    path to the anchor signing keypair JSON — REQUIRED.
                           The root of receipt trust; keep it 0600 / in a KMS.

Unlike ``scripts/serve_artifact_api.py``, this entrypoint is deliberately
strict: it never auto-creates the signing key, never falls back to SQLite,
and never exposes ``--allow-grants``. Any misconfiguration fails fast at
import time so a half-configured anchor cannot serve.
"""

from __future__ import annotations

import os
from pathlib import Path

from eopx.format.keys import EopxKey
from eopx.server.artifact_api import create_artifact_api


def _build():
    dsn = os.environ.get("ESOPTRON_ANCHOR_DSN", "").strip()
    if not dsn:
        raise RuntimeError(
            "ESOPTRON_ANCHOR_DSN is required (production runs on PostgreSQL). "
            "Set it in the service environment; never hard-code it."
        )
    if "-pooler." in dsn:
        # Not fatal, but the CAS transactions want the direct endpoint.
        import warnings
        warnings.warn(
            "ESOPTRON_ANCHOR_DSN uses the Neon POOLER endpoint; prefer the "
            "DIRECT endpoint for the anchor's compare-and-swap transactions.",
            RuntimeWarning, stacklevel=2,
        )

    key_path = os.environ.get("ESOPTRON_ANCHOR_KEY", "").strip()
    if not key_path:
        raise RuntimeError(
            "ESOPTRON_ANCHOR_KEY is required (path to the anchor signing key). "
            "Generate once with scripts/eopx_keygen.py and protect it (0600/KMS)."
        )
    key = EopxKey.load(Path(key_path).expanduser())
    if not key.has_secrets:
        raise RuntimeError(f"anchor key {key_path} has no secret material")

    from flask import Flask

    from eopx.server.postgres_ledger import PostgresArtifactLedger
    ledger = PostgresArtifactLedger(dsn)

    # allow_grants stays False: EIDOLON seeding happens in a controlled,
    # offline context, never on the public anchor.
    flask_app = Flask("eopx_artifact_anchor")
    flask_app.register_blueprint(
        create_artifact_api(ledger, key, allow_grants=False))
    return flask_app


app = _build()

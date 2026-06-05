"""The anchor ledger is backend-swappable: SQLite now, Postgres to go online.

These tests pin the contract (:class:`LedgerBackend`) so the SQLite backend
keeps satisfying it and the Postgres skeleton keeps exposing the same surface
— without needing a live PostgreSQL in CI.
"""

from __future__ import annotations

from pathlib import Path

from eopx.server.artifact_ledger import ArtifactLedger
from eopx.server.ledger_base import LedgerBackend
from eopx.server.postgres_ledger import PostgresArtifactLedger

# The methods the anchor API depends on (the full contract).
REQUIRED = [
    "mint", "transfer", "priced_transfer", "claim",
    "get", "history", "total", "account_balance", "grant_genesis",
]


def test_sqlite_backend_satisfies_protocol(tmp_path: Path):
    ledger = ArtifactLedger(tmp_path / "anchor.db")
    # runtime_checkable Protocol: structural isinstance by method presence.
    assert isinstance(ledger, LedgerBackend)
    for name in REQUIRED:
        assert callable(getattr(ledger, name))


def test_postgres_skeleton_exposes_full_surface():
    # No live PG needed: the class must expose every contract method, so the
    # API can target it unchanged once a database is wired in.
    for name in REQUIRED:
        assert callable(getattr(PostgresArtifactLedger, name)), name


def test_postgres_module_imports_without_psycopg():
    # Importing the backend must not require psycopg (lazy import); only
    # actually connecting does.
    import eopx.server.postgres_ledger as pg
    assert hasattr(pg, "SCHEMA_PG")
    assert "artifacts" in pg.SCHEMA_PG and "accounts" in pg.SCHEMA_PG

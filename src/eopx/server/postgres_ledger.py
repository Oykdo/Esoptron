"""PostgreSQL anchor backend — the "go online" implementation of LedgerBackend.

This is the networked, multi-writer, replicable backend that replaces local
SQLite when the anchor goes online (e.g. reusing Cipher's PostgreSQL *server*
with a **dedicated database/role** ``esoptron_anchor``). It implements the
same :class:`~eopx.server.ledger_base.LedgerBackend` surface as
:class:`~eopx.server.artifact_ledger.ArtifactLedger`, so the API / transfer /
crypto layers are unchanged.

How the CAS maps from SQLite to Postgres
-----------------------------------------
The anti-double-spend compare-and-swap is the conditional UPDATE
``... WHERE artifact_id = %s AND seq = %s``. Under Postgres ``READ
COMMITTED``, two concurrent transfers from the same ``seq`` serialize: the
first commits (seq advances); the second re-reads and matches 0 rows →
``StaleSequence``. The economy legs (debit/credit) take ``SELECT ... FOR
UPDATE`` row locks on the accounts, and the whole priced/claim operation runs
in **one transaction**, so payment and re-key commit together — exactly the
atomicity SQLite gave by sharing one file.

.. warning::

    **Experimental skeleton.** The SQL below is complete and faithful to the
    SQLite backend, but it is **not integration-tested in this repository's
    CI** (no PostgreSQL there). Validate against a live PG — and add a
    connection pool (``psycopg_pool``) — before production. Requires
    ``psycopg[binary] >= 3``.

The signing keys never live here: the DB holds only public ledger state
(controller pubs, seqs, balances, commitments). Possession is secured by the
controller keys + anchor-signed receipts + the transparency log, not by the
database (see EPX-M §5).
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator, List, Optional

from .artifact_ledger import (
    AlreadyClaimed,
    ArtifactEntry,
    ArtifactExists,
    ArtifactNotFound,
    HistoryEntry,
    NotClaimable,
    StaleSequence,
)
from .eidolon_ledger import InsufficientFunds

# Postgres DDL — same shape as the SQLite schema, Postgres types.
SCHEMA_PG = """
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id      TEXT    PRIMARY KEY,
    seq              BIGINT  NOT NULL,
    controller_pub   TEXT    NOT NULL,
    content_commit   TEXT    NOT NULL,
    issuer_fp        TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    claim_commitment TEXT
);
CREATE TABLE IF NOT EXISTS artifact_history (
    id             BIGSERIAL PRIMARY KEY,
    artifact_id    TEXT    NOT NULL,
    seq            BIGINT  NOT NULL,
    controller_pub TEXT    NOT NULL,
    ts             TEXT    NOT NULL,
    receipt        TEXT,
    UNIQUE(artifact_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_artifact_history ON artifact_history(artifact_id);
CREATE TABLE IF NOT EXISTS accounts (
    account_id   TEXT    PRIMARY KEY,
    balance      BIGINT  NOT NULL DEFAULT 0,
    updated_at   TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS eidolon_log (
    id           BIGSERIAL PRIMARY KEY,
    account_id   TEXT    NOT NULL,
    delta        BIGINT  NOT NULL,
    reason       TEXT,
    ref          TEXT,
    ts           TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS eidolon_grants (
    account_id   TEXT    PRIMARY KEY,
    amount       BIGINT  NOT NULL,
    ts           TEXT    NOT NULL
);
"""


class PostgresArtifactLedger:
    """LedgerBackend on PostgreSQL. See module docstring (experimental)."""

    def __init__(self, dsn: str, *, create_schema: bool = True) -> None:
        self.dsn = dsn
        if create_schema:
            with self._conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(SCHEMA_PG)
                conn.commit()

    # ------------------------------------------------------------------
    # Connection (per-op; use psycopg_pool.ConnectionPool in production)
    # ------------------------------------------------------------------

    @contextmanager
    def _conn(self) -> Iterator[Any]:
        try:
            import psycopg  # lazy: importing this module must not require PG
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "PostgresArtifactLedger requires psycopg[binary]>=3"
            ) from exc
        conn = psycopg.connect(self.dsn, autocommit=False)
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _balance(cur, account_id: str) -> int:
        cur.execute("SELECT balance FROM accounts WHERE account_id = %s",
                    (account_id.lower(),))
        row = cur.fetchone()
        return int(row[0]) if row else 0

    @classmethod
    def _apply(cls, cur, account_id: str, delta: int, reason: str,
               ref: Optional[str], ts: str) -> None:
        account_id = account_id.lower()
        cur.execute(
            "INSERT INTO accounts (account_id, balance, updated_at) "
            "VALUES (%s, 0, %s) ON CONFLICT (account_id) DO NOTHING",
            (account_id, ts),
        )
        # Lock the row, then move it.
        cur.execute("SELECT balance FROM accounts WHERE account_id = %s "
                    "FOR UPDATE", (account_id,))
        cur.execute(
            "UPDATE accounts SET balance = balance + %s, updated_at = %s "
            "WHERE account_id = %s", (int(delta), ts, account_id))
        cur.execute(
            "INSERT INTO eidolon_log (account_id, delta, reason, ref, ts) "
            "VALUES (%s, %s, %s, %s, %s)",
            (account_id, int(delta), reason, ref, ts))

    # ------------------------------------------------------------------
    # Titles (EPX-T)
    # ------------------------------------------------------------------

    def mint(self, *, artifact_id, controller_pub, content_commit, issuer_fp,
             ts, receipt=None, claim_commitment="") -> ArtifactEntry:
        artifact_id = artifact_id.lower()
        controller = controller_pub.lower()
        commit = claim_commitment.lower() or None
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM artifacts WHERE artifact_id = %s "
                            "FOR UPDATE", (artifact_id,))
                if cur.fetchone() is not None:
                    conn.rollback()
                    raise ArtifactExists(f"artifact_id already minted: {artifact_id}")
                cur.execute(
                    "INSERT INTO artifacts (artifact_id, seq, controller_pub, "
                    "content_commit, issuer_fp, updated_at, claim_commitment) "
                    "VALUES (%s, 0, %s, %s, %s, %s, %s)",
                    (artifact_id, controller, content_commit.lower(),
                     issuer_fp.lower(), ts, commit))
                cur.execute(
                    "INSERT INTO artifact_history (artifact_id, seq, "
                    "controller_pub, ts, receipt) VALUES (%s, 0, %s, %s, %s)",
                    (artifact_id, controller, ts, receipt))
            conn.commit()
        return ArtifactEntry(artifact_id, 0, controller,
                             content_commit.lower(), issuer_fp.lower(), ts,
                             commit or "")

    def transfer(self, *, artifact_id, from_seq, new_controller_pub, ts,
                 receipt=None) -> ArtifactEntry:
        artifact_id = artifact_id.lower()
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT seq, content_commit, issuer_fp FROM "
                            "artifacts WHERE artifact_id = %s FOR UPDATE",
                            (artifact_id,))
                row = cur.fetchone()
                if row is None:
                    conn.rollback()
                    raise ArtifactNotFound(artifact_id)
                cur_seq, content_commit, issuer_fp = int(row[0]), row[1], row[2]
                if cur_seq != int(from_seq):
                    conn.rollback()
                    raise StaleSequence(int(from_seq), cur_seq)
                new_seq = cur_seq + 1
                cur.execute(
                    "UPDATE artifacts SET seq = %s, controller_pub = %s, "
                    "updated_at = %s WHERE artifact_id = %s AND seq = %s",
                    (new_seq, new_controller_pub.lower(), ts, artifact_id, cur_seq))
                if cur.rowcount != 1:
                    conn.rollback()
                    raise StaleSequence(int(from_seq), cur_seq)
                cur.execute(
                    "INSERT INTO artifact_history (artifact_id, seq, "
                    "controller_pub, ts, receipt) VALUES (%s, %s, %s, %s, %s)",
                    (artifact_id, new_seq, new_controller_pub.lower(), ts, receipt))
            conn.commit()
        return ArtifactEntry(artifact_id, new_seq, new_controller_pub.lower(),
                             content_commit, issuer_fp, ts)

    def priced_transfer(self, *, artifact_id, from_seq, new_controller_pub, ts,
                        payer_account, payee_account, price, fee=0,
                        treasury_account=None, ref=None,
                        receipt=None) -> ArtifactEntry:
        artifact_id = artifact_id.lower()
        total = int(price) + int(fee)
        ref = ref or artifact_id
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT seq, content_commit, issuer_fp FROM "
                            "artifacts WHERE artifact_id = %s FOR UPDATE",
                            (artifact_id,))
                row = cur.fetchone()
                if row is None:
                    conn.rollback()
                    raise ArtifactNotFound(artifact_id)
                cur_seq, content_commit, issuer_fp = int(row[0]), row[1], row[2]
                if cur_seq != int(from_seq):
                    conn.rollback()
                    raise StaleSequence(int(from_seq), cur_seq)
                if total > 0:
                    bal = self._balance(cur, payer_account)
                    if bal < total:
                        conn.rollback()
                        raise InsufficientFunds(payer_account.lower(), bal, total)
                    self._apply(cur, payer_account, -total, "relic_purchase", ref, ts)
                if price > 0:
                    self._apply(cur, payee_account, price, "relic_sale", ref, ts)
                if fee > 0 and treasury_account:
                    self._apply(cur, treasury_account, fee, "protocol_fee", ref, ts)
                new_seq = cur_seq + 1
                cur.execute(
                    "UPDATE artifacts SET seq = %s, controller_pub = %s, "
                    "updated_at = %s WHERE artifact_id = %s AND seq = %s",
                    (new_seq, new_controller_pub.lower(), ts, artifact_id, cur_seq))
                if cur.rowcount != 1:
                    conn.rollback()
                    raise StaleSequence(int(from_seq), cur_seq)
                cur.execute(
                    "INSERT INTO artifact_history (artifact_id, seq, "
                    "controller_pub, ts, receipt) VALUES (%s, %s, %s, %s, %s)",
                    (artifact_id, new_seq, new_controller_pub.lower(), ts, receipt))
            conn.commit()
        return ArtifactEntry(artifact_id, new_seq, new_controller_pub.lower(),
                             content_commit, issuer_fp, ts)

    def claim(self, *, artifact_id, new_controller_pub, expected_commitment, ts,
              receipt=None) -> ArtifactEntry:
        artifact_id = artifact_id.lower()
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT seq, claim_commitment, content_commit, "
                            "issuer_fp FROM artifacts WHERE artifact_id = %s "
                            "FOR UPDATE", (artifact_id,))
                row = cur.fetchone()
                if row is None:
                    conn.rollback()
                    raise ArtifactNotFound(artifact_id)
                if not row[1]:
                    conn.rollback()
                    raise NotClaimable(artifact_id)
                content_commit, issuer_fp = row[2], row[3]
                cur.execute(
                    "UPDATE artifacts SET seq = 1, controller_pub = %s, "
                    "claim_commitment = NULL, updated_at = %s WHERE "
                    "artifact_id = %s AND seq = 0 AND claim_commitment = %s",
                    (new_controller_pub.lower(), ts, artifact_id,
                     expected_commitment.lower()))
                if cur.rowcount != 1:
                    conn.rollback()
                    raise AlreadyClaimed(artifact_id)
                cur.execute(
                    "INSERT INTO artifact_history (artifact_id, seq, "
                    "controller_pub, ts, receipt) VALUES (%s, 1, %s, %s, %s)",
                    (artifact_id, new_controller_pub.lower(), ts, receipt))
            conn.commit()
        return ArtifactEntry(artifact_id, 1, new_controller_pub.lower(),
                             content_commit, issuer_fp, ts)

    # ------------------------------------------------------------------
    # Reads + economy
    # ------------------------------------------------------------------

    def get(self, artifact_id: str) -> Optional[ArtifactEntry]:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT seq, controller_pub, content_commit, "
                            "issuer_fp, updated_at, claim_commitment FROM "
                            "artifacts WHERE artifact_id = %s",
                            (artifact_id.lower(),))
                row = cur.fetchone()
            conn.rollback()
        if row is None:
            return None
        return ArtifactEntry(artifact_id.lower(), int(row[0]), row[1], row[2],
                             row[3], row[4], row[5] or "")

    def history(self, artifact_id: str) -> List[HistoryEntry]:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT seq, controller_pub, ts, receipt FROM "
                            "artifact_history WHERE artifact_id = %s "
                            "ORDER BY seq ASC", (artifact_id.lower(),))
                rows = cur.fetchall()
            conn.rollback()
        return [HistoryEntry(int(r[0]), r[1], r[2], r[3]) for r in rows]

    def total(self) -> int:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM artifacts")
                n = int(cur.fetchone()[0])
            conn.rollback()
        return n

    def account_balance(self, account_id: str) -> int:
        with self._conn() as conn:
            with conn.cursor() as cur:
                bal = self._balance(cur, account_id)
            conn.rollback()
        return bal

    def grant_genesis(self, account_id: str, amount: int, *, ts: str) -> int:
        if amount <= 0:
            raise ValueError("grant amount must be positive")
        account_id = account_id.lower()
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM eidolon_grants WHERE account_id = %s "
                            "FOR UPDATE", (account_id,))
                if cur.fetchone() is None:
                    cur.execute("INSERT INTO eidolon_grants (account_id, "
                                "amount, ts) VALUES (%s, %s, %s)",
                                (account_id, int(amount), ts))
                    self._apply(cur, account_id, amount, "genesis_grant", None, ts)
                bal = self._balance(cur, account_id)
            conn.commit()
        return bal


__all__ = ["PostgresArtifactLedger", "SCHEMA_PG"]

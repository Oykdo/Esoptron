"""EIDOLON balance ledger — the anchor's persistent economy book.

A self-contained, double-entry-ish balance ledger that lives **inside the
anchor** (SQLite, same durability as the artifact ledger). It tracks
EIDOLON balances per account and the audit trail of every movement. It is
deliberately standalone — no dependency on Eidolon's proprietary economy —
so the SDK and the anchor stay self-hostable; a bridge to Eidolon's real
economy can be layered on later behind this same surface.

Accounts are opaque hex ids (typically a vault fingerprint). Amounts are
**integers** in the smallest EIDOLON unit — never floats, so balances are
exact.

The schema (``EIDOLON_SCHEMA``) is shared with :mod:`eopx.server.artifact_ledger`
so a priced titled transfer can debit/credit balances and advance the title
CAS **in a single transaction** (true atomicity — payment and re-key commit
together or not at all).
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional

# Shared so the artifact ledger can host the same tables in one DB file and
# run priced transfers atomically. ``CREATE ... IF NOT EXISTS`` is safe to
# execute from both modules.
EIDOLON_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id   TEXT    PRIMARY KEY,
    balance      INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS eidolon_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id   TEXT    NOT NULL,
    delta        INTEGER NOT NULL,
    reason       TEXT,
    ref          TEXT,
    ts           TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_eidolon_log ON eidolon_log(account_id);
CREATE TABLE IF NOT EXISTS eidolon_grants (
    account_id   TEXT    PRIMARY KEY,
    amount       INTEGER NOT NULL,
    ts           TEXT    NOT NULL
);
"""


class EconomyError(Exception):
    """Base class for economy-level rejections."""


class InsufficientFunds(EconomyError):
    """Raised when an account cannot cover a debit."""

    def __init__(self, account_id: str, balance: int, needed: int) -> None:
        super().__init__(
            f"INSUFFICIENT_FUNDS: account {account_id} has {balance}, "
            f"needs {needed}"
        )
        self.account_id = account_id
        self.balance = balance
        self.needed = needed


@dataclass(frozen=True)
class LogEntry:
    seq: int
    account_id: str
    delta: int
    reason: Optional[str]
    ref: Optional[str]
    ts: str


# ---------------------------------------------------------------------------
# Connection-level primitives (usable inside an external transaction)
# ---------------------------------------------------------------------------
#
# These take an open sqlite3.Connection so the artifact ledger can call them
# inside its own BEGIN IMMEDIATE for an atomic priced transfer. They never
# BEGIN/COMMIT themselves.

def _balance_conn(conn: sqlite3.Connection, account_id: str) -> int:
    row = conn.execute(
        "SELECT balance FROM accounts WHERE account_id = ?",
        (account_id.lower(),),
    ).fetchone()
    return int(row["balance"]) if row is not None else 0


def _apply_delta_conn(conn: sqlite3.Connection, account_id: str, delta: int,
                      reason: str, ref: Optional[str], ts: str) -> int:
    """Apply ``delta`` to an account (creating it at 0 first). Returns new balance.

    Does NOT check for negative results — the caller is responsible for
    refusing debits that would underflow (see :func:`debit_conn`).
    """
    account_id = account_id.lower()
    conn.execute(
        "INSERT INTO accounts (account_id, balance, updated_at) "
        "VALUES (?, 0, ?) ON CONFLICT(account_id) DO NOTHING",
        (account_id, ts),
    )
    conn.execute(
        "UPDATE accounts SET balance = balance + ?, updated_at = ? "
        "WHERE account_id = ?",
        (int(delta), ts, account_id),
    )
    conn.execute(
        "INSERT INTO eidolon_log (account_id, delta, reason, ref, ts) "
        "VALUES (?, ?, ?, ?, ?)",
        (account_id, int(delta), reason, ref, ts),
    )
    return _balance_conn(conn, account_id)


def debit_conn(conn: sqlite3.Connection, account_id: str, amount: int,
               reason: str, ref: Optional[str], ts: str) -> int:
    """Debit ``amount`` (>=0); raise :class:`InsufficientFunds` if too low."""
    if amount < 0:
        raise ValueError("amount must be >= 0")
    bal = _balance_conn(conn, account_id)
    if bal < amount:
        raise InsufficientFunds(account_id.lower(), bal, amount)
    return _apply_delta_conn(conn, account_id, -amount, reason, ref, ts)


def credit_conn(conn: sqlite3.Connection, account_id: str, amount: int,
                reason: str, ref: Optional[str], ts: str) -> int:
    """Credit ``amount`` (>=0)."""
    if amount < 0:
        raise ValueError("amount must be >= 0")
    return _apply_delta_conn(conn, account_id, amount, reason, ref, ts)


# ---------------------------------------------------------------------------
# Standalone ledger (own transactions) — grants, balances, plain transfers
# ---------------------------------------------------------------------------

class EidolonLedger:
    """Persistent EIDOLON balance book. Shares its DB with the title ledger."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._local = threading.local()
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(EIDOLON_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path, isolation_level=None, timeout=10.0,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        # Persistent thread-local connection (a per-op reopen would checkpoint
        # the WAL on close and erase the win). See ArtifactLedger._conn.
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        yield conn

    @staticmethod
    def _rollback(conn: sqlite3.Connection) -> None:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.OperationalError:
            pass

    def balance(self, account_id: str) -> int:
        with self._conn() as conn:
            return _balance_conn(conn, account_id)

    def credit(self, account_id: str, amount: int, *,
               reason: str = "credit", ref: Optional[str] = None,
               ts: str = "") -> int:
        if amount <= 0:
            raise ValueError("credit amount must be positive")
        with self._lock, self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                bal = credit_conn(conn, account_id, amount, reason, ref, ts)
                conn.execute("COMMIT")
                return bal
            except Exception:
                self._rollback(conn)
                raise

    def transfer(self, payer: str, payee: str, amount: int, *,
                 reason: str = "transfer", ref: Optional[str] = None,
                 ts: str = "") -> tuple[int, int]:
        """Move ``amount`` payer -> payee atomically. Returns (payer_bal, payee_bal)."""
        if amount <= 0:
            raise ValueError("transfer amount must be positive")
        with self._lock, self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                pb = debit_conn(conn, payer, amount, reason, ref, ts)
                qb = credit_conn(conn, payee, amount, reason, ref, ts)
                conn.execute("COMMIT")
                return pb, qb
            except Exception:
                self._rollback(conn)
                raise

    def grant_genesis(self, account_id: str, amount: int, *,
                      ts: str = "") -> int:
        """Idempotent one-time genesis allocation. Returns the account balance.

        Records the grant in ``eidolon_grants``; a second call for the same
        account is a no-op (so re-running a forge / re-anchoring never
        double-mints the founder allocation).
        """
        if amount <= 0:
            raise ValueError("grant amount must be positive")
        account_id = account_id.lower()
        with self._lock, self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                exists = conn.execute(
                    "SELECT 1 FROM eidolon_grants WHERE account_id = ?",
                    (account_id,),
                ).fetchone()
                if exists is None:
                    conn.execute(
                        "INSERT INTO eidolon_grants (account_id, amount, ts) "
                        "VALUES (?, ?, ?)",
                        (account_id, int(amount), ts),
                    )
                    credit_conn(conn, account_id, amount,
                                "genesis_grant", None, ts)
                bal = _balance_conn(conn, account_id)
                conn.execute("COMMIT")
                return bal
            except Exception:
                self._rollback(conn)
                raise

    def history(self, account_id: str) -> List[LogEntry]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, account_id, delta, reason, ref, ts "
                "FROM eidolon_log WHERE account_id = ? ORDER BY id ASC",
                (account_id.lower(),),
            ).fetchall()
            return [
                LogEntry(seq=int(r["id"]), account_id=r["account_id"],
                         delta=int(r["delta"]), reason=r["reason"],
                         ref=r["ref"], ts=r["ts"])
                for r in rows
            ]


__all__ = [
    "EIDOLON_SCHEMA",
    "EconomyError",
    "InsufficientFunds",
    "LogEntry",
    "EidolonLedger",
    "balance_conn",
    "debit_conn",
    "credit_conn",
]


# Public alias for the connection-level balance read (used by the artifact
# ledger inside its own transaction).
balance_conn = _balance_conn

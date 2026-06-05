"""Artifact ledger — the authoritative, monotonic state for EPX-T titles.

This is the *anchor's* source of truth (spec §3.2). Per ``artifact_id`` it
records the current sequence and the controlling public key; **ownership is,
by definition, the ``controller_pub`` at the latest ``seq``** — nothing else
(possession of a ``.eopx``, of an old key) confers it.

The anti-double-spend guarantee (spec §6) rests entirely on the
:meth:`ArtifactLedger.transfer` **compare-and-swap**: a transfer is applied
only if the caller's ``from_seq`` still equals the recorded ``seq``. Two
transfers racing from the same ``seq`` → exactly one wins; the other gets
:class:`StaleSequence`.

Backend: SQLite with explicit ``BEGIN IMMEDIATE`` transactions plus an
in-process lock, mirroring :mod:`eopx.server.sequence_state`. A receipt blob
(opaque to this layer) is persisted in the same transaction as each accepted
state change, so the history log can never drift from the state it attests.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional

from .eidolon_ledger import (
    EIDOLON_SCHEMA,
    InsufficientFunds,
    balance_conn,
    credit_conn,
    debit_conn,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id    TEXT PRIMARY KEY,
    seq            INTEGER NOT NULL,
    controller_pub TEXT    NOT NULL,
    content_commit TEXT    NOT NULL,
    issuer_fp      TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL,
    claim_commitment TEXT
);
CREATE TABLE IF NOT EXISTS artifact_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id    TEXT    NOT NULL,
    seq            INTEGER NOT NULL,
    controller_pub TEXT    NOT NULL,
    ts             TEXT    NOT NULL,
    receipt        TEXT,
    UNIQUE(artifact_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_artifact_history ON artifact_history(artifact_id);
"""


class LedgerError(Exception):
    """Base class for ledger-level rejections."""


class ArtifactExists(LedgerError):
    """Raised when minting an ``artifact_id`` that is already recorded."""


class ArtifactNotFound(LedgerError):
    """Raised when transferring an artifact the ledger has never seen."""


class StaleSequence(LedgerError):
    """Raised when a transfer's ``from_seq`` no longer matches the ledger.

    This is the anti-double-spend signal (spec §13.3): the artifact has
    already moved on, so the submitted hand-off is void.
    """

    def __init__(self, expected: int, actual: int) -> None:
        super().__init__(
            f"STALE_SEQUENCE: transfer expected seq={expected} "
            f"but ledger is at seq={actual}"
        )
        self.expected = expected
        self.actual = actual


class NotClaimable(LedgerError):
    """Raised when claiming an artifact that carries no claim commitment."""


class AlreadyClaimed(LedgerError):
    """Raised when a huntable relic has already been claimed (the race loser)."""


@dataclass(frozen=True)
class ArtifactEntry:
    """Current authoritative state of one artifact."""
    artifact_id: str        # hex
    seq: int
    controller_pub: str     # hex (ML-DSA-87 public key); "" if unclaimed
    content_commit: str     # hex (SHA3-512) or "" if none
    issuer_fp: str          # hex (SHA3-256 of issuer pubkey)
    updated_at: str         # ISO-8601 UTC
    claim_commitment: str = ""  # hex SHA3-256 if huntable+unclaimed, else ""

    @property
    def is_claimable(self) -> bool:
        return bool(self.claim_commitment) and not self.controller_pub


@dataclass(frozen=True)
class HistoryEntry:
    """One row of the per-artifact transparency log (spec §10)."""
    seq: int
    controller_pub: str     # hex
    ts: str
    receipt: Optional[str]  # opaque JSON receipt, if recorded


class ArtifactLedger:
    """Single-writer SQLite ledger with per-artifact compare-and-swap."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._local = threading.local()
        with self._conn() as conn:
            # WAL persists in the DB file header (set once, applies to every
            # connection — including the EIDOLON ledger sharing this file).
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            # Migrate pre-existing DBs that lack the huntable-relic column.
            cols = {r["name"] for r in conn.execute(
                "PRAGMA table_info(artifacts)").fetchall()}
            if "claim_commitment" not in cols:
                conn.execute(
                    "ALTER TABLE artifacts ADD COLUMN claim_commitment TEXT")
            # Host the EIDOLON economy tables in the same DB file so a priced
            # transfer can debit/credit balances and advance the title CAS in
            # one transaction (true atomicity).
            conn.executescript(EIDOLON_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path, isolation_level=None, timeout=10.0,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        # WAL + NORMAL: fsync at checkpoint, not per commit. Crash-safe (only
        # an uncommitted txn can be lost — a CAS loser just retries).
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        # Persistent, thread-local connection. Reopening per op would force a
        # WAL checkpoint (fsync) on every close, erasing the WAL win, so the
        # connection is kept open for the thread's lifetime instead. Writes
        # are serialized by ``self._lock``; WAL lets reads run concurrently.
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        yield conn

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def mint(
        self,
        *,
        artifact_id: str,
        controller_pub: str,
        content_commit: str,
        issuer_fp: str,
        ts: str,
        receipt: Optional[str] = None,
        claim_commitment: str = "",
    ) -> ArtifactEntry:
        """Record a fresh artifact at ``seq=0`` (spec §5.1, step 4).

        For a normal artifact pass the first owner's ``controller_pub``. For a
        **huntable** relic (EPX-V) pass ``controller_pub=""`` and a
        ``claim_commitment`` — it stays unclaimed until the first valid
        :meth:`claim`. Raises :class:`ArtifactExists` on a duplicate id.
        """
        artifact_id = artifact_id.lower()
        controller = controller_pub.lower()
        commit = claim_commitment.lower()
        with self._lock, self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                exists = conn.execute(
                    "SELECT 1 FROM artifacts WHERE artifact_id = ?",
                    (artifact_id,),
                ).fetchone()
                if exists is not None:
                    conn.execute("ROLLBACK")
                    raise ArtifactExists(
                        f"artifact_id already minted: {artifact_id}"
                    )
                conn.execute(
                    "INSERT INTO artifacts "
                    "(artifact_id, seq, controller_pub, content_commit, "
                    " issuer_fp, updated_at, claim_commitment) "
                    "VALUES (?, 0, ?, ?, ?, ?, ?)",
                    (artifact_id, controller, content_commit.lower(),
                     issuer_fp.lower(), ts, commit or None),
                )
                conn.execute(
                    "INSERT INTO artifact_history "
                    "(artifact_id, seq, controller_pub, ts, receipt) "
                    "VALUES (?, 0, ?, ?, ?)",
                    (artifact_id, controller, ts, receipt),
                )
                conn.execute("COMMIT")
            except Exception:
                self._safe_rollback(conn)
                raise
        return ArtifactEntry(
            artifact_id=artifact_id, seq=0,
            controller_pub=controller,
            content_commit=content_commit.lower(),
            issuer_fp=issuer_fp.lower(), updated_at=ts,
            claim_commitment=commit,
        )

    def claim(
        self,
        *,
        artifact_id: str,
        new_controller_pub: str,
        expected_commitment: str,
        ts: str,
        receipt: Optional[str] = None,
    ) -> ArtifactEntry:
        """Claim a huntable relic into ``new_controller_pub`` (EPX-V).

        Atomic first-wins transition: an unclaimed relic (``seq=0`` carrying
        ``expected_commitment``) advances to ``seq=1`` owned by the claimant,
        clearing the commitment. The secret↔commitment + PoP checks are the
        caller's (the API's :func:`verify_claim`); this enforces the state
        transition. Raises :class:`NotClaimable` (no commitment) or
        :class:`AlreadyClaimed` (someone won the race first).
        """
        artifact_id = artifact_id.lower()
        with self._lock, self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT seq, claim_commitment, content_commit, issuer_fp "
                    "FROM artifacts WHERE artifact_id = ?",
                    (artifact_id,),
                ).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    raise ArtifactNotFound(f"unknown artifact_id: {artifact_id}")
                if not row["claim_commitment"]:
                    conn.execute("ROLLBACK")
                    raise NotClaimable(
                        f"artifact {artifact_id} is not a huntable relic")
                # CAS: still unclaimed (seq 0) AND the expected commitment.
                cur = conn.execute(
                    "UPDATE artifacts SET seq = 1, controller_pub = ?, "
                    "claim_commitment = NULL, updated_at = ? "
                    "WHERE artifact_id = ? AND seq = 0 AND claim_commitment = ?",
                    (new_controller_pub.lower(), ts, artifact_id,
                     expected_commitment.lower()),
                )
                if cur.rowcount != 1:
                    conn.execute("ROLLBACK")
                    raise AlreadyClaimed(
                        f"artifact {artifact_id} already claimed")
                conn.execute(
                    "INSERT INTO artifact_history "
                    "(artifact_id, seq, controller_pub, ts, receipt) "
                    "VALUES (?, 1, ?, ?, ?)",
                    (artifact_id, new_controller_pub.lower(), ts, receipt),
                )
                conn.execute("COMMIT")
                content_commit = row["content_commit"]
                issuer_fp = row["issuer_fp"]
            except Exception:
                self._safe_rollback(conn)
                raise
        return ArtifactEntry(
            artifact_id=artifact_id, seq=1,
            controller_pub=new_controller_pub.lower(),
            content_commit=content_commit, issuer_fp=issuer_fp,
            updated_at=ts,
        )

    def transfer(
        self,
        *,
        artifact_id: str,
        from_seq: int,
        new_controller_pub: str,
        ts: str,
        receipt: Optional[str] = None,
    ) -> ArtifactEntry:
        """Advance an artifact by exactly one sequence via compare-and-swap.

        Atomic: the update is conditioned on the recorded ``seq`` still
        equalling ``from_seq``. On mismatch, raises :class:`StaleSequence`
        (the loser of a double-spend race); if the artifact is unknown,
        raises :class:`ArtifactNotFound`.
        """
        artifact_id = artifact_id.lower()
        with self._lock, self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT seq, content_commit, issuer_fp "
                    "FROM artifacts WHERE artifact_id = ?",
                    (artifact_id,),
                ).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    raise ArtifactNotFound(f"unknown artifact_id: {artifact_id}")
                current_seq = int(row["seq"])
                if current_seq != int(from_seq):
                    conn.execute("ROLLBACK")
                    raise StaleSequence(expected=int(from_seq), actual=current_seq)

                new_seq = current_seq + 1
                # The `AND seq = ?` clause makes the swap itself conditional,
                # belt-and-suspenders behind the in-process lock.
                cur = conn.execute(
                    "UPDATE artifacts SET seq = ?, controller_pub = ?, "
                    "updated_at = ? WHERE artifact_id = ? AND seq = ?",
                    (new_seq, new_controller_pub.lower(), ts,
                     artifact_id, current_seq),
                )
                if cur.rowcount != 1:
                    conn.execute("ROLLBACK")
                    raise StaleSequence(expected=int(from_seq), actual=current_seq)
                conn.execute(
                    "INSERT INTO artifact_history "
                    "(artifact_id, seq, controller_pub, ts, receipt) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (artifact_id, new_seq, new_controller_pub.lower(),
                     ts, receipt),
                )
                conn.execute("COMMIT")
                content_commit = row["content_commit"]
                issuer_fp = row["issuer_fp"]
            except Exception:
                self._safe_rollback(conn)
                raise
        return ArtifactEntry(
            artifact_id=artifact_id, seq=new_seq,
            controller_pub=new_controller_pub.lower(),
            content_commit=content_commit, issuer_fp=issuer_fp,
            updated_at=ts,
        )

    def priced_transfer(
        self,
        *,
        artifact_id: str,
        from_seq: int,
        new_controller_pub: str,
        ts: str,
        payer_account: str,
        payee_account: str,
        price: int,
        fee: int = 0,
        treasury_account: Optional[str] = None,
        ref: Optional[str] = None,
        receipt: Optional[str] = None,
    ) -> ArtifactEntry:
        """A vault-to-vault sale: pay EIDOLON and re-key the title, atomically.

        In ONE transaction: the buyer (``payer_account``) is debited
        ``price + fee``, the seller (``payee_account``) is credited
        ``price``, an optional ``fee`` goes to ``treasury_account``, and the
        artifact's controller advances by the compare-and-swap on
        ``from_seq``. Either everything commits or nothing does — payment and
        ownership move together.

        Raises :class:`~eopx.server.eidolon_ledger.InsufficientFunds` (buyer
        too poor — no debit, no re-key), :class:`StaleSequence` (the title
        already moved — no charge), or :class:`ArtifactNotFound`.
        """
        artifact_id = artifact_id.lower()
        if price < 0 or fee < 0:
            raise ValueError("price and fee must be >= 0")
        total = int(price) + int(fee)
        ref = ref or artifact_id
        with self._lock, self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT seq, content_commit, issuer_fp "
                    "FROM artifacts WHERE artifact_id = ?",
                    (artifact_id,),
                ).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    raise ArtifactNotFound(f"unknown artifact_id: {artifact_id}")
                current_seq = int(row["seq"])
                if current_seq != int(from_seq):
                    conn.execute("ROLLBACK")
                    raise StaleSequence(expected=int(from_seq), actual=current_seq)

                # Economy leg — debit first so an underfunded buyer aborts
                # before anything moves (InsufficientFunds rolls back cleanly).
                if total > 0:
                    debit_conn(conn, payer_account, total,
                               "relic_purchase", ref, ts)
                if price > 0:
                    credit_conn(conn, payee_account, price,
                                "relic_sale", ref, ts)
                if fee > 0 and treasury_account:
                    credit_conn(conn, treasury_account, fee,
                                "protocol_fee", ref, ts)

                # Title leg — the same CAS as transfer().
                new_seq = current_seq + 1
                cur = conn.execute(
                    "UPDATE artifacts SET seq = ?, controller_pub = ?, "
                    "updated_at = ? WHERE artifact_id = ? AND seq = ?",
                    (new_seq, new_controller_pub.lower(), ts,
                     artifact_id, current_seq),
                )
                if cur.rowcount != 1:
                    conn.execute("ROLLBACK")
                    raise StaleSequence(expected=int(from_seq), actual=current_seq)
                conn.execute(
                    "INSERT INTO artifact_history "
                    "(artifact_id, seq, controller_pub, ts, receipt) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (artifact_id, new_seq, new_controller_pub.lower(),
                     ts, receipt),
                )
                conn.execute("COMMIT")
                content_commit = row["content_commit"]
                issuer_fp = row["issuer_fp"]
            except Exception:
                self._safe_rollback(conn)
                raise
        return ArtifactEntry(
            artifact_id=artifact_id, seq=new_seq,
            controller_pub=new_controller_pub.lower(),
            content_commit=content_commit, issuer_fp=issuer_fp,
            updated_at=ts,
        )

    def account_balance(self, account_id: str) -> int:
        """EIDOLON balance of an account (0 if unseen)."""
        with self._conn() as conn:
            return balance_conn(conn, account_id)

    def grant_genesis(self, account_id: str, amount: int, *, ts: str) -> int:
        """Idempotent one-time EIDOLON allocation (same DB as the titles).

        Mirrors :meth:`eopx.server.eidolon_ledger.EidolonLedger.grant_genesis`
        but on this backend's connection, so the anchor API needs only the
        single ledger backend (no separate economy handle) — the key to
        swapping SQLite for Postgres without touching the API.
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
                bal = balance_conn(conn, account_id)
                conn.execute("COMMIT")
                return bal
            except Exception:
                self._safe_rollback(conn)
                raise

    @staticmethod
    def _safe_rollback(conn: sqlite3.Connection) -> None:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.OperationalError:
            pass

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get(self, artifact_id: str) -> Optional[ArtifactEntry]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT seq, controller_pub, content_commit, issuer_fp, "
                "updated_at, claim_commitment FROM artifacts "
                "WHERE artifact_id = ?",
                (artifact_id.lower(),),
            ).fetchone()
            if row is None:
                return None
            return ArtifactEntry(
                artifact_id=artifact_id.lower(),
                seq=int(row["seq"]),
                controller_pub=row["controller_pub"],
                content_commit=row["content_commit"],
                issuer_fp=row["issuer_fp"],
                updated_at=row["updated_at"],
                claim_commitment=row["claim_commitment"] or "",
            )

    def history(self, artifact_id: str) -> List[HistoryEntry]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT seq, controller_pub, ts, receipt "
                "FROM artifact_history WHERE artifact_id = ? ORDER BY seq ASC",
                (artifact_id.lower(),),
            ).fetchall()
            return [
                HistoryEntry(
                    seq=int(r["seq"]),
                    controller_pub=r["controller_pub"],
                    ts=r["ts"],
                    receipt=r["receipt"],
                )
                for r in rows
            ]

    def total(self) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM artifacts"
            ).fetchone()
            return int(row["c"])


__all__ = [
    "ArtifactLedger",
    "ArtifactEntry",
    "HistoryEntry",
    "LedgerError",
    "ArtifactExists",
    "ArtifactNotFound",
    "StaleSequence",
    "NotClaimable",
    "AlreadyClaimed",
    "InsufficientFunds",  # re-exported: the anchor's economy rejection
]

"""Sequence state — durable, monotonic global ecosystem counter.

This is the single source of truth for "vault N° X in the ecosystem".
Every vault creation path (Cipher signup ceremony, Esoptron PWA enrollment,
Eidolon CLI direct) hits this counter through ``anchor_vault()`` and
receives a sequence number that is monotonically increasing and unique
across the whole ecosystem.

The Genesis Token derivation (88 positions in [1, 333333]) is checked
against this sequence to decide whether a vault is a Genesis vault.

Backend
-------
SQLite + transaction-based serialization. No external dependencies. A
single writer at a time is sufficient for the expected ingestion rate
(at most a few vaults per second peak). The schema is:

    vault_anchors(
      sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
      vault_fp_hex   TEXT    UNIQUE NOT NULL,
      anchored_at    REAL    NOT NULL,
      source         TEXT,
      meta           TEXT
    )

Idempotency
-----------
Anchoring the same ``vault_fp_hex`` twice returns the same sequence as
the first call — safe to retry. Internally a SELECT precedes the INSERT
within the same transaction.
"""

from __future__ import annotations

import json
import sqlite3
import time
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_anchors (
    sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_fp_hex   TEXT    UNIQUE NOT NULL,
    anchored_at    REAL    NOT NULL,
    source         TEXT,
    meta           TEXT
);
CREATE INDEX IF NOT EXISTS idx_vault_fp ON vault_anchors(vault_fp_hex);
"""


@dataclass(frozen=True)
class AnchorRecord:
    sequence: int
    vault_fp_hex: str
    anchored_at: float
    source: Optional[str]
    meta: Optional[Dict[str, Any]]


class SequenceState:
    """Single-writer SQLite-backed monotonic counter.

    A module-level lock serializes writes within the same process; the
    SQLite transaction serializes them across processes.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        # ``isolation_level=None`` gives us explicit BEGIN/COMMIT control,
        # essential for the atomic SELECT-then-INSERT in ``anchor_vault``.
        conn = sqlite3.connect(self.db_path, isolation_level=None, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def anchor_vault(
        self,
        vault_fp_hex: str,
        source: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        sequence_hint: Optional[int] = None,
    ) -> AnchorRecord:
        """Assign or return the sequence for ``vault_fp_hex``.

        Atomic: SELECT precedes INSERT inside one transaction so a second
        caller racing on the same fingerprint sees the first caller's
        insert and returns the existing record.

        When ``sequence_hint`` is provided, it is honored as the
        canonical sequence number (e.g. the Eidolon lock server's
        ``vault_number``) instead of relying on local AUTOINCREMENT.
        The hint must not collide with an existing sequence for a
        different fingerprint; collisions raise ``ValueError``.
        """
        if not isinstance(vault_fp_hex, str) or len(vault_fp_hex) < 16:
            raise ValueError("vault_fp_hex must be a non-empty hex string")
        vault_fp_hex = vault_fp_hex.lower()
        meta_json = json.dumps(meta) if meta else None
        if sequence_hint is not None and sequence_hint <= 0:
            raise ValueError("sequence_hint must be a positive integer")

        with self._lock, self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT sequence, anchored_at, source, meta "
                    "FROM vault_anchors WHERE vault_fp_hex = ?",
                    (vault_fp_hex,),
                ).fetchone()
                if row is not None:
                    conn.execute("COMMIT")
                    return AnchorRecord(
                        sequence=int(row["sequence"]),
                        vault_fp_hex=vault_fp_hex,
                        anchored_at=float(row["anchored_at"]),
                        source=row["source"],
                        meta=json.loads(row["meta"]) if row["meta"] else None,
                    )
                now = time.time()
                if sequence_hint is not None:
                    clash = conn.execute(
                        "SELECT vault_fp_hex FROM vault_anchors "
                        "WHERE sequence = ?",
                        (int(sequence_hint),),
                    ).fetchone()
                    if clash is not None:
                        conn.execute("ROLLBACK")
                        raise ValueError(
                            f"sequence_hint {sequence_hint} already used by "
                            f"{clash['vault_fp_hex']!r}"
                        )
                    conn.execute(
                        "INSERT INTO vault_anchors "
                        "(sequence, vault_fp_hex, anchored_at, source, meta) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (int(sequence_hint), vault_fp_hex, now,
                         source, meta_json),
                    )
                    seq = int(sequence_hint)
                else:
                    cur = conn.execute(
                        "INSERT INTO vault_anchors "
                        "(vault_fp_hex, anchored_at, source, meta) "
                        "VALUES (?, ?, ?, ?)",
                        (vault_fp_hex, now, source, meta_json),
                    )
                    seq = int(cur.lastrowid or 0)
                conn.execute("COMMIT")
                return AnchorRecord(
                    sequence=seq,
                    vault_fp_hex=vault_fp_hex,
                    anchored_at=now,
                    source=source,
                    meta=meta,
                )
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.OperationalError:
                    pass
                raise

    def total(self) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM vault_anchors"
            ).fetchone()
            return int(row["c"])

    def max_sequence(self) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(sequence), 0) AS m FROM vault_anchors"
            ).fetchone()
            return int(row["m"])

    def lookup(self, vault_fp_hex: str) -> Optional[AnchorRecord]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT sequence, anchored_at, source, meta "
                "FROM vault_anchors WHERE vault_fp_hex = ?",
                (vault_fp_hex.lower(),),
            ).fetchone()
            if row is None:
                return None
            return AnchorRecord(
                sequence=int(row["sequence"]),
                vault_fp_hex=vault_fp_hex.lower(),
                anchored_at=float(row["anchored_at"]),
                source=row["source"],
                meta=json.loads(row["meta"]) if row["meta"] else None,
            )

    def lookup_by_sequence(self, sequence: int) -> Optional[AnchorRecord]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT vault_fp_hex, anchored_at, source, meta "
                "FROM vault_anchors WHERE sequence = ?",
                (int(sequence),),
            ).fetchone()
            if row is None:
                return None
            return AnchorRecord(
                sequence=int(sequence),
                vault_fp_hex=row["vault_fp_hex"],
                anchored_at=float(row["anchored_at"]),
                source=row["source"],
                meta=json.loads(row["meta"]) if row["meta"] else None,
            )

    def seed_initial(
        self,
        records: list[tuple[int, str, Optional[float]]],
    ) -> int:
        """Bulk-import historical anchors (e.g. from the lock server).

        Each tuple is (sequence, vault_fp_hex, anchored_at_or_None). Used
        once to backfill the existing ecosystem registry into the new
        unified counter so the ecosystem position numbers remain stable
        across the migration.
        """
        inserted = 0
        with self._lock, self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                for seq, fp, ts in records:
                    fp = fp.lower()
                    existing = conn.execute(
                        "SELECT sequence FROM vault_anchors WHERE vault_fp_hex = ?",
                        (fp,),
                    ).fetchone()
                    if existing is not None:
                        continue
                    conn.execute(
                        "INSERT INTO vault_anchors "
                        "(sequence, vault_fp_hex, anchored_at, source, meta) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (int(seq), fp, float(ts or time.time()),
                         "seed_migration", None),
                    )
                    inserted += 1
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return inserted

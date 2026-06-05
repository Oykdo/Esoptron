"""The anchor ledger contract — one interface, swappable backends.

The anchor (``eopx.server.artifact_api``) talks only to this surface, so the
storage engine can move from local SQLite to a networked/replicated database
**without touching the API, the transfer layer, or the crypto**. That is the
"go online" path: implement :class:`LedgerBackend` against PostgreSQL (see
:mod:`eopx.server.postgres_ledger`) and nothing else changes.

The contract is the union of the title registry (EPX-T) and the EIDOLON
economy (EPX-M) plus the voucher claim (EPX-V), because a priced transfer
must debit/credit balances and advance the title CAS **atomically** — so a
single backend owns both, in one transaction.

:class:`~eopx.server.artifact_ledger.ArtifactLedger` (SQLite) satisfies this
Protocol structurally; no inheritance is required.
"""

from __future__ import annotations

from typing import List, Optional, Protocol, runtime_checkable

from .artifact_ledger import ArtifactEntry, HistoryEntry


@runtime_checkable
class LedgerBackend(Protocol):
    """The persistent anchor surface every backend must provide.

    All writes are serialized per artifact (the anti-double-spend guarantee);
    reads may run concurrently. Amounts are integers; balances never go
    negative. Methods raise the shared exceptions from
    :mod:`eopx.server.artifact_ledger` / :mod:`eopx.server.eidolon_ledger`
    (``ArtifactExists``, ``ArtifactNotFound``, ``StaleSequence``,
    ``NotClaimable``, ``AlreadyClaimed``, ``InsufficientFunds``).
    """

    # ----- titles (EPX-T) ------------------------------------------------
    def mint(self, *, artifact_id: str, controller_pub: str,
             content_commit: str, issuer_fp: str, ts: str,
             receipt: Optional[str] = None,
             claim_commitment: str = "") -> ArtifactEntry: ...

    def transfer(self, *, artifact_id: str, from_seq: int,
                 new_controller_pub: str, ts: str,
                 receipt: Optional[str] = None) -> ArtifactEntry: ...

    def get(self, artifact_id: str) -> Optional[ArtifactEntry]: ...

    def history(self, artifact_id: str) -> List[HistoryEntry]: ...

    def total(self) -> int: ...

    # ----- market (EPX-M) ------------------------------------------------
    def priced_transfer(self, *, artifact_id: str, from_seq: int,
                        new_controller_pub: str, ts: str,
                        payer_account: str, payee_account: str,
                        price: int, fee: int = 0,
                        treasury_account: Optional[str] = None,
                        ref: Optional[str] = None,
                        receipt: Optional[str] = None) -> ArtifactEntry: ...

    def account_balance(self, account_id: str) -> int: ...

    def grant_genesis(self, account_id: str, amount: int, *,
                      ts: str) -> int: ...

    # ----- voucher claim (EPX-V) ----------------------------------------
    def claim(self, *, artifact_id: str, new_controller_pub: str,
              expected_commitment: str, ts: str,
              receipt: Optional[str] = None) -> ArtifactEntry: ...


__all__ = ["LedgerBackend"]

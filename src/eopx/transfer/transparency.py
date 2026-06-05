"""Transparency-log verification for the EPX-T anchor (spec §10).

Possession of a ``.eopx`` proves nothing and the anchor is a trusted
authority — but it does not have to be *blindly* trusted. The anchor emits
an append-only, anchor-signed receipt for every accepted state change
(EPX-T §5.4/§10). A client can therefore **audit** an artifact's whole
history the way Certificate Transparency audits a log:

* :func:`verify_receipt_chain` replays ``seq 0 → n`` and checks that every
  step is anchor-signed (under a *pinned* key), the sequence is gapless and
  monotonic, and each receipt agrees with the history row it accompanies.
  This catches a forged or malformed history.

* :func:`detect_equivocation` compares a history snapshot against a chain
  the client witnessed earlier. The log must be **append-only**: a prior
  view must be a prefix of the new one. If the controller recorded at some
  ``seq`` *changed*, or earlier entries vanished, the anchor equivocated —
  hard evidence of a fork, even though detection is after the fact.

This makes a centralized (or Raft) anchor's misbehaviour *detectable*; a
BFT/chain anchor would make it *preventable*. Either way the cryptographic
root is the controller keys + these signatures, not the storage backend.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import AnchorReceipt, verify_receipt


@dataclass
class ChainCheck:
    """Outcome of auditing one artifact's receipt chain."""
    ok: bool
    head_seq: Optional[int] = None
    head_controller_pub_hex: Optional[str] = None
    length: int = 0
    issues: List[str] = field(default_factory=list)
    # The verified (seq, controller_pub_hex) chain, ascending.
    chain: List[Tuple[int, str]] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok


def verify_receipt_chain(
    history_response: Dict[str, Any],
    *,
    expected_anchor_pub: bytes,
    artifact_id: Optional[bytes] = None,
) -> ChainCheck:
    """Audit a ``GET /artifact/<id>/history`` response (spec §10).

    Parameters
    ----------
    history_response:
        The parsed JSON: ``{artifact_id_hex, anchor_pub_hex, history:[{seq,
        controller_pub_hex, ts, receipt}, …]}``.
    expected_anchor_pub:
        The anchor's Dilithium public key the client **pins** — receipts are
        verified under this, never under a key the server merely reports.
    artifact_id:
        Optional 16-byte id the chain must be about (defaults to the
        response's ``artifact_id_hex``).

    Returns a :class:`ChainCheck`; ``ok`` is True only when every check
    passes. Never raises.
    """
    res = ChainCheck(ok=False)
    try:
        rows = history_response.get("history")
        if not isinstance(rows, list) or not rows:
            res.issues.append("history is empty or malformed")
            return res

        resp_aid_hex = (history_response.get("artifact_id_hex") or "").lower()
        want_aid_hex = artifact_id.hex() if artifact_id is not None else resp_aid_hex
        if not want_aid_hex:
            res.issues.append("no artifact_id to check against")
            return res
        if resp_aid_hex and resp_aid_hex != want_aid_hex:
            res.issues.append(
                f"response artifact_id {resp_aid_hex} != expected {want_aid_hex}"
            )

        # The server-reported anchor key is advisory; we pin our own.
        reported = (history_response.get("anchor_pub_hex") or "").lower()
        if reported and reported != expected_anchor_pub.hex():
            res.issues.append(
                "history anchor_pub does not match the pinned anchor key"
            )

        prev_seq = -1
        for i, row in enumerate(rows):
            seq = row.get("seq")
            controller = (row.get("controller_pub_hex") or "").lower()
            receipt_dict = row.get("receipt")

            if not isinstance(seq, int):
                res.issues.append(f"row {i}: seq is not an integer")
                return res
            # Gapless, strictly +1, starting at 0.
            if prev_seq == -1 and seq != 0:
                res.issues.append(f"chain does not start at seq 0 (got {seq})")
                return res
            if prev_seq != -1 and seq != prev_seq + 1:
                res.issues.append(
                    f"non-monotonic chain: {prev_seq} -> {seq} (gap or reorder)"
                )
                return res
            prev_seq = seq

            if not receipt_dict:
                res.issues.append(f"seq {seq}: missing receipt (cannot audit)")
                return res
            try:
                receipt = AnchorReceipt.from_dict(receipt_dict)
            except Exception as exc:
                res.issues.append(f"seq {seq}: malformed receipt: {exc}")
                return res

            # The receipt must be signed by the PINNED anchor key...
            if not verify_receipt(receipt, expected_anchor_pub):
                res.issues.append(
                    f"seq {seq}: receipt signature invalid under pinned anchor"
                )
                return res
            # ...and self-consistent with the row + the artifact under audit.
            if receipt.seq != seq:
                res.issues.append(
                    f"seq {seq}: receipt attests seq {receipt.seq}")
                return res
            if receipt.artifact_id.hex() != want_aid_hex:
                res.issues.append(
                    f"seq {seq}: receipt is for a different artifact")
                return res
            if controller and receipt.controller_pub.hex() != controller:
                res.issues.append(
                    f"seq {seq}: row controller != receipt controller")
                return res

            res.chain.append((seq, receipt.controller_pub.hex()))

        res.length = len(res.chain)
        res.head_seq, res.head_controller_pub_hex = res.chain[-1]
        # ``ok`` only if no issues at all were recorded along the way.
        res.ok = not res.issues
        return res
    except Exception as exc:  # pragma: no cover - defensive
        res.issues.append(f"unexpected error: {exc}")
        return res


def detect_equivocation(
    prior_chain: List[Tuple[int, str]],
    current_chain: List[Tuple[int, str]],
) -> Optional[Tuple[int, str, str]]:
    """Append-only consistency check between two witnessed chains.

    The log must only ever grow: every ``(seq, controller)`` the client saw
    before must still be present and identical. Returns evidence of a fork:

    * ``(seq, prior_pub, current_pub)`` if the controller at a shared ``seq``
      changed (equivocation / history rewrite);
    * ``(seq, prior_pub, "<missing>")`` if a previously-witnessed ``seq`` is
      absent from the new history (truncation / rollback).

    Returns ``None`` when ``current`` is a consistent superset (prefix-extends)
    of ``prior``.
    """
    current = {seq: pub for seq, pub in current_chain}
    for seq, prior_pub in prior_chain:
        if seq not in current:
            return (seq, prior_pub, "<missing>")
        if current[seq] != prior_pub:
            return (seq, prior_pub, current[seq])
    return None


__all__ = [
    "ChainCheck",
    "verify_receipt_chain",
    "detect_equivocation",
]

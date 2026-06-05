"""Artifact API — the EPX-T anchor: mint, transfer (CAS), query, history.

This Flask blueprint is the **online finalization** half of EPX-T (the
offline signing half is :mod:`eopx.transfer`). It is the authority that
*invalidates the old controller and designates the new one* — the only
thing that turns delivery into non-duplication (spec §1).

Endpoints (``url_prefix`` default ``/api/v1/artifact``):

``POST /mint``
    Body: a :class:`~eopx.transfer.TitledArtifact` dict. The issuer
    signature is verified before the ``artifact_id`` is claimed at
    ``seq=0``. Returns ``{seq, entry, receipt}``. 409 on a duplicate id.

``POST /transfer``
    Body: a :class:`~eopx.transfer.Transfer` dict. The signature is checked
    against the controller the ledger currently records, then the ledger
    performs an atomic compare-and-swap on ``from_seq``. Returns
    ``{seq, entry, receipt}``; **409 ``STALE_SEQUENCE``** if the artifact
    has already moved (the double-spend loser); 404 if unknown; 400 on a
    bad signature.

``GET /<artifact_id>``
    The authoritative current state ``{seq, controller_pub, …}`` — the only
    source of current ownership (spec §3.2).

``GET /<artifact_id>/history``
    The append-only transparency log of ``(seq, controller_pub, ts,
    receipt)`` (spec §10).
"""

from __future__ import annotations

import datetime as _dt
import json
import logging

from flask import Blueprint, jsonify, request

from ..capabilities import (
    CAPABILITIES,
    CAPABILITY_BY_ID,
    EPX_K_VERSION,
    OfficeProof,
    capabilities_commitment,
    verify_office,
)
from ..format.keys import EopxKey
from ..transfer import (
    ClaimProof,
    PaymentTerms,
    TitledArtifact,
    Transfer,
    sign_receipt,
    verify_artifact,
    verify_claim,
    verify_payment,
    verify_transfer,
)
from .artifact_ledger import (
    AlreadyClaimed,
    ArtifactExists,
    ArtifactLedger,
    ArtifactNotFound,
    InsufficientFunds,
    NotClaimable,
    StaleSequence,
)
from .rate_limit import rate_limit

_log = logging.getLogger("eopx.server.artifact_api")


def _grant_ts() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _entry_dict(entry) -> dict:
    return {
        "artifact_id_hex": entry.artifact_id,
        "seq": entry.seq,
        "controller_pub_hex": entry.controller_pub,
        "content_commit_hex": entry.content_commit,
        "issuer_fp_hex": entry.issuer_fp,
        "updated_at": entry.updated_at,
        "claimable": entry.is_claimable,
        "claim_commitment_hex": entry.claim_commitment,
    }


def create_artifact_api(
    ledger: ArtifactLedger,
    anchor_key: EopxKey,
    *,
    url_prefix: str = "/api/v1/artifact",
    allow_grants: bool = False,
) -> Blueprint:
    """Build the EPX-T anchor blueprint (title registry + EIDOLON economy).

    ``ledger`` is the durable per-artifact CAS store (it also hosts the
    EIDOLON balance tables); ``anchor_key`` signs receipts. Reuse the same
    key as the genesis anchor's deployment key for a single authority.

    ``allow_grants`` exposes ``POST /account/<id>/grant`` (mints EIDOLON via
    an idempotent genesis grant). It is **off by default** — only enable it
    for dev / a trusted genesis-seeding context.
    """
    if not anchor_key.has_secrets:
        raise ValueError("anchor_key must hold a Dilithium secret key")

    bp = Blueprint("eopx_artifact_api", __name__, url_prefix=url_prefix)

    @bp.route("/mint", methods=["POST"])
    @rate_limit("anchor")
    def mint():
        body = request.get_json(silent=True) or {}
        try:
            artifact = TitledArtifact.from_dict(body)
        except Exception as exc:
            return jsonify({"error": f"malformed artifact: {exc}"}), 400

        # Authenticity gate: never claim an id for an unsigned/forged record.
        if not verify_artifact(artifact):
            return jsonify({"error": "issuer signature does not verify"}), 400

        receipt = sign_receipt(
            anchor_key, artifact.artifact_id, 0,
            artifact.initial_controller_pub,
        )
        try:
            entry = ledger.mint(
                artifact_id=artifact.artifact_id.hex(),
                controller_pub=artifact.initial_controller_pub.hex(),
                content_commit=artifact.content_commit.hex(),
                issuer_fp=artifact.issuer_vault_fp.hex(),
                ts=receipt.ts,
                receipt=json.dumps(receipt.to_dict()),
            )
        except ArtifactExists:
            return jsonify({"error": "artifact_id already minted"}), 409

        return jsonify({
            "seq": entry.seq,
            "entry": _entry_dict(entry),
            "receipt": receipt.to_dict(),
        }), 200

    @bp.route("/transfer", methods=["POST"])
    @rate_limit("anchor")
    def transfer():
        body = request.get_json(silent=True) or {}
        try:
            xfer = Transfer.from_dict(body)
        except Exception as exc:
            return jsonify({"error": f"malformed transfer: {exc}"}), 400

        entry = ledger.get(xfer.artifact_id.hex())
        if entry is None:
            return jsonify({"error": "unknown artifact_id"}), 404

        # Verify the hand-off against the controller the ledger records NOW.
        # (The freshness/CAS check on `from_seq` is the ledger's atomic job.)
        current_controller = bytes.fromhex(entry.controller_pub)
        if not verify_transfer(xfer, current_controller):
            return jsonify({
                "error": "transfer signature does not verify under the "
                         "current controller",
            }), 400

        new_seq = entry.seq + 1
        receipt = sign_receipt(
            anchor_key, xfer.artifact_id, new_seq, xfer.new_controller,
        )

        # Optional priced sale (EIDOLON). The buyer's authorization is signed
        # by the SAME new controller that produced the transfer's PoP, so the
        # price cannot be lifted onto another buyer.
        payment = body.get("payment")
        try:
            if payment:
                try:
                    terms = PaymentTerms.from_dict(payment["terms"])
                except Exception as exc:
                    return jsonify({"error": f"malformed payment: {exc}"}), 400
                if terms.from_seq != xfer.from_seq:
                    return jsonify({
                        "error": "payment terms from_seq does not match transfer",
                    }), 400
                if not verify_payment(terms, xfer.artifact_id, xfer.new_controller):
                    return jsonify({
                        "error": "payment authorization does not verify under "
                                 "the new controller",
                    }), 400
                fee = int(payment.get("fee", 0))
                treasury = payment.get("treasury_account")
                committed = ledger.priced_transfer(
                    artifact_id=xfer.artifact_id.hex(),
                    from_seq=xfer.from_seq,
                    new_controller_pub=xfer.new_controller.hex(),
                    ts=receipt.ts,
                    payer_account=terms.payer_account,
                    payee_account=terms.payee_account,
                    price=terms.price,
                    fee=fee,
                    treasury_account=treasury,
                    receipt=json.dumps(receipt.to_dict()),
                )
                body_out = {
                    "seq": committed.seq,
                    "entry": _entry_dict(committed),
                    "receipt": receipt.to_dict(),
                    "payment": {
                        "price": terms.price,
                        "fee": fee,
                        "payer_account": terms.payer_account,
                        "payee_account": terms.payee_account,
                        "payer_balance": ledger.account_balance(terms.payer_account),
                        "payee_balance": ledger.account_balance(terms.payee_account),
                    },
                }
                return jsonify(body_out), 200

            committed = ledger.transfer(
                artifact_id=xfer.artifact_id.hex(),
                from_seq=xfer.from_seq,
                new_controller_pub=xfer.new_controller.hex(),
                ts=receipt.ts,
                receipt=json.dumps(receipt.to_dict()),
            )
        except InsufficientFunds as exc:
            return jsonify({
                "error": "INSUFFICIENT_FUNDS",
                "account": exc.account_id,
                "balance": exc.balance,
                "needed": exc.needed,
            }), 402
        except StaleSequence as exc:
            return jsonify({
                "error": "STALE_SEQUENCE",
                "expected_seq": exc.expected,
                "current_seq": exc.actual,
            }), 409
        except ArtifactNotFound:
            return jsonify({"error": "unknown artifact_id"}), 404

        return jsonify({
            "seq": committed.seq,
            "entry": _entry_dict(committed),
            "receipt": receipt.to_dict(),
        }), 200

    @bp.route("/account/<account_id>", methods=["GET"])
    @rate_limit("default")
    def get_account(account_id: str):
        return jsonify({
            "account_id": account_id.lower(),
            "balance": ledger.account_balance(account_id),
        }), 200

    @bp.route("/account/<account_id>/grant", methods=["POST"])
    @rate_limit("anchor")
    def grant_account(account_id: str):
        if not allow_grants:
            return jsonify({
                "error": "grants are disabled on this anchor",
            }), 403
        body = request.get_json(silent=True) or {}
        amount = body.get("amount")
        if not isinstance(amount, int) or amount <= 0:
            return jsonify({"error": "amount must be a positive integer"}), 400
        bal = ledger.grant_genesis(account_id, amount, ts=_grant_ts())
        return jsonify({
            "account_id": account_id.lower(),
            "balance": bal,
            "note": "idempotent genesis grant",
        }), 200

    @bp.route("/<artifact_id>", methods=["GET"])
    @rate_limit("default")
    def get_artifact(artifact_id: str):
        try:
            bytes.fromhex(artifact_id)
        except ValueError:
            return jsonify({"error": "artifact_id must be hex"}), 400
        entry = ledger.get(artifact_id)
        if entry is None:
            return jsonify({"error": "unknown artifact_id"}), 404
        return jsonify(_entry_dict(entry)), 200

    @bp.route("/<artifact_id>/history", methods=["GET"])
    @rate_limit("default")
    def get_history(artifact_id: str):
        try:
            bytes.fromhex(artifact_id)
        except ValueError:
            return jsonify({"error": "artifact_id must be hex"}), 400
        rows = ledger.history(artifact_id)
        if not rows:
            return jsonify({"error": "unknown artifact_id"}), 404
        return jsonify({
            "artifact_id_hex": artifact_id.lower(),
            "anchor_pub_hex": anchor_key.dilithium_pk.hex(),
            "history": [
                {
                    "seq": r.seq,
                    "controller_pub_hex": r.controller_pub,
                    "ts": r.ts,
                    "receipt": json.loads(r.receipt) if r.receipt else None,
                }
                for r in rows
            ],
        }), 200

    @bp.route("/<artifact_id>/claim", methods=["POST"])
    @rate_limit("anchor")
    def claim(artifact_id: str):
        """Claim a huntable relic by opening its voucher commitment (EPX-V).

        Body: a :class:`~eopx.transfer.ClaimProof` dict (secret + new
        controller + binding signature). First valid claim wins.
        """
        try:
            bytes.fromhex(artifact_id)
        except ValueError:
            return jsonify({"error": "artifact_id must be hex"}), 400
        entry = ledger.get(artifact_id)
        if entry is None:
            return jsonify({"error": "unknown artifact_id"}), 404
        if not entry.claim_commitment:
            return jsonify({"error": "artifact is not a huntable relic"}), 400

        body = request.get_json(silent=True) or {}
        try:
            proof = ClaimProof.from_dict(body)
        except Exception as exc:
            return jsonify({"error": f"malformed claim: {exc}"}), 400
        if proof.artifact_id.hex() != artifact_id.lower():
            return jsonify({"error": "claim artifact_id mismatch"}), 400
        if not verify_claim(proof, bytes.fromhex(artifact_id),
                            bytes.fromhex(entry.claim_commitment)):
            return jsonify({
                "error": "invalid claim (secret does not open the commitment "
                         "or signature does not verify)",
            }), 400

        receipt = sign_receipt(
            anchor_key, proof.artifact_id, 1, proof.new_controller_pub)
        try:
            committed = ledger.claim(
                artifact_id=artifact_id,
                new_controller_pub=proof.new_controller_pub.hex(),
                expected_commitment=entry.claim_commitment,
                ts=receipt.ts,
                receipt=json.dumps(receipt.to_dict()),
            )
        except AlreadyClaimed:
            return jsonify({"error": "ALREADY_CLAIMED"}), 409
        except NotClaimable:
            return jsonify({"error": "artifact is not a huntable relic"}), 400
        except ArtifactNotFound:
            return jsonify({"error": "unknown artifact_id"}), 404

        return jsonify({
            "seq": committed.seq,
            "entry": _entry_dict(committed),
            "receipt": receipt.to_dict(),
        }), 200

    # ------------------------------------------------------------------
    # EPX-K — Keys of Office: a relic's current controller holds its power.
    # ------------------------------------------------------------------

    def _capability_state(cap) -> dict:
        entry = ledger.get(cap.artifact_id_hex())
        return {
            **cap.to_dict(),
            "instated": entry is not None,
            "controller_pub_hex": entry.controller_pub if entry else None,
            "seq": entry.seq if entry else None,
        }

    @bp.route("/capability", methods=["GET"])
    @rate_limit("default")
    def list_capabilities():
        """The twelve offices and their current holders (EPX-K)."""
        return jsonify({
            "epx_k_version": EPX_K_VERSION,
            "commitment_hex": capabilities_commitment(),
            "capabilities": [_capability_state(c) for c in CAPABILITIES],
        }), 200

    @bp.route("/capability/verify", methods=["POST"])
    @rate_limit("anchor")
    def verify_capability():
        """Verify an :class:`~eopx.capabilities.OfficeProof`.

        The proof is checked against the controller the ledger records
        **now** for the capability's relic — so it is valid iff the signer
        currently holds that office. The anchor does not track nonces;
        replay protection is the calling subsystem's job.
        """
        body = request.get_json(silent=True) or {}
        try:
            proof = OfficeProof.from_dict(body)
        except Exception as exc:
            return jsonify({"error": f"malformed office proof: {exc}"}), 400
        cap = CAPABILITY_BY_ID.get(proof.cap_id)
        if cap is None:
            return jsonify({"error": "unknown capability"}), 404
        entry = ledger.get(cap.artifact_id_hex())
        if entry is None:
            return jsonify({
                "ok": False,
                "error": "office not yet instated (relic not minted)",
                "cap_id": cap.cap_id,
            }), 404
        ok = verify_office(proof, bytes.fromhex(entry.controller_pub))
        return jsonify({
            "ok": ok,
            "cap_id": cap.cap_id,
            "title": cap.title,
            "relic_key": cap.relic_key,
            "artifact_id_hex": cap.artifact_id_hex(),
            "controller_pub_hex": entry.controller_pub,
            "seq": entry.seq,
            "action": proof.action,
        }), (200 if ok else 401)

    @bp.route("/capability/<cap_id>", methods=["GET"])
    @rate_limit("default")
    def get_capability(cap_id: str):
        cap = CAPABILITY_BY_ID.get(cap_id)
        if cap is None:
            return jsonify({"error": "unknown capability"}), 404
        return jsonify(_capability_state(cap)), 200

    @bp.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "total": ledger.total()}), 200

    return bp


__all__ = ["create_artifact_api"]

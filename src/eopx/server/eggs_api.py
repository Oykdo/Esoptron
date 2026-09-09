"""Golden-egg attribution API — what a vault drew, and what it was granted.

Why a separate blueprint
------------------------
The genesis anchor (`anchor_api`) needs durable state: a sequence counter, a
deployment context, a signing key. The artifact anchor (`artifact_api`) needs
a PostgreSQL ledger. Neither is required to answer "which egg does this
fingerprint draw" — the draw is a pure function of the committed Bitcoin
block. Bolting these two routes onto either service would have dragged in
state they do not need, so they live on their own.

The two routes answer two different kinds of question:

``GET /api/v1/eggs/vault/<vault_fp_hex>``
    The founder draw. Deterministic: any client can recompute it offline from
    the committed block and MUST obtain the same egg. This endpoint is a
    convenience, never an authority — a server that disagreed with the local
    computation would be the suspect, not the reference.

``GET /api/v1/eggs/grants/<vault_fp_hex>``
    Issuer-signed attributions, which a client CANNOT recompute: a grant
    exists because the issuer signed it. Each record carries the egg actually
    drawn alongside the one granted, so a reader sees the divergence instead
    of a bare claim of having won.

Configuration
-------------
``ESOPTRON_GRANTS_LEDGER``  path to the grants ledger.
                            Default: <repo>/grants/ledger.json.
                            A missing ledger is not an error — it means no
                            grant has ever been issued.
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import Blueprint, jsonify

from ..egg_token import founder_egg
from ..genesis_token import resolve_btc_block
from .rate_limit import rate_limit


def _ledger_path() -> Path:
    configured = os.environ.get("ESOPTRON_GRANTS_LEDGER", "").strip()
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[3] / "grants" / "ledger.json"


def _parse_fp(vault_fp_hex: str) -> bytes | None:
    """Returns the fingerprint bytes, or None when the input is not hex."""
    try:
        raw = bytes.fromhex(vault_fp_hex)
    except ValueError:
        return None
    return raw or None


def create_eggs_api(*, url_prefix: str = "/api/v1/eggs") -> Blueprint:
    """Build the stateless golden-egg blueprint."""
    bp = Blueprint("eopx_eggs_api", __name__, url_prefix=url_prefix)

    @bp.route("/vault/<vault_fp_hex>", methods=["GET"])
    @rate_limit("default")
    def egg_by_vault(vault_fp_hex: str):
        vault_fp = _parse_fp(vault_fp_hex)
        if vault_fp is None:
            return jsonify({"error": "vault_fp_hex is not hexadecimal"}), 400

        block, height, committed = resolve_btc_block()
        egg = founder_egg(vault_fp, block, height)
        return jsonify({
            "vault_fp_hex": vault_fp_hex,
            "kind": "draw",
            "egg": egg.to_dict(),
            "btc_block_height": height,
            "btc_block_hash_hex": block.hex(),
            "committed": bool(committed),
            "reproducible_offline": True,
        }), 200

    @bp.route("/grants/<vault_fp_hex>", methods=["GET"])
    @rate_limit("default")
    def grants_by_vault(vault_fp_hex: str):
        if _parse_fp(vault_fp_hex) is None:
            return jsonify({"error": "vault_fp_hex is not hexadecimal"}), 400

        path = _ledger_path()
        if not path.exists():
            return jsonify({
                "vault_fp_hex": vault_fp_hex,
                "grants": [],
                "ledger_head": None,
            }), 200

        try:
            from ..egg_grant import GrantLedger
            ledger = GrantLedger.from_json(path.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - corrupted ledger
            return jsonify({"error": f"ledger unreadable: {exc}"}), 503

        wanted = vault_fp_hex.lower()
        return jsonify({
            "vault_fp_hex": vault_fp_hex,
            "grants": [g.to_dict() for g in ledger.grants
                       if g.vault_fp_hex.lower() == wanted],
            "ledger_head": ledger.head,
        }), 200

    @bp.route("/health", methods=["GET"])
    def health():
        _, height, committed = resolve_btc_block()
        return jsonify({
            "status": "ok",
            "btc_block_height": height,
            "committed": bool(committed),
            "ledger_present": _ledger_path().exists(),
        }), 200

    return bp

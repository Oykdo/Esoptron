"""Anchor API — unified ecosystem vault counter + Genesis seal minter.

Contract
--------
``POST /api/v1/genesis/anchor``
    Request:
        {
          "vault_fp_hex": "...",      # 64+ hex chars
          "source":       "cipher"    # optional: cipher|esoptron|cli|...
        }
    Response 200:
        {
          "sequence":            7674,
          "btc_block_hash_hex":  "00000...",
          "btc_block_height":    925112,
          "deployment_pk_hex":   "...",  # for clients to verify the seal
          "genesis":             true,
          "genesis_seal":        { ... }     # only when genesis is true
        }

``GET /api/v1/genesis/total``
    Returns ``{"total": N, "max_sequence": N}``.

``GET /api/v1/genesis/positions``
    Returns ``{"btc_block_hash_hex": "...", "btc_block_height": H,
              "positions": [n1, n2, ...]}`` — the 88 Genesis positions.

``GET /api/v1/genesis/seal/<int:sequence>``
    Idempotent re-fetch of a Genesis seal by sequence number. Returns
    404 if the sequence has not been anchored or is not a Genesis
    position.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

from flask import Blueprint, current_app, jsonify, request

from ..format.keys import EopxKey
from ..genesis_token import (
    BTC_BLOCK_TARGET,
    archetype_for_sequence,
    archetypes_commitment_hex,
    derive_positions,
    mint_genesis_seal,
)
from ..egg_token import derive_eggs, mint_egg_seal
from .http_delegate import HTTPDelegateSequenceState, LockServerConfig
from .rate_limit import rate_limit
from .sequence_state import SequenceState

# Both SQLite and HTTPDelegate backends expose the same anchor surface.
AnchorBackend = SequenceState | HTTPDelegateSequenceState


_log = logging.getLogger("eopx.server.anchor_api")


# ---------------------------------------------------------------------------
# Deployment context — loaded at blueprint creation time
# ---------------------------------------------------------------------------

class _DeploymentContext:
    """Anchored configuration of the running anchor service.

    Persists the Dilithium5 deployment key (pk+sk) and the Bitcoin block
    chosen at launch as the source of randomness for the 88 Genesis
    positions. Stored as JSON next to the SQLite database.

    Re-creating the file is a destructive operation: the 88 positions
    move and previously-minted Genesis seals become unverifiable. The
    constructor refuses to overwrite an existing file.
    """

    SCHEMA_VERSION = 1

    def __init__(self, path: Path,
                 deployment_key: EopxKey,
                 btc_block_hash_hex: str,
                 btc_block_height: int) -> None:
        self.path = path
        self.deployment_key = deployment_key
        self.btc_block_hash_hex = btc_block_hash_hex.lower()
        self.btc_block_height = int(btc_block_height)
        self.btc_block_hash = bytes.fromhex(self.btc_block_hash_hex)
        self.positions = derive_positions(
            self.btc_block_hash,
            btc_block_height=self.btc_block_height,
        )
        self.positions_set = set(self.positions)
        # Golden Eggs share the same committed block (EPX-E). Derived once;
        # a vault landing on an egg position auto-wins it (sealed below).
        self.eggs = derive_eggs(self.btc_block_hash, self.btc_block_height)
        self.eggs_by_position = {e.position: e for e in self.eggs}

    @classmethod
    def load_or_init(
        cls,
        path: Path,
        btc_block_hash_hex: Optional[str] = None,
        btc_block_height: Optional[int] = None,
    ) -> "_DeploymentContext":
        path = Path(path)
        if path.exists():
            return cls._load_existing(path)

        if btc_block_hash_hex is None or btc_block_height is None:
            raise RuntimeError(
                "deployment context not initialized — pass "
                "btc_block_hash_hex and btc_block_height to bootstrap it"
            )

        # Use O_CREAT|O_EXCL to atomically claim the path. If a sibling
        # process wins the race we re-open the existing file instead of
        # silently overwriting its freshly minted Dilithium key.
        path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = path.with_suffix(path.suffix + ".init.lock")
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
        except FileExistsError:
            # Another process is initialising; poll briefly for the result.
            import time as _time
            for _ in range(50):
                if path.exists():
                    return cls._load_existing(path)
                _time.sleep(0.1)
            raise RuntimeError(
                f"another process is initialising {path} but has not "
                f"published it after 5s; remove {lock_path} if stale"
            )

        try:
            # Re-check after acquiring the lock in case a writer finished
            # between our exists() check and the lock claim.
            if path.exists():
                return cls._load_existing(path)
            deployment_key = EopxKey.generate()
            ctx = cls(
                path=path,
                deployment_key=deployment_key,
                btc_block_hash_hex=btc_block_hash_hex,
                btc_block_height=btc_block_height,
            )
            ctx._persist()
            return ctx
        finally:
            try:
                lock_path.unlink()
            except OSError:
                pass

    @classmethod
    def _load_existing(cls, path: Path) -> "_DeploymentContext":
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema_version") != cls.SCHEMA_VERSION:
            raise RuntimeError(
                f"deployment context schema mismatch: "
                f"{data.get('schema_version')} != {cls.SCHEMA_VERSION}"
            )
        deployment_key = EopxKey(
            dilithium_pk=bytes.fromhex(data["deployment_pk_hex"]),
            dilithium_sk=bytes.fromhex(data["deployment_sk_hex"]),
            kyber_pk=bytes.fromhex(data["deployment_kyber_pk_hex"]),
            kyber_sk=bytes.fromhex(data["deployment_kyber_sk_hex"]),
        )
        return cls(
            path=path,
            deployment_key=deployment_key,
            btc_block_hash_hex=data["btc_block_hash_hex"],
            btc_block_height=data["btc_block_height"],
        )

    def _persist(self) -> None:
        # Write atomically: write to a temp file then rename. The file
        # carries the deployment Dilithium private key — must be 0600 on
        # POSIX and DACL-restricted on Windows.
        from ..format.file_perms import restrict_secret_file

        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "btc_block_hash_hex": self.btc_block_hash_hex,
            "btc_block_height": self.btc_block_height,
            "deployment_pk_hex": self.deployment_key.dilithium_pk.hex(),
            "deployment_sk_hex": self.deployment_key.dilithium_sk.hex(),  # pyright: ignore
            "deployment_kyber_pk_hex": self.deployment_key.kyber_pk.hex(),
            "deployment_kyber_sk_hex": self.deployment_key.kyber_sk.hex(),  # pyright: ignore
            "archetypes_commitment_hex": archetypes_commitment_hex(),
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.path)
        restrict_secret_file(self.path)


# ---------------------------------------------------------------------------
# Blueprint factory
# ---------------------------------------------------------------------------

def create_anchor_api(
    state: AnchorBackend,
    context: _DeploymentContext,
    *,
    url_prefix: str = "/api/v1/genesis",
    require_source: bool = False,
) -> Blueprint:
    """Build a Flask Blueprint serving the anchor API.

    ``state`` is the durable counter; ``context`` is the deployment
    configuration (Dilithium key + BTC block + 88 positions).
    """
    bp = Blueprint("eopx_anchor_api", __name__, url_prefix=url_prefix)

    @bp.route("/anchor", methods=["POST"])
    @rate_limit("anchor")
    def anchor():
        body = request.get_json(silent=True) or {}
        vault_fp_hex = body.get("vault_fp_hex")
        if not isinstance(vault_fp_hex, str) or len(vault_fp_hex) < 16:
            return jsonify({"error": "vault_fp_hex required (hex string)"}), 400
        try:
            bytes.fromhex(vault_fp_hex)
        except ValueError:
            return jsonify({"error": "vault_fp_hex must be valid hex"}), 400
        source = body.get("source")
        if require_source and not source:
            return jsonify({"error": "source field required"}), 400
        vault_number_hint = body.get("vault_number_hint")
        if vault_number_hint is not None:
            if not isinstance(vault_number_hint, int) or vault_number_hint <= 0:
                return jsonify({
                    "error": "vault_number_hint must be a positive integer",
                }), 400

        try:
            record = state.anchor_vault(
                vault_fp_hex=vault_fp_hex,
                source=source,
                meta=None,
                sequence_hint=vault_number_hint,
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 409
        response = {
            "sequence": record.sequence,
            "btc_block_hash_hex": context.btc_block_hash_hex,
            "btc_block_height": context.btc_block_height,
            "deployment_pk_hex": context.deployment_key.dilithium_pk.hex(),
            "genesis": record.sequence in context.positions_set,
            "archetypes_commitment_hex": archetypes_commitment_hex(),
        }
        if response["genesis"]:
            seal = mint_genesis_seal(
                vault_fp=bytes.fromhex(vault_fp_hex),
                sequence=record.sequence,
                btc_block_hash=context.btc_block_hash,
                btc_block_height=context.btc_block_height,
                positions=context.positions,
                deployment_key=context.deployment_key,
            )
            archetype = archetype_for_sequence(record.sequence,
                                               context.positions)
            response["genesis_seal"] = seal.to_dict()
            response["archetype"] = {
                "id": archetype.id if archetype else None,
                "pattern": archetype.pattern if archetype else None,
                "element": archetype.element if archetype else None,
                "glyph": archetype.glyph if archetype else None,
                "color_hue": archetype.color_hue if archetype else None,
                "council_seat": f"{archetype.id + 1} of 88"
                if archetype else None,
            }

        # Golden Egg auto-win: if the vault's sequence lands on an egg
        # position, mint + return its immutable signed seal (EPX-E).
        won = context.eggs_by_position.get(record.sequence)
        response["golden_egg"] = bool(won)
        if won is not None:
            egg_seal = mint_egg_seal(
                egg=won,
                vault_fp=bytes.fromhex(vault_fp_hex),
                btc_block_hash=context.btc_block_hash,
                btc_block_height=context.btc_block_height,
                eggs=context.eggs,
                deployment_key=context.deployment_key,
            )
            response["egg"] = won.to_dict()
            response["egg_seal"] = egg_seal.to_dict()
        return jsonify(response), 200

    @bp.route("/total", methods=["GET"])
    def total():
        return jsonify({
            "total": state.total(),
            "max_sequence": state.max_sequence(),
            "btc_block_height": context.btc_block_height,
            "first_genesis_position": context.positions[0],
            "last_genesis_position": context.positions[-1],
        }), 200

    @bp.route("/positions", methods=["GET"])
    def positions():
        return jsonify({
            "btc_block_hash_hex": context.btc_block_hash_hex,
            "btc_block_height": context.btc_block_height,
            "positions": context.positions,
            "archetypes_commitment_hex": archetypes_commitment_hex(),
            "deployment_pk_hex": context.deployment_key.dilithium_pk.hex(),
        }), 200

    @bp.route("/seal/<int:sequence>", methods=["GET"])
    @rate_limit("default")
    def seal_by_sequence(sequence: int):
        if sequence not in context.positions_set:
            return jsonify({"error": "sequence is not a Genesis position"}), 404
        record = state.lookup_by_sequence(sequence)
        if record is None:
            return jsonify({"error": "sequence not yet anchored"}), 404
        seal = mint_genesis_seal(
            vault_fp=bytes.fromhex(record.vault_fp_hex),
            sequence=sequence,
            btc_block_hash=context.btc_block_hash,
            btc_block_height=context.btc_block_height,
            positions=context.positions,
            deployment_key=context.deployment_key,
        )
        archetype = archetype_for_sequence(sequence, context.positions)
        return jsonify({
            "sequence": sequence,
            "vault_fp_hex": record.vault_fp_hex,
            "btc_block_hash_hex": context.btc_block_hash_hex,
            "btc_block_height": context.btc_block_height,
            "deployment_pk_hex": context.deployment_key.dilithium_pk.hex(),
            "genesis_seal": seal.to_dict(),
            "archetype": {
                "id": archetype.id if archetype else None,
                "pattern": archetype.pattern if archetype else None,
                "element": archetype.element if archetype else None,
                "glyph": archetype.glyph if archetype else None,
                "color_hue": archetype.color_hue if archetype else None,
            } if archetype else None,
        }), 200

    @bp.route("/egg/<int:sequence>", methods=["GET"])
    @rate_limit("default")
    def egg_by_sequence(sequence: int):
        won = context.eggs_by_position.get(sequence)
        if won is None:
            return jsonify({"error": "sequence is not a golden-egg position"}), 404
        record = state.lookup_by_sequence(sequence)
        if record is None:
            return jsonify({"error": "sequence not yet anchored"}), 404
        egg_seal = mint_egg_seal(
            egg=won, vault_fp=bytes.fromhex(record.vault_fp_hex),
            btc_block_hash=context.btc_block_hash,
            btc_block_height=context.btc_block_height,
            eggs=context.eggs, deployment_key=context.deployment_key,
        )
        return jsonify({
            "sequence": sequence,
            "vault_fp_hex": record.vault_fp_hex,
            "deployment_pk_hex": context.deployment_key.dilithium_pk.hex(),
            "egg": won.to_dict(),
            "egg_seal": egg_seal.to_dict(),
        }), 200

    @bp.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "total": state.total()}), 200

    return bp


# ---------------------------------------------------------------------------
# Convenience bootstrap for standalone serving
# ---------------------------------------------------------------------------

def bootstrap_from_env(
    db_path: Optional[Path] = None,
    context_path: Optional[Path] = None,
) -> tuple[AnchorBackend, _DeploymentContext]:
    """Build state + context from environment variables.

    Variables consumed:
      ESOPTRON_ANCHOR_DB        SQLite path (default: ./data/anchor.db)
      ESOPTRON_ANCHOR_CONTEXT   JSON path  (default: ./data/anchor_context.json)
      ESOPTRON_BTC_BLOCK_HASH   64-char hex (required on first launch)
      ESOPTRON_BTC_BLOCK_HEIGHT integer    (required on first launch)
      ESOPTRON_ANCHOR_BACKEND   "sqlite" (default) | "http"
      ESOPTRON_LOCK_SERVER_URL  required when backend="http"
                                (e.g. https://lock.eidolon-connect.xyz)
      ESOPTRON_LOCK_API_SECRET  optional; only needed if/when we hit
                                signed endpoints on the lock server
      ESOPTRON_LOCK_TIMEOUT     float seconds (default 5.0)
      ESOPTRON_LOCK_STATS_TTL   float seconds (default 2.0)
    """
    db_path = db_path or Path(
        os.environ.get("ESOPTRON_ANCHOR_DB", "data/anchor.db"))
    context_path = context_path or Path(
        os.environ.get("ESOPTRON_ANCHOR_CONTEXT", "data/anchor_context.json"))
    btc_hash = os.environ.get("ESOPTRON_BTC_BLOCK_HASH")
    btc_height_str = os.environ.get("ESOPTRON_BTC_BLOCK_HEIGHT")
    btc_height = int(btc_height_str) if btc_height_str else None
    allow_dev_defaults = (
        os.environ.get("ESOPTRON_ALLOW_DEV_DEFAULTS", "0") == "1"
    )
    if not context_path.exists() and (btc_hash is None or btc_height is None):
        if not allow_dev_defaults:
            raise RuntimeError(
                "Anchor bootstrap requires ESOPTRON_BTC_BLOCK_HASH and "
                "ESOPTRON_BTC_BLOCK_HEIGHT on first launch. Set both env "
                "vars to the chosen Bitcoin block, or export "
                "ESOPTRON_ALLOW_DEV_DEFAULTS=1 to fall back to the placeholder "
                "block (DEV/TEST ONLY — Genesis seals minted against the "
                "placeholder cannot be verified against the mainnet chain)."
            )
        _log.warning(
            "ESOPTRON_ALLOW_DEV_DEFAULTS=1: anchor bootstrap will use the "
            "PLACEHOLDER Bitcoin block %s @ height %d. Genesis seals minted "
            "in this configuration are NOT verifiable on the public chain.",
            "ff" * 32, BTC_BLOCK_TARGET,
        )
        btc_hash = btc_hash or ("ff" * 32)
        btc_height = btc_height or BTC_BLOCK_TARGET

    backend_kind = os.environ.get("ESOPTRON_ANCHOR_BACKEND", "sqlite").lower()
    if backend_kind == "http":
        lock_url = os.environ.get("ESOPTRON_LOCK_SERVER_URL")
        if not lock_url:
            raise RuntimeError(
                "ESOPTRON_ANCHOR_BACKEND=http requires "
                "ESOPTRON_LOCK_SERVER_URL (e.g. https://lock.eidolon-connect.xyz)"
            )
        timeout = float(os.environ.get("ESOPTRON_LOCK_TIMEOUT", "5.0"))
        stats_ttl = float(os.environ.get("ESOPTRON_LOCK_STATS_TTL", "2.0"))
        config = LockServerConfig(
            base_url=lock_url,
            api_secret=os.environ.get("ESOPTRON_LOCK_API_SECRET") or None,
            request_timeout=timeout,
        )
        state: AnchorBackend = HTTPDelegateSequenceState(
            cache_db_path=db_path,
            lock_server=config,
            stats_cache_ttl=stats_ttl,
        )
    elif backend_kind == "sqlite":
        state = SequenceState(db_path)
    else:
        raise RuntimeError(
            f"unknown ESOPTRON_ANCHOR_BACKEND={backend_kind!r}; "
            f"expected 'sqlite' or 'http'"
        )

    context = _DeploymentContext.load_or_init(
        context_path,
        btc_block_hash_hex=btc_hash,
        btc_block_height=btc_height,
    )
    return state, context

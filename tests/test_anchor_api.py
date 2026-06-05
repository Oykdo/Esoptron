"""Anchor API — durability + idempotence + Genesis seal interop tests."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import threading
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask

from eopx.format.keys import EopxKey
from eopx.genesis_token import (
    BTC_BLOCK_TARGET,
    archetypes_commitment_hex,
    derive_positions,
    verify_genesis_seal,
    GenesisSeal,
)
from eopx.server.anchor_api import (
    _DeploymentContext,
    bootstrap_from_env,
    create_anchor_api,
)
from eopx.server.http_delegate import (
    HTTPDelegateSequenceState,
    LockServerConfig,
    LockServerError,
)
from eopx.server.sequence_state import SequenceState


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def state(tmp_path: Path) -> SequenceState:
    return SequenceState(tmp_path / "anchor.db")


@pytest.fixture
def context(tmp_path: Path) -> _DeploymentContext:
    return _DeploymentContext.load_or_init(
        tmp_path / "anchor_context.json",
        btc_block_hash_hex="ab" * 32,
        btc_block_height=925_000,
    )


@pytest.fixture
def client(state: SequenceState, context: _DeploymentContext):
    app = Flask("test_anchor_api")
    app.register_blueprint(create_anchor_api(state, context))
    app.testing = True
    return app.test_client()


# ---------------------------------------------------------------------------
# SequenceState — counter mechanics
# ---------------------------------------------------------------------------

class TestSequenceState:
    def test_first_anchor_returns_sequence_one(self, state):
        r = state.anchor_vault("ab" * 32, source="cipher")
        assert r.sequence == 1
        assert r.vault_fp_hex == "ab" * 32
        assert r.source == "cipher"

    def test_sequence_is_monotone(self, state):
        seqs = [state.anchor_vault(f"{i:064x}").sequence for i in range(1, 11)]
        assert seqs == list(range(1, 11))

    def test_idempotent_anchor_same_fp(self, state):
        r1 = state.anchor_vault("cd" * 32)
        r2 = state.anchor_vault("cd" * 32)
        r3 = state.anchor_vault("cd" * 32)
        assert r1.sequence == r2.sequence == r3.sequence
        assert state.total() == 1

    def test_lookup_returns_record(self, state):
        r = state.anchor_vault("ef" * 32, source="esoptron")
        lk = state.lookup("ef" * 32)
        assert lk is not None
        assert lk.sequence == r.sequence
        assert lk.source == "esoptron"

    def test_lookup_unknown_returns_none(self, state):
        assert state.lookup("aa" * 32) is None

    def test_lookup_by_sequence(self, state):
        r = state.anchor_vault("11" * 32)
        lk = state.lookup_by_sequence(r.sequence)
        assert lk is not None
        assert lk.vault_fp_hex == "11" * 32

    def test_rejects_bad_fp(self, state):
        with pytest.raises(ValueError):
            state.anchor_vault("")
        with pytest.raises(ValueError):
            state.anchor_vault("short")

    def test_concurrent_anchors_no_duplicates(self, state):
        """50 threads racing on 25 distinct FPs ⇒ exactly 25 entries."""
        fps = [f"{i:064x}" for i in range(25)] * 2
        results = []
        lock = threading.Lock()

        def worker(fp: str):
            r = state.anchor_vault(fp)
            with lock:
                results.append((fp, r.sequence))

        threads = [threading.Thread(target=worker, args=(fp,)) for fp in fps]
        for t in threads: t.start()
        for t in threads: t.join()

        assert state.total() == 25
        # Each FP's two parallel attempts must agree on the same sequence
        by_fp = {}
        for fp, seq in results:
            if fp in by_fp:
                assert by_fp[fp] == seq, f"split-brain on {fp[:8]}"
            else:
                by_fp[fp] = seq

    def test_persistence_across_reopen(self, tmp_path):
        path = tmp_path / "x.db"
        s1 = SequenceState(path)
        s1.anchor_vault("aa" * 32)
        s1.anchor_vault("bb" * 32)
        s2 = SequenceState(path)
        assert s2.total() == 2
        assert s2.max_sequence() == 2
        assert s2.anchor_vault("cc" * 32).sequence == 3

    def test_seed_migration(self, state):
        inserted = state.seed_initial([
            (1, "01" * 32, None),
            (2, "02" * 32, None),
            (3, "03" * 32, None),
        ])
        assert inserted == 3
        assert state.total() == 3
        # New anchor takes 4
        r = state.anchor_vault("04" * 32)
        assert r.sequence == 4

    def test_seed_skips_duplicates(self, state):
        state.anchor_vault("aa" * 32)
        # Try to seed with conflicting FP — should skip, not crash
        inserted = state.seed_initial([(99, "aa" * 32, None)])
        assert inserted == 0


# ---------------------------------------------------------------------------
# Deployment context — persistence + immutability
# ---------------------------------------------------------------------------

class TestDeploymentContext:
    def test_first_load_creates_file(self, tmp_path):
        path = tmp_path / "ctx.json"
        assert not path.exists()
        ctx = _DeploymentContext.load_or_init(
            path, btc_block_hash_hex="cd" * 32, btc_block_height=1)
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["schema_version"] == 1
        assert data["btc_block_hash_hex"] == "cd" * 32
        assert data["btc_block_height"] == 1
        assert len(bytes.fromhex(data["deployment_pk_hex"])) == 2592
        assert len(bytes.fromhex(data["deployment_sk_hex"])) == 4896

    def test_subsequent_load_reuses_key(self, tmp_path):
        path = tmp_path / "ctx.json"
        c1 = _DeploymentContext.load_or_init(
            path, btc_block_hash_hex="cd" * 32, btc_block_height=1)
        c2 = _DeploymentContext.load_or_init(path)
        assert c1.deployment_key.dilithium_pk == c2.deployment_key.dilithium_pk
        assert c1.btc_block_hash_hex == c2.btc_block_hash_hex
        assert c1.positions == c2.positions

    def test_positions_match_genesis_token(self, context):
        # The context's 88 positions must match a fresh derivation from
        # the same BTC inputs — no drift between the API and the spec.
        expected = derive_positions(
            bytes.fromhex(context.btc_block_hash_hex),
            btc_block_height=context.btc_block_height,
        )
        assert context.positions == expected
        assert len(context.positions) == 88


# ---------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------

class TestAnchorRoutes:
    def test_anchor_returns_sequence_and_pk(self, client, context):
        r = client.post("/api/v1/genesis/anchor",
                        json={"vault_fp_hex": "ab" * 32, "source": "test"})
        assert r.status_code == 200
        body = r.get_json()
        assert body["sequence"] == 1
        assert body["btc_block_hash_hex"] == context.btc_block_hash_hex
        assert body["btc_block_height"] == context.btc_block_height
        assert body["deployment_pk_hex"] == context.deployment_key.dilithium_pk.hex()
        assert body["archetypes_commitment_hex"] == archetypes_commitment_hex()

    def test_anchor_idempotent_over_http(self, client):
        r1 = client.post("/api/v1/genesis/anchor",
                         json={"vault_fp_hex": "ab" * 32})
        r2 = client.post("/api/v1/genesis/anchor",
                         json={"vault_fp_hex": "ab" * 32})
        assert r1.get_json()["sequence"] == r2.get_json()["sequence"]

    def test_anchor_rejects_bad_fp(self, client):
        r = client.post("/api/v1/genesis/anchor",
                        json={"vault_fp_hex": "not-hex!"})
        assert r.status_code == 400

    def test_anchor_rejects_missing_fp(self, client):
        r = client.post("/api/v1/genesis/anchor", json={})
        assert r.status_code == 400

    def test_total_endpoint(self, client):
        for i in range(5):
            client.post("/api/v1/genesis/anchor",
                        json={"vault_fp_hex": f"{i:064x}"})
        r = client.get("/api/v1/genesis/total")
        body = r.get_json()
        assert body["total"] == 5
        assert body["max_sequence"] == 5
        assert "first_genesis_position" in body
        assert "last_genesis_position" in body

    def test_positions_endpoint(self, client, context):
        r = client.get("/api/v1/genesis/positions")
        body = r.get_json()
        assert body["positions"] == context.positions
        assert len(body["positions"]) == 88
        assert body["archetypes_commitment_hex"] == archetypes_commitment_hex()

    def test_health_endpoint(self, client):
        r = client.get("/api/v1/genesis/health")
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Genesis hit path — the actual 88 reveal
# ---------------------------------------------------------------------------

class TestGenesisHit:
    def test_non_genesis_sequence_returns_no_seal(self, client, context):
        # Pick a vault that will land on sequence=1 — not in positions
        # (positions[0] is always > 1 for our test block).
        assert 1 not in context.positions_set
        r = client.post("/api/v1/genesis/anchor",
                        json={"vault_fp_hex": "ab" * 32})
        body = r.get_json()
        assert body["genesis"] is False
        assert "genesis_seal" not in body
        assert "archetype" not in body

    def test_genesis_sequence_returns_signed_seal(
            self, state, context, client):
        # Anchor a vault directly at the first Genesis position via the
        # vault_number_hint contract (mimics what Eidolon does after
        # receiving vault_number from the lock server).
        target = context.positions[0]
        target_fp = "f" + "0" * 63
        r = client.post(
            "/api/v1/genesis/anchor",
            json={
                "vault_fp_hex": target_fp,
                "source": "cipher",
                "vault_number_hint": target,
            },
        )
        body = r.get_json()
        assert body["sequence"] == target
        assert body["genesis"] is True
        seal = GenesisSeal.from_dict(body["genesis_seal"])
        assert verify_genesis_seal(
            seal,
            deployment_pk=context.deployment_key.dilithium_pk,
            positions=context.positions,
        )
        # Archetype 0 = sorted-rank-0 archetype
        assert body["archetype"]["id"] == 0
        assert body["archetype"]["pattern"] == "Source"
        assert body["archetype"]["element"] == "Air"
        assert body["archetype"]["council_seat"] == "1 of 88"

    def test_seal_by_sequence_endpoint(self, state, context, client):
        # Anchor the first Genesis vault directly via hint, then re-
        # fetch via /seal/<n>.
        target = context.positions[0]
        target_fp = "11" + "0" * 62
        client.post(
            "/api/v1/genesis/anchor",
            json={
                "vault_fp_hex": target_fp,
                "vault_number_hint": target,
            },
        )
        r = client.get(f"/api/v1/genesis/seal/{target}")
        assert r.status_code == 200
        body = r.get_json()
        assert body["sequence"] == target
        assert body["vault_fp_hex"] == target_fp
        seal = GenesisSeal.from_dict(body["genesis_seal"])
        assert verify_genesis_seal(
            seal,
            deployment_pk=context.deployment_key.dilithium_pk,
            positions=context.positions,
        )

    def test_seal_by_sequence_404_when_not_anchored(self, context, client):
        target = context.positions[0]
        r = client.get(f"/api/v1/genesis/seal/{target}")
        assert r.status_code == 404

    def test_seal_by_sequence_404_when_not_genesis(self, client):
        r = client.get("/api/v1/genesis/seal/1")  # 1 is not in positions
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Golden Eggs — auto-win on landing (EPX-E)
# ---------------------------------------------------------------------------

class TestGoldenEggHit:
    def test_landing_on_egg_position_wins_a_sealed_egg(
            self, state, context, client):
        from eopx.egg_token import EggSeal, verify_egg_seal
        egg = context.eggs[0]
        r = client.post("/api/v1/genesis/anchor", json={
            "vault_fp_hex": "f" + "0" * 63,
            "vault_number_hint": egg.position,
        })
        body = r.get_json()
        assert body["golden_egg"] is True
        assert body["egg"]["egg_id"] == egg.egg_id
        seal = EggSeal.from_dict(body["egg_seal"])
        assert verify_egg_seal(
            seal, deployment_pk=context.deployment_key.dilithium_pk,
            eggs=context.eggs)

    def test_non_egg_sequence_has_no_egg(self, context, client):
        # Pick a sequence guaranteed not to be an egg position.
        seq = 1
        assert seq not in context.eggs_by_position
        r = client.post("/api/v1/genesis/anchor",
                        json={"vault_fp_hex": "ab" * 32,
                              "vault_number_hint": seq})
        body = r.get_json()
        assert body["golden_egg"] is False
        assert "egg_seal" not in body

    def test_egg_by_sequence_endpoint(self, state, context, client):
        egg = context.eggs[1]
        client.post("/api/v1/genesis/anchor", json={
            "vault_fp_hex": "cc" * 32, "vault_number_hint": egg.position})
        r = client.get(f"/api/v1/genesis/egg/{egg.position}")
        assert r.status_code == 200
        assert r.get_json()["egg"]["egg_id"] == egg.egg_id

    def test_egg_by_sequence_404_when_not_egg(self, client):
        r = client.get("/api/v1/genesis/egg/1")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Bootstrap helper
# ---------------------------------------------------------------------------

class TestBootstrap:
    def test_bootstrap_creates_dirs_and_files(
            self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv(
            "ESOPTRON_ANCHOR_DB", str(tmp_path / "a.db"))
        monkeypatch.setenv(
            "ESOPTRON_ANCHOR_CONTEXT", str(tmp_path / "a.json"))
        monkeypatch.setenv(
            "ESOPTRON_BTC_BLOCK_HASH", "12" * 32)
        monkeypatch.setenv(
            "ESOPTRON_BTC_BLOCK_HEIGHT", "925100")
        state, context = bootstrap_from_env()
        assert (tmp_path / "a.db").exists()
        assert (tmp_path / "a.json").exists()
        assert context.btc_block_height == 925100
        assert state.total() == 0

    def test_bootstrap_http_backend(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("ESOPTRON_ANCHOR_DB", str(tmp_path / "a.db"))
        monkeypatch.setenv("ESOPTRON_ANCHOR_CONTEXT", str(tmp_path / "a.json"))
        monkeypatch.setenv("ESOPTRON_BTC_BLOCK_HASH", "12" * 32)
        monkeypatch.setenv("ESOPTRON_BTC_BLOCK_HEIGHT", "925100")
        monkeypatch.setenv("ESOPTRON_ANCHOR_BACKEND", "http")
        monkeypatch.setenv(
            "ESOPTRON_LOCK_SERVER_URL", "https://lock.example.invalid")
        state, _ = bootstrap_from_env()
        assert isinstance(state, HTTPDelegateSequenceState)

    def test_bootstrap_http_backend_missing_url_raises(
            self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("ESOPTRON_ANCHOR_DB", str(tmp_path / "a.db"))
        monkeypatch.setenv("ESOPTRON_ANCHOR_CONTEXT", str(tmp_path / "a.json"))
        monkeypatch.setenv("ESOPTRON_BTC_BLOCK_HASH", "12" * 32)
        monkeypatch.setenv("ESOPTRON_BTC_BLOCK_HEIGHT", "925100")
        monkeypatch.setenv("ESOPTRON_ANCHOR_BACKEND", "http")
        monkeypatch.delenv("ESOPTRON_LOCK_SERVER_URL", raising=False)
        with pytest.raises(RuntimeError, match="ESOPTRON_LOCK_SERVER_URL"):
            bootstrap_from_env()

    def test_bootstrap_refuses_missing_btc_block_by_default(
            self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("ESOPTRON_ANCHOR_DB", str(tmp_path / "a.db"))
        monkeypatch.setenv("ESOPTRON_ANCHOR_CONTEXT", str(tmp_path / "a.json"))
        monkeypatch.delenv("ESOPTRON_BTC_BLOCK_HASH", raising=False)
        monkeypatch.delenv("ESOPTRON_BTC_BLOCK_HEIGHT", raising=False)
        monkeypatch.delenv("ESOPTRON_ALLOW_DEV_DEFAULTS", raising=False)
        with pytest.raises(RuntimeError, match="ESOPTRON_BTC_BLOCK_HASH"):
            bootstrap_from_env()

    def test_bootstrap_uses_dev_defaults_when_opted_in(
            self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("ESOPTRON_ANCHOR_DB", str(tmp_path / "a.db"))
        monkeypatch.setenv("ESOPTRON_ANCHOR_CONTEXT", str(tmp_path / "a.json"))
        monkeypatch.delenv("ESOPTRON_BTC_BLOCK_HASH", raising=False)
        monkeypatch.delenv("ESOPTRON_BTC_BLOCK_HEIGHT", raising=False)
        monkeypatch.setenv("ESOPTRON_ALLOW_DEV_DEFAULTS", "1")
        state, context = bootstrap_from_env()
        assert context.btc_block_hash_hex == "ff" * 32


# ---------------------------------------------------------------------------
# sequence_hint — vault_number coming from the Eidolon lock server
# ---------------------------------------------------------------------------

class TestSequenceHint:
    def test_hint_assigns_explicit_sequence(self, state):
        r = state.anchor_vault("aa" * 32, sequence_hint=7674)
        assert r.sequence == 7674
        assert state.total() == 1
        assert state.max_sequence() == 7674

    def test_hint_idempotent_returns_existing_sequence(self, state):
        r1 = state.anchor_vault("aa" * 32, sequence_hint=42)
        r2 = state.anchor_vault("aa" * 32, sequence_hint=42)
        r3 = state.anchor_vault("aa" * 32)  # no hint, cached
        assert r1.sequence == r2.sequence == r3.sequence == 42

    def test_hint_collision_raises(self, state):
        state.anchor_vault("aa" * 32, sequence_hint=10)
        with pytest.raises(ValueError, match="already used"):
            state.anchor_vault("bb" * 32, sequence_hint=10)

    def test_hint_rejects_zero_or_negative(self, state):
        with pytest.raises(ValueError):
            state.anchor_vault("aa" * 32, sequence_hint=0)
        with pytest.raises(ValueError):
            state.anchor_vault("aa" * 32, sequence_hint=-1)

    def test_hint_then_autoincrement_picks_up_after_hint(self, state):
        # Hint 100 → next autoincrement should respect SQLite's
        # ROWID semantics: next AUTOINCREMENT > current max.
        state.anchor_vault("aa" * 32, sequence_hint=100)
        r = state.anchor_vault("bb" * 32)
        assert r.sequence == 101

    def test_anchor_route_accepts_vault_number_hint(self, client):
        r = client.post(
            "/api/v1/genesis/anchor",
            json={"vault_fp_hex": "cd" * 32, "vault_number_hint": 5000},
        )
        assert r.status_code == 200
        assert r.get_json()["sequence"] == 5000

    def test_anchor_route_rejects_non_positive_hint(self, client):
        r = client.post(
            "/api/v1/genesis/anchor",
            json={"vault_fp_hex": "cd" * 32, "vault_number_hint": 0},
        )
        assert r.status_code == 400

    def test_anchor_route_returns_409_on_hint_collision(self, client):
        client.post(
            "/api/v1/genesis/anchor",
            json={"vault_fp_hex": "aa" * 32, "vault_number_hint": 10},
        )
        r = client.post(
            "/api/v1/genesis/anchor",
            json={"vault_fp_hex": "bb" * 32, "vault_number_hint": 10},
        )
        assert r.status_code == 409


# ---------------------------------------------------------------------------
# HTTPDelegateSequenceState — lock-server-backed counter
# ---------------------------------------------------------------------------

def _mock_lock_response(next_vault_number: int):
    """Build a fake urlopen context manager returning the lock server
    stats payload shape (``data.next_vault_number``)."""
    payload = {
        "success": True,
        "message": "Stats retrieved",
        "data": {
            "total_machines": next_vault_number - 1,
            "total_vaults": next_vault_number - 1,
            "next_vault_number": next_vault_number,
            "founder_slots_remaining": 100_000 - (next_vault_number - 1),
        },
    }
    raw = json.dumps(payload).encode("utf-8")

    class _Ctx:
        def __enter__(self):
            return io.BytesIO(raw)

        def __exit__(self, *exc):
            return False

    return _Ctx()


class TestHTTPDelegate:
    def _build(self, tmp_path: Path, **kwargs) -> HTTPDelegateSequenceState:
        cfg = LockServerConfig(
            base_url="https://lock.example.invalid",
            api_secret=None,
            request_timeout=1.0,
        )
        return HTTPDelegateSequenceState(
            cache_db_path=tmp_path / "delegate.db",
            lock_server=cfg,
            stats_cache_ttl=kwargs.pop("stats_cache_ttl", 0.0),
        )

    def test_anchor_uses_hint_and_skips_http(self, tmp_path):
        delegate = self._build(tmp_path)
        with patch("eopx.server.http_delegate.urllib.request.urlopen") as up:
            up.side_effect = AssertionError("HTTP should not be called")
            r = delegate.anchor_vault(
                "aa" * 32, source="cipher", sequence_hint=1234,
            )
        assert r.sequence == 1234
        assert delegate.total() == 1
        assert delegate.lookup("aa" * 32).sequence == 1234

    def test_anchor_without_hint_queries_lock_server(self, tmp_path):
        delegate = self._build(tmp_path)
        with patch(
            "eopx.server.http_delegate.urllib.request.urlopen",
            return_value=_mock_lock_response(50),
        ):
            r = delegate.anchor_vault("aa" * 32, source="cipher")
        assert r.sequence == 50

    def test_anchor_idempotent_avoids_extra_http(self, tmp_path):
        delegate = self._build(tmp_path)
        with patch(
            "eopx.server.http_delegate.urllib.request.urlopen",
            return_value=_mock_lock_response(7),
        ) as up:
            delegate.anchor_vault("aa" * 32, source="cipher")
        # Second call hits the local cache, no HTTP at all.
        with patch(
            "eopx.server.http_delegate.urllib.request.urlopen",
            side_effect=AssertionError("HTTP should not be called"),
        ):
            r2 = delegate.anchor_vault("aa" * 32)
        assert r2.sequence == 7

    def test_lock_server_unreachable_raises(self, tmp_path):
        import urllib.error
        delegate = self._build(tmp_path)
        with patch(
            "eopx.server.http_delegate.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            with pytest.raises(LockServerError):
                delegate.anchor_vault("aa" * 32)

    def test_stats_payload_without_next_vault_number_falls_back_to_total(
            self, tmp_path):
        cfg = LockServerConfig(
            base_url="https://lock.example.invalid",
            request_timeout=1.0,
        )
        delegate = HTTPDelegateSequenceState(
            cache_db_path=tmp_path / "x.db",
            lock_server=cfg,
            stats_cache_ttl=0.0,
        )
        payload = {"success": True, "data": {"total_vaults": 41}}
        raw = json.dumps(payload).encode("utf-8")

        class _Ctx:
            def __enter__(self_inner):
                return io.BytesIO(raw)
            def __exit__(self_inner, *exc):
                return False

        with patch(
            "eopx.server.http_delegate.urllib.request.urlopen",
            return_value=_Ctx(),
        ):
            r = delegate.anchor_vault("aa" * 32)
        assert r.sequence == 42  # total_vaults(41) + 1

    def test_stats_payload_garbage_raises(self, tmp_path):
        delegate = self._build(tmp_path)
        raw = b"not json at all"

        class _Ctx:
            def __enter__(self_inner):
                return io.BytesIO(raw)
            def __exit__(self_inner, *exc):
                return False

        with patch(
            "eopx.server.http_delegate.urllib.request.urlopen",
            return_value=_Ctx(),
        ):
            with pytest.raises(LockServerError):
                delegate.anchor_vault("aa" * 32)

    def test_hmac_sign_uses_canonical_json(self, tmp_path):
        cfg = LockServerConfig(
            base_url="https://lock.example.invalid",
            api_secret="0123456789abcdef" * 4,
            request_timeout=1.0,
        )
        delegate = HTTPDelegateSequenceState(
            cache_db_path=tmp_path / "x.db",
            lock_server=cfg,
        )
        sig1, ts1, n1 = delegate._sign({"b": 2, "a": 1})
        sig2, ts2, n2 = delegate._sign({"a": 1, "b": 2})
        # Signature is 64-hex (sha256), nonce is 32-hex (16 bytes).
        assert len(sig1) == 64 and len(sig2) == 64
        assert len(n1) == 32 and len(n2) == 32
        # Per-request nonce makes signatures unique even with identical
        # payloads and timestamps (replay protection).
        assert sig1 != sig2 or n1 != n2

    def test_hmac_sign_binds_timestamp_and_nonce(self, tmp_path):
        cfg = LockServerConfig(
            base_url="https://lock.example.invalid",
            api_secret="topsecret",
            request_timeout=1.0,
        )
        delegate = HTTPDelegateSequenceState(
            cache_db_path=tmp_path / "x.db",
            lock_server=cfg,
        )
        sig, ts, nonce = delegate._sign({"x": 1})
        # Manually recompute with the canonical form and verify it matches.
        canonical = f"{ts}\n{nonce}\n" + '{"x": 1}'
        expected = hmac.new(
            b"topsecret",
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        assert sig == expected
        # A different timestamp must yield a different signature.
        other = f"{int(ts) + 1}\n{nonce}\n" + '{"x": 1}'
        other_sig = hmac.new(
            b"topsecret",
            other.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        assert sig != other_sig

    def test_hmac_sign_without_secret_raises(self, tmp_path):
        delegate = self._build(tmp_path)
        with pytest.raises(LockServerError):
            delegate._sign({"a": 1})

    def test_delegate_implements_full_sequence_state_surface(self, tmp_path):
        delegate = self._build(tmp_path)
        # Seed via the wrapped sqlite cache.
        delegate.seed_initial([(1, "01" * 32, None), (2, "02" * 32, None)])
        assert delegate.total() == 2
        assert delegate.max_sequence() == 2
        assert delegate.lookup("01" * 32).sequence == 1
        assert delegate.lookup_by_sequence(2).vault_fp_hex == "02" * 32

    def test_delegate_persists_across_reopen(self, tmp_path):
        cfg = LockServerConfig(
            base_url="https://lock.example.invalid", request_timeout=1.0)
        d1 = HTTPDelegateSequenceState(
            cache_db_path=tmp_path / "d.db", lock_server=cfg)
        d1.anchor_vault("aa" * 32, sequence_hint=10)
        d2 = HTTPDelegateSequenceState(
            cache_db_path=tmp_path / "d.db", lock_server=cfg)
        assert d2.lookup("aa" * 32).sequence == 10

    def test_health_check_success(self, tmp_path):
        delegate = self._build(tmp_path)
        payload = {"status": "ok", "timestamp": "2026-05-28T12:00:00Z"}
        raw = json.dumps(payload).encode("utf-8")

        class _Ctx:
            def __enter__(self_inner):
                return io.BytesIO(raw)
            def __exit__(self_inner, *exc):
                return False

        with patch(
            "eopx.server.http_delegate.urllib.request.urlopen",
            return_value=_Ctx(),
        ):
            h = delegate.health_check()
        assert h.reachable is True
        assert h.latency_ms >= 0
        assert h.server_time == "2026-05-28T12:00:00Z"
        assert h.error is None

    def test_health_check_failure(self, tmp_path):
        import urllib.error
        delegate = self._build(tmp_path)
        with patch(
            "eopx.server.http_delegate.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            h = delegate.health_check()
        assert h.reachable is False
        assert "connection refused" in (h.error or "").lower()

    def test_verify_vault_binding_success(self, tmp_path):
        cfg = LockServerConfig(
            base_url="https://lock.example.invalid",
            api_secret="secret123",
            request_timeout=1.0,
            max_retries=1,
        )
        delegate = HTTPDelegateSequenceState(
            cache_db_path=tmp_path / "d.db",
            lock_server=cfg,
        )
        payload = {
            "success": True,
            "data": {
                "verified": True,
                "vault_number": 42,
                "machine_fp_hex": "bb" * 32,
            },
        }
        raw = json.dumps(payload).encode("utf-8")

        class _Ctx:
            def __enter__(self_inner):
                return io.BytesIO(raw)
            def __exit__(self_inner, *exc):
                return False

        with patch(
            "eopx.server.http_delegate.urllib.request.urlopen",
            return_value=_Ctx(),
        ):
            r = delegate.verify_vault_binding("aa" * 32, "bb" * 32)
        assert r.verified is True
        assert r.vault_number == 42

    def test_verify_vault_binding_no_secret(self, tmp_path):
        delegate = self._build(tmp_path)  # no api_secret
        r = delegate.verify_vault_binding("aa" * 32, "bb" * 32)
        assert r.verified is False
        assert "api_secret" in (r.error or "").lower()

    def test_get_ecosystem_stats(self, tmp_path):
        delegate = self._build(tmp_path)
        with patch(
            "eopx.server.http_delegate.urllib.request.urlopen",
            return_value=_mock_lock_response(100),
        ):
            stats = delegate.get_ecosystem_stats()
        assert stats["next_vault_number"] == 100
        assert stats["total_vaults"] == 99

    def test_retry_with_backoff(self, tmp_path):
        import urllib.error
        cfg = LockServerConfig(
            base_url="https://lock.example.invalid",
            request_timeout=0.1,
            max_retries=3,
            backoff_base=0.01,
            backoff_max=0.05,
        )
        delegate = HTTPDelegateSequenceState(
            cache_db_path=tmp_path / "d.db",
            lock_server=cfg,
            stats_cache_ttl=0.0,
        )
        call_count = [0]

        def _fail_then_succeed(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 3:
                raise urllib.error.URLError("temporary failure")
            return _mock_lock_response(55)

        with patch(
            "eopx.server.http_delegate.urllib.request.urlopen",
            side_effect=_fail_then_succeed,
        ):
            r = delegate.anchor_vault("cc" * 32)
        assert r.sequence == 55
        assert call_count[0] == 3  # 2 failures + 1 success

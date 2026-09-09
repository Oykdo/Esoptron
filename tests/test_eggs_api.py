"""Golden-egg attribution API.

The draw route is asserted against the OFFLINE computation, not against a
frozen fixture: the server adds convenience, never authority, so the only
meaningful assertion is that it agrees with what a client computes alone.

The grants route serves what cannot be recomputed, so the test verifies the
served payload's signature end to end rather than its shape.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from flask import Flask

from eopx.format.keys import EopxKey
from eopx import egg_token as E
from eopx import egg_grant as G
from eopx.genesis_token import resolve_btc_block
from eopx.server.eggs_api import create_eggs_api

VAULT_FP = hashlib.sha3_256(b"eggs-api-vault").digest()
OTHER_FP = hashlib.sha3_256(b"eggs-api-vault-2").digest()


@pytest.fixture
def client():
    app = Flask("test_eggs_api")
    app.register_blueprint(create_eggs_api())
    app.testing = True
    return app.test_client()


@pytest.fixture
def committed_block():
    block, height, _ = resolve_btc_block()
    return block, height


class TestDrawRoute:
    def test_agrees_with_the_offline_computation(self, client, committed_block):
        block, height = committed_block
        response = client.get(f"/api/v1/eggs/vault/{VAULT_FP.hex()}")
        assert response.status_code == 200

        payload = response.get_json()
        assert payload["egg"] == E.founder_egg(VAULT_FP, block, height).to_dict()
        assert payload["kind"] == "draw"
        assert payload["reproducible_offline"] is True
        assert payload["btc_block_height"] == height

    def test_distinct_vaults_draw_distinct_eggs(self, client):
        a = client.get(f"/api/v1/eggs/vault/{VAULT_FP.hex()}").get_json()
        b = client.get(f"/api/v1/eggs/vault/{OTHER_FP.hex()}").get_json()
        assert a["egg"]["egg_id"] != b["egg"]["egg_id"]

    def test_is_stable_across_calls(self, client):
        first = client.get(f"/api/v1/eggs/vault/{VAULT_FP.hex()}").get_json()
        second = client.get(f"/api/v1/eggs/vault/{VAULT_FP.hex()}").get_json()
        assert first["egg"] == second["egg"]

    @pytest.mark.parametrize("bad", ["nothex", "zz", ""])
    def test_rejects_non_hex(self, client, bad):
        assert client.get(f"/api/v1/eggs/vault/{bad}").status_code in (400, 404)


class TestGrantsRoute:
    def _write_ledger(self, tmp_path: Path, block, height) -> tuple[Path, EopxKey]:
        key = EopxKey.generate()
        eggs = E.derive_eggs(block, height)
        drawn = eggs[E.founder_draw_index(VAULT_FP, block, total=len(eggs))]
        granted = next(e for e in eggs if e.egg_id != drawn.egg_id)

        ledger = G.GrantLedger()
        ledger.append(G.mint_egg_grant(
            egg=granted, vault_fp=VAULT_FP, btc_block_hash=block,
            btc_block_height=height, eggs=eggs, deployment_key=key,
            kind=G.KIND_ISSUER, reason="Test grant",
            prev_link_hex=ledger.head,
        ))
        path = tmp_path / "ledger.json"
        path.write_text(ledger.to_json(), encoding="utf-8")
        return path, key

    def test_absent_ledger_is_empty_not_an_error(self, client, monkeypatch,
                                                 tmp_path):
        monkeypatch.setenv("ESOPTRON_GRANTS_LEDGER", str(tmp_path / "none.json"))
        response = client.get(f"/api/v1/eggs/grants/{VAULT_FP.hex()}")
        assert response.status_code == 200
        assert response.get_json()["grants"] == []

    def test_served_grant_verifies_against_the_issuer_key(
            self, client, monkeypatch, tmp_path, committed_block):
        block, height = committed_block
        path, key = self._write_ledger(tmp_path, block, height)
        monkeypatch.setenv("ESOPTRON_GRANTS_LEDGER", str(path))

        payload = client.get(f"/api/v1/eggs/grants/{VAULT_FP.hex()}").get_json()
        assert len(payload["grants"]) == 1

        grant = G.EggGrant.from_dict(payload["grants"][0])
        assert G.verify_egg_grant(
            grant, deployment_pk=key.dilithium_pk,
            eggs=E.derive_eggs(block, height), btc_block_hash=block,
        )
        assert grant.diverges_from_draw
        assert grant.drawn_egg_id != grant.egg_id

    def test_a_vault_never_sees_another_s_grant(self, client, monkeypatch,
                                                tmp_path, committed_block):
        block, height = committed_block
        path, _ = self._write_ledger(tmp_path, block, height)
        monkeypatch.setenv("ESOPTRON_GRANTS_LEDGER", str(path))

        payload = client.get(f"/api/v1/eggs/grants/{OTHER_FP.hex()}").get_json()
        assert payload["grants"] == []
        assert payload["ledger_head"] is not None

    def test_rejects_non_hex(self, client):
        assert client.get("/api/v1/eggs/grants/zz").status_code == 400


class TestHealth:
    def test_reports_block_and_ledger_presence(self, client, monkeypatch,
                                               tmp_path):
        monkeypatch.setenv("ESOPTRON_GRANTS_LEDGER", str(tmp_path / "none.json"))
        payload = client.get("/api/v1/eggs/health").get_json()
        assert payload["status"] == "ok"
        assert payload["ledger_present"] is False
        assert isinstance(payload["btc_block_height"], int)

"""EPX-K capability endpoints + the 'office follows the relic' invariant.

End-to-end against the real EPX-T anchor blueprint: mint a relic, prove the
office under its controller, transfer the relic, and confirm the power moves
with it (and only with it). Needs the native crypto; skipped without it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flask import Flask

pytest.importorskip("pqcrypto")

from eopx.capabilities import CAPABILITY_BY_ID, sign_office  # noqa: E402
from eopx.collection import CODEX_BY_KEY  # noqa: E402
from eopx.format.keys import EopxKey  # noqa: E402
from eopx.server.artifact_api import create_artifact_api  # noqa: E402
from eopx.server.artifact_ledger import ArtifactLedger  # noqa: E402

CAP = "EPX-K:audit"
BASE = "/api/v1/artifact"


@pytest.fixture
def client(tmp_path: Path):
    ledger = ArtifactLedger(tmp_path / "artifacts.db")
    anchor = EopxKey.generate()
    app = Flask("test_caps")
    app.register_blueprint(create_artifact_api(ledger, anchor))
    return app.test_client(), ledger


def _relic_artifact_id() -> str:
    return CODEX_BY_KEY[CAPABILITY_BY_ID[CAP].relic_key].artifact_id().hex()


def test_list_offices_before_any_mint(client):
    c, _ = client
    body = c.get(f"{BASE}/capability").get_json()
    assert len(body["capabilities"]) == 12
    assert len(body["commitment_hex"]) == 64
    assert all(not cap["instated"] for cap in body["capabilities"])


def test_verify_is_404_when_office_not_instated(client):
    c, _ = client
    holder = EopxKey.generate()
    proof = sign_office(holder, CAP, "publish", nonce_hex="00", ts="t0")
    r = c.post(f"{BASE}/capability/verify", json=proof.to_dict())
    assert r.status_code == 404
    assert r.get_json()["ok"] is False


def test_office_follows_the_relic(client):
    c, ledger = client
    aid = _relic_artifact_id()
    holder = EopxKey.generate()
    successor = EopxKey.generate()

    # Mint the relic to the first holder → office instated.
    ledger.mint(artifact_id=aid, controller_pub=holder.dilithium_pk.hex(),
                content_commit="", issuer_fp="22" * 32, ts="t0")

    proof = sign_office(holder, CAP, "publish-audit", nonce_hex="ab", ts="t1")
    r = c.post(f"{BASE}/capability/verify", json=proof.to_dict())
    assert r.status_code == 200 and r.get_json()["ok"] is True
    assert r.get_json()["controller_pub_hex"] == holder.dilithium_pk.hex()

    # Transfer the relic → the office must move to the successor.
    ledger.transfer(artifact_id=aid, from_seq=0,
                    new_controller_pub=successor.dilithium_pk.hex(), ts="t2")

    # The former holder's proof no longer verifies (401)…
    stale = sign_office(holder, CAP, "publish-audit", nonce_hex="cd", ts="t3")
    r = c.post(f"{BASE}/capability/verify", json=stale.to_dict())
    assert r.status_code == 401 and r.get_json()["ok"] is False

    # …and the successor's does.
    fresh = sign_office(successor, CAP, "publish-audit", nonce_hex="ef", ts="t4")
    r = c.post(f"{BASE}/capability/verify", json=fresh.to_dict())
    assert r.status_code == 200 and r.get_json()["ok"] is True

    # GET reflects the new holder.
    state = c.get(f"{BASE}/capability/{CAP}").get_json()
    assert state["instated"] is True
    assert state["controller_pub_hex"] == successor.dilithium_pk.hex()


def test_unknown_capability_is_404(client):
    c, _ = client
    assert c.get(f"{BASE}/capability/EPX-K:phantom").status_code == 404

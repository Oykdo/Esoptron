"""EIDOLON economy on the anchor — balance ledger, payment authorization,
and atomic priced (vault-to-vault) titled transfers.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flask import Flask

from eopx.format.keys import EopxKey
from eopx.server.artifact_api import create_artifact_api
from eopx.server.artifact_ledger import (
    ArtifactLedger,
    InsufficientFunds,
    StaleSequence,
)
from eopx.server.eidolon_ledger import EidolonLedger
from eopx.transfer import (
    build_handoff,
    build_transfer,
    generate_controller,
    mint_artifact,
    sign_payment,
    verify_payment,
)

A = "aa" * 16
B = "bb" * 16
C = "cc" * 16
TREAS = "ee" * 16


# ---------------------------------------------------------------------------
# EidolonLedger
# ---------------------------------------------------------------------------

class TestEidolonLedger:
    @pytest.fixture
    def ledger(self, tmp_path: Path) -> EidolonLedger:
        return EidolonLedger(tmp_path / "anchor.db")

    def test_balance_defaults_to_zero(self, ledger):
        assert ledger.balance(A) == 0

    def test_credit_and_balance(self, ledger):
        assert ledger.credit(A, 100, ts="t") == 100
        assert ledger.balance(A) == 100

    def test_transfer_moves_funds(self, ledger):
        ledger.credit(A, 100, ts="t")
        pa, pb = ledger.transfer(A, B, 30, ts="t")
        assert (pa, pb) == (70, 30)
        assert ledger.balance(A) == 70 and ledger.balance(B) == 30

    def test_transfer_insufficient_funds_is_atomic(self, ledger):
        ledger.credit(A, 10, ts="t")
        with pytest.raises(InsufficientFunds):
            ledger.transfer(A, B, 50, ts="t")
        # Nothing moved.
        assert ledger.balance(A) == 10 and ledger.balance(B) == 0

    def test_grant_genesis_is_idempotent(self, ledger):
        assert ledger.grant_genesis(A, 500, ts="t") == 500
        assert ledger.grant_genesis(A, 500, ts="t") == 500  # no double-mint
        assert ledger.balance(A) == 500

    def test_history_records_movements(self, ledger):
        ledger.credit(A, 100, ts="t")
        ledger.transfer(A, B, 40, ts="t")
        deltas = [e.delta for e in ledger.history(A)]
        assert deltas == [100, -40]


# ---------------------------------------------------------------------------
# Payment authorization
# ---------------------------------------------------------------------------

class TestPaymentAuthorization:
    def test_sign_verify_round_trip(self):
        bob = generate_controller()
        aid = b"\x01" * 16
        terms = sign_payment(bob, aid, 0, 250, payer_account=B, payee_account=A)
        assert verify_payment(terms, aid, bob.dilithium_pk)

    def test_rejected_under_wrong_controller(self):
        bob = generate_controller()
        mallory = generate_controller()
        aid = b"\x01" * 16
        terms = sign_payment(bob, aid, 0, 250, payer_account=B, payee_account=A)
        assert not verify_payment(terms, aid, mallory.dilithium_pk)

    def test_tampered_price_fails(self):
        bob = generate_controller()
        aid = b"\x01" * 16
        terms = sign_payment(bob, aid, 0, 250, payer_account=B, payee_account=A)
        terms.price = 1  # tamper after signing
        assert not verify_payment(terms, aid, bob.dilithium_pk)


# ---------------------------------------------------------------------------
# Atomic priced transfer (ledger level)
# ---------------------------------------------------------------------------

class TestPricedTransferLedger:
    @pytest.fixture
    def setup(self, tmp_path: Path):
        db = tmp_path / "anchor.db"
        ledger = ArtifactLedger(db)
        econ = EidolonLedger(db)
        issuer = EopxKey.generate()
        alice = generate_controller()
        artifact, _ = mint_artifact(issuer, "relic", alice.public_only())
        ledger.mint(
            artifact_id=artifact.artifact_id.hex(),
            controller_pub=alice.dilithium_pk.hex(),
            content_commit="", issuer_fp=artifact.issuer_vault_fp.hex(),
            ts="t0",
        )
        return ledger, econ, artifact, alice

    def test_priced_sale_moves_balances_and_title(self, setup):
        ledger, econ, artifact, _alice = setup
        bob = generate_controller()
        econ.grant_genesis(B, 1000, ts="t0")
        entry = ledger.priced_transfer(
            artifact_id=artifact.artifact_id.hex(), from_seq=0,
            new_controller_pub=bob.dilithium_pk.hex(), ts="t1",
            payer_account=B, payee_account=A, price=300, fee=10,
            treasury_account=TREAS,
        )
        assert entry.seq == 1
        assert entry.controller_pub == bob.dilithium_pk.hex()
        assert econ.balance(B) == 690
        assert econ.balance(A) == 300
        assert econ.balance(TREAS) == 10

    def test_insufficient_funds_aborts_everything(self, setup):
        ledger, econ, artifact, _alice = setup
        bob = generate_controller()
        econ.grant_genesis(B, 100, ts="t0")
        with pytest.raises(InsufficientFunds):
            ledger.priced_transfer(
                artifact_id=artifact.artifact_id.hex(), from_seq=0,
                new_controller_pub=bob.dilithium_pk.hex(), ts="t1",
                payer_account=B, payee_account=A, price=300,
            )
        # No debit, no re-key.
        assert econ.balance(B) == 100 and econ.balance(A) == 0
        assert ledger.get(artifact.artifact_id.hex()).seq == 0

    def test_stale_seq_does_not_charge(self, setup):
        ledger, econ, artifact, _alice = setup
        bob = generate_controller()
        econ.grant_genesis(B, 1000, ts="t0")
        with pytest.raises(StaleSequence):
            ledger.priced_transfer(
                artifact_id=artifact.artifact_id.hex(), from_seq=5,  # wrong
                new_controller_pub=bob.dilithium_pk.hex(), ts="t1",
                payer_account=B, payee_account=A, price=300,
            )
        assert econ.balance(B) == 1000  # buyer untouched
        assert ledger.get(artifact.artifact_id.hex()).seq == 0


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------

class TestPricedTransferAPI:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        ledger = ArtifactLedger(tmp_path / "anchor.db")
        anchor = EopxKey.generate()
        app = Flask("test_market")
        app.register_blueprint(
            create_artifact_api(ledger, anchor, allow_grants=True))
        app.testing = True
        client = app.test_client()
        issuer = EopxKey.generate()
        alice = generate_controller()
        artifact, _ = mint_artifact(issuer, "relic", alice.public_only())
        client.post("/api/v1/artifact/mint", json=artifact.to_dict())
        return client, artifact, alice

    def test_grant_and_balance(self, ctx):
        client, _artifact, _alice = ctx
        r = client.post(f"/api/v1/artifact/account/{B}/grant",
                        json={"amount": 1000})
        assert r.status_code == 200 and r.get_json()["balance"] == 1000
        assert client.get(
            f"/api/v1/artifact/account/{B}").get_json()["balance"] == 1000

    def test_priced_transfer_happy_path(self, ctx):
        client, artifact, alice = ctx
        aid = artifact.artifact_id
        bob = generate_controller()
        client.post(f"/api/v1/artifact/account/{B}/grant", json={"amount": 1000})
        xfer, _ = build_transfer(alice, 0, build_handoff(bob, aid))
        terms = sign_payment(bob, aid, 0, 300, payer_account=B, payee_account=A)
        r = client.post("/api/v1/artifact/transfer", json={
            **xfer.to_dict(),
            "payment": {"terms": terms.to_dict(), "fee": 10,
                        "treasury_account": TREAS},
        })
        assert r.status_code == 200, r.get_json()
        body = r.get_json()
        assert body["seq"] == 1
        assert body["payment"]["payer_balance"] == 690
        assert body["payment"]["payee_balance"] == 300

    def test_priced_transfer_insufficient_funds_402(self, ctx):
        client, artifact, alice = ctx
        aid = artifact.artifact_id
        bob = generate_controller()  # B has no balance
        xfer, _ = build_transfer(alice, 0, build_handoff(bob, aid))
        terms = sign_payment(bob, aid, 0, 300, payer_account=B, payee_account=A)
        r = client.post("/api/v1/artifact/transfer", json={
            **xfer.to_dict(), "payment": {"terms": terms.to_dict()},
        })
        assert r.status_code == 402
        assert r.get_json()["error"] == "INSUFFICIENT_FUNDS"
        # Title did not move.
        assert client.get(
            f"/api/v1/artifact/{aid.hex()}").get_json()["seq"] == 0

    def test_priced_transfer_bad_authorization_400(self, ctx):
        client, artifact, alice = ctx
        aid = artifact.artifact_id
        bob = generate_controller()
        client.post(f"/api/v1/artifact/account/{B}/grant", json={"amount": 1000})
        xfer, _ = build_transfer(alice, 0, build_handoff(bob, aid))
        # Authorization signed by the WRONG key (not the new controller).
        terms = sign_payment(alice, aid, 0, 300, payer_account=B, payee_account=A)
        r = client.post("/api/v1/artifact/transfer", json={
            **xfer.to_dict(), "payment": {"terms": terms.to_dict()},
        })
        assert r.status_code == 400

    def test_priced_transfer_seq_mismatch_400(self, ctx):
        client, artifact, alice = ctx
        aid = artifact.artifact_id
        bob = generate_controller()
        client.post(f"/api/v1/artifact/account/{B}/grant", json={"amount": 1000})
        xfer, _ = build_transfer(alice, 0, build_handoff(bob, aid))
        # Payment authorizes a different from_seq than the transfer.
        terms = sign_payment(bob, aid, 9, 300, payer_account=B, payee_account=A)
        r = client.post("/api/v1/artifact/transfer", json={
            **xfer.to_dict(), "payment": {"terms": terms.to_dict()},
        })
        assert r.status_code == 400

    def test_grants_disabled_by_default(self, tmp_path):
        ledger = ArtifactLedger(tmp_path / "x.db")
        app = Flask("nogrants")
        app.register_blueprint(create_artifact_api(ledger, EopxKey.generate()))
        app.testing = True
        r = app.test_client().post(
            f"/api/v1/artifact/account/{B}/grant", json={"amount": 5})
        assert r.status_code == 403

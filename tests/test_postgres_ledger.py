"""Integration tests for the PostgreSQL anchor backend.

These run **only** when ``ESOPTRON_TEST_PG_DSN`` points at a reachable test
database (and ``psycopg`` is installed); otherwise the whole module is
skipped. This is the harness to validate the "go online" backend before
production:

    createdb esoptron_anchor_test
    ESOPTRON_TEST_PG_DSN="postgresql://user:pass@localhost/esoptron_anchor_test" \
        python -m pytest tests/test_postgres_ledger.py -v

Each test uses a unique ``artifact_id`` so a shared test DB does not need
truncation between runs.
"""

from __future__ import annotations

import os
import secrets

import pytest

DSN = os.environ.get("ESOPTRON_TEST_PG_DSN", "").strip()

pytestmark = pytest.mark.skipif(
    not DSN, reason="set ESOPTRON_TEST_PG_DSN to run Postgres integration tests"
)

# Skip cleanly if psycopg is absent even when a DSN is set.
psycopg = pytest.importorskip("psycopg") if DSN else None

if DSN:
    from eopx.server.artifact_ledger import (
        AlreadyClaimed,
        ArtifactExists,
        InsufficientFunds,
        NotClaimable,
        StaleSequence,
    )
    from eopx.server.postgres_ledger import PostgresArtifactLedger
    from eopx.transfer import claim_commitment


@pytest.fixture(scope="module")
def ledger():
    return PostgresArtifactLedger(DSN)


def _aid() -> str:
    return secrets.token_bytes(16).hex()


def test_mint_and_get(ledger):
    aid = _aid()
    ledger.mint(artifact_id=aid, controller_pub="11" * 100,
                content_commit="", issuer_fp="22" * 32, ts="t0")
    e = ledger.get(aid)
    assert e is not None and e.seq == 0
    assert e.controller_pub == "11" * 100


def test_duplicate_mint_rejected(ledger):
    aid = _aid()
    ledger.mint(artifact_id=aid, controller_pub="11" * 100,
                content_commit="", issuer_fp="22" * 32, ts="t0")
    with pytest.raises(ArtifactExists):
        ledger.mint(artifact_id=aid, controller_pub="11" * 100,
                    content_commit="", issuer_fp="22" * 32, ts="t0")


def test_transfer_cas_and_stale(ledger):
    aid = _aid()
    ledger.mint(artifact_id=aid, controller_pub="11" * 100,
                content_commit="", issuer_fp="22" * 32, ts="t0")
    e = ledger.transfer(artifact_id=aid, from_seq=0,
                        new_controller_pub="33" * 100, ts="t1")
    assert e.seq == 1
    with pytest.raises(StaleSequence):
        ledger.transfer(artifact_id=aid, from_seq=0,
                        new_controller_pub="44" * 100, ts="t2")


def test_priced_transfer_atomic(ledger):
    aid = _aid()
    payer = _aid()
    payee = _aid()
    ledger.mint(artifact_id=aid, controller_pub="11" * 100,
                content_commit="", issuer_fp="22" * 32, ts="t0")
    ledger.grant_genesis(payer, 1000, ts="t0")
    e = ledger.priced_transfer(
        artifact_id=aid, from_seq=0, new_controller_pub="33" * 100, ts="t1",
        payer_account=payer, payee_account=payee, price=300, fee=0)
    assert e.seq == 1
    assert ledger.account_balance(payer) == 700
    assert ledger.account_balance(payee) == 300


def test_priced_transfer_insufficient_funds(ledger):
    aid = _aid()
    payer = _aid()
    ledger.mint(artifact_id=aid, controller_pub="11" * 100,
                content_commit="", issuer_fp="22" * 32, ts="t0")
    with pytest.raises(InsufficientFunds):
        ledger.priced_transfer(
            artifact_id=aid, from_seq=0, new_controller_pub="33" * 100, ts="t1",
            payer_account=payer, payee_account=_aid(), price=999)
    # No re-key on failure.
    assert ledger.get(aid).seq == 0


def test_grant_idempotent(ledger):
    acct = _aid()
    assert ledger.grant_genesis(acct, 500, ts="t0") == 500
    assert ledger.grant_genesis(acct, 500, ts="t0") == 500  # no double-credit


def test_claim_huntable(ledger):
    aid_b = secrets.token_bytes(16)
    aid = aid_b.hex()
    secret = secrets.token_bytes(32)
    ledger.mint(artifact_id=aid, controller_pub="", content_commit="",
                issuer_fp="22" * 32, ts="t0",
                claim_commitment=claim_commitment(aid_b, secret).hex())
    assert ledger.get(aid).is_claimable
    e = ledger.claim(artifact_id=aid, new_controller_pub="ab" * 100,
                     expected_commitment=claim_commitment(aid_b, secret).hex(),
                     ts="t1")
    assert e.seq == 1 and e.controller_pub == "ab" * 100
    # Re-claim now refused (commitment cleared).
    with pytest.raises((AlreadyClaimed, NotClaimable)):
        ledger.claim(artifact_id=aid, new_controller_pub="cd" * 100,
                     expected_commitment=claim_commitment(aid_b, secret).hex(),
                     ts="t2")


def test_history_chain(ledger):
    aid = _aid()
    ledger.mint(artifact_id=aid, controller_pub="11" * 100,
                content_commit="", issuer_fp="22" * 32, ts="t0", receipt="r0")
    ledger.transfer(artifact_id=aid, from_seq=0,
                    new_controller_pub="33" * 100, ts="t1", receipt="r1")
    hist = ledger.history(aid)
    assert [h.seq for h in hist] == [0, 1]

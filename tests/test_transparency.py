"""Transparency-log audit (EPX-T §10): receipt-chain verification and
equivocation/fork detection.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
from flask import Flask

from eopx.format.keys import EopxKey
from eopx.server.artifact_api import create_artifact_api
from eopx.server.artifact_ledger import ArtifactLedger
from eopx.transfer import (
    build_handoff,
    build_transfer,
    detect_equivocation,
    generate_controller,
    mint_artifact,
    verify_receipt_chain,
)


@pytest.fixture
def chain(tmp_path: Path):
    """A live anchor with one relic transferred alice→bob→carol→dave."""
    ledger = ArtifactLedger(tmp_path / "anchor.db")
    anchor = EopxKey.generate()
    app = Flask("test_transparency")
    app.register_blueprint(create_artifact_api(ledger, anchor))
    app.testing = True
    client = app.test_client()

    issuer = EopxKey.generate()
    alice = generate_controller()
    artifact, _ = mint_artifact(issuer, "relic", alice.public_only())
    aid = artifact.artifact_id
    client.post("/api/v1/artifact/mint", json=artifact.to_dict())

    holders = [alice, generate_controller(), generate_controller(),
               generate_controller()]
    for seq in range(3):
        cur, nxt = holders[seq], holders[seq + 1]
        x, _ = build_transfer(cur, seq, build_handoff(nxt, aid))
        client.post("/api/v1/artifact/transfer", json=x.to_dict())

    history = client.get(f"/api/v1/artifact/{aid.hex()}/history").get_json()
    return anchor, aid, history


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------

class TestVerifyChain:
    def test_valid_chain_audits(self, chain):
        anchor, aid, history = chain
        chk = verify_receipt_chain(
            history, expected_anchor_pub=anchor.dilithium_pk, artifact_id=aid)
        assert chk.ok
        assert chk.length == 4
        assert chk.head_seq == 3
        assert [s for s, _ in chk.chain] == [0, 1, 2, 3]

    def test_wrong_pinned_anchor_rejected(self, chain):
        _anchor, aid, history = chain
        other = EopxKey.generate()
        chk = verify_receipt_chain(
            history, expected_anchor_pub=other.dilithium_pk, artifact_id=aid)
        assert not chk.ok

    def test_tampered_receipt_rejected(self, chain):
        anchor, aid, history = chain
        bad = copy.deepcopy(history)
        bad["history"][1]["receipt"]["controller_pub_hex"] = \
            EopxKey.generate().dilithium_pk.hex()
        chk = verify_receipt_chain(
            bad, expected_anchor_pub=anchor.dilithium_pk, artifact_id=aid)
        assert not chk.ok
        assert any("signature invalid" in i for i in chk.issues)

    def test_seq_gap_rejected(self, chain):
        anchor, aid, history = chain
        gapped = copy.deepcopy(history)
        del gapped["history"][2]  # remove seq 2
        chk = verify_receipt_chain(
            gapped, expected_anchor_pub=anchor.dilithium_pk, artifact_id=aid)
        assert not chk.ok
        assert any("non-monotonic" in i for i in chk.issues)

    def test_does_not_start_at_zero_rejected(self, chain):
        anchor, aid, history = chain
        sliced = copy.deepcopy(history)
        sliced["history"] = sliced["history"][1:]  # starts at seq 1
        chk = verify_receipt_chain(
            sliced, expected_anchor_pub=anchor.dilithium_pk, artifact_id=aid)
        assert not chk.ok

    def test_wrong_artifact_id_flagged(self, chain):
        anchor, _aid, history = chain
        chk = verify_receipt_chain(
            history, expected_anchor_pub=anchor.dilithium_pk,
            artifact_id=b"\x00" * 16)
        assert not chk.ok

    def test_empty_history_rejected(self, chain):
        anchor, aid, _history = chain
        chk = verify_receipt_chain(
            {"history": []}, expected_anchor_pub=anchor.dilithium_pk,
            artifact_id=aid)
        assert not chk.ok


# ---------------------------------------------------------------------------
# Equivocation detection across snapshots
# ---------------------------------------------------------------------------

class TestEquivocation:
    def test_append_only_extension_is_consistent(self, chain):
        anchor, aid, history = chain
        chk = verify_receipt_chain(
            history, expected_anchor_pub=anchor.dilithium_pk, artifact_id=aid)
        # An earlier prefix extends to the full chain with no conflict.
        assert detect_equivocation(chk.chain[:2], chk.chain) is None

    def test_rewritten_controller_is_a_fork(self, chain):
        anchor, aid, history = chain
        chk = verify_receipt_chain(
            history, expected_anchor_pub=anchor.dilithium_pk, artifact_id=aid)
        forked = list(chk.chain)
        forked[1] = (1, EopxKey.generate().dilithium_pk.hex())
        ev = detect_equivocation(chk.chain, forked)
        assert ev is not None and ev[0] == 1

    def test_truncation_is_a_fork(self, chain):
        anchor, aid, history = chain
        chk = verify_receipt_chain(
            history, expected_anchor_pub=anchor.dilithium_pk, artifact_id=aid)
        truncated = chk.chain[:2]  # rolled back below what we witnessed
        ev = detect_equivocation(chk.chain, truncated)
        assert ev is not None and ev[2] == "<missing>"

    def test_priced_history_audits(self, tmp_path):
        # A priced sale records a receipt too; the chain must still audit.
        ledger = ArtifactLedger(tmp_path / "m.db")
        anchor = EopxKey.generate()
        app = Flask("t")
        app.register_blueprint(
            create_artifact_api(ledger, anchor, allow_grants=True))
        app.testing = True
        client = app.test_client()
        issuer = EopxKey.generate()
        alice = generate_controller()
        artifact, _ = mint_artifact(issuer, "relic", alice.public_only())
        aid = artifact.artifact_id
        client.post("/api/v1/artifact/mint", json=artifact.to_dict())
        client.post("/api/v1/artifact/account/bb/grant", json={"amount": 1000})
        from eopx.transfer import sign_payment
        bob = generate_controller()
        x, _ = build_transfer(alice, 0, build_handoff(bob, aid))
        terms = sign_payment(bob, aid, 0, 300, payer_account="bb",
                             payee_account="aa")
        client.post("/api/v1/artifact/transfer", json={
            **x.to_dict(), "payment": {"terms": terms.to_dict()}})
        history = client.get(
            f"/api/v1/artifact/{aid.hex()}/history").get_json()
        chk = verify_receipt_chain(
            history, expected_anchor_pub=anchor.dilithium_pk, artifact_id=aid)
        assert chk.ok and chk.head_seq == 1

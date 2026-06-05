"""EPX-T Titled Transfer — protocol invariants (spec §13) + crypto round-trips.

Covers the seven normative invariants of ``docs/specs/EPX-T_titled_transfer.md``
§13, plus the content-sealing envelope, ownership verification, and the
anchor HTTP surface (mint / transfer / query / history).
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from flask import Flask

from eopx.format.keys import EopxKey
from eopx.server.artifact_api import create_artifact_api
from eopx.server.artifact_ledger import (
    ArtifactExists,
    ArtifactLedger,
    ArtifactNotFound,
    StaleSequence,
)
from eopx.transfer import (
    AnchorReceipt,
    LedgerView,
    Transfer,
    build_handoff,
    build_transfer,
    content_commitment,
    generate_controller,
    mint_artifact,
    open_content,
    ownership_challenge,
    prove_ownership,
    reseal_content,
    seal_content,
    sign_receipt,
    verify_against_ledger,
    verify_artifact,
    verify_handoff,
    verify_ownership_proof,
    verify_receipt,
    verify_transfer,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def anchor() -> EopxKey:
    return EopxKey.generate()


@pytest.fixture
def issuer() -> EopxKey:
    return EopxKey.generate()


@pytest.fixture
def ledger(tmp_path: Path) -> ArtifactLedger:
    return ArtifactLedger(tmp_path / "artifacts.db")


@pytest.fixture
def client(ledger: ArtifactLedger, anchor: EopxKey):
    app = Flask("test_artifact_api")
    app.register_blueprint(create_artifact_api(ledger, anchor))
    app.testing = True
    return app.test_client()


def _mint_over_http(client, issuer: EopxKey, *, content: bytes | None = None):
    """Mint an artifact + first controller and anchor it; return parts."""
    alice = generate_controller()
    artifact, sealed = mint_artifact(
        issuer, "token", alice.public_only(), content=content,
    )
    r = client.post("/api/v1/artifact/mint", json=artifact.to_dict())
    assert r.status_code == 200, r.get_json()
    return artifact, alice, sealed, r.get_json()


# ---------------------------------------------------------------------------
# Crypto layer — mint / verify / content sealing
# ---------------------------------------------------------------------------

class TestMintAndContent:
    def test_mint_round_trip_and_authenticity(self, issuer):
        alice = generate_controller()
        artifact, sealed = mint_artifact(
            issuer, "sphere", alice.public_only(), content=b"vault state",
        )
        assert sealed is not None
        assert artifact.type == "sphere"
        assert artifact.has_content
        assert artifact.issuer_vault_fp == issuer.dilithium_pk_fp
        # §13.6 authenticity: issuer_sig verifies, content commit matches.
        assert verify_artifact(artifact, content=b"vault state")
        assert verify_artifact(
            artifact, expected_issuer_fp=issuer.dilithium_pk_fp,
        )

    def test_mint_without_content_has_empty_commit(self, issuer):
        alice = generate_controller()
        artifact, sealed = mint_artifact(issuer, "credential", alice.public_only())
        assert sealed is None
        assert not artifact.has_content
        assert artifact.content_commit == b""
        assert verify_artifact(artifact)

    def test_tampered_type_fails_authenticity(self, issuer):
        alice = generate_controller()
        artifact, _ = mint_artifact(issuer, "token", alice.public_only())
        artifact.type = "sphere"  # tamper after signing
        assert not verify_artifact(artifact)

    def test_wrong_content_fails_commit_check(self, issuer):
        alice = generate_controller()
        artifact, _ = mint_artifact(
            issuer, "token", alice.public_only(), content=b"real",
        )
        assert not verify_artifact(artifact, content=b"fake")

    def test_wrong_issuer_fp_rejected(self, issuer):
        alice = generate_controller()
        artifact, _ = mint_artifact(issuer, "token", alice.public_only())
        assert not verify_artifact(artifact, expected_issuer_fp=b"\x00" * 32)

    def test_seal_open_round_trip(self):
        alice = generate_controller()
        aid = b"\x01" * 16
        sealed = seal_content(b"secret payload", alice.public_only(), aid)
        assert open_content(sealed, alice) == b"secret payload"
        # The bound content commitment matches the plaintext SHA3-512.
        assert content_commitment(b"secret payload") == \
            __import__("hashlib").sha3_512(b"secret payload").digest()

    def test_reseal_delivers_to_new_owner_only(self):
        alice = generate_controller()
        bob = generate_controller()
        aid = b"\x02" * 16
        sealed = seal_content(b"sphere config", alice.public_only(), aid)
        resealed = reseal_content(sealed, alice, bob.kyber_pk)
        # Bob can open the re-sealed copy.
        assert open_content(resealed, bob) == b"sphere config"
        # The bulk ciphertext is unchanged across the re-key.
        assert resealed.content_ciphertext == sealed.content_ciphertext
        # Bob cannot open Alice's original wrap (wrong KEM recipient).
        with pytest.raises(Exception):
            open_content(sealed, bob)


# ---------------------------------------------------------------------------
# Crypto layer — hand-off / transfer signing
# ---------------------------------------------------------------------------

class TestTransferSigning:
    def test_handoff_pop_round_trip(self):
        bob = generate_controller()
        aid = b"\x03" * 16
        h = build_handoff(bob, aid)
        assert verify_handoff(h, aid)

    def test_handoff_pop_rejected_for_wrong_artifact(self):
        bob = generate_controller()
        h = build_handoff(bob, b"\x03" * 16)
        assert not verify_handoff(h, b"\x04" * 16)

    def test_build_transfer_refuses_bad_pop(self):
        alice = generate_controller()
        bob = generate_controller()
        aid = b"\x05" * 16
        h = build_handoff(bob, aid)
        # Corrupt the PoP so the hand-off no longer verifies.
        h.pop = bytes(len(h.pop))
        with pytest.raises(ValueError, match="PoP"):
            build_transfer(alice, 0, h)

    def test_verify_transfer_checks_current_controller(self):
        alice = generate_controller()
        bob = generate_controller()
        carol = generate_controller()
        aid = b"\x06" * 16
        xfer, _ = build_transfer(alice, 0, build_handoff(bob, aid))
        assert verify_transfer(xfer, alice.dilithium_pk)
        # §13.5-flavoured: must fail under a non-current controller.
        assert not verify_transfer(xfer, carol.dilithium_pk)

    def test_pop_invariant_forged_new_controller_rejected(self):
        """§13.5: a transfer whose new_controller lacks a valid PoP fails."""
        alice = generate_controller()
        bob = generate_controller()
        mallory = generate_controller()
        aid = b"\x07" * 16
        xfer, _ = build_transfer(alice, 0, build_handoff(bob, aid))
        # Swap in Mallory's key as the new controller without a matching PoP.
        forged = Transfer.from_dict(xfer.to_dict())
        forged.new_controller = mallory.dilithium_pk
        assert not verify_transfer(forged, alice.dilithium_pk)


# ---------------------------------------------------------------------------
# Ledger — compare-and-swap mechanics (spec §13.1–§13.4)
# ---------------------------------------------------------------------------

class TestLedger:
    def _mint(self, ledger: ArtifactLedger, aid: str = "ab" * 8):
        return ledger.mint(
            artifact_id=aid, controller_pub="11" * 100,
            content_commit="", issuer_fp="22" * 32, ts="t0",
        )

    def test_uniqueness_rejects_duplicate_mint(self, ledger):
        """§13.1: mint rejects a duplicate artifact_id."""
        self._mint(ledger)
        with pytest.raises(ArtifactExists):
            self._mint(ledger)

    def test_monotonicity_increments_by_one(self, ledger):
        """§13.2: seq increases by exactly 1 per accepted transfer."""
        self._mint(ledger)
        e1 = ledger.transfer(
            artifact_id="ab" * 8, from_seq=0,
            new_controller_pub="33" * 100, ts="t1",
        )
        assert e1.seq == 1
        e2 = ledger.transfer(
            artifact_id="ab" * 8, from_seq=1,
            new_controller_pub="44" * 100, ts="t2",
        )
        assert e2.seq == 2

    def test_cas_double_spend_one_winner(self, ledger):
        """§13.3: two transfers from the same seq → one wins, one STALE."""
        self._mint(ledger)
        ledger.transfer(
            artifact_id="ab" * 8, from_seq=0,
            new_controller_pub="33" * 100, ts="t1",
        )
        with pytest.raises(StaleSequence) as exc:
            ledger.transfer(
                artifact_id="ab" * 8, from_seq=0,
                new_controller_pub="44" * 100, ts="t2",
            )
        assert exc.value.expected == 0
        assert exc.value.actual == 1

    def test_transfer_unknown_artifact(self, ledger):
        with pytest.raises(ArtifactNotFound):
            ledger.transfer(
                artifact_id="ff" * 8, from_seq=0,
                new_controller_pub="33" * 100, ts="t",
            )

    def test_history_records_every_state(self, ledger):
        self._mint(ledger)
        ledger.transfer(
            artifact_id="ab" * 8, from_seq=0,
            new_controller_pub="33" * 100, ts="t1",
        )
        hist = ledger.history("ab" * 8)
        assert [h.seq for h in hist] == [0, 1]

    def test_concurrent_transfers_single_success(self, ledger):
        """50 threads transferring from seq=0 → exactly one advances to 1."""
        self._mint(ledger)
        ok = []
        stale = []
        lock = threading.Lock()

        def worker(i: int):
            try:
                ledger.transfer(
                    artifact_id="ab" * 8, from_seq=0,
                    new_controller_pub=f"{i:0200x}", ts=f"t{i}",
                )
                with lock:
                    ok.append(i)
            except StaleSequence:
                with lock:
                    stale.append(i)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(ok) == 1
        assert len(stale) == 49
        assert ledger.get("ab" * 8).seq == 1


# ---------------------------------------------------------------------------
# Anchor receipts (spec §13.7)
# ---------------------------------------------------------------------------

class TestReceipts:
    def test_receipt_verifies_under_anchor_key(self, anchor):
        r = sign_receipt(anchor, b"\x08" * 16, 3, b"\x09" * 64)
        assert verify_receipt(r)
        assert verify_receipt(r, anchor.dilithium_pk)

    def test_receipt_rejected_under_wrong_key(self, anchor):
        other = EopxKey.generate()
        r = sign_receipt(anchor, b"\x08" * 16, 3, b"\x09" * 64)
        assert not verify_receipt(r, other.dilithium_pk)

    def test_receipt_rejected_when_tampered(self, anchor):
        r = sign_receipt(anchor, b"\x08" * 16, 3, b"\x09" * 64)
        tampered = AnchorReceipt.from_dict({**r.to_dict(), "seq": 4})
        assert not verify_receipt(tampered)


# ---------------------------------------------------------------------------
# Ownership verification (spec §5.3)
# ---------------------------------------------------------------------------

class TestOwnership:
    def test_challenge_response_round_trip(self):
        owner = generate_controller()
        aid = b"\x0a" * 16
        nonce = ownership_challenge()
        proof = prove_ownership(owner, aid, nonce)
        assert verify_ownership_proof(aid, nonce, proof, owner.dilithium_pk)

    def test_proof_rejected_under_wrong_controller(self):
        owner = generate_controller()
        other = generate_controller()
        aid = b"\x0a" * 16
        nonce = ownership_challenge()
        proof = prove_ownership(owner, aid, nonce)
        assert not verify_ownership_proof(aid, nonce, proof, other.dilithium_pk)

    def test_verify_against_ledger_full(self, issuer):
        owner = generate_controller()
        artifact, _ = mint_artifact(
            issuer, "token", owner.public_only(), content=b"x",
        )
        view = LedgerView(
            artifact_id=artifact.artifact_id, seq=0,
            controller_pub=owner.dilithium_pk,
            content_commit=artifact.content_commit,
            issuer_fp=artifact.issuer_vault_fp,
        )
        nonce = ownership_challenge()
        proof = prove_ownership(owner, artifact.artifact_id, nonce)
        assert verify_against_ledger(
            artifact, view,
            claimed_owner_proof=proof, challenge_nonce=nonce, content=b"x",
        )

    def test_verify_against_ledger_rejects_mismatched_commit(self, issuer):
        owner = generate_controller()
        artifact, _ = mint_artifact(issuer, "token", owner.public_only())
        view = LedgerView(
            artifact_id=artifact.artifact_id, seq=0,
            controller_pub=owner.dilithium_pk,
            content_commit=b"\xff" * 64,  # wrong
            issuer_fp=artifact.issuer_vault_fp,
        )
        assert not verify_against_ledger(artifact, view)


# ---------------------------------------------------------------------------
# HTTP anchor surface — end-to-end
# ---------------------------------------------------------------------------

class TestArtifactAPI:
    def test_mint_returns_seq_zero_and_valid_receipt(self, client, issuer, anchor):
        artifact, alice, sealed, body = _mint_over_http(
            client, issuer, content=b"100 EIDOLON",
        )
        assert body["seq"] == 0
        receipt = AnchorReceipt.from_dict(body["receipt"])
        assert verify_receipt(receipt, anchor.dilithium_pk)
        assert receipt.controller_pub == alice.dilithium_pk

    def test_mint_rejects_forged_issuer_sig(self, client, issuer):
        alice = generate_controller()
        artifact, _ = mint_artifact(issuer, "token", alice.public_only())
        artifact.issuer_sig = bytes(len(artifact.issuer_sig))
        r = client.post("/api/v1/artifact/mint", json=artifact.to_dict())
        assert r.status_code == 400

    def test_duplicate_mint_returns_409(self, client, issuer):
        artifact, _alice, _sealed, _body = _mint_over_http(client, issuer)
        r = client.post("/api/v1/artifact/mint", json=artifact.to_dict())
        assert r.status_code == 409

    def test_transfer_advances_and_updates_owner(self, client, issuer, anchor):
        artifact, alice, sealed, _ = _mint_over_http(client, issuer, content=b"s")
        bob = generate_controller()
        handoff = build_handoff(bob, artifact.artifact_id)
        xfer, resealed = build_transfer(
            alice, 0, handoff, sealed_content=sealed,
        )
        r = client.post("/api/v1/artifact/transfer", json=xfer.to_dict())
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["seq"] == 1
        # New owner recorded; receipt valid; Bob can open re-sealed content.
        cur = client.get(f"/api/v1/artifact/{artifact.artifact_id.hex()}")
        assert cur.get_json()["controller_pub_hex"] == bob.dilithium_pk.hex()
        assert open_content(resealed, bob) == b"s"

    def test_transfer_unknown_artifact_404(self, client, issuer):
        alice = generate_controller()
        bob = generate_controller()
        aid = b"\xab" * 16
        xfer, _ = build_transfer(alice, 0, build_handoff(bob, aid))
        r = client.post("/api/v1/artifact/transfer", json=xfer.to_dict())
        assert r.status_code == 404

    def test_forward_secrecy_old_owner_cannot_respend(self, client, issuer):
        """§13.4: after A→B anchors, A's key can no longer move the artifact."""
        artifact, alice, _sealed, _ = _mint_over_http(client, issuer)
        bob = generate_controller()
        carol = generate_controller()
        # A → B succeeds.
        xfer_b, _ = build_transfer(alice, 0, build_handoff(bob, artifact.artifact_id))
        assert client.post(
            "/api/v1/artifact/transfer", json=xfer_b.to_dict()
        ).status_code == 200
        # A tries again from the now-stale seq=0 toward Carol → rejected.
        xfer_c, _ = build_transfer(alice, 0, build_handoff(carol, artifact.artifact_id))
        r = client.post("/api/v1/artifact/transfer", json=xfer_c.to_dict())
        assert r.status_code >= 400  # 400 (stale controller) is the live path

    def test_concurrent_transfer_exactly_one_winner(self, client, issuer):
        """§13.3 over HTTP: a true race yields one 200 and one 409."""
        artifact, alice, _sealed, _ = _mint_over_http(client, issuer)
        bob = generate_controller()
        carol = generate_controller()
        xb, _ = build_transfer(alice, 0, build_handoff(bob, artifact.artifact_id))
        xc, _ = build_transfer(alice, 0, build_handoff(carol, artifact.artifact_id))
        codes = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def go(x):
            cl = client.application.test_client()
            barrier.wait()
            r = cl.post("/api/v1/artifact/transfer", json=x.to_dict())
            with lock:
                codes.append(r.status_code)

        threads = [threading.Thread(target=go, args=(x,)) for x in (xb, xc)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert codes.count(200) == 1
        assert any(c >= 400 for c in codes)

    def test_history_chain_and_receipts(self, client, issuer, anchor):
        artifact, alice, sealed, _ = _mint_over_http(client, issuer, content=b"s")
        bob = generate_controller()
        carol = generate_controller()
        xfer_b, resealed = build_transfer(
            alice, 0, build_handoff(bob, artifact.artifact_id),
            sealed_content=sealed,
        )
        client.post("/api/v1/artifact/transfer", json=xfer_b.to_dict())
        xfer_c, _ = build_transfer(
            bob, 1, build_handoff(carol, artifact.artifact_id),
            sealed_content=resealed,
        )
        client.post("/api/v1/artifact/transfer", json=xfer_c.to_dict())

        r = client.get(f"/api/v1/artifact/{artifact.artifact_id.hex()}/history")
        body = r.get_json()
        assert [e["seq"] for e in body["history"]] == [0, 1, 2]
        # §13.7: every recorded state change carries a valid anchor receipt.
        for e in body["history"]:
            receipt = AnchorReceipt.from_dict(e["receipt"])
            assert verify_receipt(receipt, anchor.dilithium_pk)

    def test_get_unknown_artifact_404(self, client):
        r = client.get(f"/api/v1/artifact/{'cd' * 16}")
        assert r.status_code == 404

    def test_health(self, client):
        r = client.get("/api/v1/artifact/health")
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"

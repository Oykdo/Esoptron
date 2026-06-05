"""EPX-V Voucher claim — the treasure-hunt mechanism: claim a huntable relic
by opening its commitment with the secret printed on a scannable A4 sheet.
"""

from __future__ import annotations

import secrets
import threading
from pathlib import Path

import pytest
from flask import Flask

from eopx.format.keys import EopxKey
from eopx.server.artifact_api import create_artifact_api
from eopx.server.artifact_ledger import (
    AlreadyClaimed,
    ArtifactLedger,
    NotClaimable,
)
from eopx.transfer import (
    ClaimProof,
    claim_commitment,
    generate_controller,
    make_claim,
    verify_claim,
)


# ---------------------------------------------------------------------------
# Voucher crypto
# ---------------------------------------------------------------------------

class TestVoucherCrypto:
    def test_commitment_is_deterministic_and_bound(self):
        aid = b"\x01" * 16
        s = secrets.token_bytes(32)
        assert claim_commitment(aid, s) == claim_commitment(aid, s)
        # Bound to the artifact: same secret, different artifact → different commit.
        assert claim_commitment(aid, s) != claim_commitment(b"\x02" * 16, s)

    def test_make_verify_round_trip(self):
        aid = b"\x03" * 16
        s = secrets.token_bytes(32)
        finder = generate_controller()
        proof = make_claim(finder, aid, s)
        assert verify_claim(proof, aid, claim_commitment(aid, s))

    def test_wrong_secret_does_not_open(self):
        aid = b"\x03" * 16
        s = secrets.token_bytes(32)
        proof = make_claim(generate_controller(), aid, secrets.token_bytes(32))
        assert not verify_claim(proof, aid, claim_commitment(aid, s))

    def test_tampered_controller_breaks_binding(self):
        aid = b"\x03" * 16
        s = secrets.token_bytes(32)
        finder = generate_controller()
        proof = make_claim(finder, aid, s)
        # Swap the new controller without re-signing → signature no longer binds.
        forged = ClaimProof.from_dict(proof.to_dict())
        forged.new_controller_pub = generate_controller().dilithium_pk
        assert not verify_claim(forged, aid, claim_commitment(aid, s))

    def test_proof_for_other_artifact_rejected(self):
        s = secrets.token_bytes(32)
        proof = make_claim(generate_controller(), b"\x03" * 16, s)
        assert not verify_claim(proof, b"\x04" * 16,
                                claim_commitment(b"\x04" * 16, s))


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class TestVoucherLedger:
    @pytest.fixture
    def ledger(self, tmp_path: Path) -> ArtifactLedger:
        return ArtifactLedger(tmp_path / "anchor.db")

    def _mint_huntable(self, ledger, aid: bytes, secret: bytes):
        ledger.mint(
            artifact_id=aid.hex(), controller_pub="", content_commit="",
            issuer_fp="22" * 32, ts="t0",
            claim_commitment=claim_commitment(aid, secret).hex(),
        )

    def test_minted_huntable_is_claimable(self, ledger):
        aid, s = secrets.token_bytes(16), secrets.token_bytes(32)
        self._mint_huntable(ledger, aid, s)
        e = ledger.get(aid.hex())
        assert e.is_claimable
        assert e.controller_pub == ""
        assert e.seq == 0

    def test_claim_transitions_to_owner(self, ledger):
        aid, s = secrets.token_bytes(16), secrets.token_bytes(32)
        self._mint_huntable(ledger, aid, s)
        finder = generate_controller()
        e = ledger.claim(
            artifact_id=aid.hex(),
            new_controller_pub=finder.dilithium_pk.hex(),
            expected_commitment=claim_commitment(aid, s).hex(), ts="t1",
        )
        assert e.seq == 1
        assert e.controller_pub == finder.dilithium_pk.hex()
        assert not ledger.get(aid.hex()).is_claimable  # commitment cleared

    def test_claim_non_huntable_raises(self, ledger):
        aid = secrets.token_bytes(16)
        ledger.mint(artifact_id=aid.hex(), controller_pub="11" * 100,
                    content_commit="", issuer_fp="22" * 32, ts="t0")
        with pytest.raises(NotClaimable):
            ledger.claim(artifact_id=aid.hex(),
                         new_controller_pub="33" * 100,
                         expected_commitment="ab" * 16, ts="t1")

    def test_concurrent_claims_single_winner(self, ledger):
        aid, s = secrets.token_bytes(16), secrets.token_bytes(32)
        self._mint_huntable(ledger, aid, s)
        commit = claim_commitment(aid, s).hex()
        ok, lost = [], []
        lock = threading.Lock()

        def worker(i: int):
            try:
                ledger.claim(
                    artifact_id=aid.hex(),
                    new_controller_pub=f"{i:0200x}",
                    expected_commitment=commit, ts=f"t{i}",
                )
                with lock:
                    ok.append(i)
            except (AlreadyClaimed, NotClaimable):
                with lock:
                    lost.append(i)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(ok) == 1
        assert len(lost) == 19
        assert ledger.get(aid.hex()).seq == 1


# ---------------------------------------------------------------------------
# HTTP claim surface
# ---------------------------------------------------------------------------

class TestVoucherAPI:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        ledger = ArtifactLedger(tmp_path / "anchor.db")
        anchor = EopxKey.generate()
        app = Flask("test_voucher")
        app.register_blueprint(create_artifact_api(ledger, anchor))
        app.testing = True
        return ledger, app.test_client()

    def _mint(self, ledger, aid: bytes, secret: bytes):
        ledger.mint(
            artifact_id=aid.hex(), controller_pub="", content_commit="",
            issuer_fp="22" * 32, ts="t0",
            claim_commitment=claim_commitment(aid, secret).hex(),
        )

    def test_claim_happy_path(self, ctx):
        ledger, client = ctx
        aid, s = secrets.token_bytes(16), secrets.token_bytes(32)
        self._mint(ledger, aid, s)
        finder = generate_controller()
        r = client.post(f"/api/v1/artifact/{aid.hex()}/claim",
                        json=make_claim(finder, aid, s).to_dict())
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["seq"] == 1
        assert r.get_json()["entry"]["controller_pub_hex"] == \
            finder.dilithium_pk.hex()

    def test_wrong_secret_400_and_still_claimable(self, ctx):
        ledger, client = ctx
        aid, s = secrets.token_bytes(16), secrets.token_bytes(32)
        self._mint(ledger, aid, s)
        bad = make_claim(generate_controller(), aid, secrets.token_bytes(32))
        r = client.post(f"/api/v1/artifact/{aid.hex()}/claim", json=bad.to_dict())
        assert r.status_code == 400
        assert ledger.get(aid.hex()).is_claimable

    def test_claim_non_huntable_400(self, ctx):
        ledger, client = ctx
        aid = secrets.token_bytes(16)
        ledger.mint(artifact_id=aid.hex(), controller_pub="11" * 100,
                    content_commit="", issuer_fp="22" * 32, ts="t0")
        r = client.post(f"/api/v1/artifact/{aid.hex()}/claim",
                        json=make_claim(generate_controller(), aid,
                                        secrets.token_bytes(32)).to_dict())
        assert r.status_code == 400

    def test_sequential_reclaim_rejected(self, ctx):
        ledger, client = ctx
        aid, s = secrets.token_bytes(16), secrets.token_bytes(32)
        self._mint(ledger, aid, s)
        first = generate_controller()
        assert client.post(f"/api/v1/artifact/{aid.hex()}/claim",
                           json=make_claim(first, aid, s).to_dict()
                           ).status_code == 200
        r = client.post(f"/api/v1/artifact/{aid.hex()}/claim",
                        json=make_claim(generate_controller(), aid, s).to_dict())
        assert r.status_code >= 400  # commitment cleared -> not huntable
        assert ledger.get(aid.hex()).controller_pub == first.dilithium_pk.hex()

    def test_concurrent_claim_one_winner(self, ctx):
        ledger, client = ctx
        aid, s = secrets.token_bytes(16), secrets.token_bytes(32)
        self._mint(ledger, aid, s)
        codes = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def go(_):
            cl = client.application.test_client()
            proof = make_claim(generate_controller(), aid, s)
            barrier.wait()
            r = cl.post(f"/api/v1/artifact/{aid.hex()}/claim", json=proof.to_dict())
            with lock:
                codes.append(r.status_code)

        threads = [threading.Thread(target=go, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert codes.count(200) == 1
        assert any(c >= 400 for c in codes)

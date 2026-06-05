"""EPX-K — Keys of Office tests.

The mapping / commitment / statement layer is pure and always runs. The
signing layer needs the native ML-DSA-87 binding, so it is skipped cleanly
when ``pqcrypto`` is absent (same pattern as the Postgres harness).
"""

from __future__ import annotations

import pytest

from eopx.capabilities import (
    CAPABILITIES,
    CAPABILITY_BY_ID,
    OfficeProof,
    artifact_id_for_capability,
    capabilities_commitment,
    office_statement,
    sign_office,
    verify_office,
)
from eopx.collection import CODEX, CODEX_BY_KEY


class TestMapping:
    def test_one_office_per_relic_bijection(self):
        assert len(CAPABILITIES) == len(CODEX) == 12
        relic_keys = {c.relic_key for c in CAPABILITIES}
        assert relic_keys == {r.key for r in CODEX}  # exact cover, no dupes

    def test_cap_ids_distinct_and_prefixed(self):
        ids = [c.cap_id for c in CAPABILITIES]
        assert len(set(ids)) == len(ids)
        assert all(i.startswith("EPX-K:") for i in ids)

    def test_artifact_id_tracks_the_relic(self):
        for cap in CAPABILITIES:
            assert (artifact_id_for_capability(cap.cap_id)
                    == CODEX_BY_KEY[cap.relic_key].artifact_id().hex())

    def test_unknown_capability_resolves_to_none(self):
        assert artifact_id_for_capability("EPX-K:does-not-exist") is None


class TestCommitment:
    def test_deterministic(self):
        assert capabilities_commitment() == capabilities_commitment()

    def test_hex_sha3_256(self):
        c = capabilities_commitment()
        assert len(c) == 64 and int(c, 16) >= 0

    def test_independent_of_presentation(self):
        # Rewording title/power must NOT move the commitment — it covers only
        # (cap_id, relic_key, artifact_id). Reword every office and confirm
        # the commitment is unchanged.
        from dataclasses import replace
        reworded = [replace(c, title=c.title.upper(), power="(reworded)")
                    for c in CAPABILITIES]
        assert capabilities_commitment(reworded) == capabilities_commitment()


class TestStatement:
    def test_domain_separated_and_deterministic(self):
        s1 = office_statement("EPX-K:audit", "publish", "00ff", "t0")
        s2 = office_statement("EPX-K:audit", "publish", "00ff", "t0")
        assert s1 == s2
        assert s1.startswith(b"esoptron.epx_k.office.v1|")

    def test_varies_with_every_field(self):
        base = office_statement("EPX-K:audit", "publish", "00ff", "t0")
        assert office_statement("EPX-K:seal", "publish", "00ff", "t0") != base
        assert office_statement("EPX-K:audit", "revoke", "00ff", "t0") != base
        assert office_statement("EPX-K:audit", "publish", "abcd", "t0") != base
        assert office_statement("EPX-K:audit", "publish", "00ff", "t1") != base

    def test_proof_dict_round_trip(self):
        p = OfficeProof("EPX-K:audit", "publish", "00ff", "t0", b"\x01\x02\x03")
        assert OfficeProof.from_dict(p.to_dict()) == p


# --------------------------------------------------------------------------
# Signing layer — requires the native crypto.
# --------------------------------------------------------------------------

pqcrypto = pytest.importorskip("pqcrypto")
from eopx.format.keys import EopxKey  # noqa: E402  (after importorskip)


class TestOfficeProofs:
    def test_sign_and_verify_roundtrip(self):
        key = EopxKey.generate()
        proof = sign_office(key, "EPX-K:audit", "publish-report",
                            nonce_hex="dead", ts="2026-05-31T00:00:00Z")
        assert verify_office(proof, key.dilithium_pk) is True

    def test_tampered_action_fails(self):
        key = EopxKey.generate()
        proof = sign_office(key, "EPX-K:audit", "publish-report",
                            nonce_hex="dead", ts="2026-05-31T00:00:00Z")
        forged = OfficeProof(proof.cap_id, "grant-self-everything",
                             proof.nonce_hex, proof.ts, proof.sig)
        assert verify_office(forged, key.dilithium_pk) is False

    def test_wrong_controller_fails(self):
        holder = EopxKey.generate()
        impostor = EopxKey.generate()
        proof = sign_office(holder, "EPX-K:registry", "set-fee",
                            nonce_hex="beef", ts="2026-05-31T00:00:00Z")
        assert verify_office(proof, holder.dilithium_pk) is True
        assert verify_office(proof, impostor.dilithium_pk) is False

    def test_unknown_capability_rejected_both_ways(self):
        key = EopxKey.generate()
        with pytest.raises(ValueError):
            sign_office(key, "EPX-K:phantom", "x", nonce_hex="00", ts="t")
        # A proof carrying an unknown cap never verifies, regardless of sig.
        bogus = OfficeProof("EPX-K:phantom", "x", "00", "t", b"\x00")
        assert verify_office(bogus, key.dilithium_pk) is False

    def test_capability_count_matches_relics(self):
        assert set(CAPABILITY_BY_ID) == {c.cap_id for c in CAPABILITIES}

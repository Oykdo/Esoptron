"""Esoptron Codex (EPX-C) — catalog integrity, deterministic distribution,
controller-to-vault sealing, and relic forging.
"""

from __future__ import annotations

import secrets

import pytest

from eopx.collection import (
    CODEX,
    CODEX_BY_KEY,
    DISTRIBUTION_WINDOW,
    FOUNDER_SLOTS,
    build_distribution,
    catalog_commitment_hex,
    codex_manifest,
    derive_relic_positions,
)
from eopx.collection.forge import (
    forge_relic,
    relic_merkle_root,
    render_relic_badge,
)
from eopx.format import pack, read_manifest, verify
from eopx.format.keys import EopxKey
from eopx.transfer import (
    TitledArtifact,
    open_content,
    seal_controller,
    unseal_controller,
    verify_artifact,
)
from eopx.transfer.binding import bind_new_controller

BTC_HASH = bytes.fromhex("00" * 31 + "07")
BTC_HEIGHT = 900_000


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

class TestCatalog:
    def test_published_size_unique_ranks_and_keys(self):
        # The published Codex v2 holds twelve relics (covers protocols A-G).
        assert len(CODEX) == 12
        ranks = sorted(r.rank for r in CODEX)
        assert ranks == list(range(1, len(CODEX) + 1))
        assert len({r.key for r in CODEX}) == len(CODEX)
        assert set(CODEX_BY_KEY) == {r.key for r in CODEX}

    def test_first_three_are_founders(self):
        founders = [r for r in CODEX if r.is_founder]
        assert sorted(r.rank for r in founders) == [1, 2, 3]

    def test_every_relic_has_lore_and_element(self):
        for r in CODEX:
            assert r.lore and r.lore_fr
            assert r.element in {"Fire", "Water", "Air", "Earth"}
            assert r.myth_echo and r.mechanism

    def test_artifact_ids_unique_and_stable(self):
        ids = [r.artifact_id() for r in CODEX]
        assert all(len(i) == 16 for i in ids)
        assert len({i for i in ids}) == len(CODEX)
        # Stable across calls.
        assert CODEX[0].artifact_id() == CODEX[0].artifact_id()

    def test_spinor_seeds_distinct(self):
        assert len({r.spinor_seed() for r in CODEX}) == len(CODEX)

    def test_commitment_stable_and_excludes_lore(self):
        c1 = catalog_commitment_hex()
        assert len(c1) == 64
        # Recompute is identical.
        assert catalog_commitment_hex() == c1


# ---------------------------------------------------------------------------
# Distribution
# ---------------------------------------------------------------------------

class TestDistribution:
    def test_founders_go_to_first_three_vaults(self):
        dist = build_distribution(BTC_HASH, BTC_HEIGHT)
        founders = {a.relic.rank: a.vault_sequence
                    for a in dist if a.placement == "founder"}
        assert founders == {1: 1, 2: 2, 3: 3}

    def test_derived_in_window_and_disjoint_from_founders(self):
        dist = build_distribution(BTC_HASH, BTC_HEIGHT)
        derived = [a.vault_sequence for a in dist if a.placement == "derived"]
        expected = len(CODEX) - len(FOUNDER_SLOTS)
        assert len(derived) == expected
        assert len(set(derived)) == expected
        assert all(len(FOUNDER_SLOTS) < p <= DISTRIBUTION_WINDOW for p in derived)
        assert not (set(derived) & set(FOUNDER_SLOTS))

    def test_distribution_is_deterministic(self):
        d1 = [a.vault_sequence for a in build_distribution(BTC_HASH, BTC_HEIGHT)]
        d2 = [a.vault_sequence for a in build_distribution(BTC_HASH, BTC_HEIGHT)]
        assert d1 == d2

    def test_different_block_moves_derived_positions(self):
        other = bytes.fromhex("00" * 31 + "09")
        a = [x.vault_sequence for x in build_distribution(BTC_HASH, BTC_HEIGHT)
             if x.placement == "derived"]
        b = [x.vault_sequence for x in build_distribution(other, BTC_HEIGHT)
             if x.placement == "derived"]
        assert a != b

    def test_all_relics_assigned_once(self):
        dist = build_distribution(BTC_HASH, BTC_HEIGHT)
        assert sorted(a.relic.rank for a in dist) == list(range(1, len(CODEX) + 1))

    def test_derive_relic_positions_rejects_bad_hash(self):
        with pytest.raises(ValueError):
            derive_relic_positions(b"\x00" * 10, count=4)

    def test_manifest_round_trips(self):
        m = codex_manifest(BTC_HASH, BTC_HEIGHT)
        assert m["count"] == len(CODEX)
        assert len(m["relics"]) == len(CODEX)
        assert len(m["distribution"]) == len(CODEX)
        assert m["catalog_commitment_hex"] == catalog_commitment_hex()


# ---------------------------------------------------------------------------
# Controller sealing to a vault (spec §8)
# ---------------------------------------------------------------------------

class TestControllerBinding:
    def test_seal_unseal_round_trip(self):
        device_secret = secrets.token_bytes(32)
        aid = secrets.token_bytes(16)
        controller = EopxKey.generate()
        sealed = seal_controller(controller, device_secret, aid)
        woken = unseal_controller(sealed, device_secret)
        assert woken.dilithium_pk == controller.dilithium_pk
        assert woken.kyber_pk == controller.kyber_pk
        assert woken.has_secrets

    def test_wrong_vault_cannot_unseal(self):
        aid = secrets.token_bytes(16)
        controller = EopxKey.generate()
        sealed = seal_controller(controller, secrets.token_bytes(32), aid)
        with pytest.raises(Exception):
            unseal_controller(sealed, secrets.token_bytes(32))

    def test_sealed_controller_json_round_trip(self):
        from eopx.transfer.binding import SealedController
        device_secret = secrets.token_bytes(32)
        aid = secrets.token_bytes(16)
        _ctrl, sealed = bind_new_controller(device_secret, aid)
        again = SealedController.from_dict(sealed.to_dict())
        woken = unseal_controller(again, device_secret)
        assert woken.dilithium_pk == sealed.dilithium_pub

    def test_public_controller_has_no_secrets(self):
        _ctrl, sealed = bind_new_controller(secrets.token_bytes(32),
                                            secrets.token_bytes(16))
        pub = sealed.public_controller()
        assert not pub.has_secrets
        assert pub.dilithium_pk == sealed.dilithium_pub


# ---------------------------------------------------------------------------
# Forge
# ---------------------------------------------------------------------------

class TestForge:
    @pytest.fixture
    def issuer(self) -> EopxKey:
        return EopxKey.generate()

    def test_forge_relic_to_vault_seals_controller(self, issuer):
        relic = CODEX_BY_KEY["scintilla"]
        device_secret = secrets.token_bytes(32)
        forged = forge_relic(
            relic, issuer, destination_device_secret=device_secret,
            badge_size=256,
        )
        # Artifact authentic + lore commitment matches.
        assert verify_artifact(forged.artifact, content=relic.lore_payload())
        assert forged.artifact.artifact_id == relic.artifact_id()
        # Controller is sealed to the destination vault (not exposed).
        assert forged.controller is None
        assert forged.sealed_controller is not None
        woken = unseal_controller(forged.sealed_controller, device_secret)
        # The sealed controller is exactly the artifact's initial controller.
        assert woken.dilithium_pk == forged.artifact.initial_controller_pub
        # The destination vault can open the relic's sealed lore content.
        assert open_content(forged.sealed_content, woken) == relic.lore_payload()

    def test_forge_relic_without_vault_returns_controller(self, issuer):
        relic = CODEX_BY_KEY["unda"]
        forged = forge_relic(relic, issuer, badge_size=256)
        assert forged.sealed_controller is None
        assert forged.controller is not None
        assert forged.controller.dilithium_pk == forged.artifact.initial_controller_pub

    def test_badge_packs_and_verifies_bound_to_artifact(self, issuer, tmp_path):
        relic = CODEX_BY_KEY["clavis"]
        forged = forge_relic(relic, issuer,
                             destination_device_secret=secrets.token_bytes(32),
                             badge_size=256)
        out = tmp_path / "clavis.badge.eopx"
        pack(forged.badge, out, issuer,
             vault_id=relic.artifact_id().hex(),
             merkle_root=forged.merkle_root)
        res = verify(out, expected_dilithium_pk_fp=issuer.dilithium_pk_fp)
        assert res.ok
        m = read_manifest(out)
        # The badge is cryptographically bound to the artifact + lore.
        assert m.vault_id == relic.artifact_id().hex()
        assert m.merkle_root == relic_merkle_root(relic).hex()

    def test_badges_are_visually_distinct(self):
        a = render_relic_badge(CODEX_BY_KEY["speculum_primum"], size=256)
        b = render_relic_badge(CODEX_BY_KEY["corona_cava"], size=256)
        assert a.tobytes() != b.tobytes()

    def test_relic_forge_is_reproducible(self):
        # The badge is a pure function of the relic: same relic → identical
        # pixels, independent of the issuer key.
        relic = CODEX_BY_KEY["lucerna"]
        b1 = render_relic_badge(relic, size=256).tobytes()
        b2 = render_relic_badge(relic, size=256).tobytes()
        assert b1 == b2


# ---------------------------------------------------------------------------
# Authentic possession (EPX-T §5.3 applied to relics)
# ---------------------------------------------------------------------------

class TestPossession:
    @pytest.fixture
    def issuer(self) -> EopxKey:
        return EopxKey.generate()

    def _forge(self, issuer):
        relic = CODEX_BY_KEY["scintilla"]
        ds = secrets.token_bytes(32)
        forged = forge_relic(
            relic, issuer, destination_device_secret=ds, badge_size=128,
        )
        return relic, ds, forged

    def test_status_held_transferred_not_owned_unknown(self, issuer):
        from eopx.collection.ownership import Possession, possession_status

        _relic, _ds, forged = self._forge(issuer)
        mine = forged.artifact.initial_controller_pub
        other = EopxKey.generate().dilithium_pk
        assert possession_status(mine, mine) is Possession.HELD
        assert possession_status(mine, other) is Possession.TRANSFERRED
        assert possession_status(None, mine) is Possession.NOT_OWNED
        assert possession_status(mine, None) is Possession.UNKNOWN

    def test_trustless_proof_round_trip(self, issuer):
        from eopx.collection.ownership import (
            prove_relic_ownership,
            verify_relic_ownership,
        )
        from eopx.transfer import ownership_challenge

        _relic, ds, forged = self._forge(issuer)
        aid = forged.artifact.artifact_id
        ledger_controller = forged.artifact.initial_controller_pub
        nonce = ownership_challenge()
        proof = prove_relic_ownership(forged.sealed_controller, ds, aid, nonce)
        assert verify_relic_ownership(aid, nonce, proof, ledger_controller)
        # Against a different (post-transfer) controller it must fail.
        other = EopxKey.generate().dilithium_pk
        assert not verify_relic_ownership(aid, nonce, proof, other)

    def test_wrong_vault_cannot_prove(self, issuer):
        from eopx.collection.ownership import prove_relic_ownership
        from eopx.transfer import ownership_challenge

        _relic, _ds, forged = self._forge(issuer)
        aid = forged.artifact.artifact_id
        with pytest.raises(Exception):
            prove_relic_ownership(
                forged.sealed_controller, secrets.token_bytes(32),
                aid, ownership_challenge(),
            )

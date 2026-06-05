"""Golden Eggs (egg_token) — deterministic clutch, tiers, immutable seal,
and the verifiable founder attribution.
"""

from __future__ import annotations

import hashlib
from collections import Counter

from eopx.format.keys import EopxKey
from eopx import egg_token as E

BLOCK = hashlib.sha3_256(b"egg-test-block").digest()
HEIGHT = 900_000


class TestClutch:
    def test_555_distinct_positions_in_window(self):
        eggs = E.derive_eggs(BLOCK, HEIGHT)
        assert len(eggs) == E.TOTAL_EGGS == 555
        positions = [e.position for e in eggs]
        assert len(set(positions)) == 555
        assert all(1 <= p <= E.EGG_WINDOW for p in positions)
        assert positions == sorted(positions)

    def test_deterministic(self):
        a = [e.position for e in E.derive_eggs(BLOCK, HEIGHT)]
        b = [e.position for e in E.derive_eggs(BLOCK, HEIGHT)]
        assert a == b

    def test_different_block_moves_eggs(self):
        other = hashlib.sha3_256(b"egg-test-block-2").digest()
        a = [e.position for e in E.derive_eggs(BLOCK, HEIGHT)]
        b = [e.position for e in E.derive_eggs(other, HEIGHT)]
        assert a != b

    def test_tier_distribution(self):
        eggs = E.derive_eggs(BLOCK, HEIGHT)
        counts = Counter(e.tier for e in eggs)
        assert counts == {"Cosmic": 5, "Stellar": 50, "Lunar": 100,
                          "Crystal": 150, "Stone": 250}

    def test_identity_fields_unique_and_stable(self):
        eggs = E.derive_eggs(BLOCK, HEIGHT)
        assert len({e.egg_id for e in eggs}) == 555
        assert len({e.egg_hash for e in eggs}) == 555
        assert [e.egg_number for e in eggs] == list(range(1, 556))
        assert eggs[0].egg_id == "GE-001"

    def test_tiers_commitment_stable(self):
        assert len(E.tiers_commitment_hex()) == 64
        assert E.tiers_commitment_hex() == E.tiers_commitment_hex()


class TestSeal:
    def test_mint_and_verify(self):
        eggs = E.derive_eggs(BLOCK, HEIGHT)
        deploy = EopxKey.generate()
        egg = eggs[42]
        seal = E.mint_egg_seal(egg=egg, vault_fp=b"\x01" * 32,
                               btc_block_hash=BLOCK, btc_block_height=HEIGHT,
                               eggs=eggs, deployment_key=deploy)
        assert E.verify_egg_seal(seal, deployment_pk=deploy.dilithium_pk, eggs=eggs)

    def test_verify_rejects_wrong_key(self):
        eggs = E.derive_eggs(BLOCK, HEIGHT)
        deploy = EopxKey.generate()
        seal = E.mint_egg_seal(egg=eggs[0], vault_fp=b"\x01" * 32,
                               btc_block_hash=BLOCK, btc_block_height=HEIGHT,
                               eggs=eggs, deployment_key=deploy)
        assert not E.verify_egg_seal(
            seal, deployment_pk=EopxKey.generate().dilithium_pk, eggs=eggs)

    def test_verify_rejects_tampered_tier(self):
        eggs = E.derive_eggs(BLOCK, HEIGHT)
        deploy = EopxKey.generate()
        seal = E.mint_egg_seal(egg=eggs[0], vault_fp=b"\x01" * 32,
                               btc_block_hash=BLOCK, btc_block_height=HEIGHT,
                               eggs=eggs, deployment_key=deploy)
        tampered = E.EggSeal.from_dict({**seal.to_dict(), "tier": "Cosmic"})
        assert not E.verify_egg_seal(
            tampered, deployment_pk=deploy.dilithium_pk, eggs=eggs)


class TestFounderAttribution:
    def test_founder_egg_deterministic_and_in_clutch(self):
        vault = b"\xab" * 32
        egg = E.founder_egg(vault, BLOCK, HEIGHT)
        again = E.founder_egg(vault, BLOCK, HEIGHT)
        assert egg == again
        assert egg in E.derive_eggs(BLOCK, HEIGHT)

    def test_founder_draw_index_in_range(self):
        idx = E.founder_draw_index(b"\xcd" * 32, BLOCK)
        assert 0 <= idx < E.TOTAL_EGGS

    def test_different_vaults_can_draw_different_eggs(self):
        e1 = E.founder_egg(b"\x01" * 32, BLOCK, HEIGHT)
        e2 = E.founder_egg(b"\x02" * 32, BLOCK, HEIGHT)
        # Not guaranteed distinct, but the draw is vault-dependent: at least
        # the index function differs for these two.
        assert (E.founder_draw_index(b"\x01" * 32, BLOCK)
                != E.founder_draw_index(b"\x02" * 32, BLOCK)) or e1 != e2

    def test_egg_for_sequence(self):
        eggs = E.derive_eggs(BLOCK, HEIGHT)
        pos = eggs[7].position
        assert E.egg_for_sequence(pos, eggs).egg_id == eggs[7].egg_id
        assert E.egg_for_sequence(999_999_999, eggs) is None

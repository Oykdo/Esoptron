"""Egg grants — draw grants cannot lie, issuer grants must own up, and the
ledger makes removal, reordering and double attribution detectable.

These cover the gap left by ``verify_egg_seal``, which never recomputes
``founder_draw_index``: a seal for an egg the vault did not win verifies just
fine. ``egg_grant`` closes that for new attributions.
"""

from __future__ import annotations

import hashlib

import pytest

from eopx.format.keys import EopxKey
from eopx import egg_token as E
from eopx import egg_grant as G

BLOCK = hashlib.sha3_256(b"grant-test-block").digest()
HEIGHT = 900_000
VAULT = hashlib.sha3_256(b"grant-test-vault").digest()
OTHER_VAULT = hashlib.sha3_256(b"grant-test-vault-2").digest()


@pytest.fixture(scope="module")
def eggs():
    return E.derive_eggs(BLOCK, HEIGHT)


@pytest.fixture(scope="module")
def key():
    return EopxKey.generate()


@pytest.fixture(scope="module")
def drawn(eggs):
    """The egg the fair draw yields for VAULT."""
    return eggs[E.founder_draw_index(VAULT, BLOCK, total=len(eggs))]


@pytest.fixture(scope="module")
def other_egg(eggs, drawn):
    """Any egg of the clutch that VAULT did not draw."""
    return next(e for e in eggs if e.egg_id != drawn.egg_id)


def _mint(eggs, key, egg, vault=VAULT, **kw):
    kw.setdefault("kind", G.KIND_DRAW)
    return G.mint_egg_grant(
        egg=egg, vault_fp=vault, btc_block_hash=BLOCK,
        btc_block_height=HEIGHT, eggs=eggs, deployment_key=key, **kw,
    )


class TestDrawGrant:
    def test_draw_grant_of_the_drawn_egg_verifies(self, eggs, key, drawn):
        grant = _mint(eggs, key, drawn)
        assert grant.kind == G.KIND_DRAW
        assert not grant.diverges_from_draw
        assert G.verify_egg_grant(
            grant, deployment_pk=key.dilithium_pk, eggs=eggs, btc_block_hash=BLOCK
        )

    def test_draw_grant_of_another_egg_is_refused_at_mint(self, eggs, key, other_egg):
        """The check egg_token's seal never performed."""
        with pytest.raises(ValueError, match="draw grant mismatch"):
            _mint(eggs, key, other_egg)

    def test_draw_grant_forged_after_mint_fails_verification(self, eggs, key, drawn, other_egg):
        grant = _mint(eggs, key, drawn)
        forged = G.EggGrant.from_dict({
            **grant.to_dict(),
            "egg_id": other_egg.egg_id,
            "egg_number": other_egg.egg_number,
            "position": other_egg.position,
            "egg_hash": other_egg.egg_hash,
            "tier": other_egg.tier,
        })
        assert not G.verify_egg_grant(
            forged, deployment_pk=key.dilithium_pk, eggs=eggs, btc_block_hash=BLOCK
        )


class TestIssuerGrant:
    def test_issuer_grant_records_the_real_draw(self, eggs, key, drawn, other_egg):
        grant = _mint(eggs, key, other_egg, kind=G.KIND_ISSUER, reason="Issuer decision")
        assert grant.egg_id == other_egg.egg_id
        assert grant.drawn_egg_id == drawn.egg_id
        assert grant.diverges_from_draw
        assert G.verify_egg_grant(
            grant, deployment_pk=key.dilithium_pk, eggs=eggs, btc_block_hash=BLOCK
        )

    def test_issuer_grant_requires_a_reason(self, eggs, key, other_egg):
        with pytest.raises(ValueError, match="must state a reason"):
            _mint(eggs, key, other_egg, kind=G.KIND_ISSUER)

    def test_misstating_the_draw_fails_verification(self, eggs, key, other_egg):
        """An issuer grant may diverge, but not lie about what was drawn."""
        grant = _mint(eggs, key, other_egg, kind=G.KIND_ISSUER, reason="Issuer decision")
        forged = G.EggGrant.from_dict({
            **grant.to_dict(),
            "drawn_egg_id": other_egg.egg_id,
            "drawn_egg_number": other_egg.egg_number,
        })
        assert not G.verify_egg_grant(
            forged, deployment_pk=key.dilithium_pk, eggs=eggs, btc_block_hash=BLOCK
        )

    def test_reason_is_covered_by_the_signature(self, eggs, key, other_egg):
        grant = _mint(eggs, key, other_egg, kind=G.KIND_ISSUER, reason="Issuer decision")
        tampered = G.EggGrant.from_dict({**grant.to_dict(), "reason": "Won fairly"})
        assert not G.verify_egg_grant(
            tampered, deployment_pk=key.dilithium_pk, eggs=eggs, btc_block_hash=BLOCK
        )

    def test_unknown_kind_is_refused(self, eggs, key, drawn):
        with pytest.raises(ValueError, match="kind must be one of"):
            _mint(eggs, key, drawn, kind="gift")


class TestSigner:
    def test_another_key_does_not_verify(self, eggs, key, drawn):
        grant = _mint(eggs, key, drawn)
        stranger = EopxKey.generate()
        assert not G.verify_egg_grant(
            grant, deployment_pk=stranger.dilithium_pk, eggs=eggs, btc_block_hash=BLOCK
        )

    def test_egg_outside_the_clutch_is_refused(self, eggs, key, drawn):
        alien = E.derive_eggs(hashlib.sha3_256(b"other-block").digest(), HEIGHT)[0]
        if alien.position in {e.position for e in eggs}:
            pytest.skip("clutches overlap on this position")
        with pytest.raises(ValueError, match="not part of the published clutch"):
            _mint(eggs, key, alien, kind=G.KIND_ISSUER, reason="Issuer decision")


class TestSealProvenance:
    """The gap verify_egg_seal leaves: an authentic seal proves the issuer
    signed it, never that the vault legitimately obtained the egg."""

    def _seal(self, eggs, key, egg, vault=VAULT):
        return E.mint_egg_seal(
            egg=egg, vault_fp=vault, btc_block_hash=BLOCK,
            btc_block_height=HEIGHT, eggs=eggs, deployment_key=key,
        )

    def test_organic_win_is_recognised_by_sequence(self, eggs, key, other_egg):
        """What the anchor API mints on: sequence landed on the egg position."""
        seal = self._seal(eggs, key, other_egg)
        assert G.seal_provenance(
            seal, eggs=eggs, btc_block_hash=BLOCK,
            vault_sequence=other_egg.position,
        ) == G.PROVENANCE_SEQUENCE

    def test_founder_draw_is_recognised_without_a_sequence(self, eggs, key, drawn):
        seal = self._seal(eggs, key, drawn)
        assert G.seal_provenance(
            seal, eggs=eggs, btc_block_hash=BLOCK,
        ) == G.PROVENANCE_DRAW

    def test_unexplained_attribution_is_flagged(self, eggs, key, other_egg):
        """Authentic signature, but neither path explains the attribution."""
        seal = self._seal(eggs, key, other_egg)
        assert E.verify_egg_seal(seal, deployment_pk=key.dilithium_pk, eggs=eggs)
        assert G.seal_provenance(
            seal, eggs=eggs, btc_block_hash=BLOCK, vault_sequence=1,
        ) == G.PROVENANCE_UNPROVEN

    def test_a_wrong_sequence_does_not_promote_an_unproven_seal(self, eggs, key, other_egg):
        seal = self._seal(eggs, key, other_egg)
        assert G.seal_provenance(
            seal, eggs=eggs, btc_block_hash=BLOCK,
            vault_sequence=other_egg.position + 1,
        ) == G.PROVENANCE_UNPROVEN


class TestLedger:
    def test_chain_links_and_verifies(self, eggs, key, drawn, other_egg):
        ledger = G.GrantLedger()
        assert ledger.head == G.GENESIS_LINK

        first = _mint(eggs, key, drawn, prev_link_hex=ledger.head)
        ledger.append(first)
        second = _mint(eggs, key, other_egg, vault=OTHER_VAULT,
                       kind=G.KIND_ISSUER, reason="Issuer decision",
                       prev_link_hex=ledger.head)
        ledger.append(second)

        assert ledger.verify_chain()
        assert ledger.head == second.link_hex()

    def test_append_out_of_chain_is_refused(self, eggs, key, drawn):
        ledger = G.GrantLedger()
        detached = _mint(eggs, key, drawn, prev_link_hex="ff" * 32)
        with pytest.raises(ValueError, match="does not chain"):
            ledger.append(detached)

    def test_rewriting_a_past_grant_breaks_the_chain(self, eggs, key, drawn, other_egg):
        ledger = G.GrantLedger()
        ledger.append(_mint(eggs, key, drawn, prev_link_hex=ledger.head))
        ledger.append(_mint(eggs, key, other_egg, vault=OTHER_VAULT,
                            kind=G.KIND_ISSUER, reason="Issuer decision",
                            prev_link_hex=ledger.head))

        ledger.grants[0] = G.EggGrant.from_dict(
            {**ledger.grants[0].to_dict(), "reason": "rewritten"}
        )
        assert not ledger.verify_chain()

    def test_double_attribution_is_detected(self, eggs, key, other_egg):
        ledger = G.GrantLedger()
        ledger.append(_mint(eggs, key, other_egg, kind=G.KIND_ISSUER,
                            reason="Issuer decision", prev_link_hex=ledger.head))
        ledger.append(_mint(eggs, key, other_egg, vault=OTHER_VAULT,
                            kind=G.KIND_ISSUER, reason="Issuer decision",
                            prev_link_hex=ledger.head))

        duplicates = ledger.duplicate_eggs()
        assert other_egg.egg_id in duplicates
        assert len(duplicates[other_egg.egg_id]) == 2

    def test_distinct_eggs_are_not_flagged(self, eggs, key, drawn, other_egg):
        ledger = G.GrantLedger()
        ledger.append(_mint(eggs, key, drawn, prev_link_hex=ledger.head))
        ledger.append(_mint(eggs, key, other_egg, vault=OTHER_VAULT,
                            kind=G.KIND_ISSUER, reason="Issuer decision",
                            prev_link_hex=ledger.head))
        assert ledger.duplicate_eggs() == {}

    def test_json_round_trip_preserves_the_chain(self, eggs, key, drawn):
        ledger = G.GrantLedger()
        ledger.append(_mint(eggs, key, drawn, prev_link_hex=ledger.head))
        restored = G.GrantLedger.from_json(ledger.to_json())

        assert restored.verify_chain()
        assert restored.head == ledger.head
        assert restored.grants[0].to_dict() == ledger.grants[0].to_dict()

    def test_json_with_a_wrong_head_is_refused(self, eggs, key, drawn):
        ledger = G.GrantLedger()
        ledger.append(_mint(eggs, key, drawn, prev_link_hex=ledger.head))
        raw = ledger.to_json().replace(ledger.head, "ab" * 32)
        with pytest.raises(ValueError, match="head does not match"):
            G.GrantLedger.from_json(raw)

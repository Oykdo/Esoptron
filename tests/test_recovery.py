"""Holographic Recovery — round-trip, tamper, and serialization tests."""

from __future__ import annotations

import json
import secrets

import pytest

from eopx.format.keys import EopxKey
from eopx.recovery import (
    CardPinShare,
    KyberShare,
    PassphraseShare,
    RecoveryCredentials,
    RecoveryPackage,
    SCHEMA_VERSION,
    recover_entropy,
    setup_recovery,
    # Flexible k-of-n
    ShareConfig,
    FlexibleCredentials,
    setup_recovery_flexible,
    recover_entropy_flexible,
)


@pytest.fixture
def entropy() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture
def contact_key() -> EopxKey:
    return EopxKey.generate()


@pytest.fixture
def vault_fp() -> str:
    return "ab" * 32


@pytest.fixture
def package(entropy, contact_key, vault_fp) -> RecoveryPackage:
    return setup_recovery(
        entropy,
        card_pin="123456",
        contact_kyber_pk=contact_key.kyber_pk,
        cloud_passphrase="correct horse battery staple",
        vault_fp_hex=vault_fp,
    )


# ---------------------------------------------------------------------------
# Setup invariants
# ---------------------------------------------------------------------------

def test_setup_emits_three_shares_in_canonical_order(package):
    assert len(package.shares) == 3
    assert isinstance(package.shares[0], CardPinShare)
    assert isinstance(package.shares[1], KyberShare)
    assert isinstance(package.shares[2], PassphraseShare)
    assert [s.index for s in package.shares] == [1, 2, 3]
    assert package.threshold == 2
    assert package.total == 3
    assert package.schema_version == SCHEMA_VERSION


def test_setup_rejects_invalid_threshold(entropy, contact_key):
    with pytest.raises(NotImplementedError):
        setup_recovery(
            entropy, card_pin="123456",
            contact_kyber_pk=contact_key.kyber_pk,
            cloud_passphrase="long passphrase here",
            vault_fp_hex="00" * 32,
            threshold=3, total=5,
        )


def test_setup_rejects_short_pin(entropy, contact_key):
    with pytest.raises(ValueError, match="card_pin"):
        setup_recovery(
            entropy, card_pin="12",
            contact_kyber_pk=contact_key.kyber_pk,
            cloud_passphrase="long passphrase here",
            vault_fp_hex="00" * 32,
        )


def test_setup_requires_at_least_two_credentials(entropy):
    with pytest.raises(ValueError):
        setup_recovery(
            entropy, card_pin="123456",
            contact_kyber_pk=None, cloud_passphrase=None,
            vault_fp_hex="00" * 32,
        )


def test_setup_rejects_empty_entropy(contact_key):
    with pytest.raises(ValueError):
        setup_recovery(
            b"", card_pin="123456",
            contact_kyber_pk=contact_key.kyber_pk,
            cloud_passphrase="passphrase here",
            vault_fp_hex="00" * 32,
        )


# ---------------------------------------------------------------------------
# Round-trip — every 2-of-3 combination recovers the secret
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("combo", ["pin+kyber", "pin+pass", "kyber+pass"])
def test_recovery_round_trip_each_pair(entropy, contact_key, package, combo):
    if combo == "pin+kyber":
        creds = RecoveryCredentials(
            card_pin="123456",
            contact_kyber_sk=contact_key.kyber_sk,
        )
    elif combo == "pin+pass":
        creds = RecoveryCredentials(
            card_pin="123456",
            cloud_passphrase="correct horse battery staple",
        )
    else:
        creds = RecoveryCredentials(
            contact_kyber_sk=contact_key.kyber_sk,
            cloud_passphrase="correct horse battery staple",
        )
    assert recover_entropy(package, creds) == entropy


def test_recovery_with_three_credentials_works_too(entropy, contact_key,
                                                     package):
    """Providing all 3 still recovers (stops after threshold opened)."""
    creds = RecoveryCredentials(
        card_pin="123456",
        contact_kyber_sk=contact_key.kyber_sk,
        cloud_passphrase="correct horse battery staple",
    )
    assert recover_entropy(package, creds) == entropy


def test_recovery_fails_with_single_credential(package, contact_key):
    for creds in [
        RecoveryCredentials(card_pin="123456"),
        RecoveryCredentials(contact_kyber_sk=contact_key.kyber_sk),
        RecoveryCredentials(cloud_passphrase="correct horse battery staple"),
        RecoveryCredentials(),  # nothing
    ]:
        with pytest.raises(ValueError, match="could not open enough shares"):
            recover_entropy(package, creds)


def test_recovery_fails_with_wrong_pin(package, contact_key):
    creds = RecoveryCredentials(
        card_pin="999999",  # wrong
        cloud_passphrase="correct horse battery staple",
    )
    # Only one share opens (the passphrase one); threshold not met → fail.
    with pytest.raises(ValueError, match="could not open enough shares"):
        recover_entropy(package, creds)


def test_recovery_fails_with_wrong_passphrase(package):
    creds = RecoveryCredentials(
        card_pin="123456",
        cloud_passphrase="totally wrong passphrase",
    )
    with pytest.raises(ValueError, match="could not open enough shares"):
        recover_entropy(package, creds)


def test_recovery_fails_with_wrong_kyber_key(package):
    other = EopxKey.generate()
    creds = RecoveryCredentials(
        contact_kyber_sk=other.kyber_sk,
        cloud_passphrase="correct horse battery staple",
    )
    with pytest.raises(ValueError, match="could not open enough shares"):
        recover_entropy(package, creds)


# ---------------------------------------------------------------------------
# Tamper resistance — mutating any field of a share breaks recovery
# ---------------------------------------------------------------------------

def test_tamper_pin_ciphertext_breaks_recovery(package, contact_key, entropy):
    # Flip a bit in share #1's ciphertext
    s1 = package.shares[0]
    bad = bytearray(s1.ciphertext)
    bad[0] ^= 0x01
    s1.ciphertext = bytes(bad)

    creds = RecoveryCredentials(
        card_pin="123456",
        contact_kyber_sk=contact_key.kyber_sk,
        cloud_passphrase="correct horse battery staple",
    )
    # Still recovers via shares #2 and #3.
    assert recover_entropy(package, creds) == entropy

    # But if only PIN + cloud were available, recovery would fail
    # because share #1 no longer opens.
    creds2 = RecoveryCredentials(card_pin="123456")
    with pytest.raises(ValueError):
        recover_entropy(package, creds2)


def test_tamper_pin_salt_breaks_only_that_share(package, contact_key, entropy):
    s1 = package.shares[0]
    assert isinstance(s1, CardPinShare)
    bad = bytearray(s1.salt)
    bad[0] ^= 0xFF
    s1.salt = bytes(bad)

    # Recovery via kyber+pass still works
    creds = RecoveryCredentials(
        contact_kyber_sk=contact_key.kyber_sk,
        cloud_passphrase="correct horse battery staple",
    )
    assert recover_entropy(package, creds) == entropy


def test_tamper_group_id_breaks_all_shares(package, contact_key):
    """Group ID is part of AAD; changing it invalidates every share's AEAD tag."""
    package.group_id = "ff" * 16  # different group_id
    creds = RecoveryCredentials(
        card_pin="123456",
        contact_kyber_sk=contact_key.kyber_sk,
        cloud_passphrase="correct horse battery staple",
    )
    with pytest.raises(ValueError, match="could not open enough shares"):
        recover_entropy(package, creds)


def test_tamper_share_index_breaks_aead(package, contact_key, entropy):
    """Swapping share #2 and #3 indices breaks their AEAD AAD."""
    pkg = package
    pkg.shares[1].index = 99
    creds = RecoveryCredentials(
        contact_kyber_sk=contact_key.kyber_sk,
        cloud_passphrase="correct horse battery staple",
    )
    with pytest.raises(ValueError):
        recover_entropy(pkg, creds)


def test_tamper_kyber_kem_ciphertext(package, contact_key, entropy):
    s2 = package.shares[1]
    assert isinstance(s2, KyberShare)
    bad = bytearray(s2.kem_ciphertext)
    bad[10] ^= 0x55
    s2.kem_ciphertext = bytes(bad)

    creds_kyber_only = RecoveryCredentials(
        contact_kyber_sk=contact_key.kyber_sk,
        cloud_passphrase="correct horse battery staple",
    )
    # The KEM still decapsulates to *some* shared secret (ML-KEM doesn't
    # explicitly reject malformed CTs — IND-CCA via implicit rejection)
    # but the derived AEAD key is wrong → AEAD tag fails → only the
    # passphrase share opens, threshold not met.
    with pytest.raises(ValueError, match="could not open enough shares"):
        recover_entropy(package, creds_kyber_only)

    # And PIN+pass still works:
    creds_other = RecoveryCredentials(
        card_pin="123456",
        cloud_passphrase="correct horse battery staple",
    )
    assert recover_entropy(package, creds_other) == entropy


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------

def test_to_json_from_json_round_trip(package, contact_key, entropy):
    blob = package.to_json()
    restored = RecoveryPackage.from_json(blob)
    assert restored.group_id == package.group_id
    assert restored.threshold == package.threshold
    assert restored.total == package.total
    assert restored.vault_fp_hex == package.vault_fp_hex
    assert [s.kind for s in restored.shares] == [
        "card_pin", "kyber_pk", "passphrase",
    ]
    creds = RecoveryCredentials(
        card_pin="123456",
        contact_kyber_sk=contact_key.kyber_sk,
        cloud_passphrase="correct horse battery staple",
    )
    assert recover_entropy(restored, creds) == entropy


def test_from_dict_rejects_wrong_schema_version(package):
    d = package.to_dict()
    d["schema_version"] = 999
    with pytest.raises(ValueError, match="schema_version"):
        RecoveryPackage.from_dict(d)


def test_from_dict_rejects_unknown_kind(package):
    d = package.to_dict()
    d["shares"][0]["kind"] = "telepathy"
    with pytest.raises(ValueError, match="unknown share kind"):
        RecoveryPackage.from_dict(d)


def test_serialized_does_not_leak_secret(package, entropy):
    blob = package.to_json()
    assert entropy.hex() not in blob
    assert entropy not in blob.encode("utf-8")


def test_pin_salt_is_random_per_setup(entropy, contact_key, vault_fp):
    p1 = setup_recovery(
        entropy, card_pin="123456",
        contact_kyber_pk=contact_key.kyber_pk,
        cloud_passphrase="passphrase here",
        vault_fp_hex=vault_fp,
    )
    p2 = setup_recovery(
        entropy, card_pin="123456",
        contact_kyber_pk=contact_key.kyber_pk,
        cloud_passphrase="passphrase here",
        vault_fp_hex=vault_fp,
    )
    s1 = p1.shares[0]; s2 = p2.shares[0]
    assert isinstance(s1, CardPinShare) and isinstance(s2, CardPinShare)
    assert s1.salt != s2.salt
    assert s1.nonce != s2.nonce
    assert s1.ciphertext != s2.ciphertext
    assert p1.group_id != p2.group_id


def test_group_id_canonical_length(package):
    # uuid4 hex = 32 hex chars
    assert len(package.group_id) == 32
    int(package.group_id, 16)  # parses as hex


# ---------------------------------------------------------------------------
# Flexible k-of-n API tests
# ---------------------------------------------------------------------------

class TestFlexibleRecovery:
    def test_3_of_5_mixed_shares(self, entropy, contact_key, vault_fp):
        alice = EopxKey.generate()
        bob = EopxKey.generate()

        pkg = setup_recovery_flexible(
            entropy,
            share_configs=[
                ShareConfig(kind="card_pin", secret="111111"),
                ShareConfig(kind="card_pin", secret="222222"),
                ShareConfig(kind="kyber_pk", recipient_pk=alice.kyber_pk),
                ShareConfig(kind="kyber_pk", recipient_pk=bob.kyber_pk),
                ShareConfig(kind="passphrase", secret="long secret phrase"),
            ],
            vault_fp_hex=vault_fp,
            threshold=3,
        )

        assert pkg.threshold == 3
        assert pkg.total == 5
        assert len(pkg.shares) == 5
        assert isinstance(pkg.shares[0], CardPinShare)
        assert isinstance(pkg.shares[2], KyberShare)
        assert isinstance(pkg.shares[4], PassphraseShare)

        # Recover with shares 1, 3, 5 (PIN + Alice Kyber + passphrase)
        creds = FlexibleCredentials(
            pins={1: "111111"},
            kyber_sks={3: alice.kyber_sk},
            passphrases={5: "long secret phrase"},
        )
        recovered = recover_entropy_flexible(pkg, creds)
        assert recovered == entropy

    def test_2_of_4_all_passphrases(self, entropy, vault_fp):
        pkg = setup_recovery_flexible(
            entropy,
            share_configs=[
                ShareConfig(kind="passphrase", secret="phrase one here"),
                ShareConfig(kind="passphrase", secret="phrase two here"),
                ShareConfig(kind="passphrase", secret="phrase three here"),
                ShareConfig(kind="passphrase", secret="phrase four here"),
            ],
            vault_fp_hex=vault_fp,
            threshold=2,
        )

        assert pkg.threshold == 2
        assert pkg.total == 4

        # Recover with any 2
        creds = FlexibleCredentials(
            passphrases={2: "phrase two here", 4: "phrase four here"},
        )
        recovered = recover_entropy_flexible(pkg, creds)
        assert recovered == entropy

    def test_flexible_rejects_threshold_greater_than_total(self, entropy, vault_fp):
        with pytest.raises(ValueError, match="threshold.*>.*total"):
            setup_recovery_flexible(
                entropy,
                share_configs=[
                    ShareConfig(kind="passphrase", secret="12345678"),
                    ShareConfig(kind="passphrase", secret="87654321"),
                ],
                vault_fp_hex=vault_fp,
                threshold=3,  # > 2 shares
            )

    def test_flexible_rejects_threshold_below_2(self, entropy, vault_fp):
        with pytest.raises(ValueError, match="threshold must be at least 2"):
            setup_recovery_flexible(
                entropy,
                share_configs=[
                    ShareConfig(kind="passphrase", secret="12345678"),
                    ShareConfig(kind="passphrase", secret="87654321"),
                ],
                vault_fp_hex=vault_fp,
                threshold=1,
            )

    def test_flexible_rejects_short_pin(self, entropy, vault_fp):
        with pytest.raises(ValueError, match="card_pin must be >= 4"):
            setup_recovery_flexible(
                entropy,
                share_configs=[
                    ShareConfig(kind="card_pin", secret="123"),  # too short
                    ShareConfig(kind="passphrase", secret="12345678"),
                ],
                vault_fp_hex=vault_fp,
                threshold=2,
            )

    def test_flexible_rejects_short_passphrase(self, entropy, vault_fp):
        with pytest.raises(ValueError, match="passphrase must be >= 8"):
            setup_recovery_flexible(
                entropy,
                share_configs=[
                    ShareConfig(kind="passphrase", secret="short"),  # too short
                    ShareConfig(kind="passphrase", secret="12345678"),
                ],
                vault_fp_hex=vault_fp,
                threshold=2,
            )

    def test_flexible_recovery_not_enough_shares(self, entropy, vault_fp):
        pkg = setup_recovery_flexible(
            entropy,
            share_configs=[
                ShareConfig(kind="passphrase", secret="phrase one here"),
                ShareConfig(kind="passphrase", secret="phrase two here"),
                ShareConfig(kind="passphrase", secret="phrase three here"),
            ],
            vault_fp_hex=vault_fp,
            threshold=2,
        )

        # Provide only 1 credential for threshold=2
        creds = FlexibleCredentials(passphrases={1: "phrase one here"})
        with pytest.raises(ValueError, match="could not open enough shares"):
            recover_entropy_flexible(pkg, creds)

    def test_flexible_wrong_credential_fails(self, entropy, vault_fp):
        pkg = setup_recovery_flexible(
            entropy,
            share_configs=[
                ShareConfig(kind="passphrase", secret="correct phrase here"),
                ShareConfig(kind="passphrase", secret="another phrase here"),
            ],
            vault_fp_hex=vault_fp,
            threshold=2,
        )

        # Wrong passphrase
        creds = FlexibleCredentials(passphrases={1: "wrong phrase", 2: "another phrase here"})
        with pytest.raises(ValueError, match="could not open enough shares"):
            recover_entropy_flexible(pkg, creds)

    def test_flexible_serialization_roundtrip(self, entropy, vault_fp):
        pkg = setup_recovery_flexible(
            entropy,
            share_configs=[
                ShareConfig(kind="card_pin", secret="123456"),
                ShareConfig(kind="passphrase", secret="long passphrase here"),
                ShareConfig(kind="passphrase", secret="another long phrase"),
            ],
            vault_fp_hex=vault_fp,
            threshold=2,
        )

        # Serialize and deserialize
        json_str = pkg.to_json()
        restored = RecoveryPackage.from_json(json_str)

        assert restored.threshold == pkg.threshold
        assert restored.total == pkg.total
        assert len(restored.shares) == len(pkg.shares)

        # Recover from restored package
        creds = FlexibleCredentials(
            pins={1: "123456"},
            passphrases={3: "another long phrase"},
        )
        recovered = recover_entropy_flexible(restored, creds)
        assert recovered == entropy

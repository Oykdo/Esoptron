"""Tests for Protocol F: cross-machine vault migration."""

import secrets
import time

import pytest

from eopx.vault.migrate import (
    CHALLENGE_TTL_SECONDS,
    MigrationChallenge,
    MigrationProof,
    MigrationResult,
    compute_verify_tag,
    new_migration_challenge,
    prove_migration,
    verify_migration,
)


def _random_32() -> bytes:
    return secrets.token_bytes(32)


class TestMigrationChallenge:
    def test_create_challenge(self):
        vault_id = _random_32()
        source = _random_32()
        target = _random_32()

        ch = new_migration_challenge(vault_id, source, target)

        assert ch.vault_id == vault_id
        assert ch.source_lock == source
        assert ch.target_lock == target
        assert len(ch.nonce) == 32
        assert ch.timestamp > 0

    def test_challenge_rejects_bad_lengths(self):
        with pytest.raises(ValueError, match="vault_id"):
            new_migration_challenge(b"short", _random_32(), _random_32())
        with pytest.raises(ValueError, match="source_lock"):
            new_migration_challenge(_random_32(), b"short", _random_32())
        with pytest.raises(ValueError, match="target_lock"):
            new_migration_challenge(_random_32(), _random_32(), b"short")


class TestProveAndVerify:
    def test_roundtrip_success(self):
        master_key = _random_32()
        vault_id = _random_32()
        source_lock = _random_32()
        target_lock = _random_32()

        ch = new_migration_challenge(vault_id, source_lock, target_lock)
        proof = prove_migration(master_key, ch)

        assert proof.vault_id == vault_id
        assert proof.source_lock == source_lock
        assert proof.target_lock == target_lock
        assert len(proof.commitment) == 32
        assert len(proof.response) == 32

        result = verify_migration(proof, master_key, target_lock, check_ttl=False)

        assert result is not None
        assert result.vault_id == vault_id
        assert len(result.machine_bound_key) == 32
        assert len(result.session_key) == 32

    def test_wrong_master_key_fails(self):
        master_key = _random_32()
        wrong_key = _random_32()
        vault_id = _random_32()
        source_lock = _random_32()
        target_lock = _random_32()

        ch = new_migration_challenge(vault_id, source_lock, target_lock)
        proof = prove_migration(master_key, ch)

        result = verify_migration(proof, wrong_key, target_lock, check_ttl=False)
        assert result is None

    def test_wrong_target_fails(self):
        master_key = _random_32()
        vault_id = _random_32()
        source_lock = _random_32()
        target_lock = _random_32()
        wrong_target = _random_32()

        ch = new_migration_challenge(vault_id, source_lock, target_lock)
        proof = prove_migration(master_key, ch)

        result = verify_migration(proof, master_key, wrong_target, check_ttl=False)
        assert result is None

    def test_ttl_expired_fails(self):
        master_key = _random_32()
        vault_id = _random_32()
        source_lock = _random_32()
        target_lock = _random_32()

        ch = MigrationChallenge(
            vault_id=vault_id,
            source_lock=source_lock,
            target_lock=target_lock,
            nonce=secrets.token_bytes(32),
            timestamp=time.time() - CHALLENGE_TTL_SECONDS - 10,
        )
        proof = prove_migration(master_key, ch)

        result = verify_migration(proof, master_key, target_lock, check_ttl=True)
        assert result is None

        # But works with TTL disabled
        result = verify_migration(proof, master_key, target_lock, check_ttl=False)
        assert result is not None

    def test_tampered_commitment_fails(self):
        master_key = _random_32()
        vault_id = _random_32()
        source_lock = _random_32()
        target_lock = _random_32()

        ch = new_migration_challenge(vault_id, source_lock, target_lock)
        proof = prove_migration(master_key, ch)

        # Tamper with commitment
        tampered = MigrationProof(
            vault_id=proof.vault_id,
            source_lock=proof.source_lock,
            target_lock=proof.target_lock,
            nonce=proof.nonce,
            commitment=_random_32(),  # tampered
            response=proof.response,
            timestamp=proof.timestamp,
        )

        result = verify_migration(tampered, master_key, target_lock, check_ttl=False)
        assert result is None

    def test_tampered_response_fails(self):
        master_key = _random_32()
        vault_id = _random_32()
        source_lock = _random_32()
        target_lock = _random_32()

        ch = new_migration_challenge(vault_id, source_lock, target_lock)
        proof = prove_migration(master_key, ch)

        # Tamper with response
        tampered = MigrationProof(
            vault_id=proof.vault_id,
            source_lock=proof.source_lock,
            target_lock=proof.target_lock,
            nonce=proof.nonce,
            commitment=proof.commitment,
            response=_random_32(),  # tampered
            timestamp=proof.timestamp,
        )

        result = verify_migration(tampered, master_key, target_lock, check_ttl=False)
        assert result is None


class TestDeterminism:
    def test_same_inputs_same_proof(self):
        master_key = _random_32()
        vault_id = _random_32()
        source_lock = _random_32()
        target_lock = _random_32()
        nonce = _random_32()
        ts = time.time()

        ch1 = MigrationChallenge(vault_id, source_lock, target_lock, nonce, ts)
        ch2 = MigrationChallenge(vault_id, source_lock, target_lock, nonce, ts)

        proof1 = prove_migration(master_key, ch1)
        proof2 = prove_migration(master_key, ch2)

        assert proof1.commitment == proof2.commitment
        assert proof1.response == proof2.response

    def test_different_nonce_different_proof(self):
        master_key = _random_32()
        vault_id = _random_32()
        source_lock = _random_32()
        target_lock = _random_32()

        ch1 = new_migration_challenge(vault_id, source_lock, target_lock)
        ch2 = new_migration_challenge(vault_id, source_lock, target_lock)

        proof1 = prove_migration(master_key, ch1)
        proof2 = prove_migration(master_key, ch2)

        assert proof1.commitment != proof2.commitment
        assert proof1.response != proof2.response


class TestMachineBinding:
    def test_different_targets_different_keys(self):
        master_key = _random_32()
        vault_id = _random_32()
        source_lock = _random_32()
        target1 = _random_32()
        target2 = _random_32()

        ch1 = new_migration_challenge(vault_id, source_lock, target1)
        ch2 = new_migration_challenge(vault_id, source_lock, target2)

        proof1 = prove_migration(master_key, ch1)
        proof2 = prove_migration(master_key, ch2)

        result1 = verify_migration(proof1, master_key, target1, check_ttl=False)
        result2 = verify_migration(proof2, master_key, target2, check_ttl=False)

        assert result1 is not None
        assert result2 is not None
        assert result1.machine_bound_key != result2.machine_bound_key
        assert result1.session_key != result2.session_key


class TestVerifyTag:
    def test_compute_verify_tag(self):
        master_key = _random_32()
        vault_id = _random_32()

        tag = compute_verify_tag(master_key, vault_id)

        assert len(tag) == 32
        # Same inputs produce same tag
        assert compute_verify_tag(master_key, vault_id) == tag

    def test_different_keys_different_tags(self):
        key1 = _random_32()
        key2 = _random_32()
        vault_id = _random_32()

        assert compute_verify_tag(key1, vault_id) != compute_verify_tag(key2, vault_id)

    def test_timestamp_tampering_rejected(self):
        master_key = _random_32()
        vault_id = _random_32()
        source_lock = _random_32()
        target_lock = _random_32()

        ch = new_migration_challenge(vault_id, source_lock, target_lock)
        proof = prove_migration(master_key, ch)

        tampered = MigrationProof(
            vault_id=proof.vault_id,
            source_lock=proof.source_lock,
            target_lock=proof.target_lock,
            nonce=proof.nonce,
            commitment=proof.commitment,
            response=proof.response,
            timestamp=proof.timestamp + 60.0,
        )
        assert verify_migration(
            tampered, master_key, target_lock, check_ttl=False
        ) is None


class TestSerialization:
    def test_proof_roundtrip(self):
        master_key = _random_32()
        vault_id = _random_32()
        source_lock = _random_32()
        target_lock = _random_32()

        ch = new_migration_challenge(vault_id, source_lock, target_lock)
        proof = prove_migration(master_key, ch)

        d = proof.to_dict()
        restored = MigrationProof.from_dict(d)

        assert restored == proof
        # Verify the restored proof still works
        result = verify_migration(restored, master_key, target_lock, check_ttl=False)
        assert result is not None


class TestEdgeCases:
    def test_prove_rejects_bad_master_key_length(self):
        vault_id = _random_32()
        ch = new_migration_challenge(vault_id, _random_32(), _random_32())

        with pytest.raises(ValueError, match="master_key"):
            prove_migration(b"short", ch)

    def test_verify_rejects_bad_lengths(self):
        master_key = _random_32()
        vault_id = _random_32()
        source_lock = _random_32()
        target_lock = _random_32()

        ch = new_migration_challenge(vault_id, source_lock, target_lock)
        proof = prove_migration(master_key, ch)

        with pytest.raises(ValueError, match="master_key"):
            verify_migration(proof, b"short", target_lock)

        with pytest.raises(ValueError, match="local_machine_lock"):
            verify_migration(proof, master_key, b"short")

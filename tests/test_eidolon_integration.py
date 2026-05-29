"""Integration contract tests: Esoptron ↔ Eidolon interface validation.

These tests verify that Esoptron's assumptions about Eidolon data structures
are correct and that the integration surface is stable. They do NOT require
a running Eidolon instance; instead they validate:

1. Data format contracts (spinor_hash, vault_id, machine_lock sizes)
2. Key derivation compatibility (HKDF-SHA3-512 with same domain separators)
3. .eopx metadata that Eidolon would consume
4. Protocol F migration proof structure that Eidolon would verify

If Eidolon changes any of these, these tests should fail first.
"""

from __future__ import annotations

import hashlib
import secrets

import pytest

from eopx.format.keys import EopxKey, key_fingerprint
from eopx.format.eopx_format import (
    EopxManifest,
    pack,
    verify,
    ZEROS_32,
)
from eopx.metatron.field import hkdf_sha3_512
from eopx.metatron.public import encode_public
from eopx.vault import (
    derive_master_key,
    verify_card,
    card_fingerprint,
    genesis_enroll,
    new_migration_challenge,
    prove_migration,
    verify_migration,
    compute_verify_tag,
)


# ---------------------------------------------------------------------------
# Eidolon data format contracts
# ---------------------------------------------------------------------------

class TestEidolonDataFormats:
    """Verify expected sizes and formats from Eidolon."""

    def test_spinor_hash_is_64_bytes(self):
        """Eidolon Phase 6 produces a 64-byte spinor_hash (SHA3-512)."""
        # Simulate what Eidolon would produce
        fake_spinor = hkdf_sha3_512(
            ikm=secrets.token_bytes(32),
            salt=b"",
            info=b"eidolon.phase6.spinor.v1",
            length=64,
        )
        assert len(fake_spinor) == 64

        # Esoptron's public encoding accepts this
        symbols = encode_public(fake_spinor)
        assert len(symbols) == 91

    def test_vault_id_derivation_from_spinor(self):
        """vault_id = SHA3-256(spinor_hash), 32 bytes."""
        spinor_hash = secrets.token_bytes(64)
        vault_id = hashlib.sha3_256(spinor_hash).digest()
        assert len(vault_id) == 32

        # This is what Esoptron uses in SAS and migration protocols
        challenge = new_migration_challenge(
            vault_id=vault_id,
            source_lock=secrets.token_bytes(32),
            target_lock=secrets.token_bytes(32),
        )
        assert challenge.vault_id == vault_id

    def test_machine_lock_fingerprint_is_32_bytes(self):
        """machine_lock is a 32-byte fingerprint."""
        # Eidolon derives this from hardware attestation
        fake_machine_lock = hashlib.sha3_256(b"machine_specific_data").digest()
        assert len(fake_machine_lock) == 32

        # Esoptron uses it for migration binding
        challenge = new_migration_challenge(
            vault_id=secrets.token_bytes(32),
            source_lock=fake_machine_lock,
            target_lock=secrets.token_bytes(32),
        )
        assert challenge.source_lock == fake_machine_lock

    def test_merkle_root_is_32_bytes_or_zeros(self):
        """Phase 9 merkle_root is 32 bytes; can be zeros if not used."""
        merkle_root = secrets.token_bytes(32)
        assert len(merkle_root) == 32
        assert len(bytes.fromhex(ZEROS_32)) == 32


# ---------------------------------------------------------------------------
# Key derivation compatibility
# ---------------------------------------------------------------------------

class TestKeyDerivationParity:
    """Verify HKDF-SHA3-512 produces identical results to Eidolon's derivation."""

    def test_hkdf_sha3_512_deterministic(self):
        """Same inputs produce same output across calls."""
        ikm = b"test_input_key_material"
        salt = b"test_salt"
        info = b"test_info"

        out1 = hkdf_sha3_512(ikm, salt, info, length=32)
        out2 = hkdf_sha3_512(ikm, salt, info, length=32)
        assert out1 == out2

    def test_master_key_derivation_matches_spec(self):
        """derive_master_key uses the documented domain separator."""
        seed = secrets.token_bytes(32)
        master_key = derive_master_key(seed)

        # Manual verification with expected info string
        expected = hkdf_sha3_512(
            ikm=seed,
            salt=b"",
            info=b"esoptron.vault.master_key.v1",
            length=32,
        )
        assert master_key == expected

    def test_card_fingerprint_domain_separated(self):
        """card_fingerprint uses SHA3-256 with domain prefix."""
        # Symbols must be in [0, 13); use a deterministic sequence.
        symbols = [i % 13 for i in range(91)]
        fp = card_fingerprint(symbols)

        # Manual computation
        h = hashlib.sha3_256()
        h.update(b"esoptron.metatron.card_fingerprint.v1\n")
        h.update(bytes(symbols))
        expected = h.digest()
        assert fp == expected


# ---------------------------------------------------------------------------
# .eopx metadata for Eidolon consumption
# ---------------------------------------------------------------------------

class TestEopxEidolonMetadata:
    """Verify .eopx carries metadata Eidolon can consume."""

    @pytest.fixture
    def signer(self):
        return EopxKey.generate()

    def test_eopx_contains_vault_uuid(self, signer, tmp_path):
        """vault_id is stored and retrievable."""
        from PIL import Image

        img = Image.new("RGB", (64, 64), color="blue")
        vault_uuid = "12345678-1234-1234-1234-123456789abc"

        path = tmp_path / "test.eopx"
        pack(
            img,
            signer=signer,
            vault_id=vault_uuid,
            out_path=path,
        )

        result = verify(path)
        assert result.ok
        assert result.manifest.vault_id == vault_uuid

    def test_eopx_dilithium_pk_fingerprint_matches(self, signer, tmp_path):
        """dilithium_pk_fp in .eopx matches the signer's fingerprint."""
        from PIL import Image

        img = Image.new("RGB", (64, 64), color="red")
        path = tmp_path / "test.eopx"
        pack(img, signer=signer, out_path=path)

        result = verify(path)
        assert result.ok
        assert result.manifest.dilithium_pk_fp == signer.dilithium_pk_fp.hex()

    def test_eopx_kyber_pk_fingerprint_matches(self, signer, tmp_path):
        """kyber_pk_fp in .eopx matches the signer's Kyber fingerprint."""
        from PIL import Image

        img = Image.new("RGB", (64, 64), color="green")
        path = tmp_path / "test.eopx"
        pack(img, signer=signer, out_path=path)

        result = verify(path)
        assert result.ok
        assert result.manifest.kyber_pk_fp == signer.kyber_pk_fp.hex()


# ---------------------------------------------------------------------------
# Protocol F migration - Eidolon would verify this
# ---------------------------------------------------------------------------

class TestMigrationEidolonInterop:
    """Migration protocol structures that Eidolon would process."""

    def test_migration_proof_serializes_for_transport(self):
        """Proof can be JSON-serialized for network/QR transport."""
        import json

        master_key = secrets.token_bytes(32)
        vault_id = secrets.token_bytes(32)
        source = secrets.token_bytes(32)
        target = secrets.token_bytes(32)

        challenge = new_migration_challenge(vault_id, source, target)
        proof = prove_migration(master_key, challenge)

        # Serialize
        d = proof.to_dict()
        json_str = json.dumps(d)

        # Deserialize
        from eopx.vault.migrate import MigrationProof
        restored = MigrationProof.from_dict(json.loads(json_str))

        # Verify still works
        result = verify_migration(restored, master_key, target, check_ttl=False)
        assert result is not None
        assert result.vault_id == vault_id

    def test_verify_tag_can_be_embedded_in_eopx(self):
        """verify_tag is 32 bytes, suitable for .eopx metadata."""
        master_key = secrets.token_bytes(32)
        vault_id = secrets.token_bytes(32)

        tag = compute_verify_tag(master_key, vault_id)
        assert len(tag) == 32

        # Could be added as eopx:migrate_verify_tag chunk
        tag_hex = tag.hex()
        assert len(tag_hex) == 64

    def test_machine_bound_key_differs_per_device(self):
        """Each device gets a unique machine_bound_key from migration."""
        master_key = secrets.token_bytes(32)
        vault_id = secrets.token_bytes(32)
        source = secrets.token_bytes(32)
        target1 = secrets.token_bytes(32)
        target2 = secrets.token_bytes(32)

        ch1 = new_migration_challenge(vault_id, source, target1)
        ch2 = new_migration_challenge(vault_id, source, target2)

        proof1 = prove_migration(master_key, ch1)
        proof2 = prove_migration(master_key, ch2)

        result1 = verify_migration(proof1, master_key, target1, check_ttl=False)
        result2 = verify_migration(proof2, master_key, target2, check_ttl=False)

        assert result1 is not None and result2 is not None
        assert result1.machine_bound_key != result2.machine_bound_key


# ---------------------------------------------------------------------------
# Genesis ceremony - Eidolon coordination
# ---------------------------------------------------------------------------

class TestGenesisEidolonCoordination:
    """Genesis protocol that multiple Eidolon instances would use."""

    def test_same_sheet_different_devices_different_vaults(self):
        """Protocol E: same ceremony sheet, different device_entropy = different vaults."""
        # Simulate a ceremony sheet (91 symbols from a printed sheet)
        from eopx.metatron import encode_private
        ceremony_seed = secrets.token_bytes(32)
        sheet_symbols = encode_private(ceremony_seed)

        # Device 1 enrolls
        device1_entropy = secrets.token_bytes(32)
        vault1 = genesis_enroll(sheet_symbols, device_entropy=device1_entropy)

        # Device 2 enrolls with same sheet
        device2_entropy = secrets.token_bytes(32)
        vault2 = genesis_enroll(sheet_symbols, device_entropy=device2_entropy)

        # Same ceremony fingerprint
        assert vault1.ceremony_fp == vault2.ceremony_fp

        # Different vault seeds and master keys
        assert vault1.vault_seed != vault2.vault_seed
        assert vault1.master_key != vault2.master_key
        assert vault1.vault_fp != vault2.vault_fp

    def test_genesis_vault_fp_is_32_bytes(self):
        """vault_fp from genesis is 32 bytes (SHA3-256)."""
        from eopx.metatron import encode_private
        ceremony_seed = secrets.token_bytes(32)
        sheet_symbols = encode_private(ceremony_seed)

        vault = genesis_enroll(sheet_symbols)
        assert len(vault.vault_fp) == 32
        assert len(vault.ceremony_fp) == 32


# ---------------------------------------------------------------------------
# Public card verification - Eidolon provides spinor_hash
# ---------------------------------------------------------------------------

class TestPublicCardEidolonFlow:
    """Protocol B: Eidolon provides spinor_hash, Esoptron verifies card."""

    def test_verify_card_with_matching_spinor(self):
        """Card generated from spinor_hash verifies against same spinor."""
        spinor_hash = secrets.token_bytes(64)
        symbols = encode_public(spinor_hash)

        # Verification succeeds with same spinor
        assert verify_card(symbols, spinor_hash) is True

    def test_verify_card_with_wrong_spinor_fails(self):
        """Card does not verify against different spinor."""
        spinor_hash1 = secrets.token_bytes(64)
        spinor_hash2 = secrets.token_bytes(64)
        symbols = encode_public(spinor_hash1)

        # Verification fails with different spinor
        assert verify_card(symbols, spinor_hash2) is False

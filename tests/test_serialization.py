"""Tests for ``eopx.server.serialization``.

Verifies that the wire format consumed by the PWA / mobile clients is:
  * stable (key set, hex/list types)
  * safe by default (no secret fields when include_secrets=False)
  * opt-in for secrets (include_secrets=True surfaces them)
  * round-trippable for the public projection
"""

from __future__ import annotations

import json

import pytest

from eopx.flows import Intent, ScanResult
from eopx.server.serialization import (
    enrollment_to_dict,
    extract_result_to_dict,
    genesis_vault_to_dict,
    intent_from_str,
    scan_result_to_dict,
)
from eopx.vault import EnrollmentRecord, GenesisVault


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_enrollment() -> EnrollmentRecord:
    return EnrollmentRecord(
        vault_fp=b"\xa1" * 32,
        device_secret=b"\xde" * 32,
        enrollment_fp=b"\xb2" * 32,
        public_tag=b"\xc3" * 16,
        shadow_hologram=b"\xd4" * 64,
    )


@pytest.fixture
def sample_genesis() -> GenesisVault:
    return GenesisVault(
        ceremony_fp=b"\x11" * 32,
        device_entropy=b"\x22" * 32,
        vault_seed=b"\x33" * 32,
        master_key=b"\x44" * 32,
        vault_fp=b"\x55" * 32,
    )


# ---------------------------------------------------------------------------
# enrollment_to_dict
# ---------------------------------------------------------------------------

class TestEnrollmentSerialization:
    def test_public_view_omits_secrets(self, sample_enrollment):
        d = enrollment_to_dict(sample_enrollment)
        assert set(d.keys()) == {
            "vault_fp_hex", "enrollment_fp_hex",
            "public_tag_hex", "shadow_hologram_hex",
        }
        # No secret bytes should appear in the serialized form.
        assert "device_secret" not in d
        assert "device_secret_hex" not in d
        assert "de" * 32 not in json.dumps(d)

    def test_secret_view_includes_device_secret(self, sample_enrollment):
        d = enrollment_to_dict(sample_enrollment, include_secrets=True)
        assert d["device_secret_hex"] == "de" * 32

    def test_hex_encoding_is_lowercase(self, sample_enrollment):
        d = enrollment_to_dict(sample_enrollment)
        for v in d.values():
            assert v == v.lower(), f"hex must be lowercase: {v}"

    def test_json_roundtrip(self, sample_enrollment):
        d = enrollment_to_dict(sample_enrollment)
        as_json = json.dumps(d)
        back = json.loads(as_json)
        assert back == d


# ---------------------------------------------------------------------------
# genesis_vault_to_dict
# ---------------------------------------------------------------------------

class TestGenesisSerialization:
    def test_public_view_omits_secrets(self, sample_genesis):
        d = genesis_vault_to_dict(sample_genesis)
        assert set(d.keys()) == {"ceremony_fp_hex", "vault_fp_hex"}
        assert "33" * 32 not in json.dumps(d)
        assert "44" * 32 not in json.dumps(d)

    def test_secret_view_includes_seed_master_entropy(self, sample_genesis):
        d = genesis_vault_to_dict(sample_genesis, include_secrets=True)
        assert d["vault_seed_hex"] == "33" * 32
        assert d["master_key_hex"] == "44" * 32
        assert d["device_entropy_hex"] == "22" * 32


# ---------------------------------------------------------------------------
# scan_result_to_dict
# ---------------------------------------------------------------------------

class TestScanResultSerialization:
    def test_minimal_failure_result(self):
        r = ScanResult(success=False, errors=["detection_failed"])
        d = scan_result_to_dict(r)
        assert d["success"] is False
        assert d["intent"] is None
        assert d["errors"] == ["detection_failed"]
        assert "card_fingerprint_hex" in d
        assert d["card_fingerprint_hex"] is None

    def test_verify_intent_no_secrets(self):
        r = ScanResult(
            success=True,
            intent=Intent.VERIFY,
            verify_ok=True,
            card_fingerprint_hex="ab" * 32,
            detection_method="cube",
            markers_used=4,
        )
        d = scan_result_to_dict(r)
        assert d["success"] is True
        assert d["intent"] == "verify"
        assert d["verify_ok"] is True
        assert d["detection_method"] == "cube"
        assert d["markers_used"] == 4
        # No symbols leaked by default.
        assert "symbols" not in d
        assert "session_key_hex" not in d

    def test_unlock_with_secrets(self):
        r = ScanResult(
            success=True,
            intent=Intent.UNLOCK,
            session_key=b"\x01" * 32,
        )
        public = scan_result_to_dict(r)
        assert "session_key_hex" not in public, "session_key must be opt-in"
        secret = scan_result_to_dict(r, include_secrets=True)
        assert secret["session_key_hex"] == "01" * 32

    def test_unlock_private_with_secrets(self):
        r = ScanResult(
            success=True,
            intent=Intent.UNLOCK_PRIVATE,
            vault_seed=b"\x02" * 32,
            vault_master_key=b"\x03" * 32,
            symbols=[0, 1, 2, 3],
        )
        public = scan_result_to_dict(r)
        assert "vault_seed_hex" not in public
        assert "vault_master_key_hex" not in public
        # symbols are gated as secrets too
        assert "symbols" not in public

        secret = scan_result_to_dict(r, include_secrets=True)
        assert secret["vault_seed_hex"] == "02" * 32
        assert secret["vault_master_key_hex"] == "03" * 32
        assert secret["symbols"] == [0, 1, 2, 3]

    def test_enrollment_secret_propagates(self, sample_enrollment):
        r = ScanResult(
            success=True,
            intent=Intent.ENROLL,
            enrollment=sample_enrollment,
            recovery_phrase=["alpha", "beta", "gamma"],
        )
        d_public = scan_result_to_dict(r)
        assert d_public["recovery_phrase"] == ["alpha", "beta", "gamma"]
        # nested enrollment must not leak device_secret when not opted in
        assert "device_secret_hex" not in d_public["enrollment"]

        d_secret = scan_result_to_dict(r, include_secrets=True)
        assert "device_secret_hex" in d_secret["enrollment"]

    def test_genesis_nested(self, sample_genesis):
        r = ScanResult(
            success=True,
            intent=Intent.GENESIS,
            genesis_vault=sample_genesis,
        )
        d = scan_result_to_dict(r, include_secrets=True)
        assert d["genesis_vault"]["vault_seed_hex"] == "33" * 32
        assert d["genesis_vault"]["master_key_hex"] == "44" * 32

    def test_intent_serialization_uses_enum_value(self):
        for intent in Intent:
            r = ScanResult(success=True, intent=intent)
            d = scan_result_to_dict(r)
            assert d["intent"] == intent.value


# ---------------------------------------------------------------------------
# extract_result_to_dict
# ---------------------------------------------------------------------------

class TestExtractResultSerialization:
    def test_basic_shape(self):
        r = ScanResult(
            success=True,
            card_fingerprint_hex="ff" * 32,
            symbols=[1, 2, 3, 4, 5],
            detection_method="cube",
            markers_used=4,
        )
        d = extract_result_to_dict(r)
        assert d == {
            "success": True,
            "card_fingerprint_hex": "ff" * 32,
            "symbols": [1, 2, 3, 4, 5],
            "detection_method": "cube",
            "markers_used": 4,
            "errors": [],
        }

    def test_symbols_optional(self):
        r = ScanResult(success=False, errors=["no_card"])
        d = extract_result_to_dict(r)
        assert d["symbols"] is None
        assert d["errors"] == ["no_card"]


# ---------------------------------------------------------------------------
# intent_from_str
# ---------------------------------------------------------------------------

class TestIntentParsing:
    def test_each_intent_parses(self):
        for intent in Intent:
            assert intent_from_str(intent.value) == intent

    def test_case_insensitive(self):
        assert intent_from_str("VERIFY") == Intent.VERIFY
        assert intent_from_str("EnRolL") == Intent.ENROLL

    def test_unknown_raises_with_valid_list(self):
        with pytest.raises(ValueError) as exc:
            intent_from_str("transmute")
        msg = str(exc.value)
        assert "transmute" in msg
        assert "verify" in msg
        assert "enroll" in msg


# ---------------------------------------------------------------------------
# Stability of the public projection
# ---------------------------------------------------------------------------

class TestStability:
    def test_public_enrollment_keys_are_frozen(self, sample_enrollment):
        """If new public keys are added to the schema, ack here intentionally."""
        d = enrollment_to_dict(sample_enrollment)
        expected = frozenset({
            "vault_fp_hex", "enrollment_fp_hex",
            "public_tag_hex", "shadow_hologram_hex",
        })
        assert frozenset(d.keys()) == expected, (
            f"public enrollment schema changed: {set(d.keys())} vs {set(expected)}"
        )

    def test_public_genesis_keys_are_frozen(self, sample_genesis):
        d = genesis_vault_to_dict(sample_genesis)
        expected = frozenset({"ceremony_fp_hex", "vault_fp_hex"})
        assert frozenset(d.keys()) == expected

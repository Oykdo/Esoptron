"""Tests for Protocol G — Identity Reclaim (``eopx.vault.reclaim``).

Covers:
  * ReclaimClaim wire format invariants (binary + JSON, size, version)
  * Bit-for-bit reproduction of the original EnrollmentRecord (Path P)
  * Roundtrip via Shamir shards (Path S) producing the same enrollment
  * HMAC verification: correct device_secret accepts, wrong rejects
  * Tamper detection: mutating any byte breaks verification
  * TTL / replay: stale claims rejected
  * Fingerprint pinning: enrollment_fp / vault_fp mismatch rejected
  * Wire roundtrip: to_bytes/from_bytes, to_dict/from_dict
"""

from __future__ import annotations

import json
import struct
import time

import pytest

from eopx.recovery import (
    FlexibleCredentials,
    ShareConfig,
    setup_recovery_flexible,
)
from eopx.vault import (
    NO_TARGET_CONTEXT,
    PATH_OTHER,
    PATH_PHRASE,
    PATH_SHARDS,
    RECLAIM_CLAIM_VERSION,
    ReclaimClaim,
    enroll_from_card,
    reclaim_from_entropy,
    reclaim_from_phrase,
    reclaim_from_shards,
    verify_reclaim,
)
from eopx.vault.genesis import entropy_to_recovery_phrase
from eopx.vault.reclaim import (
    CLAIM_BINARY_SIZE,
    FP_BYTES,
    _compute_claim_id,
    _compute_claim_tag,
)


# ---------------------------------------------------------------------------
# Deterministic fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def card_symbols():
    return [i % 13 for i in range(91)]


@pytest.fixture
def device_entropy():
    return b"\x00" * 32


@pytest.fixture
def reference_enrollment(card_symbols, device_entropy):
    return enroll_from_card(card_symbols, device_entropy=device_entropy)


@pytest.fixture
def fixed_nonce():
    return b"\xab" * 32


@pytest.fixture
def fixed_timestamp():
    return 1_748_620_800  # 2025-05-30T16:00:00Z


# ---------------------------------------------------------------------------
# Path P — BIP-39 phrase reclaim
# ---------------------------------------------------------------------------

class TestPathPhrase:
    def test_reproduces_original_enrollment(self, card_symbols, device_entropy,
                                             reference_enrollment):
        phrase = entropy_to_recovery_phrase(device_entropy)
        rederived, _claim = reclaim_from_phrase(card_symbols, phrase)
        # Every field MUST match bit-for-bit.
        assert rederived.vault_fp == reference_enrollment.vault_fp
        assert rederived.device_secret == reference_enrollment.device_secret
        assert rederived.enrollment_fp == reference_enrollment.enrollment_fp
        assert rederived.public_tag == reference_enrollment.public_tag
        assert rederived.shadow_hologram == reference_enrollment.shadow_hologram

    def test_claim_path_label(self, card_symbols, device_entropy):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(card_symbols, phrase)
        assert claim.path == PATH_PHRASE

    def test_invalid_phrase_rejected(self, card_symbols):
        with pytest.raises(ValueError):
            reclaim_from_phrase(card_symbols, ["not", "a", "real", "phrase"])

    def test_wrong_card_yields_different_enrollment(self, device_entropy):
        phrase = entropy_to_recovery_phrase(device_entropy)
        good_card = [i % 13 for i in range(91)]
        bad_card = [(i + 1) % 13 for i in range(91)]
        _, claim_good = reclaim_from_phrase(good_card, phrase, nonce=b"\x01" * 32,
                                             timestamp=1)
        _, claim_bad = reclaim_from_phrase(bad_card, phrase, nonce=b"\x01" * 32,
                                            timestamp=1)
        assert claim_good.enrollment_fp != claim_bad.enrollment_fp
        assert claim_good.vault_fp != claim_bad.vault_fp


# ---------------------------------------------------------------------------
# Path S — Shamir shard quorum reclaim
# ---------------------------------------------------------------------------

class TestPathShards:
    @pytest.fixture
    def recovery_package(self, device_entropy):
        return setup_recovery_flexible(
            device_entropy,
            share_configs=[
                ShareConfig(kind="card_pin", secret="123456"),
                ShareConfig(kind="card_pin", secret="654321"),
                ShareConfig(kind="passphrase", secret="long backup passphrase here"),
            ],
            vault_fp_hex="ab" * 32,
            threshold=2,
            group_id="testgrouphexstring0123456789abcd",
        )

    def test_reproduces_original_enrollment(self, card_symbols,
                                             reference_enrollment,
                                             recovery_package):
        creds = FlexibleCredentials(pins={1: "123456", 2: "654321"})
        rederived, claim = reclaim_from_shards(
            card_symbols, recovery_package, creds,
        )
        assert rederived.device_secret == reference_enrollment.device_secret
        assert rederived.enrollment_fp == reference_enrollment.enrollment_fp
        assert claim.path == PATH_SHARDS

    def test_insufficient_shards_fails(self, card_symbols, recovery_package):
        creds = FlexibleCredentials(pins={1: "123456"})  # 1 < threshold=2
        with pytest.raises(ValueError):
            reclaim_from_shards(card_symbols, recovery_package, creds)


# ---------------------------------------------------------------------------
# ReclaimClaim wire format
# ---------------------------------------------------------------------------

class TestWireFormat:
    @pytest.fixture
    def sample_claim(self, card_symbols, device_entropy, fixed_nonce, fixed_timestamp):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(
            card_symbols, phrase,
            nonce=fixed_nonce, timestamp=fixed_timestamp,
        )
        return claim

    def test_binary_size_is_201(self, sample_claim):
        assert CLAIM_BINARY_SIZE == 201
        assert len(sample_claim.to_bytes()) == 201

    def test_binary_roundtrip(self, sample_claim):
        raw = sample_claim.to_bytes()
        decoded = ReclaimClaim.from_bytes(raw, path=sample_claim.path)
        assert decoded.to_bytes() == raw
        assert decoded.version == sample_claim.version
        assert decoded.enrollment_fp == sample_claim.enrollment_fp
        assert decoded.vault_fp == sample_claim.vault_fp
        assert decoded.target_context == sample_claim.target_context
        assert decoded.nonce == sample_claim.nonce
        assert decoded.timestamp == sample_claim.timestamp
        assert decoded.claim_id == sample_claim.claim_id
        assert decoded.claim_tag == sample_claim.claim_tag

    def test_binary_rejects_wrong_length(self):
        with pytest.raises(ValueError):
            ReclaimClaim.from_bytes(b"\x01" * 200)
        with pytest.raises(ValueError):
            ReclaimClaim.from_bytes(b"\x01" * 202)

    def test_json_roundtrip(self, sample_claim):
        d = sample_claim.to_dict()
        as_json = json.dumps(d)
        decoded = ReclaimClaim.from_dict(json.loads(as_json))
        assert decoded.to_bytes() == sample_claim.to_bytes()
        assert decoded.path == sample_claim.path

    def test_json_type_field(self, sample_claim):
        assert sample_claim.to_dict()["type"] == "epx-g.reclaim_claim.v1"

    def test_json_rejects_wrong_type(self, sample_claim):
        d = sample_claim.to_dict()
        d["type"] = "something.else"
        with pytest.raises(ValueError):
            ReclaimClaim.from_dict(d)

    def test_version_byte_pinned(self, sample_claim):
        assert sample_claim.to_bytes()[0] == RECLAIM_CLAIM_VERSION

    def test_construct_with_wrong_version_rejected(self, sample_claim):
        with pytest.raises(ValueError):
            ReclaimClaim(
                version=2,
                enrollment_fp=sample_claim.enrollment_fp,
                vault_fp=sample_claim.vault_fp,
                target_context=sample_claim.target_context,
                nonce=sample_claim.nonce,
                timestamp=sample_claim.timestamp,
                claim_id=sample_claim.claim_id,
                claim_tag=sample_claim.claim_tag,
            )

    @pytest.mark.parametrize("field, bad", [
        ("enrollment_fp", b"\x00" * 31),
        ("vault_fp", b"\x00" * 33),
        ("nonce", b"\x00" * 16),
        ("target_context", b"\x00" * 30),
        ("claim_id", b"\x00" * 31),
        ("claim_tag", b"\x00" * 31),
    ])
    def test_field_length_enforced(self, sample_claim, field, bad):
        kwargs = sample_claim.to_dict()
        kwargs.pop("type", None)
        kwargs.pop("path", None)
        # Build a kwarg dict matching ReclaimClaim signature, with one bad field.
        clean = {
            "version": sample_claim.version,
            "enrollment_fp": sample_claim.enrollment_fp,
            "vault_fp": sample_claim.vault_fp,
            "target_context": sample_claim.target_context,
            "nonce": sample_claim.nonce,
            "timestamp": sample_claim.timestamp,
            "claim_id": sample_claim.claim_id,
            "claim_tag": sample_claim.claim_tag,
        }
        clean[field] = bad
        with pytest.raises(ValueError):
            ReclaimClaim(**clean)


# ---------------------------------------------------------------------------
# Verification — happy path + threat-model rejections
# ---------------------------------------------------------------------------

class TestVerification:
    def test_correct_device_secret_accepts(self, card_symbols, device_entropy,
                                            reference_enrollment, fixed_nonce,
                                            fixed_timestamp):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(
            card_symbols, phrase,
            nonce=fixed_nonce, timestamp=fixed_timestamp,
        )
        assert verify_reclaim(
            claim, reference_enrollment.device_secret,
            now=fixed_timestamp,
        ) is True

    def test_wrong_device_secret_rejects(self, card_symbols, device_entropy,
                                          fixed_nonce, fixed_timestamp):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(
            card_symbols, phrase,
            nonce=fixed_nonce, timestamp=fixed_timestamp,
        )
        assert verify_reclaim(
            claim, b"\xff" * 32, now=fixed_timestamp,
        ) is False

    def test_expired_claim_rejected(self, card_symbols, device_entropy,
                                     reference_enrollment, fixed_nonce):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(
            card_symbols, phrase, nonce=fixed_nonce, timestamp=1000,
        )
        # 'now' is well past TTL=600
        assert verify_reclaim(
            claim, reference_enrollment.device_secret,
            now=1000 + 601,
        ) is False

    def test_future_claim_rejected(self, card_symbols, device_entropy,
                                    reference_enrollment, fixed_nonce):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(
            card_symbols, phrase, nonce=fixed_nonce, timestamp=10_000,
        )
        # 'now' too far in the past relative to claim
        assert verify_reclaim(
            claim, reference_enrollment.device_secret,
            now=10_000 - 601,
        ) is False

    def test_custom_ttl(self, card_symbols, device_entropy, reference_enrollment,
                        fixed_nonce):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(
            card_symbols, phrase, nonce=fixed_nonce, timestamp=1000,
        )
        assert verify_reclaim(
            claim, reference_enrollment.device_secret,
            now=2000, ttl=2000,
        ) is True

    def test_enrollment_fp_pin(self, card_symbols, device_entropy,
                                reference_enrollment, fixed_timestamp):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(
            card_symbols, phrase, timestamp=fixed_timestamp,
        )
        # Correct pin
        assert verify_reclaim(
            claim, reference_enrollment.device_secret,
            enrollment_fp=reference_enrollment.enrollment_fp,
            now=fixed_timestamp,
        ) is True
        # Wrong pin
        assert verify_reclaim(
            claim, reference_enrollment.device_secret,
            enrollment_fp=b"\x00" * 32,
            now=fixed_timestamp,
        ) is False

    def test_vault_fp_pin(self, card_symbols, device_entropy,
                           reference_enrollment, fixed_timestamp):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(
            card_symbols, phrase, timestamp=fixed_timestamp,
        )
        assert verify_reclaim(
            claim, reference_enrollment.device_secret,
            vault_fp=reference_enrollment.vault_fp,
            now=fixed_timestamp,
        ) is True
        assert verify_reclaim(
            claim, reference_enrollment.device_secret,
            vault_fp=b"\x00" * 32,
            now=fixed_timestamp,
        ) is False


# ---------------------------------------------------------------------------
# Tamper detection — every byte of the message body must matter
# ---------------------------------------------------------------------------

class TestTamperDetection:
    def test_each_byte_of_tag_matters(self, card_symbols, device_entropy,
                                       reference_enrollment, fixed_nonce,
                                       fixed_timestamp):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(
            card_symbols, phrase, nonce=fixed_nonce, timestamp=fixed_timestamp,
        )
        raw = bytearray(claim.to_bytes())
        # Flip one bit in claim_tag (last 32 bytes).
        for i in (raw.__len__() - 1, raw.__len__() - 16, raw.__len__() - 32):
            mutated = bytearray(raw)
            mutated[i] ^= 0x01
            tampered = ReclaimClaim.from_bytes(bytes(mutated), path=claim.path)
            assert verify_reclaim(
                tampered, reference_enrollment.device_secret,
                now=fixed_timestamp,
            ) is False

    def test_tampering_nonce_breaks(self, card_symbols, device_entropy,
                                     reference_enrollment, fixed_timestamp):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(
            card_symbols, phrase, nonce=b"\xab" * 32, timestamp=fixed_timestamp,
        )
        tampered = ReclaimClaim(
            version=claim.version,
            enrollment_fp=claim.enrollment_fp,
            vault_fp=claim.vault_fp,
            target_context=claim.target_context,
            nonce=b"\xac" * 32,           # different nonce → claim_id mismatch
            timestamp=claim.timestamp,
            claim_id=claim.claim_id,
            claim_tag=claim.claim_tag,
            path=claim.path,
        )
        assert verify_reclaim(
            tampered, reference_enrollment.device_secret,
            now=fixed_timestamp,
        ) is False

    def test_tampering_timestamp_breaks(self, card_symbols, device_entropy,
                                         reference_enrollment, fixed_nonce):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(
            card_symbols, phrase, nonce=fixed_nonce, timestamp=1000,
        )
        tampered = ReclaimClaim(
            version=claim.version,
            enrollment_fp=claim.enrollment_fp,
            vault_fp=claim.vault_fp,
            target_context=claim.target_context,
            nonce=claim.nonce,
            timestamp=1001,               # bumped — claim_id mismatch
            claim_id=claim.claim_id,
            claim_tag=claim.claim_tag,
        )
        # Use ttl large enough to skip the freshness gate.
        assert verify_reclaim(
            tampered, reference_enrollment.device_secret,
            now=1001, ttl=10_000,
        ) is False


# ---------------------------------------------------------------------------
# target_context behaviour
# ---------------------------------------------------------------------------

class TestTargetContext:
    def test_default_context_is_deterministic(self, card_symbols, device_entropy):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, c1 = reclaim_from_phrase(card_symbols, phrase,
                                     nonce=b"\x01" * 32, timestamp=1)
        _, c2 = reclaim_from_phrase(card_symbols, phrase,
                                     nonce=b"\x01" * 32, timestamp=1)
        assert c1.target_context == c2.target_context == NO_TARGET_CONTEXT
        # Equal inputs → equal claims (deterministic).
        assert c1.to_bytes() == c2.to_bytes()

    def test_explicit_context_changes_claim_id(self, card_symbols, device_entropy,
                                                fixed_nonce, fixed_timestamp):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, c1 = reclaim_from_phrase(card_symbols, phrase,
                                     nonce=fixed_nonce, timestamp=fixed_timestamp)
        _, c2 = reclaim_from_phrase(card_symbols, phrase,
                                     nonce=fixed_nonce, timestamp=fixed_timestamp,
                                     target_context=b"\x42" * 32)
        assert c1.target_context != c2.target_context
        assert c1.claim_id != c2.claim_id
        assert c1.claim_tag != c2.claim_tag

    def test_bad_context_length_rejected(self, card_symbols, device_entropy):
        phrase = entropy_to_recovery_phrase(device_entropy)
        with pytest.raises(ValueError):
            reclaim_from_phrase(card_symbols, phrase,
                                 target_context=b"\x00" * 31)


# ---------------------------------------------------------------------------
# Path-agnosticism: phrase vs entropy paths must produce equal claims
# ---------------------------------------------------------------------------

class TestPathAgnosticism:
    def test_phrase_vs_entropy_produce_same_message_body(
            self, card_symbols, device_entropy, fixed_nonce, fixed_timestamp):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, c_phrase = reclaim_from_phrase(
            card_symbols, phrase,
            nonce=fixed_nonce, timestamp=fixed_timestamp,
        )
        _, c_entropy = reclaim_from_entropy(
            card_symbols, device_entropy,
            nonce=fixed_nonce, timestamp=fixed_timestamp,
        )
        # Only the documentary ``path`` field differs.
        assert c_phrase.enrollment_fp == c_entropy.enrollment_fp
        assert c_phrase.vault_fp == c_entropy.vault_fp
        assert c_phrase.claim_id == c_entropy.claim_id
        assert c_phrase.claim_tag == c_entropy.claim_tag
        # Binary message body equal (everything except `path` is in to_bytes).
        assert c_phrase.to_bytes() == c_entropy.to_bytes()


# ---------------------------------------------------------------------------
# Internal primitives — match spec §3.3
# ---------------------------------------------------------------------------

class TestPrimitives:
    def test_claim_id_deterministic(self):
        a = _compute_claim_id(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, 1234)
        b = _compute_claim_id(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, 1234)
        assert a == b
        assert len(a) == 32

    def test_claim_id_changes_with_any_input(self):
        base = _compute_claim_id(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, 1234)
        assert base != _compute_claim_id(b"\x99" * 32, b"\x02" * 32, b"\x03" * 32, 1234)
        assert base != _compute_claim_id(b"\x01" * 32, b"\x99" * 32, b"\x03" * 32, 1234)
        assert base != _compute_claim_id(b"\x01" * 32, b"\x02" * 32, b"\x99" * 32, 1234)
        assert base != _compute_claim_id(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, 1235)

    def test_claim_tag_uses_hmac_sha3_256(self):
        secret = b"\x42" * 32
        cid = b"\x11" * 32
        tag = _compute_claim_tag(secret, cid)
        assert len(tag) == 32
        # Different key → different tag.
        assert tag != _compute_claim_tag(b"\xff" * 32, cid)
        # Different claim_id → different tag.
        assert tag != _compute_claim_tag(secret, b"\x22" * 32)


# ---------------------------------------------------------------------------
# Constructor / API edge cases
# ---------------------------------------------------------------------------

class TestApiEdgeCases:
    def test_wrong_card_length_rejected(self, device_entropy):
        phrase = entropy_to_recovery_phrase(device_entropy)
        with pytest.raises(ValueError):
            reclaim_from_phrase([0] * 90, phrase)

    def test_wrong_entropy_length_rejected(self, card_symbols):
        with pytest.raises(ValueError):
            reclaim_from_entropy(card_symbols, b"\x00" * 31)

    def test_verify_requires_32_byte_secret(self, card_symbols, device_entropy,
                                              reference_enrollment, fixed_timestamp):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(card_symbols, phrase,
                                         timestamp=fixed_timestamp)
        with pytest.raises(ValueError):
            verify_reclaim(claim, b"\x00" * 31, now=fixed_timestamp)

    def test_negative_ttl_rejected(self, card_symbols, device_entropy,
                                    reference_enrollment, fixed_timestamp):
        phrase = entropy_to_recovery_phrase(device_entropy)
        _, claim = reclaim_from_phrase(card_symbols, phrase,
                                         timestamp=fixed_timestamp)
        with pytest.raises(ValueError):
            verify_reclaim(claim, reference_enrollment.device_secret,
                            now=fixed_timestamp, ttl=-1)

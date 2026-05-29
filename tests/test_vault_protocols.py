"""End-to-end tests for the four vault protocols A, B, C, D."""

from __future__ import annotations

import hashlib

import pytest

from eopx.metatron import (
    encode_public, encode_private, render, extract_canonical,
)
from eopx.vault import (
    unlock_from_private_symbols, unlock_from_seed, derive_master_key,
    verify_card, card_fingerprint,
    new_challenge, respond, verify_response,
    enroll_from_card, derive_shadow_hologram,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed(passphrase: str) -> bytes:
    return hashlib.sha3_256(passphrase.encode()).digest()


def _spinor(passphrase: str) -> bytes:
    return hashlib.sha3_512(passphrase.encode()).digest()


# ---------------------------------------------------------------------------
# Protocol A
# ---------------------------------------------------------------------------

class TestProtocolA:
    def test_unlock_from_seed_is_deterministic(self):
        s = _seed("alpha")
        k1 = unlock_from_seed(s)
        k2 = unlock_from_seed(s)
        assert k1 == k2 and len(k1) == 32

    def test_unlock_from_seed_changes_with_seed(self):
        assert unlock_from_seed(_seed("a")) != unlock_from_seed(_seed("b"))

    def test_end_to_end_private_sheet(self):
        s = _seed("vault.test")
        syms = encode_private(s)
        seed_back, master = unlock_from_private_symbols(syms)
        assert seed_back == s
        assert master == derive_master_key(s)

    def test_end_to_end_via_rendered_image(self):
        """Render -> extract_canonical -> unlock, must round-trip."""
        s = _seed("vault.canonical.roundtrip")
        syms = encode_private(s)
        img = render(syms, size=1024)
        recovered, _dists = extract_canonical(img)
        assert recovered == list(syms)
        seed_back, _master = unlock_from_private_symbols(recovered)
        assert seed_back == s


# ---------------------------------------------------------------------------
# Protocol B
# ---------------------------------------------------------------------------

class TestProtocolB:
    def test_card_matches_local_vault(self):
        spinor = _spinor("vault.match")
        syms = encode_public(spinor)
        assert verify_card(syms, spinor) is True

    def test_card_rejects_other_vault(self):
        spinor_a = _spinor("vault.a")
        spinor_b = _spinor("vault.b")
        syms_a = encode_public(spinor_a)
        assert verify_card(syms_a, spinor_b) is False

    def test_card_fingerprint_is_stable(self):
        syms = encode_public(_spinor("fp.stability"))
        assert card_fingerprint(syms) == card_fingerprint(syms)

    def test_card_fingerprint_distinguishes_inputs(self):
        a = card_fingerprint(encode_public(_spinor("fp.a")))
        b = card_fingerprint(encode_public(_spinor("fp.b")))
        assert a != b

    def test_rejects_wrong_symbol_length(self):
        with pytest.raises(ValueError):
            verify_card([0] * 90, _spinor("x"))


# ---------------------------------------------------------------------------
# Protocol C
# ---------------------------------------------------------------------------

class TestProtocolC:
    def _setup(self):
        spinor = _spinor("vault.sas.test")
        syms = encode_public(spinor)
        vault_id = hashlib.sha3_256(spinor).digest()
        challenge = new_challenge(vault_id, nonce=b"\x42" * 32,
                                    issued_at=1_000_000.0)
        return spinor, syms, challenge

    def test_happy_path(self):
        spinor, syms, challenge = self._setup()
        resp = respond(syms, spinor, challenge)
        session = verify_response(resp, spinor, syms, now=1_000_001.0)
        assert session is not None and len(session) == 32

    def test_wrong_card_rejected_at_respond(self):
        spinor, _syms, challenge = self._setup()
        other_syms = encode_public(_spinor("vault.other"))
        with pytest.raises(ValueError):
            respond(other_syms, spinor, challenge)

    def test_replay_outside_ttl_fails(self):
        spinor, syms, challenge = self._setup()
        resp = respond(syms, spinor, challenge)
        # 1 day later
        assert verify_response(resp, spinor, syms,
                                now=1_000_000.0 + 86_400.0) is None

    def test_tampered_tag_rejected(self):
        spinor, syms, challenge = self._setup()
        resp = respond(syms, spinor, challenge)
        bad = resp.__class__(challenge=resp.challenge, card_fp=resp.card_fp,
                              tag=b"\x00" * 32)
        assert verify_response(bad, spinor, syms, now=1_000_001.0) is None

    def test_session_key_changes_with_nonce(self):
        spinor = _spinor("vault.sas.nonces")
        syms = encode_public(spinor)
        vault_id = hashlib.sha3_256(spinor).digest()
        c1 = new_challenge(vault_id, nonce=b"\x01" * 32, issued_at=1_000.0)
        c2 = new_challenge(vault_id, nonce=b"\x02" * 32, issued_at=1_000.0)
        s1 = verify_response(respond(syms, spinor, c1), spinor, syms, now=1_001.0)
        s2 = verify_response(respond(syms, spinor, c2), spinor, syms, now=1_001.0)
        assert s1 is not None and s2 is not None
        assert s1 != s2


# ---------------------------------------------------------------------------
# Protocol D
# ---------------------------------------------------------------------------

class TestProtocolD:
    def test_enroll_is_deterministic_given_entropy(self):
        syms = encode_public(_spinor("issuer.card"))
        e = b"\x07" * 32
        r1 = enroll_from_card(syms, device_entropy=e)
        r2 = enroll_from_card(syms, device_entropy=e)
        assert r1 == r2

    def test_same_card_different_devices_yields_different_holograms(self):
        syms = encode_public(_spinor("issuer.card"))
        r1 = enroll_from_card(syms, device_entropy=b"\x01" * 32)
        r2 = enroll_from_card(syms, device_entropy=b"\x02" * 32)
        # Same public card so the vault fingerprint is shared:
        assert r1.vault_fp == r2.vault_fp
        # but enrollment_fp is UNIQUE per device:
        assert r1.enrollment_fp != r2.enrollment_fp
        # and every other field must diverge:
        assert r1.device_secret != r2.device_secret
        assert r1.public_tag != r2.public_tag
        assert r1.shadow_hologram != r2.shadow_hologram

    def test_different_cards_yield_different_fingerprints(self):
        s1 = encode_public(_spinor("issuer.a"))
        s2 = encode_public(_spinor("issuer.b"))
        e = b"\xa5" * 32
        assert (enroll_from_card(s1, device_entropy=e).vault_fp
                != enroll_from_card(s2, device_entropy=e).vault_fp)

    def test_device_secret_never_in_public_dict(self):
        syms = encode_public(_spinor("issuer.x"))
        rec = enroll_from_card(syms, device_entropy=b"\xee" * 32)
        pub = rec.to_public_dict()
        assert rec.device_secret.hex() not in str(pub)

    def test_shadow_hologram_length(self):
        fp = b"\xa3" * 32
        e = b"\x91" * 32
        h = derive_shadow_hologram(fp, e)
        assert len(h) == 64


# ---------------------------------------------------------------------------
# Full chain: card on disk -> scan -> open
# ---------------------------------------------------------------------------

class TestFullChain:
    def test_private_sheet_full_chain(self):
        s = _seed("full.chain.private")
        cw = encode_private(s)
        img = render(cw, size=1024)
        recovered, _ = extract_canonical(img)
        assert recovered == list(cw)
        seed_back, master_key = unlock_from_private_symbols(recovered)
        assert seed_back == s and len(master_key) == 32

    def test_public_card_full_chain(self):
        spinor = _spinor("full.chain.public")
        cw = encode_public(spinor)
        img = render(cw, size=1024)
        recovered, _ = extract_canonical(img)
        assert verify_card(recovered, spinor)
        vault_id = hashlib.sha3_256(spinor).digest()
        ch = new_challenge(vault_id, nonce=b"\x11" * 32, issued_at=100.0)
        resp = respond(recovered, spinor, ch)
        assert verify_response(resp, spinor, recovered, now=101.0) is not None

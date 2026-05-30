"""Property-based / Hypothesis fuzz tests for pure-function invariants.

These tests check that core cryptographic and encoding primitives
respect their algebraic contracts across the entire input domain (not
just the few hand-crafted vectors used in unit tests).

We target only **pure**, deterministic functions; randomised primitives
(e.g. ``shamir_split`` itself) are wrapped in a round-trip with their
inverse so the property under test is deterministic.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from eopx.format.shamir import shamir_combine, shamir_split
from eopx.metatron.grid import (
    decode_grid,
    encode_grid,
    f13_to_grid_pair,
    grid_pair_to_f13,
)
from eopx.metatron.reed_solomon import (
    BLOCK_K,
    BLOCK_N,
    NUM_BLOCKS,
    TOTAL_K,
    TOTAL_N,
    block_decode,
    block_encode,
    decode as rs_decode,
    encode as rs_encode,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import sign_spec  # noqa: E402


# ---------------------------------------------------------------------------
# F_13 ↔ base-6 grid pair bijection
# ---------------------------------------------------------------------------

class TestGridPairBijection:
    @given(st.integers(min_value=0, max_value=12))
    def test_roundtrip(self, symbol):
        hi, lo = f13_to_grid_pair(symbol)
        assert grid_pair_to_f13(hi, lo) == symbol

    @given(st.integers(min_value=0, max_value=12))
    def test_pair_in_range(self, symbol):
        hi, lo = f13_to_grid_pair(symbol)
        assert 0 <= hi < 6
        assert 0 <= lo < 6

    @given(st.integers(min_value=-100, max_value=-1) | st.integers(min_value=13, max_value=200))
    def test_out_of_range_rejected(self, symbol):
        with pytest.raises(ValueError):
            f13_to_grid_pair(symbol)


# ---------------------------------------------------------------------------
# Grid encode / decode round-trip
# ---------------------------------------------------------------------------

class TestGridRoundtrip:
    @given(st.lists(st.integers(min_value=0, max_value=12),
                    min_size=91, max_size=91))
    @settings(max_examples=200)
    def test_91_symbols_roundtrip(self, symbols):
        pairs = encode_grid(symbols)
        assert len(pairs) == 96
        # Flatten back to the 192 base-6 digits decode_grid expects.
        flat = []
        for hi, lo in pairs:
            flat.extend([hi, lo])
        decoded = decode_grid(flat)
        assert decoded == symbols


# ---------------------------------------------------------------------------
# Reed-Solomon: block-level
# ---------------------------------------------------------------------------

class TestReedSolomonBlock:
    @given(st.lists(st.integers(min_value=0, max_value=12),
                    min_size=BLOCK_K, max_size=BLOCK_K))
    @settings(max_examples=200)
    def test_block_encode_decode_clean(self, message):
        cw = block_encode(message)
        assert len(cw) == BLOCK_N
        recovered = block_decode(cw)
        assert recovered == message

    @given(
        st.lists(st.integers(min_value=0, max_value=12),
                 min_size=BLOCK_K, max_size=BLOCK_K),
        st.integers(min_value=0, max_value=BLOCK_N - 1),
    )
    @settings(max_examples=200,
              suppress_health_check=[HealthCheck.too_slow])
    def test_block_corrects_one_error(self, message, err_pos):
        cw = block_encode(message)
        # Flip one symbol to a different value.
        cw = list(cw)
        cw[err_pos] = (cw[err_pos] + 1) % 13
        recovered = block_decode(cw)
        assert recovered == message


# ---------------------------------------------------------------------------
# Reed-Solomon: interleaved 91-symbol code
# ---------------------------------------------------------------------------

class TestReedSolomonInterleaved:
    @given(st.lists(st.integers(min_value=0, max_value=12),
                    min_size=TOTAL_K, max_size=TOTAL_K))
    @settings(max_examples=100)
    def test_full_code_roundtrip(self, message):
        cw = rs_encode(message)
        assert len(cw) == TOTAL_N
        assert rs_decode(cw) == message

    @given(
        st.lists(st.integers(min_value=0, max_value=12),
                 min_size=TOTAL_K, max_size=TOTAL_K),
        st.integers(min_value=0, max_value=TOTAL_N - 1),
        st.data(),
    )
    @settings(max_examples=60,
              suppress_health_check=[HealthCheck.too_slow])
    def test_single_error_corrected(self, message, err_pos, data):
        """One symbol error anywhere is correctable because of the
        7-way interleaving (each block sees at most 1 error)."""
        cw = list(rs_encode(message))
        new_val = data.draw(
            st.integers(min_value=0, max_value=12).filter(lambda v: v != cw[err_pos])
        )
        cw[err_pos] = new_val
        assert rs_decode(cw) == message


# ---------------------------------------------------------------------------
# Shamir secret sharing
# ---------------------------------------------------------------------------

class TestShamirRoundtrip:
    @given(
        st.binary(min_size=1, max_size=64),
        st.integers(min_value=2, max_value=8),
        st.integers(min_value=0, max_value=4),
    )
    @settings(max_examples=80,
              suppress_health_check=[HealthCheck.too_slow])
    def test_combine_recovers_secret(self, secret, k, extra):
        n = k + extra
        shares = shamir_split(secret, k=k, n=n)
        # Combine exactly k shares (random subset).
        rng = random.Random(0xC0FFEE)
        chosen = rng.sample(shares, k)
        assert shamir_combine(chosen) == secret

    @given(
        st.binary(min_size=1, max_size=32),
        st.integers(min_value=3, max_value=6),
    )
    @settings(max_examples=40)
    def test_fewer_than_k_does_not_recover(self, secret, k):
        n = k + 1
        shares = shamir_split(secret, k=k, n=n)
        few = shares[: k - 1]
        # Combining k-1 shares either raises or returns garbage.
        try:
            out = shamir_combine(few)
        except (ValueError, IndexError):
            return
        assert out != secret, "should not recover with fewer than k shares"


# ---------------------------------------------------------------------------
# Document normalisation: idempotent + insensitive transforms
# ---------------------------------------------------------------------------

# Restrict to printable ASCII (excluding control chars that interact
# weirdly with the normalisation) so we don't generate unicode chars
# that NFC would legitimately re-write.
_TEXT_CHARS = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd", "Zs"),
        whitelist_characters=" .,;:-_/'\"",
    ),
    min_size=0, max_size=64,
)


class TestNormalisationIdempotence:
    @given(st.lists(_TEXT_CHARS, max_size=30))
    @settings(max_examples=200)
    def test_idempotent(self, lines):
        text = "\n".join(lines).encode("utf-8")
        once = sign_spec.normalise_bytes(text)
        twice = sign_spec.normalise_bytes(once)
        assert once == twice

    @given(st.lists(_TEXT_CHARS, max_size=30))
    @settings(max_examples=200)
    def test_crlf_lf_equivalence(self, lines):
        lf_text = "\n".join(lines).encode("utf-8")
        crlf_text = "\r\n".join(lines).encode("utf-8")
        assert sign_spec.normalise_bytes(lf_text) == sign_spec.normalise_bytes(crlf_text)

    @given(st.lists(_TEXT_CHARS, max_size=30))
    @settings(max_examples=200)
    def test_bom_invariance(self, lines):
        body = "\n".join(lines).encode("utf-8")
        with_bom = b"\xef\xbb\xbf" + body
        assert sign_spec.normalise_bytes(body) == sign_spec.normalise_bytes(with_bom)

    @given(st.lists(_TEXT_CHARS, max_size=20),
           st.integers(min_value=1, max_value=8))
    @settings(max_examples=100)
    def test_trailing_whitespace_invariance(self, lines, ws):
        pad = " " * ws
        clean = "\n".join(lines).encode("utf-8")
        padded = "\n".join(line + pad for line in lines).encode("utf-8")
        assert sign_spec.normalise_bytes(clean) == sign_spec.normalise_bytes(padded)

    @given(st.text(min_size=0, max_size=64),
           st.integers(min_value=0, max_value=5))
    @settings(max_examples=80)
    def test_extra_trailing_newlines_normalised(self, body, n):
        """Adding more trailing LFs after the first one shouldn't change
        the normalised hash (we collapse to a single final LF)."""
        a = (body + "\n").encode("utf-8")
        b = (body + "\n" * (1 + n)).encode("utf-8")
        try:
            na = sign_spec.normalise_bytes(a)
            nb = sign_spec.normalise_bytes(b)
        except UnicodeDecodeError:
            return  # hypothesis-generated body that round-trips poorly
        assert na == nb

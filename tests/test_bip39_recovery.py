"""BIP-39 recovery phrase round-trip tests for vault.genesis helpers."""

from __future__ import annotations

import secrets

import pytest

from eopx.vault.genesis import (
    DEVICE_ENTROPY_BYTES,
    RECOVERY_PHRASE_WORDS,
    entropy_to_recovery_phrase,
    recovery_phrase_to_entropy,
)


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

def test_default_entropy_yields_24_words() -> None:
    entropy = secrets.token_bytes(DEVICE_ENTROPY_BYTES)
    words = entropy_to_recovery_phrase(entropy)
    assert len(words) == RECOVERY_PHRASE_WORDS == 24


def test_round_trip_random_entropies() -> None:
    for _ in range(20):
        e = secrets.token_bytes(DEVICE_ENTROPY_BYTES)
        words = entropy_to_recovery_phrase(e)
        recovered = recovery_phrase_to_entropy(words)
        assert recovered == e


@pytest.mark.parametrize("n_bytes,n_words", [
    (16, 12), (20, 15), (24, 18), (28, 21), (32, 24),
])
def test_round_trip_all_bip39_lengths(n_bytes: int, n_words: int) -> None:
    e = secrets.token_bytes(n_bytes)
    words = entropy_to_recovery_phrase(e)
    assert len(words) == n_words
    assert recovery_phrase_to_entropy(words) == e


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_invalid_entropy_length_rejected() -> None:
    with pytest.raises(ValueError):
        entropy_to_recovery_phrase(b"\x00" * 17)


def test_corrupted_mnemonic_rejected() -> None:
    e = secrets.token_bytes(DEVICE_ENTROPY_BYTES)
    words = entropy_to_recovery_phrase(e)
    # Swap two adjacent words: this will (almost surely) break the checksum.
    swapped = list(words)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    with pytest.raises(ValueError):
        recovery_phrase_to_entropy(swapped)


def test_unknown_word_rejected() -> None:
    e = secrets.token_bytes(DEVICE_ENTROPY_BYTES)
    words = entropy_to_recovery_phrase(e)
    words[0] = "definitelynotabip39word"
    with pytest.raises(ValueError):
        recovery_phrase_to_entropy(words)


# ---------------------------------------------------------------------------
# BIP-39 official test vector (English)
# https://github.com/trezor/python-mnemonic/blob/master/vectors.json
# ---------------------------------------------------------------------------

def test_official_bip39_vector_all_zeros() -> None:
    # 32 zero bytes -> the canonical BIP-39 24-word vector.
    entropy = bytes(32)
    words = entropy_to_recovery_phrase(entropy)
    expected = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon art"
    ).split()
    assert words == expected
    assert recovery_phrase_to_entropy(words) == entropy

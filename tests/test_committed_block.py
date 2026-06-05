"""The committed Genesis block is baked in and reproduces the frozen
distribution (docs/GENESIS_COMMITMENT.md). This is a regression gate: if these
constants ever drift, every deterministic distribution silently changes.
"""

from __future__ import annotations

from eopx.collection import codex_manifest
from eopx.genesis_token import (
    COMMITTED_BTC_BLOCK_HASH,
    COMMITTED_BTC_BLOCK_HASH_HEX,
    COMMITTED_BTC_BLOCK_HEIGHT,
    resolve_btc_block,
)

# Frozen values from docs/GENESIS_COMMITMENT.md (hash-tracked in SPECS.SHA3-256).
_DOC_HASH = "00000000000000000000c253697e024b6bbe3c7702981277146fdd6767d43ee6"
_DOC_HEIGHT = 951_848
_DOC_CATALOG_COMMITMENT = \
    "3593d4d549f6fca41486de53a7423564919e130fc8c227040f30d742542b8ab4"


def test_committed_constants_match_the_document():
    assert COMMITTED_BTC_BLOCK_HASH_HEX == _DOC_HASH
    assert COMMITTED_BTC_BLOCK_HEIGHT == _DOC_HEIGHT
    assert COMMITTED_BTC_BLOCK_HASH == bytes.fromhex(_DOC_HASH)


def test_committed_block_reproduces_the_catalog_commitment():
    m = codex_manifest(COMMITTED_BTC_BLOCK_HASH, COMMITTED_BTC_BLOCK_HEIGHT)
    assert m["catalog_commitment_hex"] == _DOC_CATALOG_COMMITMENT


def test_resolve_defaults_to_committed_without_env():
    block, height, committed = resolve_btc_block({})
    assert block == COMMITTED_BTC_BLOCK_HASH
    assert height == _DOC_HEIGHT
    assert committed is True


def test_resolve_env_matching_committed_is_committed():
    _, _, committed = resolve_btc_block(
        {"ESOPTRON_BTC_BLOCK_HASH": _DOC_HASH,
         "ESOPTRON_BTC_BLOCK_HEIGHT": str(_DOC_HEIGHT)})
    assert committed is True


def test_resolve_env_test_block_is_not_committed():
    block, height, committed = resolve_btc_block(
        {"ESOPTRON_BTC_BLOCK_HASH": "aa" * 32,
         "ESOPTRON_BTC_BLOCK_HEIGHT": "123"})
    assert block == bytes.fromhex("aa" * 32)
    assert height == 123
    assert committed is False


def test_resolve_garbage_env_falls_back_to_committed():
    block, height, committed = resolve_btc_block(
        {"ESOPTRON_BTC_BLOCK_HASH": "not-a-hash"})
    assert block == COMMITTED_BTC_BLOCK_HASH
    assert height == _DOC_HEIGHT
    assert committed is True

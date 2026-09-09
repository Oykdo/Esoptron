"""EPX-F §5 — epoch links: both-ended signing, and what a weak link costs."""

import base64
import json
from dataclasses import replace

import pytest

from eopx.epoch_chain import (
    EpochLink,
    build_link,
    dump_chain,
    load_chain,
    resolve_epoch,
    verify_link,
)
from eopx.format.keys import EopxKey, key_fingerprint


@pytest.fixture(scope="module")
def keys():
    """Four epochs: k1 -> k2 -> k3, plus an independent witness."""
    return [EopxKey.generate() for _ in range(4)]


@pytest.fixture(scope="module")
def chain(keys):
    """A strong two-hop lineage, newest link first."""
    k1, k2, k3, _ = keys
    return [build_link(k2, k3, statement="rotation 2"),
            build_link(k1, k2, statement="rotation 1")]


# --- one link --------------------------------------------------------------

def test_strong_link_verifies_from_both_ends(keys):
    k1, k2, _, _ = keys
    link = build_link(k1, k2)
    verdict = verify_link(link)
    assert verdict.ok and verdict.strong
    assert verdict.errors == []
    assert link.predecessor_fp == k1.dilithium_pk_fp
    assert link.successor_fp == k2.dilithium_pk_fp


def test_weak_link_is_valid_but_not_strong(keys):
    """The predecessor secret is gone; the link is honest about it."""
    k1, k2, _, _ = keys
    link = build_link(k1.public_only(), k2)
    assert link.predecessor_sig_b64 == ""
    verdict = verify_link(link)
    assert verdict.ok
    assert not verdict.strong


def test_tampering_with_the_statement_breaks_the_signatures(keys):
    k1, k2, _, _ = keys
    link = build_link(k1, k2, statement="rotation 1")
    forged = replace(link, statement="rotation 1 (and epoch 0 too)")
    assert not verify_link(forged).ok


def test_swapping_the_predecessor_key_breaks_the_link(keys):
    """The pk is inside the digest, so a substituted ancestor cannot pass."""
    k1, k2, k3, _ = keys
    link = build_link(k1, k2)
    forged = replace(
        link,
        predecessor_pk_b64=base64.b64encode(k3.dilithium_pk).decode("ascii"))
    assert not verify_link(forged).ok


def test_a_key_cannot_succeed_itself(keys):
    k1 = keys[0]
    with pytest.raises(ValueError):
        build_link(k1, k1)


def test_missing_successor_signature_is_refused(keys):
    k1, k2, _, _ = keys
    link = build_link(k1, k2)
    verdict = verify_link(replace(link, successor_sig_b64=""))
    assert not verdict.ok
    assert "missing successor signature" in verdict.errors


# --- witness ---------------------------------------------------------------

def test_witness_must_be_the_expected_key(keys):
    k1, k2, k3, w = keys
    link = build_link(k1, k2, witness=w)
    assert verify_link(link, witness_pk=w.dilithium_pk).witnessed
    # a witness the caller did not expect proves nothing
    bad = verify_link(link, witness_pk=k3.dilithium_pk)
    assert not bad.ok
    assert "witness key is not the expected one" in bad.errors


def test_expected_witness_missing_from_the_link(keys):
    k1, k2, _, w = keys
    link = build_link(k1, k2)
    verdict = verify_link(link, witness_pk=w.dilithium_pk)
    assert not verdict.ok


# --- walking the chain -----------------------------------------------------

def test_resolves_an_old_epoch_from_todays_key(keys, chain):
    """The whole point: verify a 3-epochs-old badge holding only k3."""
    k1, _, k3, _ = keys
    resolved = resolve_epoch(chain, trusted_pk=k3.dilithium_pk,
                             target_fp=k1.dilithium_pk_fp)
    assert resolved == k1.dilithium_pk


def test_trusted_key_is_its_own_epoch(keys, chain):
    k3 = keys[2]
    assert resolve_epoch(chain, trusted_pk=k3.dilithium_pk,
                         target_fp=k3.dilithium_pk_fp) == k3.dilithium_pk


def test_unknown_epoch_does_not_resolve(keys, chain):
    w = keys[3]
    assert resolve_epoch(chain, trusted_pk=keys[2].dilithium_pk,
                         target_fp=w.dilithium_pk_fp) is None


def test_weak_links_are_refused_by_default(keys):
    """A compromised current key can forge a lineage — but only a weak one."""
    k1, k2, _, _ = keys
    forged = [build_link(k1.public_only(), k2)]
    assert resolve_epoch(forged, trusted_pk=k2.dilithium_pk,
                         target_fp=k1.dilithium_pk_fp) is None
    assert resolve_epoch(forged, trusted_pk=k2.dilithium_pk,
                         target_fp=k1.dilithium_pk_fp,
                         require_strong=False) == k1.dilithium_pk


def test_cycle_cannot_spin_the_walk(keys):
    k1, k2, _, _ = keys
    cyclic = [build_link(k1, k2), build_link(k2, k1)]
    assert resolve_epoch(cyclic, trusted_pk=k2.dilithium_pk,
                         target_fp=keys[3].dilithium_pk_fp) is None


def test_hop_budget_is_enforced(keys, chain):
    k1, _, k3, _ = keys
    assert resolve_epoch(chain, trusted_pk=k3.dilithium_pk,
                         target_fp=k1.dilithium_pk_fp, max_hops=1) is None


# --- publication -----------------------------------------------------------

def test_chain_round_trips_through_json(tmp_path, keys, chain):
    path = tmp_path / "epochs.json"
    path.write_text(dump_chain(chain), encoding="utf-8")
    loaded = load_chain(path)
    assert [ln.digest() for ln in loaded] == [ln.digest() for ln in chain]
    k1, _, k3, _ = keys
    assert resolve_epoch(loaded, trusted_pk=k3.dilithium_pk,
                         target_fp=k1.dilithium_pk_fp) == k1.dilithium_pk


def test_published_chain_carries_no_secret_material(chain):
    blob = dump_chain(chain)
    assert "sk_b64" not in blob
    assert "dilithium_sk" not in blob
    doc = json.loads(blob)
    assert doc["version"] == 1
    assert doc["links"][0]["predecessor_pk_fp"].startswith("sha3-256:")


def test_from_dict_rejects_a_foreign_version(chain):
    d = chain[0].to_dict()
    d["version"] = 2
    with pytest.raises(ValueError):
        EpochLink.from_dict(d)


def test_fingerprints_in_the_document_match_the_keys(chain):
    for link in chain:
        d = link.to_dict()
        assert d["predecessor_pk_fp"] == (
            f"sha3-256:{key_fingerprint(link.predecessor_pk).hex()}")
        assert d["successor_pk_fp"] == (
            f"sha3-256:{key_fingerprint(link.successor_pk).hex()}")

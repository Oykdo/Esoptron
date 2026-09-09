"""One definition of ``vault_fp``, and a guard against the next one.

Three derivations used to coexist and disagree for the same vault. The tests
that matter here are not that the function returns bytes -- it is that every
call site reaches the *same* bytes, and that the abandoned derivations stay
abandoned. A fourth definition would be as bad as the first three, and it
would arrive the same way: quietly, in a script.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from eopx.metatron import encode_public
from eopx.vault.identity import (
    VAULT_FP_BYTES,
    is_vault_fingerprint,
    require_vault_fingerprint,
    vault_fingerprint,
    vault_fingerprint_from_card,
)
from eopx.vault.verify_card import card_fingerprint

ROOT = Path(__file__).resolve().parents[1]

SPINOR = hashlib.sha3_512(b"esoptron.test.vault_identity").digest()


def test_the_two_entry_points_are_one_function():
    """A scanner starts from the card, an issuer from the spinor.

    They must land on the same fingerprint or the definition has forked again
    -- which is exactly how the three derivations came about.
    """
    from_spinor = vault_fingerprint(SPINOR)
    from_card = vault_fingerprint_from_card(encode_public(SPINOR))
    assert from_spinor == from_card
    assert from_spinor == card_fingerprint(encode_public(SPINOR))
    assert len(from_spinor) == VAULT_FP_BYTES


def test_a_scan_alone_is_enough():
    """The property that decided the definition: no secret is required.

    Only the 91 symbols go in. If this ever needs the spinor or the seed, the
    scan-driven flows stop being able to identify a vault.
    """
    symbols = encode_public(SPINOR)
    assert vault_fingerprint_from_card(symbols) == vault_fingerprint(SPINOR)


def test_distinct_vaults_get_distinct_fingerprints():
    other = hashlib.sha3_512(b"esoptron.test.vault_identity.other").digest()
    assert vault_fingerprint(SPINOR) != vault_fingerprint(other)


def test_spinor_lengths_the_vault_layer_actually_emits():
    # Eidolon's Phase-6 output is 64 bytes; 32 and 48 also occur.
    seen = {len(SPINOR[:n]): vault_fingerprint(SPINOR[:n]) for n in (32, 48, 64)}
    assert len(set(seen.values())) == 3, "truncation must not collide"


def test_an_empty_spinor_is_refused():
    with pytest.raises(ValueError):
        vault_fingerprint(b"")


# --------------------------------------------------------------------------- #
# The guard at the boundaries that consume a fingerprint
# --------------------------------------------------------------------------- #

def test_malformed_fingerprints_raise_instead_of_hashing():
    """A truncated fingerprint reaching a KDF yields a plausible wrong answer.

    ``founder_egg`` draws a golden egg from this value and the EPX-H seal picks
    a hexagram from it. Neither would notice 16 bytes; both would be wrong.
    """
    good = vault_fingerprint(SPINOR)
    assert is_vault_fingerprint(good)
    assert require_vault_fingerprint(good) == good

    for bad in (good[:16], good + b"\x00", b"", good.hex()):
        assert not is_vault_fingerprint(bad)
        with pytest.raises(ValueError, match="32 raw bytes"):
            require_vault_fingerprint(bad)


def test_the_error_names_the_field():
    with pytest.raises(ValueError, match="merkle_root"):
        require_vault_fingerprint(b"\x00" * 4, "merkle_root")


# --------------------------------------------------------------------------- #
# The abandoned derivations must not come back
# --------------------------------------------------------------------------- #

_ABANDONED = (
    # scripts/make_invitation.py -- hashed the seed, so only the holder of the
    # secret could recompute the identifier.
    b"esoptron.vault_fp.v1",
    # scripts/eopx_badge.py -- its own hash of the spinor, which made the
    # revealed seal disagree with every other component.
    b"epx-h.badge.vault_fp.v1",
)


@pytest.mark.parametrize("domain", _ABANDONED)
def test_abandoned_domain_strings_are_gone_from_the_tree(domain):
    """Grep, deliberately: this is a fact about the repository, not a unit.

    A new derivation will not announce itself in an import graph; it will
    appear as a new domain string in a script, which is how the last two did.
    """
    needle = domain.decode("ascii")
    offenders = []
    for path in list((ROOT / "src").rglob("*.py")) + list((ROOT / "scripts").rglob("*.py")):
        # identity.py quotes both strings on purpose: it is the record of what
        # was abandoned and why, which is the one place they should survive.
        if path.resolve() == (ROOT / "src" / "eopx" / "vault" / "identity.py").resolve():
            continue
        if needle in path.read_text(encoding="utf-8"):
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, (
        f"{needle!r} is an abandoned vault_fp derivation, still present in "
        f"{offenders}. vault_fp is card_fingerprint (eopx.vault.identity)."
    )


def test_no_call_site_hashes_its_own_vault_fp():
    """Catch the shape of the mistake, not just the two known instances."""
    pattern = re.compile(r"vault_fp\s*=\s*hashlib\.")
    offenders = [
        str(p.relative_to(ROOT))
        for p in list((ROOT / "src").rglob("*.py")) + list((ROOT / "scripts").rglob("*.py"))
        if pattern.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, (
        f"{offenders} derive a vault_fp by hashing directly; use "
        "eopx.vault.identity.vault_fingerprint"
    )


# --------------------------------------------------------------------------- #
# The spec vector has to agree with the code
# --------------------------------------------------------------------------- #

def test_epx2_test_vector_matches_the_canonical_definition():
    """EPX-2 section 4.1 pins a vault_fp; it must be the one the code computes.

    The vector previously carried a seed-derived value, so a port reproducing
    the spec byte for byte would have disagreed with the implementation.
    """
    spec = (ROOT / "docs" / "specs" / "EPX-2_card_v2.md").read_text(encoding="utf-8")
    m = re.search(r"vault_fp_hex\s*=\s*([0-9a-f]{64})", spec)
    assert m, "EPX-2 no longer pins a vault_fp_hex"

    # The invitation the vector is drawn from is regenerated from its code.
    code = "ESPX-SIGMA-VAULT-6119"
    spinor = hashlib.sha3_512(
        b"esoptron.invitation.v1|" + code.encode("utf-8") + b"|spinor"
    ).digest()
    assert m.group(1) == vault_fingerprint(spinor).hex()


# --------------------------------------------------------------------------- #
# A relic seal seed is not a vault fingerprint
# --------------------------------------------------------------------------- #

def test_relic_seal_seed_keeps_its_value_across_the_rename():
    """Renaming must not redraw twelve badges that are already minted.

    ``relic_seal_seed`` was called ``relic_vault_fp``, which made it a fourth
    thing named after a vault fingerprint. It identifies no vault -- it only
    selects the revealed hexagram -- but the twelve relics on the live anchor
    derive their seals from it, so the value is pinned here and the deprecated
    alias must keep returning it.
    """
    import hashlib

    from eopx.collection import CODEX
    from eopx.collection.forge import relic_seal_seed, relic_vault_fp

    for relic in CODEX:
        expected = hashlib.sha3_256(relic.artifact_id()).digest()
        assert relic_seal_seed(relic) == expected
        assert relic_vault_fp(relic) == expected

    # And it is emphatically not the vault fingerprint of anything.
    first = CODEX[0]
    assert relic_seal_seed(first) != vault_fingerprint(first.spinor_seed())


# --------------------------------------------------------------------------- #
# Domain-separation strings: the most permanent bytes in the repository
# --------------------------------------------------------------------------- #
#
# EPX-F §8: FIGURE_VERSION is baked into INFO_CONTENT / INFO_EPOCH, and "v1
# must keep producing v1 grids forever", because a printed badge outlives the
# software that made it. A domain string is therefore frozen by objects that
# have already left the building -- there is no way to withdraw one.
#
# docs/research_notes/yuga_lexicon_analysis.md §3.2 once licensed choosing
# these strings from a decorative corpus on the grounds that the KDF does not
# care what the bytes say. True, and beside the point: the cost is not to
# security but to mutability. eopx.egg_token shows what it costs -- its tier
# names reached _egg_hash() and tiers_commitment_hex(), so "Lunar" now sits
# inside an ML-DSA-87-signed digest and cannot be renamed.

def _bytes_literals():
    """(path, lineno, value) for every bytes literal under src/eopx."""
    import ast

    for path in sorted((ROOT / "src" / "eopx").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
                yield path.relative_to(ROOT), node.lineno, node.value


def _encoded_str_literals():
    """(path, lineno, value) for every ``"...".encode(...)`` under src/eopx.

    Scanning bytes literals for non-ASCII would be vacuous: Python's parser
    already rejects ``b"kṛta"`` outright ("bytes can only contain ASCII
    literal characters"). The only way non-ASCII reaches a KDF is through a
    str literal that is encoded, so that is what this looks at.
    """
    import ast

    for path in sorted((ROOT / "src" / "eopx").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "encode"
                    and isinstance(node.func.value, ast.Constant)
                    and isinstance(node.func.value.value, str)):
                yield (path.relative_to(ROOT), node.lineno,
                       node.func.value.value)


def test_no_encoded_string_carries_non_ascii():
    """Non-ASCII reaching a derivation is a silent interop bug, not a style one.

    ``tools/sign_spec.py`` had to add NFC normalisation because byte-identity
    of prose is fragile. ``hkdf_sha3_512(info=...)`` has no such step: a source
    file re-saved in NFD would change the derivation, and no test vector would
    catch it because the vectors are regenerated from that same file.
    Transliterated Sanskrit -- Kṛta, Dvāpara, sandhyā -- is the worst case.
    """
    offenders = [
        f"{rel}:{lineno} {text!r}"
        for rel, lineno, text in _encoded_str_literals()
        if not text.isascii()
    ]
    assert not offenders, (
        "non-ASCII text is encoded to bytes here and may reach a KDF, which "
        f"cannot normalise it: {offenders}"
    )


def test_no_decorative_corpus_reaches_a_domain_string():
    """The specific move §3.2 licensed, caught in the shape it would take.

    A display lexicon is welcome in a caption and forbidden in a derivation.
    The word list is deliberately wide, including the terms a contributor
    would reach for while reading the note -- the two vault_fp derivations
    this file already guards against arrived exactly that way, retyped into a
    script rather than imported.
    """
    corpus = (
        "yuga", "kalpa", "manvantara", "mahayuga", "chaturyuga",
        "sandhya", "krita", "satya", "treta", "dvapara", "kali",
    )
    candidates = [(rel, ln, v.decode("ascii", "replace"))
                  for rel, ln, v in _bytes_literals()]
    candidates += list(_encoded_str_literals())
    offenders = []
    for rel, lineno, text in candidates:
        for word in corpus:
            if word in text.lower():
                offenders.append(f"{rel}:{lineno} contains {word!r}")
    assert not offenders, (
        "a decorative lexicon reached a bytes literal. It is display-only "
        "(yuga_lexicon_analysis.md §5); a domain string is frozen for the "
        f"life of the printed parc: {offenders}"
    )

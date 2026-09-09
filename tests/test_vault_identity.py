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

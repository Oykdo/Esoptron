"""The wire format's parameters belong to the format, not to the dependency.

``eopx.format.keys`` used to read the six ML-DSA-87 / ML-KEM-1024 sizes off
``pqcrypto`` at import time, and ``eopx_format`` validates a `.eopx` against
them: `pack` rejects a public key that is not ``SIG_PUBLIC_KEY_SIZE`` bytes,
`verify` rejects a signature that is not ``SIG_SIGNATURE_SIZE``. So the
admissibility rules of a frozen wire format moved with whatever the installed
library defined. These tests pin the FIPS values and check that a disagreeing
backend is refused rather than followed.
"""

from __future__ import annotations

import builtins
import sys

import pytest

from eopx.format import keys as K


# FIPS 204 ML-DSA-87 and FIPS 203 ML-KEM-1024, from the standards.
FIPS_SIZES = {
    "SIG_PUBLIC_KEY_SIZE": 2592,
    "SIG_SECRET_KEY_SIZE": 4896,
    "SIG_SIGNATURE_SIZE": 4627,
    "KEM_PUBLIC_KEY_SIZE": 1568,
    "KEM_SECRET_KEY_SIZE": 3168,
    "KEM_CIPHERTEXT_SIZE": 1568,
}


@pytest.mark.parametrize("name,value", sorted(FIPS_SIZES.items()))
def test_sizes_are_pinned_to_the_standard(name, value):
    assert getattr(K, name) == value


def test_the_installed_backend_agrees_with_the_pinned_sizes():
    """The check that makes pinning safe rather than merely stubborn."""
    dsa, kem = K._backend()
    assert dsa.PUBLIC_KEY_SIZE == K.SIG_PUBLIC_KEY_SIZE
    assert dsa.SECRET_KEY_SIZE == K.SIG_SECRET_KEY_SIZE
    assert dsa.SIGNATURE_SIZE == K.SIG_SIGNATURE_SIZE
    assert kem.PUBLIC_KEY_SIZE == K.KEM_PUBLIC_KEY_SIZE
    assert kem.SECRET_KEY_SIZE == K.KEM_SECRET_KEY_SIZE
    assert kem.CIPHERTEXT_SIZE == K.KEM_CIPHERTEXT_SIZE


def test_a_real_key_has_the_pinned_shape():
    key = K.EopxKey.generate()
    assert len(key.dilithium_pk) == K.SIG_PUBLIC_KEY_SIZE
    assert len(key.kyber_pk) == K.KEM_PUBLIC_KEY_SIZE
    assert len(key.sign(b"message")) == K.SIG_SIGNATURE_SIZE


class _Dsa:
    PUBLIC_KEY_SIZE = 2592
    SECRET_KEY_SIZE = 4896
    SIGNATURE_SIZE = 4627

    def generate_keypair(self):  # pragma: no cover - never called
        raise AssertionError


class _Kem:
    PUBLIC_KEY_SIZE = 1568
    SECRET_KEY_SIZE = 3168
    CIPHERTEXT_SIZE = 1568

    def generate_keypair(self):  # pragma: no cover - never called
        raise AssertionError


def test_a_backend_bound_to_another_parameter_set_is_refused():
    """The failure this guards against is silent, which is what makes it bad.

    A backend rebound to ML-DSA-44 would have redefined what a valid `.eopx`
    signature *is*, under a format that is frozen.
    """
    weak = _Dsa()
    weak.PUBLIC_KEY_SIZE = 1312  # ML-DSA-44
    weak.SECRET_KEY_SIZE = 2560
    weak.SIGNATURE_SIZE = 2420
    with pytest.raises(RuntimeError, match="ML-DSA-87 public key size"):
        K._check_backend(weak, _Kem())


@pytest.mark.parametrize("field,bad", [
    ("SIGNATURE_SIZE", 4628),
    ("SECRET_KEY_SIZE", 4895),
])
def test_every_signature_size_is_checked_not_just_the_first(field, bad):
    dsa = _Dsa()
    setattr(dsa, field, bad)
    with pytest.raises(RuntimeError, match="pinned"):
        K._check_backend(dsa, _Kem())


@pytest.mark.parametrize("field,bad", [
    ("PUBLIC_KEY_SIZE", 1184),
    ("CIPHERTEXT_SIZE", 1088),
])
def test_kem_sizes_are_checked_too(field, bad):
    kem = _Kem()
    setattr(kem, field, bad)
    with pytest.raises(RuntimeError, match="ML-KEM-1024"):
        K._check_backend(_Dsa(), kem)


def test_the_pqcrypto_1_0_api_break_is_named():
    """Lifting the `pqcrypto<1.0` cap must say so, not raise AttributeError.

    1.0 renamed ``generate_keypair()`` to ``keygen()``; without this the break
    surfaces from inside a key operation with no hint about the cap.
    """
    # Standalone, not a subclass of _Dsa: inheriting would keep
    # generate_keypair reachable and the test would pass for the wrong reason.
    class Renamed:
        PUBLIC_KEY_SIZE = 2592
        SECRET_KEY_SIZE = 4896
        SIGNATURE_SIZE = 4627

        def keygen(self):  # pragma: no cover - never called
            raise AssertionError

    assert not hasattr(Renamed(), "generate_keypair")
    with pytest.raises(RuntimeError, match="keygen"):
        K._check_backend(Renamed(), _Kem())


def test_pure_python_modules_import_without_the_backend(monkeypatch):
    """Audit 2026-05-28 P2-2: Shamir and friends must not need pqcrypto.

    The import error keeps its wording; it simply arrives at the first key
    operation instead of at import of anything at all.
    """
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name.startswith("pqcrypto"):
            raise ImportError("pqcrypto unavailable (simulated)")
        return real_import(name, *args, **kwargs)

    for mod in [m for m in sys.modules if m.startswith(("eopx", "pqcrypto"))]:
        monkeypatch.delitem(sys.modules, mod, raising=False)
    monkeypatch.setattr(builtins, "__import__", blocked)

    import eopx.format.keys as fresh  # noqa: F401  (import is the assertion)
    import eopx.format.shamir  # noqa: F401

    with pytest.raises(RuntimeError, match="pqcrypto is required"):
        fresh.EopxKey.generate()

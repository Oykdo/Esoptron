"""Esoptron public verification SDK.

A minimal, dependency-light package for third parties who need to
*verify* ``.eopx`` artefacts without pulling in the full Esoptron
codebase (no Metatron, no OpenCV, no Eidolon).

Only this SDK is intended to be distributed publicly. The signing /
packing path lives in the main Esoptron repository under
``eopx.format`` and is NOT part of the SDK surface.

Dependencies
------------
* ``Pillow`` (PNG chunk parsing)
* ``pqcrypto`` (ML-DSA-87 / Dilithium5 verification)

Usage
-----
.. code-block:: python

    from esoptron import verify

    result = verify("vault.eopx")
    if result.ok:
        print("vault is signed by", result.manifest.dilithium_pk_fp)
    else:
        for err in result.errors:
            print("INVALID:", err)
"""

from .eopx_verify import (
    Manifest,
    VerificationResult,
    read_manifest,
    verify,
    __version__,
)

__all__ = ["Manifest", "VerificationResult", "read_manifest", "verify",
           "__version__"]

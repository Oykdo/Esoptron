"""Bind an EPX-T controller secret to a vault (spec §8, "sealed-to-vault").

The owner of a titled artifact must be able to produce the controller
secret ``C_sec`` to transfer it. Per spec §8 that secret is *derived from
or sealed to the owner vault* — so the vault's existing recovery (Protocol
A unlock / G reclaim / Shamir k-of-n) already protects it.

A *purely derived* controller (deterministic PQ keygen from the vault's
``device_secret``) is not achievable with the current ``pqcrypto`` binding:
``generate_keypair()`` takes no seed. We therefore implement the **sealed**
reading: the controller is an ordinary random :class:`EopxKey`, and its
secret material is wrapped under a key derived from the vault's
``device_secret`` (the 32-byte root from :func:`eopx.vault.enroll_from_card`).

Holding the vault ⇒ being able to unseal ``C_sec`` ⇒ controlling the relic.
Nothing but ``device_secret`` can unwrap it; losing the device but
recovering the vault (and thus ``device_secret``) re-derives the wrap key
and restores control.

The wrap key is bound to ``artifact_id`` so one vault's relics are sealed
under *distinct* keys, and a sealed blob can never be replayed against a
different artifact.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ..format.keys import EopxKey
from . import AEAD_NONCE_LEN, _h, _u

# Frozen at v1.
EPXT_CONTROLLER_BIND = b"epx-t.controller.bind.v1"
WRAP_KEY_LEN = 32


def _wrap_key(device_secret: bytes, artifact_id: bytes) -> bytes:
    from ..metatron.field import hkdf_sha3_512
    return hkdf_sha3_512(
        ikm=device_secret, salt=artifact_id,
        info=EPXT_CONTROLLER_BIND, length=WRAP_KEY_LEN,
    )


@dataclass
class SealedController:
    """A controller keypair whose secret halves are sealed to a vault.

    The public halves travel in clear (the ledger records
    ``dilithium_pub`` as the controller of record; ``kyber_pub`` is the
    content-delivery target). The secret halves are recoverable only by the
    vault that holds the binding ``device_secret``.
    """
    artifact_id: bytes
    dilithium_pub: bytes
    kyber_pub: bytes
    nonce: bytes
    sealed_blob: bytes  # AEAD over (dilithium_sk || kyber_sk)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id_hex": _h(self.artifact_id),
            "dilithium_pub_hex": _h(self.dilithium_pub),
            "kyber_pub_hex": _h(self.kyber_pub),
            "nonce_hex": _h(self.nonce),
            "sealed_blob_hex": _h(self.sealed_blob),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SealedController":
        return cls(
            artifact_id=_u(d["artifact_id_hex"]),
            dilithium_pub=_u(d["dilithium_pub_hex"]),
            kyber_pub=_u(d["kyber_pub_hex"]),
            nonce=_u(d["nonce_hex"]),
            sealed_blob=_u(d["sealed_blob_hex"]),
        )

    def public_controller(self) -> EopxKey:
        """The public-only controller view (for the ledger / hand-offs)."""
        return EopxKey(dilithium_pk=self.dilithium_pub, kyber_pk=self.kyber_pub)


def _encode_secrets(controller: EopxKey) -> bytes:
    sk_d = controller.dilithium_sk
    sk_k = controller.kyber_sk
    if sk_d is None or sk_k is None:
        raise ValueError("controller must hold secret key material to seal")
    return len(sk_d).to_bytes(4, "big") + sk_d + sk_k


def _decode_secrets(blob: bytes) -> tuple[bytes, bytes]:
    n = int.from_bytes(blob[:4], "big")
    sk_d = blob[4:4 + n]
    sk_k = blob[4 + n:]
    return sk_d, sk_k


def seal_controller(controller: EopxKey, device_secret: bytes,
                    artifact_id: bytes) -> SealedController:
    """Seal a controller's secret halves to a vault's ``device_secret``.

    ``device_secret`` is the 32-byte vault root produced by enrollment
    (:func:`eopx.vault.enroll_from_card`). The returned object is safe to
    persist alongside the relic — only the vault can reopen it.
    """
    if len(device_secret) != 32:
        raise ValueError("device_secret must be 32 bytes")
    key = _wrap_key(device_secret, artifact_id)
    nonce = secrets.token_bytes(AEAD_NONCE_LEN)
    blob = ChaCha20Poly1305(key).encrypt(
        nonce, _encode_secrets(controller), artifact_id,
    )
    return SealedController(
        artifact_id=artifact_id,
        dilithium_pub=controller.dilithium_pk,
        kyber_pub=controller.kyber_pk,
        nonce=nonce,
        sealed_blob=blob,
    )


def unseal_controller(sealed: SealedController, device_secret: bytes) -> EopxKey:
    """Recover the full controller :class:`EopxKey` from the vault secret.

    Raises (via the AEAD layer) if ``device_secret`` is wrong — there is no
    partial-failure oracle. This is the "wake the relic" step: scan the
    private sheet → ``device_secret`` → unseal → sign.
    """
    if len(device_secret) != 32:
        raise ValueError("device_secret must be 32 bytes")
    key = _wrap_key(device_secret, sealed.artifact_id)
    plain = ChaCha20Poly1305(key).decrypt(
        sealed.nonce, sealed.sealed_blob, sealed.artifact_id,
    )
    sk_d, sk_k = _decode_secrets(plain)
    return EopxKey(
        dilithium_pk=sealed.dilithium_pub,
        kyber_pk=sealed.kyber_pub,
        dilithium_sk=sk_d,
        kyber_sk=sk_k,
    )


def bind_new_controller(device_secret: bytes,
                        artifact_id: bytes) -> tuple[EopxKey, SealedController]:
    """Generate a fresh controller and immediately seal it to the vault.

    Convenience for mint / receive: returns ``(controller, sealed)`` where
    ``controller`` holds secrets (use it now to sign), and ``sealed`` is the
    persistable, vault-bound form to ship with the relic.
    """
    controller = EopxKey.generate()
    sealed = seal_controller(controller, device_secret, artifact_id)
    return controller, sealed


__all__ = [
    "EPXT_CONTROLLER_BIND",
    "SealedController",
    "seal_controller",
    "unseal_controller",
    "bind_new_controller",
]

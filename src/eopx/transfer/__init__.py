"""EPX-T — Titled Transfer: anti-duplication artifacts, vault to vault.

A **titled artifact** is a transferable object whose *control* can move
from one vault to another **without duplication**. Control is bound to a
per-artifact **controller key** (a Dilithium5 + Kyber1024 :class:`EopxKey`);
the current controller's public key is recorded, per ``artifact_id``, in a
monotonic **anchor ledger** (:mod:`eopx.server.artifact_ledger`).

A transfer is a *forward-secure anchored re-key* (see ``docs/specs/
EPX-T_titled_transfer.md``):

1. the recipient B generates a fresh controller key the sender A never
   learns, and a proof-of-possession (PoP) over it;
2. A signs the hand-off with the *current* controller key and re-seals the
   confidential content to B's Kyber key (the delivery step);
3. the anchor atomically advances the artifact's sequence under a
   compare-and-swap on the expected ``seq`` — **voiding A's key**. The
   first transfer to anchor wins; every later or concurrent attempt fails
   with ``STALE_SEQUENCE``.

This package is the **offline-capable** half (mint / build / sign / verify
/ seal). The online *finalization* half (the CAS) lives in the anchor
server. A ``.eopx`` file alone is never proof of current ownership — only
a fresh signature under the controller recorded at the latest ``seq`` is.

Design notes
------------
* Canonical payloads are **length-prefixed** field concatenations (see
  :func:`lp`) so a variable-length ``type`` tag can never be confused with
  its neighbours. The byte layout is FROZEN at v1 — any change must bump
  the domain separators.
* The controller key reuses :class:`eopx.format.keys.EopxKey`: its
  Dilithium half proves *control* (signs transfers), its Kyber half is the
  *delivery* target for sealed content. One per-artifact keypair, two
  roles.
* No function here touches the network. The anchor is the source of truth;
  this layer is the courier.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ..format.keys import EopxKey, key_fingerprint

# ---------------------------------------------------------------------------
# Frozen constants — v1 wire format
# ---------------------------------------------------------------------------

WIRE_VERSION = 1

# Domain separators (spec §4) — frozen at v1.
EPXT_ISSUE = b"epx-t.issue.v1"
EPXT_TRANSFER = b"epx-t.transfer.v1"
EPXT_POP = b"epx-t.pop.v1"
EPXT_RECEIPT = b"epx-t.receipt.v1"
EPXT_PAY = b"epx-t.payment.v1"  # buyer's authorization of a priced sale

# Content sealing (KEM-wrap of a per-artifact content key).
EPXT_CONTENT_WRAP = b"epx-t.content.wrap.v1"

ARTIFACT_ID_LEN = 16
NONCE_LEN = 16        # protocol nonces (issue / transfer hand-off)
AEAD_NONCE_LEN = 12   # ChaCha20-Poly1305 nonce
CONTENT_KEY_LEN = 32

# An empty 64-byte commitment marks "no confidential content".
NO_CONTENT_COMMIT = b""


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------

def lp(*parts: bytes) -> bytes:
    """Unambiguous length-prefixed concatenation of byte fields.

    Each part is encoded as ``uint32-big-endian length || bytes``. This
    makes the boundary between fields explicit, so a variable-length tag
    (e.g. the artifact ``type``) cannot be slid into an adjacent field to
    forge a colliding signed payload.
    """
    out = bytearray()
    for p in parts:
        out += len(p).to_bytes(4, "big")
        out += p
    return bytes(out)


def content_commitment(content: Optional[bytes]) -> bytes:
    """SHA3-512 of the confidential content, or ``b""`` when there is none."""
    if content is None:
        return NO_CONTENT_COMMIT
    return hashlib.sha3_512(content).digest()


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _h(b: bytes) -> str:
    return b.hex()


def _u(s: str) -> bytes:
    return bytes.fromhex(s) if s else b""


# ---------------------------------------------------------------------------
# Canonical signed payloads (spec §5)
# ---------------------------------------------------------------------------

def issue_payload(artifact_id: bytes, type_: str,
                  content_commit: bytes, c0_pub: bytes,
                  nonce: bytes) -> bytes:
    """Bytes signed by the issuer at mint (spec §5.1.3)."""
    return EPXT_ISSUE + lp(
        artifact_id, type_.encode("utf-8"), content_commit, c0_pub, nonce,
    )


def transfer_payload(artifact_id: bytes, from_seq: int,
                     prev_controller: bytes, new_controller: bytes,
                     nonce_b: bytes) -> bytes:
    """Bytes signed by the current controller at transfer (spec §5.2.3)."""
    return EPXT_TRANSFER + lp(
        artifact_id, int(from_seq).to_bytes(8, "big"),
        prev_controller, new_controller, nonce_b,
    )


def pop_payload(artifact_id: bytes, nonce_b: bytes) -> bytes:
    """Bytes signed by the *new* controller to prove possession (spec §5.2.1)."""
    return EPXT_POP + lp(artifact_id, nonce_b)


def receipt_payload(artifact_id: bytes, seq: int,
                    controller_pub: bytes, ts: str) -> bytes:
    """Bytes signed by the anchor for a receipt (spec §5.4)."""
    return EPXT_RECEIPT + lp(
        artifact_id, int(seq).to_bytes(8, "big"),
        controller_pub, ts.encode("utf-8"),
    )


def payment_payload(artifact_id: bytes, from_seq: int, price: int,
                    payer_account: str, payee_account: str) -> bytes:
    """Bytes signed by the BUYER (new controller) authorizing a priced sale.

    Binds the exact sale terms — artifact, position, price, and both
    EIDOLON accounts — to the same key that proves possession of the new
    controller, so the price cannot be altered and the authorization cannot
    be replayed against another transfer.
    """
    return EPXT_PAY + lp(
        artifact_id, int(from_seq).to_bytes(8, "big"),
        int(price).to_bytes(8, "big"),
        payer_account.encode("utf-8"), payee_account.encode("utf-8"),
    )


def controller_fp(c_pub: bytes) -> bytes:
    """Compact controller index ``SHA3-256(EPXT_ISSUE || C_pub)`` (spec §4)."""
    return hashlib.sha3_256(EPXT_ISSUE + c_pub).digest()


# ---------------------------------------------------------------------------
# Controller keys
# ---------------------------------------------------------------------------

def generate_controller() -> EopxKey:
    """Generate a fresh per-artifact controller keypair.

    The Dilithium half signs ownership transfers; the Kyber half is the
    delivery target for sealed content. Keep the secret half under vault
    protection (spec §8) — losing it means recovering the vault to
    re-derive it.
    """
    return EopxKey.generate()


# ---------------------------------------------------------------------------
# Confidential content envelope
# ---------------------------------------------------------------------------

def _kdf_wrap(shared_secret: bytes) -> bytes:
    from ..metatron.field import hkdf_sha3_256
    return hkdf_sha3_256(
        ikm=shared_secret, salt=b"", info=EPXT_CONTENT_WRAP,
        length=CONTENT_KEY_LEN,
    )


@dataclass
class KeyWrap:
    """A content key wrapped to one recipient's ML-KEM public key.

    Re-keying on transfer replaces only this object; the bulk
    ``content_ciphertext`` is never re-encrypted.
    """
    recipient_kyber_fp: bytes
    kem_ciphertext: bytes
    wrap_nonce: bytes
    wrapped_key: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recipient_kyber_fp_hex": _h(self.recipient_kyber_fp),
            "kem_ciphertext_hex": _h(self.kem_ciphertext),
            "wrap_nonce_hex": _h(self.wrap_nonce),
            "wrapped_key_hex": _h(self.wrapped_key),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "KeyWrap":
        return cls(
            recipient_kyber_fp=_u(d["recipient_kyber_fp_hex"]),
            kem_ciphertext=_u(d["kem_ciphertext_hex"]),
            wrap_nonce=_u(d["wrap_nonce_hex"]),
            wrapped_key=_u(d["wrapped_key_hex"]),
        )


@dataclass
class SealedContent:
    """Confidential artifact content, sealed under a per-artifact key.

    ``content_ciphertext`` is ChaCha20-Poly1305 over the plaintext with
    a random ``content_key``; ``key_wrap`` carries that key wrapped to the
    *current owner's* Kyber key. Transfer rotates ``key_wrap`` only.
    """
    artifact_id: bytes
    content_nonce: bytes
    content_ciphertext: bytes
    key_wrap: KeyWrap

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id_hex": _h(self.artifact_id),
            "content_nonce_hex": _h(self.content_nonce),
            "content_ciphertext_hex": _h(self.content_ciphertext),
            "key_wrap": self.key_wrap.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SealedContent":
        return cls(
            artifact_id=_u(d["artifact_id_hex"]),
            content_nonce=_u(d["content_nonce_hex"]),
            content_ciphertext=_u(d["content_ciphertext_hex"]),
            key_wrap=KeyWrap.from_dict(d["key_wrap"]),
        )

    @property
    def commitment(self) -> bytes:
        """SHA3-512 over the bulk ciphertext is *not* the content commit.

        The content commitment binds the *plaintext* and is carried in the
        :class:`TitledArtifact`; this property is intentionally absent to
        avoid confusing the two.
        """
        raise NotImplementedError  # pragma: no cover


def _wrap_to(content_key: bytes, recipient_kyber_pub: bytes,
             artifact_id: bytes) -> KeyWrap:
    pub = EopxKey(dilithium_pk=b"", kyber_pk=recipient_kyber_pub)
    kem_ct, ss = pub.kem_encapsulate()
    wrap_key = _kdf_wrap(ss)
    wrap_nonce = secrets.token_bytes(AEAD_NONCE_LEN)
    wrapped = ChaCha20Poly1305(wrap_key).encrypt(
        wrap_nonce, content_key, artifact_id,
    )
    return KeyWrap(
        recipient_kyber_fp=key_fingerprint(recipient_kyber_pub),
        kem_ciphertext=kem_ct,
        wrap_nonce=wrap_nonce,
        wrapped_key=wrapped,
    )


def _unwrap(key_wrap: KeyWrap, owner: EopxKey, artifact_id: bytes) -> bytes:
    ss = owner.kem_decapsulate(key_wrap.kem_ciphertext)
    wrap_key = _kdf_wrap(ss)
    return ChaCha20Poly1305(wrap_key).decrypt(
        key_wrap.wrap_nonce, key_wrap.wrapped_key, artifact_id,
    )


def seal_content(content: bytes, recipient: EopxKey,
                 artifact_id: bytes) -> SealedContent:
    """Encrypt ``content`` and wrap its key to ``recipient``'s Kyber key.

    ``recipient`` may be a public-only :class:`EopxKey` (the first owner's
    controller). ``artifact_id`` is bound as AEAD associated data so a
    sealed blob cannot be replayed under a different artifact.
    """
    content_key = secrets.token_bytes(CONTENT_KEY_LEN)
    content_nonce = secrets.token_bytes(AEAD_NONCE_LEN)
    content_ct = ChaCha20Poly1305(content_key).encrypt(
        content_nonce, content, artifact_id,
    )
    wrap = _wrap_to(content_key, recipient.kyber_pk, artifact_id)
    return SealedContent(
        artifact_id=artifact_id,
        content_nonce=content_nonce,
        content_ciphertext=content_ct,
        key_wrap=wrap,
    )


def open_content(sealed: SealedContent, owner: EopxKey) -> bytes:
    """Decrypt sealed content using the current owner's secret Kyber key."""
    content_key = _unwrap(sealed.key_wrap, owner, sealed.artifact_id)
    return ChaCha20Poly1305(content_key).decrypt(
        sealed.content_nonce, sealed.content_ciphertext, sealed.artifact_id,
    )


def reseal_content(sealed: SealedContent, current_owner: EopxKey,
                   recipient_kyber_pub: bytes) -> SealedContent:
    """Re-wrap the content key to a new recipient (the §5.2 delivery step).

    Performed by the *current* owner during a transfer: it unwraps the
    content key with its own secret, then wraps it to the recipient's
    Kyber key. The bulk ciphertext is untouched, so a prior owner who keeps
    the old ``.eopx`` retains only the *old* wrap and learns nothing new.
    """
    content_key = _unwrap(sealed.key_wrap, current_owner, sealed.artifact_id)
    new_wrap = _wrap_to(content_key, recipient_kyber_pub, sealed.artifact_id)
    return SealedContent(
        artifact_id=sealed.artifact_id,
        content_nonce=sealed.content_nonce,
        content_ciphertext=sealed.content_ciphertext,
        key_wrap=new_wrap,
    )


# ---------------------------------------------------------------------------
# Titled artifact record (spec §3.1)
# ---------------------------------------------------------------------------

@dataclass
class TitledArtifact:
    """A titled object minted by an issuer and signed at genesis.

    ``issuer_sig`` covers ``EPXT_ISSUE || artifact_id || type ||
    content_commit || initial_controller_pub || issue_nonce`` and is
    verifiable against ``issuer_pub``. ``issue_seq`` is *not* signed — it is
    assigned by the anchor at mint and filled in from the receipt.
    """
    artifact_id: bytes
    type: str
    content_commit: bytes          # SHA3-512(content) or b"" if none
    issuer_pub: bytes              # ML-DSA-87 public key
    initial_controller_pub: bytes  # C0_pub (Dilithium)
    issue_nonce: bytes
    issuer_sig: bytes
    issue_seq: Optional[int] = None
    wire_version: int = WIRE_VERSION

    @property
    def issuer_vault_fp(self) -> bytes:
        """SHA3-256 fingerprint of the issuer's Dilithium public key."""
        return key_fingerprint(self.issuer_pub)

    @property
    def has_content(self) -> bool:
        return bool(self.content_commit)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "wire_version": self.wire_version,
            "artifact_id_hex": _h(self.artifact_id),
            "type": self.type,
            "content_commit_hex": _h(self.content_commit),
            "issuer_pub_hex": _h(self.issuer_pub),
            "issuer_vault_fp_hex": _h(self.issuer_vault_fp),
            "initial_controller_pub_hex": _h(self.initial_controller_pub),
            "issue_nonce_hex": _h(self.issue_nonce),
            "issuer_sig_hex": _h(self.issuer_sig),
            "issue_seq": self.issue_seq,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TitledArtifact":
        if d.get("wire_version", WIRE_VERSION) != WIRE_VERSION:
            raise ValueError(
                f"unsupported EPX-T wire_version: {d.get('wire_version')}"
            )
        return cls(
            artifact_id=_u(d["artifact_id_hex"]),
            type=d["type"],
            content_commit=_u(d["content_commit_hex"]),
            issuer_pub=_u(d["issuer_pub_hex"]),
            initial_controller_pub=_u(d["initial_controller_pub_hex"]),
            issue_nonce=_u(d["issue_nonce_hex"]),
            issuer_sig=_u(d["issuer_sig_hex"]),
            issue_seq=d.get("issue_seq"),
        )


# ---------------------------------------------------------------------------
# Transfer hand-off objects (spec §5.2)
# ---------------------------------------------------------------------------

@dataclass
class ControllerHandoff:
    """What the recipient B sends A to receive control (offline, §5.2.2)."""
    artifact_id: bytes
    new_controller_pub: bytes      # C_{n+1}_pub (Dilithium)
    new_controller_kyber_pub: bytes  # for content delivery
    nonce_b: bytes
    pop: bytes                     # PoP over (artifact_id, nonce_b)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id_hex": _h(self.artifact_id),
            "new_controller_pub_hex": _h(self.new_controller_pub),
            "new_controller_kyber_pub_hex": _h(self.new_controller_kyber_pub),
            "nonce_b_hex": _h(self.nonce_b),
            "pop_hex": _h(self.pop),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ControllerHandoff":
        return cls(
            artifact_id=_u(d["artifact_id_hex"]),
            new_controller_pub=_u(d["new_controller_pub_hex"]),
            new_controller_kyber_pub=_u(d["new_controller_kyber_pub_hex"]),
            nonce_b=_u(d["nonce_b_hex"]),
            pop=_u(d["pop_hex"]),
        )


@dataclass
class Transfer:
    """A signed hand-off from the current controller to the next (§5.2.3).

    Submitted to the anchor for finalization. ``xfer_sig`` is by
    ``prev_controller``; ``pop`` (carried for the anchor's convenience) is
    by ``new_controller``.
    """
    artifact_id: bytes
    from_seq: int
    prev_controller: bytes
    new_controller: bytes
    new_controller_kyber_pub: bytes
    nonce_b: bytes
    xfer_sig: bytes
    pop: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id_hex": _h(self.artifact_id),
            "from_seq": self.from_seq,
            "prev_controller_hex": _h(self.prev_controller),
            "new_controller_hex": _h(self.new_controller),
            "new_controller_kyber_pub_hex": _h(self.new_controller_kyber_pub),
            "nonce_b_hex": _h(self.nonce_b),
            "xfer_sig_hex": _h(self.xfer_sig),
            "pop_hex": _h(self.pop),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Transfer":
        return cls(
            artifact_id=_u(d["artifact_id_hex"]),
            from_seq=int(d["from_seq"]),
            prev_controller=_u(d["prev_controller_hex"]),
            new_controller=_u(d["new_controller_hex"]),
            new_controller_kyber_pub=_u(d["new_controller_kyber_pub_hex"]),
            nonce_b=_u(d["nonce_b_hex"]),
            xfer_sig=_u(d["xfer_sig_hex"]),
            pop=_u(d["pop_hex"]),
        )


# ---------------------------------------------------------------------------
# Anchor receipt (spec §5.4)
# ---------------------------------------------------------------------------

@dataclass
class AnchorReceipt:
    """Anchor-signed attestation that the ledger now reads ``seq``."""
    artifact_id: bytes
    seq: int
    controller_pub: bytes
    ts: str
    anchor_pub: bytes
    sig: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id_hex": _h(self.artifact_id),
            "seq": self.seq,
            "controller_pub_hex": _h(self.controller_pub),
            "ts": self.ts,
            "anchor_pub_hex": _h(self.anchor_pub),
            "sig_hex": _h(self.sig),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AnchorReceipt":
        return cls(
            artifact_id=_u(d["artifact_id_hex"]),
            seq=int(d["seq"]),
            controller_pub=_u(d["controller_pub_hex"]),
            ts=d["ts"],
            anchor_pub=_u(d["anchor_pub_hex"]),
            sig=_u(d["sig_hex"]),
        )


def sign_receipt(anchor: EopxKey, artifact_id: bytes, seq: int,
                 controller_pub: bytes, ts: Optional[str] = None) -> AnchorReceipt:
    """Mint an anchor-signed receipt for the state ``(artifact_id, seq)``."""
    ts = ts or _utc_now()
    sig = anchor.sign(receipt_payload(artifact_id, seq, controller_pub, ts))
    return AnchorReceipt(
        artifact_id=artifact_id, seq=seq, controller_pub=controller_pub,
        ts=ts, anchor_pub=anchor.dilithium_pk, sig=sig,
    )


def verify_receipt(receipt: AnchorReceipt,
                   expected_anchor_pub: Optional[bytes] = None) -> bool:
    """Verify a receipt's anchor signature (and optionally the anchor key)."""
    if expected_anchor_pub is not None and receipt.anchor_pub != expected_anchor_pub:
        return False
    pub = EopxKey(dilithium_pk=receipt.anchor_pub, kyber_pk=b"")
    return pub.verify(
        receipt_payload(receipt.artifact_id, receipt.seq,
                        receipt.controller_pub, receipt.ts),
        receipt.sig,
    )


# ---------------------------------------------------------------------------
# Priced sale — the buyer's payment authorization
# ---------------------------------------------------------------------------

@dataclass
class PaymentTerms:
    """A buyer's signed authorization to pay for a titled transfer.

    Signed by the **new controller** (the buyer B, who also produced the
    transfer's PoP), so it is bound to the same party taking control.
    ``payer_account`` / ``payee_account`` are opaque EIDOLON account ids
    (hex vault fingerprints, typically); ``price`` is in the smallest
    EIDOLON unit.
    """
    price: int
    payer_account: str
    payee_account: str
    from_seq: int
    sig: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "price": self.price,
            "payer_account": self.payer_account,
            "payee_account": self.payee_account,
            "from_seq": self.from_seq,
            "sig_hex": _h(self.sig),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PaymentTerms":
        return cls(
            price=int(d["price"]),
            payer_account=d["payer_account"],
            payee_account=d["payee_account"],
            from_seq=int(d["from_seq"]),
            sig=_u(d["sig_hex"]),
        )


def sign_payment(new_controller: EopxKey, artifact_id: bytes, from_seq: int,
                 price: int, payer_account: str,
                 payee_account: str) -> PaymentTerms:
    """Buyer side: authorize paying ``price`` for this exact transfer."""
    if not new_controller.has_secrets:
        raise ValueError("new_controller must hold a Dilithium secret key")
    if price < 0:
        raise ValueError("price must be >= 0")
    sig = new_controller.sign(
        payment_payload(artifact_id, from_seq, price,
                        payer_account, payee_account)
    )
    return PaymentTerms(
        price=int(price), payer_account=payer_account,
        payee_account=payee_account, from_seq=int(from_seq), sig=sig,
    )


def verify_payment(terms: PaymentTerms, artifact_id: bytes,
                   new_controller_pub: bytes) -> bool:
    """Anchor/verifier side: check the buyer authorized these exact terms.

    ``new_controller_pub`` MUST be the new controller from the transfer
    being settled, so the authorization cannot be lifted onto a different
    buyer. Returns ``False`` on any mismatch — never raises.
    """
    try:
        pub = EopxKey(dilithium_pk=new_controller_pub, kyber_pk=b"")
        return pub.verify(
            payment_payload(artifact_id, terms.from_seq, terms.price,
                            terms.payer_account, terms.payee_account),
            terms.sig,
        )
    except Exception:
        return False


from .mint import mint_artifact, verify_artifact, new_artifact_id  # noqa: E402
from .transfer import (  # noqa: E402
    build_handoff,
    verify_handoff,
    build_transfer,
    verify_transfer,
)
from .verify import (  # noqa: E402
    ownership_challenge,
    prove_ownership,
    verify_ownership_proof,
    LedgerView,
    verify_against_ledger,
)
from .binding import (  # noqa: E402
    SealedController,
    seal_controller,
    unseal_controller,
    bind_new_controller,
)
from .transparency import (  # noqa: E402
    ChainCheck,
    verify_receipt_chain,
    detect_equivocation,
)
from .voucher import (  # noqa: E402
    EPXT_VOUCHER,
    ClaimProof,
    claim_commitment,
    make_claim,
    verify_claim,
)

__all__ = [
    "WIRE_VERSION",
    "EPXT_ISSUE", "EPXT_TRANSFER", "EPXT_POP", "EPXT_RECEIPT",
    "ARTIFACT_ID_LEN", "NONCE_LEN",
    # canonicalization
    "lp", "content_commitment", "controller_fp",
    "issue_payload", "transfer_payload", "pop_payload", "receipt_payload",
    # keys
    "generate_controller",
    # content
    "KeyWrap", "SealedContent",
    "seal_content", "open_content", "reseal_content",
    # records
    "TitledArtifact", "ControllerHandoff", "Transfer", "AnchorReceipt",
    "sign_receipt", "verify_receipt",
    # priced sale (EIDOLON)
    "EPXT_PAY", "PaymentTerms", "payment_payload",
    "sign_payment", "verify_payment",
    # mint
    "mint_artifact", "verify_artifact", "new_artifact_id",
    # transfer
    "build_handoff", "verify_handoff", "build_transfer", "verify_transfer",
    # ownership verification
    "ownership_challenge", "prove_ownership", "verify_ownership_proof",
    "LedgerView", "verify_against_ledger",
    # vault binding (sealed-to-vault controller, spec §8)
    "SealedController", "seal_controller", "unseal_controller",
    "bind_new_controller",
    # transparency log (spec §10)
    "ChainCheck", "verify_receipt_chain", "detect_equivocation",
    # voucher claim (EPX-V treasure hunt)
    "EPXT_VOUCHER", "ClaimProof", "claim_commitment",
    "make_claim", "verify_claim",
]

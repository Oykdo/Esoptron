"""EPX-F §5 — epoch links: keeping a printed artifact verifiable past its key.

A badge minted in 2026 carries a `dilithium_pk_fp` in its signed manifest. In
2030 that key may be retired, lost or compromised, and a verifier who only ever
learned the *current* key has no way to check the badge's ML-DSA-87 signature —
it does not hold the public key that made it. Without a bridge, a parc of
printed artifacts has the lifetime of a single key.

An :class:`EpochLink` is that bridge: one record binding two consecutive
epochs, carrying the predecessor's **full public key** (not just its
fingerprint — a fingerprint identifies, it does not verify) and signed from
both ends.

Both directions, and why
------------------------
* ``successor_sig`` — the new key vouches for the old one. This is what lets a
  verifier holding only today's key walk *backwards* to an artifact minted
  years ago.
* ``predecessor_sig`` — the old key, while it is still alive, signs the same
  digest. This is what stops a compromised current key from inventing an
  ancestor: an attacker holding only the successor's secret can forge a
  ``successor_sig``, and with it a whole fake lineage, but cannot produce the
  predecessor's signature over that link.

A link carrying both is **strong**; one carrying only ``successor_sig`` is
**weak** and is only honest when the predecessor key is genuinely gone.
:func:`resolve_epoch` refuses weak links unless asked otherwise, so accepting
one is always a deliberate act.

* ``witness_sig`` — an optional third, independent key over the same digest,
  using the same two-key pattern as the signed-doc manifest
  (``tools/sign_spec.py``). It is the answer to "both my keys were in the same
  place when they were stolen".

What this is not
----------------
A link says *"this key succeeded that one"*. It says nothing about whether the
predecessor was honest, whether an artifact is genuine, or whether a key was
compromised before the rotation. Revocation is a separate problem and is
deliberately out of scope for v1: a chain that also had to express "and ignore
everything epoch N signed after date D" would be a different, larger object.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .format.keys import EopxKey, key_fingerprint

#: Bumping this changes every digest, and therefore every signature. FROZEN.
LINK_VERSION = 1

LINK_DOMAIN = b"esoptron.epoch.link.v1"


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class EpochLink:
    """One rotation: ``predecessor`` handed over to ``successor``."""

    predecessor_pk_b64: str
    successor_pk_b64: str
    issued_utc: str
    statement: str = ""
    successor_sig_b64: str = ""
    predecessor_sig_b64: str = ""
    witness_pk_b64: str = ""
    witness_sig_b64: str = ""
    version: int = LINK_VERSION

    # ----- identities --------------------------------------------------

    @property
    def predecessor_pk(self) -> bytes:
        return _b64d(self.predecessor_pk_b64)

    @property
    def successor_pk(self) -> bytes:
        return _b64d(self.successor_pk_b64)

    @property
    def predecessor_fp(self) -> bytes:
        return key_fingerprint(self.predecessor_pk)

    @property
    def successor_fp(self) -> bytes:
        return key_fingerprint(self.successor_pk)

    # ----- canonical form ----------------------------------------------

    def canonical_bytes(self) -> bytes:
        """The byte string both signatures cover. Field set and order FROZEN.

        Signatures are excluded (they sign this), and so is the witness key —
        a witness attests to an existing link; adding one must not invalidate
        the two signatures already on it.
        """
        lines = [
            LINK_DOMAIN.decode("ascii"),
            f"version={self.version}",
            f"predecessor_pk_b64={self.predecessor_pk_b64}",
            f"successor_pk_b64={self.successor_pk_b64}",
            f"issued_utc={self.issued_utc}",
            f"statement={self.statement}",
        ]
        return ("\n".join(lines)).encode("utf-8")

    def digest(self) -> bytes:
        """SHA3-512 of :meth:`canonical_bytes` — what actually gets signed."""
        return hashlib.sha3_512(self.canonical_bytes()).digest()

    # ----- serialization -------------------------------------------------

    def to_dict(self) -> Dict[str, object]:
        out: Dict[str, object] = {
            "version": self.version,
            "predecessor_pk_b64": self.predecessor_pk_b64,
            "predecessor_pk_fp": f"sha3-256:{self.predecessor_fp.hex()}",
            "successor_pk_b64": self.successor_pk_b64,
            "successor_pk_fp": f"sha3-256:{self.successor_fp.hex()}",
            "issued_utc": self.issued_utc,
            "statement": self.statement,
            "successor_sig_b64": self.successor_sig_b64,
        }
        if self.predecessor_sig_b64:
            out["predecessor_sig_b64"] = self.predecessor_sig_b64
        if self.witness_pk_b64:
            out["witness_pk_b64"] = self.witness_pk_b64
            out["witness_sig_b64"] = self.witness_sig_b64
        return out

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "EpochLink":
        version = int(d.get("version", 0))
        if version != LINK_VERSION:
            raise ValueError(f"unsupported epoch-link version: {version!r}")
        return cls(
            predecessor_pk_b64=str(d["predecessor_pk_b64"]),
            successor_pk_b64=str(d["successor_pk_b64"]),
            issued_utc=str(d["issued_utc"]),
            statement=str(d.get("statement", "")),
            successor_sig_b64=str(d.get("successor_sig_b64", "")),
            predecessor_sig_b64=str(d.get("predecessor_sig_b64", "")),
            witness_pk_b64=str(d.get("witness_pk_b64", "")),
            witness_sig_b64=str(d.get("witness_sig_b64", "")),
            version=version,
        )


@dataclass
class LinkVerdict:
    """Why a link was accepted or rejected. Never raises on a bad link."""

    ok: bool = False
    strong: bool = False
    witnessed: bool = False
    errors: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.ok


def build_link(predecessor: EopxKey, successor: EopxKey, *,
               issued_utc: Optional[str] = None,
               statement: str = "",
               witness: Optional[EopxKey] = None) -> EpochLink:
    """Mint a link handing ``predecessor`` over to ``successor``.

    ``successor`` must hold secret material. ``predecessor`` should too — that
    is what makes the link *strong*; pass a public-only key only when the old
    secret is genuinely unavailable, and expect verifiers to refuse the result
    unless they opt in.

    A ``witness`` (third, independent key) cosigns the same digest.
    """
    if not successor.has_secrets:
        raise ValueError("successor key has no secret material")

    link = EpochLink(
        predecessor_pk_b64=_b64e(predecessor.dilithium_pk),
        successor_pk_b64=_b64e(successor.dilithium_pk),
        issued_utc=issued_utc or _utc_now(),
        statement=statement,
    )
    if link.predecessor_fp == link.successor_fp:
        raise ValueError("a key cannot succeed itself")

    digest = link.digest()
    predecessor_sig = (_b64e(predecessor.sign(digest))
                       if predecessor.has_secrets else "")
    witness_pk = _b64e(witness.dilithium_pk) if witness is not None else ""
    witness_sig = ""
    if witness is not None:
        if not witness.has_secrets:
            raise ValueError("witness key has no secret material")
        witness_sig = _b64e(witness.sign(digest))

    return EpochLink(
        predecessor_pk_b64=link.predecessor_pk_b64,
        successor_pk_b64=link.successor_pk_b64,
        issued_utc=link.issued_utc,
        statement=link.statement,
        successor_sig_b64=_b64e(successor.sign(digest)),
        predecessor_sig_b64=predecessor_sig,
        witness_pk_b64=witness_pk,
        witness_sig_b64=witness_sig,
    )


def verify_link(link: EpochLink, *,
                witness_pk: Optional[bytes] = None) -> LinkVerdict:
    """Check a link's signatures. Never raises — inspect the verdict.

    ``witness_pk``: the witness key the caller *expects*. A witness signature
    is only worth anything against a key known in advance; verifying it against
    the key the link itself carries would prove nothing, so an unexpected
    witness key is reported as an error rather than silently trusted.
    """
    verdict = LinkVerdict()
    try:
        digest = link.digest()
        pred_pub = EopxKey(dilithium_pk=link.predecessor_pk, kyber_pk=b"")
        succ_pub = EopxKey(dilithium_pk=link.successor_pk, kyber_pk=b"")
    except Exception as exc:  # malformed base64, wrong version...
        verdict.errors.append(f"malformed link: {exc}")
        return verdict

    if link.predecessor_fp == link.successor_fp:
        verdict.errors.append("a key cannot succeed itself")
        return verdict

    if not link.successor_sig_b64:
        verdict.errors.append("missing successor signature")
        return verdict
    if not succ_pub.verify(digest, _b64d(link.successor_sig_b64)):
        verdict.errors.append("successor signature does not verify")
        return verdict

    if link.predecessor_sig_b64:
        if pred_pub.verify(digest, _b64d(link.predecessor_sig_b64)):
            verdict.strong = True
        else:
            verdict.errors.append("predecessor signature does not verify")
            return verdict

    if witness_pk is not None:
        if not link.witness_pk_b64:
            verdict.errors.append("witness expected but the link carries none")
            return verdict
        if _b64d(link.witness_pk_b64) != witness_pk:
            verdict.errors.append("witness key is not the expected one")
            return verdict
        wit_pub = EopxKey(dilithium_pk=witness_pk, kyber_pk=b"")
        if not wit_pub.verify(digest, _b64d(link.witness_sig_b64)):
            verdict.errors.append("witness signature does not verify")
            return verdict
        verdict.witnessed = True

    verdict.ok = True
    return verdict


def resolve_epoch(chain: Sequence[EpochLink], *, trusted_pk: bytes,
                  target_fp: bytes, require_strong: bool = True,
                  witness_pk: Optional[bytes] = None,
                  max_hops: int = 64) -> Optional[bytes]:
    """Walk back from ``trusted_pk`` to ``target_fp``; return the public key.

    ``trusted_pk`` is the one key the verifier actually trusts (pinned, or
    fetched from the issuer's well-known endpoint). ``target_fp`` is the
    ``dilithium_pk_fp`` an artifact claims. The returned key is what the
    artifact's own signature should be verified against — resolving an epoch
    is *not* verifying the artifact.

    Returns ``None`` when no valid path exists. Weak links (no predecessor
    signature) are refused unless ``require_strong=False``; ``max_hops`` bounds
    the walk so a cyclic or adversarial chain cannot spin.
    """
    if key_fingerprint(trusted_pk) == target_fp:
        return trusted_pk

    by_successor: Dict[bytes, EpochLink] = {}
    for link in chain:
        try:
            by_successor.setdefault(link.successor_fp, link)
        except Exception:
            continue  # malformed entries simply do not participate

    current = trusted_pk
    seen = {key_fingerprint(current)}
    for _ in range(max_hops):
        link = by_successor.get(key_fingerprint(current))
        if link is None:
            return None
        if link.successor_pk != current:
            return None  # fingerprint collision or a substituted key
        verdict = verify_link(link, witness_pk=witness_pk)
        if not verdict.ok:
            return None
        if require_strong and not verdict.strong:
            return None
        current = link.predecessor_pk
        fp = key_fingerprint(current)
        if fp in seen:
            return None  # cycle
        seen.add(fp)
        if fp == target_fp:
            return current
    return None


def load_chain(path: str | Path) -> List[EpochLink]:
    """Read a published chain: ``{"version": 1, "links": [...]}``."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("version") != LINK_VERSION:
        raise ValueError(f"unsupported chain version: {data.get('version')!r}")
    return [EpochLink.from_dict(d) for d in data.get("links", [])]


def dump_chain(chain: Sequence[EpochLink]) -> str:
    """Serialise a chain for publication (newest link first)."""
    return json.dumps(
        {"version": LINK_VERSION, "links": [ln.to_dict() for ln in chain]},
        indent=2, ensure_ascii=False, sort_keys=False) + "\n"


__all__ = [
    "LINK_VERSION", "LINK_DOMAIN",
    "EpochLink", "LinkVerdict",
    "build_link", "verify_link", "resolve_epoch",
    "load_chain", "dump_chain",
]

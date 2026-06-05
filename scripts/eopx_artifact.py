"""EPX-T titled artifacts — mint, transfer, and verify from the CLI.

A *titled artifact* moves control from vault to vault **without
duplication** (see ``docs/specs/EPX-T_titled_transfer.md``). This tool
drives the offline half (mint / hand-off / sign) and optionally submits to
a running anchor for the online finalization (the atomic re-key).

Lifecycle
---------
::

    # 0. each party holds a vault key (eopx_keygen.py); the recipient also
    #    generates a fresh per-artifact controller key:
    py scripts/eopx_artifact.py gen-controller --out alice.ctrl.json

    # 1. issuer mints a titled artifact bound to Alice's controller:
    py scripts/eopx_artifact.py mint --issuer issuer.json \
        --controller alice.ctrl.json --type token \
        --content note.txt --out widget.artifact.json \
        --sealed widget.sealed.json --anchor-url http://localhost:8788

    # 2. Bob (recipient) builds a hand-off for Alice:
    py scripts/eopx_artifact.py gen-controller --out bob.ctrl.json
    py scripts/eopx_artifact.py handoff --controller bob.ctrl.json \
        --artifact widget.artifact.json --out bob.handoff.json

    # 3. Alice (current owner) signs the transfer + re-seals content,
    #    then finalizes at the anchor:
    py scripts/eopx_artifact.py transfer --controller alice.ctrl.json \
        --artifact widget.artifact.json --from-seq 0 \
        --handoff bob.handoff.json \
        --sealed-in widget.sealed.json --sealed-out widget.sealed.bob.json \
        --out widget.transfer.json --anchor-url http://localhost:8788

    # 4. anyone verifies authenticity + current ownership:
    py scripts/eopx_artifact.py verify --artifact widget.artifact.json \
        --anchor-url http://localhost:8788

``--anchor-url`` is optional everywhere: without it the tool only produces
the offline JSON objects, which can be couriered (QR / file / NFC) and
submitted later. A ``.eopx`` (or any of these files) alone is never proof
of current ownership — only the anchor's latest record is.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

from eopx.format.keys import EopxKey
from eopx.collection.ownership import (
    Possession,
    possession_status,
    prove_relic_ownership,
    verify_relic_ownership,
)
from eopx.transfer import (
    AnchorReceipt,
    ControllerHandoff,
    PaymentTerms,
    SealedContent,
    SealedController,
    TitledArtifact,
    build_handoff,
    build_transfer,
    detect_equivocation,
    generate_controller,
    mint_artifact,
    ownership_challenge,
    sign_payment,
    verify_artifact,
    verify_receipt,
    verify_receipt_chain,
)


# ---------------------------------------------------------------------------
# Small JSON / HTTP helpers
# ---------------------------------------------------------------------------

def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _post(anchor_url: str, route: str, payload: dict) -> tuple[int, dict]:
    url = anchor_url.rstrip("/") + route
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, {"error": body}


def _get(anchor_url: str, route: str) -> tuple[int, dict]:
    url = anchor_url.rstrip("/") + route
    try:
        with urllib.request.urlopen(url, timeout=10.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, {"error": body}


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_gen_controller(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser()
    if out.exists() and not args.force:
        print(f"refusing to overwrite {out} (pass --force)", file=sys.stderr)
        return 2
    key = generate_controller()
    key.save(out)
    print(f"wrote controller keypair {out}")
    print(f"  controller_pub_fp = {key.dilithium_pk_fp.hex()}")
    print(f"  kyber_pk_fp       = {key.kyber_pk_fp.hex()}")
    return 0


def cmd_mint(args: argparse.Namespace) -> int:
    issuer = EopxKey.load(Path(args.issuer).expanduser())
    controller = EopxKey.load(Path(args.controller).expanduser())
    content: Optional[bytes] = None
    if args.content:
        content = Path(args.content).expanduser().read_bytes()

    artifact, sealed = mint_artifact(
        issuer, args.type, controller.public_only(), content=content,
    )
    _write_json(Path(args.out).expanduser(), artifact.to_dict())
    print(f"minted artifact {artifact.artifact_id.hex()} (type={artifact.type})")
    print(f"  wrote {args.out}")
    if sealed is not None:
        if not args.sealed:
            print("  NOTE: content was sealed but --sealed not given; "
                  "the sealed blob was discarded", file=sys.stderr)
        else:
            _write_json(Path(args.sealed).expanduser(), sealed.to_dict())
            print(f"  wrote sealed content {args.sealed}")

    if args.anchor_url:
        status, body = _post(args.anchor_url, "/api/v1/artifact/mint",
                             artifact.to_dict())
        if status != 200:
            print(f"anchor mint failed [{status}]: {body.get('error', body)}",
                  file=sys.stderr)
            return 1
        print(f"  anchored at seq={body['seq']}")
        if args.receipt:
            _write_json(Path(args.receipt).expanduser(), body["receipt"])
            print(f"  wrote receipt {args.receipt}")
    return 0


def cmd_handoff(args: argparse.Namespace) -> int:
    controller = EopxKey.load(Path(args.controller).expanduser())
    artifact = TitledArtifact.from_dict(_read_json(Path(args.artifact)))
    handoff = build_handoff(controller, artifact.artifact_id)
    _write_json(Path(args.out).expanduser(), handoff.to_dict())
    print(f"built hand-off for artifact {artifact.artifact_id.hex()}")
    print(f"  new controller fp = {controller.dilithium_pk_fp.hex()}")
    print(f"  wrote {args.out}")

    # Optionally authorize a priced sale: the BUYER (this new controller)
    # signs "I will pay <price> from <payer> to <payee> at seq <from_seq>".
    if args.price is not None:
        if not (args.payer and args.payee):
            print("  --price requires --payer and --payee", file=sys.stderr)
            return 2
        terms = sign_payment(
            controller, artifact.artifact_id, args.from_seq, args.price,
            payer_account=args.payer, payee_account=args.payee,
        )
        out = args.payment_out or (str(Path(args.out)) + ".payment.json")
        _write_json(Path(out).expanduser(), terms.to_dict())
        print(f"  authorized payment {args.price} EIDOLON "
              f"({args.payer[:8]}... -> {args.payee[:8]}...) at seq "
              f"{args.from_seq}")
        print(f"  wrote {out}")
    return 0


def cmd_transfer(args: argparse.Namespace) -> int:
    controller = EopxKey.load(Path(args.controller).expanduser())
    artifact = TitledArtifact.from_dict(_read_json(Path(args.artifact)))
    handoff = ControllerHandoff.from_dict(_read_json(Path(args.handoff)))

    sealed_in: Optional[SealedContent] = None
    if args.sealed_in:
        sealed_in = SealedContent.from_dict(_read_json(Path(args.sealed_in)))

    try:
        transfer, resealed = build_transfer(
            controller, args.from_seq, handoff, sealed_content=sealed_in,
        )
    except ValueError as exc:
        print(f"refusing to build transfer: {exc}", file=sys.stderr)
        return 1

    _write_json(Path(args.out).expanduser(), transfer.to_dict())
    print(f"signed transfer of {artifact.artifact_id.hex()} "
          f"from seq={args.from_seq}")
    print(f"  -> new controller {handoff.new_controller_pub[:6].hex()}...")
    print(f"  wrote {args.out}")
    if resealed is not None:
        if not args.sealed_out:
            print("  NOTE: content was re-sealed but --sealed-out not given",
                  file=sys.stderr)
        else:
            _write_json(Path(args.sealed_out).expanduser(), resealed.to_dict())
            print(f"  wrote re-sealed content {args.sealed_out}")

    submission = transfer.to_dict()
    if args.payment:
        terms = PaymentTerms.from_dict(_read_json(Path(args.payment)))
        pay = {"terms": terms.to_dict()}
        if args.fee:
            pay["fee"] = args.fee
        if args.treasury:
            pay["treasury_account"] = args.treasury
        submission["payment"] = pay
        print(f"  priced sale: {terms.price} EIDOLON "
              f"{terms.payer_account[:8]}... -> {terms.payee_account[:8]}...")

    if args.anchor_url:
        status, body = _post(args.anchor_url, "/api/v1/artifact/transfer",
                             submission)
        if status != 200:
            print(f"anchor transfer rejected [{status}]: "
                  f"{body.get('error', body)}", file=sys.stderr)
            return 1
        print(f"  anchored at seq={body['seq']}")
        if "payment" in body:
            p = body["payment"]
            print(f"  paid: payer={p['payer_balance']} payee={p['payee_balance']}")
        if args.receipt:
            _write_json(Path(args.receipt).expanduser(), body["receipt"])
            print(f"  wrote receipt {args.receipt}")
    return 0


def cmd_balance(args: argparse.Namespace) -> int:
    status, body = _get(args.anchor_url,
                        f"/api/v1/artifact/account/{args.account}")
    if status != 200:
        print(f"balance query failed [{status}]: {body.get('error', body)}",
              file=sys.stderr)
        return 1
    print(f"account {args.account}")
    print(f"  balance = {body['balance']} EIDOLON")
    return 0


def cmd_grant(args: argparse.Namespace) -> int:
    status, body = _post(
        args.anchor_url, f"/api/v1/artifact/account/{args.account}/grant",
        {"amount": args.amount},
    )
    if status != 200:
        print(f"grant rejected [{status}]: {body.get('error', body)}",
              file=sys.stderr)
        return 1
    print(f"granted; account {args.account} balance = {body['balance']} EIDOLON")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    artifact = TitledArtifact.from_dict(_read_json(Path(args.artifact)))
    content: Optional[bytes] = None
    if args.content:
        content = Path(args.content).expanduser().read_bytes()

    authentic = verify_artifact(artifact, content=content)
    print(f"artifact {artifact.artifact_id.hex()} (type={artifact.type})")
    print(f"  issuer_fp   = {artifact.issuer_vault_fp.hex()}")
    print(f"  authentic   = {authentic}"
          + ("" if content is None else " (incl. content commitment)"))
    if not authentic:
        return 1

    if args.anchor_url:
        status, body = _get(
            args.anchor_url,
            f"/api/v1/artifact/{artifact.artifact_id.hex()}",
        )
        if status != 200:
            print(f"  anchor query failed [{status}]: {body.get('error', body)}",
                  file=sys.stderr)
            return 1
        print(f"  current seq = {body['seq']}")
        print(f"  owner (controller_pub_fp) = "
              f"{__import__('hashlib').sha3_256(bytes.fromhex(body['controller_pub_hex'])).hexdigest()}")
        print(f"  updated_at  = {body['updated_at']}")
        print("  NOTE: possession of this file is NOT ownership; the line "
              "above is the anchor's current record.")
    return 0


def cmd_own(args: argparse.Namespace) -> int:
    """Check whether a vault currently *possesses* an artifact (not just holds a file)."""
    artifact = TitledArtifact.from_dict(_read_json(Path(args.artifact)))
    aid = artifact.artifact_id
    sealed = SealedController.from_dict(_read_json(Path(args.sealed_controller)))
    my_controller_pub = sealed.dilithium_pub

    # The ledger's current controller is the ONLY source of current ownership.
    ledger_controller_pub = None
    if args.anchor_url:
        status, body = _get(
            args.anchor_url, f"/api/v1/artifact/{aid.hex()}",
        )
        if status == 200:
            ledger_controller_pub = bytes.fromhex(body["controller_pub_hex"])
        elif status == 404:
            print(f"artifact {aid.hex()} is not minted on this anchor",
                  file=sys.stderr)
        else:
            print(f"anchor query failed [{status}]: {body.get('error', body)}",
                  file=sys.stderr)

    state = possession_status(my_controller_pub, ledger_controller_pub)
    print(f"artifact {aid.hex()} (type={artifact.type})")
    print(f"  possession  = {state.value.upper()}")

    # When held, demonstrate the trustless proof end to end (unseal -> sign
    # -> verify against the ledger controller), if we can unseal.
    if state is Possession.HELD and (args.device_secret or args.vault):
        try:
            ds = _load_device_secret(args)
            nonce = ownership_challenge()
            proof = prove_relic_ownership(sealed, ds, aid, nonce)
            ok = verify_relic_ownership(
                aid, nonce, proof, ledger_controller_pub,  # type: ignore[arg-type]
            )
            print(f"  proof       = {'VERIFIED' if ok else 'FAILED'}")
        except Exception as exc:
            print(f"  proof       = could not produce ({exc})", file=sys.stderr)
            return 1
    elif state is Possession.UNKNOWN:
        print("  NOTE: anchor unreachable; pass --anchor-url to determine "
              "current ownership.")
    return 0 if state is Possession.HELD else 1


def _load_device_secret(args: argparse.Namespace) -> bytes:
    if args.device_secret:
        return bytes.fromhex(args.device_secret)
    data = _read_json(Path(args.vault))
    return bytes.fromhex(data["device_secret_hex"])


def cmd_audit(args: argparse.Namespace) -> int:
    """Audit an artifact's transparency log: verify the receipt chain and
    detect equivocation against a previously-witnessed view (CT-style)."""
    if args.artifact:
        artifact = TitledArtifact.from_dict(_read_json(Path(args.artifact)))
        aid_hex = artifact.artifact_id.hex()
    elif args.artifact_id:
        aid_hex = args.artifact_id.lower()
    else:
        print("audit requires --artifact or --artifact-id", file=sys.stderr)
        return 2

    status, hist = _get(args.anchor_url,
                        f"/api/v1/artifact/{aid_hex}/history")
    if status != 200:
        print(f"history fetch failed [{status}]: {hist.get('error', hist)}",
              file=sys.stderr)
        return 1

    # Pin the anchor key: from a flag, else trust the server's reported key
    # but say so loudly (an unpinned audit only proves internal consistency).
    if args.anchor_pub:
        anchor_pub = bytes.fromhex(args.anchor_pub)
    elif args.anchor_key:
        anchor_pub = EopxKey.load(Path(args.anchor_key).expanduser()).dilithium_pk
    else:
        anchor_pub = bytes.fromhex(hist.get("anchor_pub_hex", ""))
        print("  WARNING: anchor key not pinned (--anchor-pub/--anchor-key); "
              "trusting the server's reported key.", file=sys.stderr)

    chk = verify_receipt_chain(hist, expected_anchor_pub=anchor_pub,
                               artifact_id=bytes.fromhex(aid_hex))
    print(f"artifact {aid_hex}")
    print(f"  chain length = {chk.length}")
    if chk.head_seq is not None:
        print(f"  head         = seq {chk.head_seq} -> "
              f"{(chk.head_controller_pub_hex or '')[:16]}...")
    print(f"  chain valid  = {chk.ok}")
    for issue in chk.issues:
        print(f"    - {issue}")

    forked = False
    if args.witness:
        wpath = Path(args.witness).expanduser()
        if wpath.exists():
            prior_raw = _read_json(wpath).get("chain", [])
            prior = [(int(s), p) for s, p in prior_raw]
            ev = detect_equivocation(prior, chk.chain)
            if ev is not None:
                forked = True
                seq, was, now = ev
                print(f"  !! EQUIVOCATION at seq {seq}: witnessed "
                      f"{was[:16]}... now {now[:16] if now != '<missing>' else now}")
            else:
                print("  fork check  = consistent (append-only extension)")
        # Update the witnessed view for next time.
        _write_json(wpath, {"artifact_id_hex": aid_hex, "chain": chk.chain})
        print(f"  witnessed view saved to {wpath}")

    return 0 if (chk.ok and not forked) else 1


def cmd_verify_receipt(args: argparse.Namespace) -> int:
    receipt = AnchorReceipt.from_dict(_read_json(Path(args.receipt)))
    ok = verify_receipt(receipt)
    print(f"receipt for {receipt.artifact_id.hex()} @ seq={receipt.seq}")
    print(f"  anchor_fp = {__import__('hashlib').sha3_256(receipt.anchor_pub).hexdigest()}")
    print(f"  valid     = {ok}")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("gen-controller",
                       help="Generate a per-artifact controller keypair")
    g.add_argument("--out", required=True)
    g.add_argument("--force", action="store_true")
    g.set_defaults(func=cmd_gen_controller)

    m = sub.add_parser("mint", help="Mint a titled artifact")
    m.add_argument("--issuer", required=True, help="Issuer keypair JSON (secret)")
    m.add_argument("--controller", required=True,
                   help="First owner's controller keypair JSON")
    m.add_argument("--type", required=True, help="Artifact type tag")
    m.add_argument("--content", help="Optional file to seal as content")
    m.add_argument("--out", required=True, help="Where to write the artifact JSON")
    m.add_argument("--sealed", help="Where to write the sealed content JSON")
    m.add_argument("--anchor-url", help="Anchor base URL to finalize the mint")
    m.add_argument("--receipt", help="Where to write the anchor receipt JSON")
    m.set_defaults(func=cmd_mint)

    h = sub.add_parser("handoff",
                       help="Recipient: build a hand-off bundle for the sender")
    h.add_argument("--controller", required=True,
                   help="Recipient's NEW controller keypair JSON")
    h.add_argument("--artifact", required=True)
    h.add_argument("--out", required=True)
    h.add_argument("--price", type=int,
                   help="Authorize a priced sale: EIDOLON the buyer will pay")
    h.add_argument("--payer", help="Buyer's EIDOLON account id (with --price)")
    h.add_argument("--payee", help="Seller's EIDOLON account id (with --price)")
    h.add_argument("--from-seq", type=int, default=0,
                   help="Sequence the sale is bound to (default 0)")
    h.add_argument("--payment-out", help="Where to write the payment authorization")
    h.set_defaults(func=cmd_handoff)

    t = sub.add_parser("transfer",
                       help="Sender: sign a transfer and (optionally) finalize")
    t.add_argument("--controller", required=True,
                   help="Current owner's controller keypair JSON")
    t.add_argument("--artifact", required=True)
    t.add_argument("--from-seq", type=int, required=True,
                   help="Sequence the sender believes is current")
    t.add_argument("--handoff", required=True, help="Recipient's hand-off JSON")
    t.add_argument("--sealed-in", help="Current sealed content JSON to re-key")
    t.add_argument("--sealed-out", help="Where to write the re-sealed content")
    t.add_argument("--out", required=True, help="Where to write the transfer JSON")
    t.add_argument("--anchor-url", help="Anchor base URL to finalize the transfer")
    t.add_argument("--receipt", help="Where to write the anchor receipt JSON")
    t.add_argument("--payment", help="Buyer's payment authorization JSON (priced sale)")
    t.add_argument("--fee", type=int, help="Protocol fee in EIDOLON (to --treasury)")
    t.add_argument("--treasury", help="Treasury account id for the protocol fee")
    t.set_defaults(func=cmd_transfer)

    bal = sub.add_parser("balance", help="Query an EIDOLON account balance")
    bal.add_argument("--account", required=True)
    bal.add_argument("--anchor-url", required=True)
    bal.set_defaults(func=cmd_balance)

    gr = sub.add_parser("grant",
                        help="Genesis-grant EIDOLON to an account (anchor must allow)")
    gr.add_argument("--account", required=True)
    gr.add_argument("--amount", type=int, required=True)
    gr.add_argument("--anchor-url", required=True)
    gr.set_defaults(func=cmd_grant)

    v = sub.add_parser("verify",
                       help="Verify authenticity + (optional) current ownership")
    v.add_argument("--artifact", required=True)
    v.add_argument("--content", help="Optional content file to check the commitment")
    v.add_argument("--anchor-url", help="Anchor base URL to query current owner")
    v.set_defaults(func=cmd_verify)

    o = sub.add_parser(
        "own",
        help="Check whether a vault currently possesses an artifact",
    )
    o.add_argument("--artifact", required=True)
    o.add_argument("--sealed-controller", required=True,
                   help="The vault's sealed controller for this artifact")
    o.add_argument("--anchor-url", help="Anchor base URL (current owner of record)")
    o.add_argument("--device-secret", help="Vault device_secret (hex) for the proof")
    o.add_argument("--vault", help="Vault JSON holding device_secret_hex")
    o.set_defaults(func=cmd_own)

    au = sub.add_parser(
        "audit",
        help="Audit the transparency log: verify the receipt chain + detect forks",
    )
    au.add_argument("--artifact", help="Artifact JSON (for the artifact_id)")
    au.add_argument("--artifact-id", help="Artifact id hex (instead of --artifact)")
    au.add_argument("--anchor-url", required=True)
    au.add_argument("--anchor-pub", help="Pinned anchor public key (hex)")
    au.add_argument("--anchor-key", help="Pinned anchor key JSON (reads its pubkey)")
    au.add_argument("--witness",
                    help="Witnessed-chain file: compare for equivocation, then update")
    au.set_defaults(func=cmd_audit)

    vr = sub.add_parser("verify-receipt", help="Verify an anchor receipt signature")
    vr.add_argument("--receipt", required=True)
    vr.set_defaults(func=cmd_verify_receipt)

    return p


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv[1:])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

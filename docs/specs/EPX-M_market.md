# EPX-M — Market: EIDOLON-priced titled transfers on the anchor

| Field           | Value                                                   |
| --------------- | ------------------------------------------------------- |
| Identifier      | EPX-M                                                   |
| Status          | Draft                                                   |
| Version         | 1                                                       |
| Date            | 2026-05-30                                              |
| Author          | Jérémy ZGONEC                                           |
| Layer           | `eopx.server` (anchor) + `eopx.transfer` (payment auth) |
| Wire compat     | Additive — extends EPX-T transfer with an optional payment |
| Dependencies    | EPX-T (titled transfer), ML-DSA-87, the anchor          |

## Abstract

EPX-M turns a titled transfer into a **sale**: control of an artifact moves
from vault A to vault B *and* B pays a **price in EIDOLON** to A, **atomically**.
The economy is a self-contained, persistent balance ledger that lives **inside
the anchor** (same SQLite file as the title registry), so the payment legs and
the title compare-and-swap commit in **one transaction** — they move together
or not at all. This is also the durable home the project's "persistent genesis
registry" needed: one anchor-side registry of titles, balances, and payments.

The economy is deliberately standalone (no dependency on Eidolon's proprietary
runtime); a bridge to Eidolon's real economy can later sit behind this surface.

## 1. Accounts and amounts

* An **account** is an opaque lowercase hex id — typically a vault fingerprint.
* **Amounts are integers** in the smallest EIDOLON unit. Never floats; balances
  are exact. Balances never go negative (a debit that would underflow is
  refused, `INSUFFICIENT_FUNDS`).

## 2. Genesis grants

`grant_genesis(account, amount)` credits an account once, recording the grant in
an `eidolon_grants` table. It is **idempotent**: a second grant for the same
account is a no-op, so re-running a forge or re-anchoring never double-mints a
founder allocation. Grants are an authority action — the HTTP endpoint is
**off by default** (`allow_grants=False`).

## 3. Payment authorization (the buyer's signature)

The buyer B authorizes the price with the **same new controller key** that
produced the transfer's proof-of-possession (EPX-T §5.2). B signs:

```
EPXT_PAY ‖ lp(artifact_id, from_seq, price, payer_account, payee_account)
EPXT_PAY = b"epx-t.payment.v1"   (frozen v1)
```

Because the authorization is bound to `artifact_id`, `from_seq`, and the exact
accounts and price, it cannot be altered or replayed against another transfer,
and it cannot be lifted onto a different buyer (it only verifies under the
transfer's `new_controller`).

`PaymentTerms = { price, payer_account, payee_account, from_seq, sig }`.

## 4. Atomic priced transfer

The anchor settles `POST /api/v1/artifact/transfer` with a `payment` block in
**one transaction** over the shared SQLite file:

1. read the current `seq` (CAS precondition — `STALE_SEQUENCE` if it moved);
2. **debit** `payer_account` by `price + fee` (`INSUFFICIENT_FUNDS` aborts here,
   before anything moves);
3. **credit** `payee_account` by `price`;
4. **credit** `treasury_account` by `fee` (optional, default 0);
5. advance the title CAS (`seq+1`, new controller) + append history;
6. COMMIT.

If any step fails the whole transaction rolls back: a poor buyer is never
charged and never receives control; a stale transfer never charges anyone.

Order matters: the debit is **first**, so an underfunded buyer aborts the sale
before the seller loses control.

## 5. Trust model

* **Authorization.** B's payment signature (under the new controller) authorizes
  debiting `payer_account`. The buyer is authorizing their *own* purchase; the
  protocol trusts controller keys exactly as the rest of EPX-T does.
* **Account ⇄ vault binding (MVP caveat).** This version does not yet *prove*
  that the signer owns `payer_account` (an account is an opaque id the buyer
  names and signs over). Griefing requires the buyer to sign away their own
  declared funds, which is self-harm. A future revision binds an account to a
  vault key (a signature under the account's controlling key) for trustless
  third-party debits.
* **Atomicity.** Payment and title move in one SQLite transaction — no window
  where one commits without the other.
* **No negative balances; integer amounts.** Exact accounting.

## 6. HTTP surface (additive)

| Route | Effect |
|-------|--------|
| `POST /api/v1/artifact/transfer` with `payment` | Priced sale (atomic). `402 INSUFFICIENT_FUNDS`, `400` on bad/mismatched authorization, `409 STALE_SEQUENCE`. |
| `GET  /api/v1/artifact/account/<id>` | EIDOLON balance of an account. |
| `POST /api/v1/artifact/account/<id>/grant` | Idempotent genesis grant (gated by `allow_grants`; `403` when disabled). |

A transfer with **no** `payment` block is the ordinary free EPX-T transfer,
unchanged.

## 7. Invariants (for implementation)

1. **Exact accounting:** integer amounts; no negative balances; debit refused
   when `balance < price + fee`.
2. **Idempotent grants:** a repeated `grant_genesis` does not double-credit.
3. **Atomic sale:** on success, `payer -= price+fee`, `payee += price`,
   `treasury += fee`, and `seq += 1` to the new controller — all or nothing.
4. **Insufficient funds:** no debit and no re-key; `402`.
5. **Stale sale:** a payment bound to a stale `from_seq` charges nobody; `409`.
6. **Authorization binding:** the payment verifies only under the transfer's
   `new_controller`, and only for the matching `from_seq`.

## 8. File manifest

| File | Purpose |
|------|---------|
| `src/eopx/server/eidolon_ledger.py` | persistent balance ledger, grants, transfers |
| `src/eopx/server/artifact_ledger.py` | `priced_transfer` (atomic debit+credit+CAS) |
| `src/eopx/transfer/__init__.py` | `PaymentTerms`, `sign_payment`, `verify_payment` |
| `src/eopx/server/artifact_api.py` | priced `/transfer`, `/account/<id>`, `/grant` |
| `scripts/eopx_artifact.py` | CLI: `balance`, `grant`, priced `handoff`/`transfer` |
| `tests/test_eidolon_economy.py` | invariants §7 |

## 9. References

- `docs/specs/EPX-T_titled_transfer.md` — the underlying titled-transfer protocol
- `docs/specs/EPX-C_codex.md` — the relic collection that trades on this market

---

*Ownership is the ledger's line under your name; a price is the ledger moving
two lines at once.*

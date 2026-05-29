# Whitepaper IV — From scan to vault: four protocols on the Metatron canvas

**Status**: draft v0 — prototype-aligned with `src/eopx/vault/`
**Companion modules**: `unlock.py`, `verify_card.py`, `sas.py`, `enroll.py`

This whitepaper closes the loop that the first three opened. Whitepapers
I–III defined the Metatron canvas and how to inscribe / read it; this one
specifies **what to do with the symbols once you have them** so that they
unlock, attest, or initialize a vault.

---

## 0. Notation

- `C ⊂ F_13^{91}` — the systematic Reed-Solomon code from Whitepaper II.
- `S = (s_0, …, s_90)` — the 91 symbols recovered from a photograph.
- `seed` — 256-bit user secret (only meaningful for private sheets).
- `spinor_hash` — 512-bit Eidolon Phase 6 output (only meaningful for
  public cards).
- `HKDF(.)` denotes HKDF-SHA3-512 (RFC 5869).
- `card_fp(S) = SHA3-256("esoptron.metatron.card_fingerprint.v1\n" ‖ S_bytes)`.

The four protocols share a single primitive surface: `S ∈ F_13^{91}`.
They differ only in **whether `S ∈ C`** and **what the device already
knows**.

| Protocol | Sheet kind | Device must know | Output |
|---------|------------|------------------|--------|
| A. Unlock | PRIVATE (`S ∈ C`) | nothing | `master_key` (full unlock) |
| B. Verify | PUBLIC (`S ∉ C` w.h.p.) | local `spinor_hash` | yes/no |
| C. SAS    | PUBLIC | local `spinor_hash` + fresh nonce | session key |
| D. Enroll | PUBLIC | device entropy only | new identity + hologram |

---

## 1. Protocol A — Unlock (sheet alone is the secret)

```
photo ── rectify ── S ── decode_private ── seed
                                            │
                                            ▼
                              master_key = HKDF(seed, info = "esoptron.vault.master_key.v1", 32)
```

### Security
- The seed never leaves RAM after recovery; the implementation in
  `unlock.py` returns it because some applications require key
  rotation. Production deployments should zero `seed` after deriving
  subkeys.
- Any attacker who photographs the sheet recovers `master_key`. The
  sheet must be physically protected (safe, sealed envelope). The
  whitepaper III banner ("PRIVATE INSCRIPTION — DO NOT SHARE") is the
  human-readable mitigation.

### Failure modes
- ≤ 3 erasures per RS block (21 total) are recoverable; beyond that the
  decoder raises. The detection layer flags low-confidence carriers
  automatically via `erasures_from_confidences`.

---

## 2. Protocol B — Verify (public attestation)

```
S_scan  ──── card_fp(S_scan) ───┐
spinor_local ── encode_public ── card_fp(...) ─── compare (constant-time)
```

### Why it works
By Whitepaper III Theorem 2, two distinct spinors yield indistinguishable
distributions on `F_13^{91}` (perceptual symmetry), but EQUAL spinors
yield IDENTICAL symbol vectors (HKDF is a deterministic function). The
verification is therefore an exact equality check at the symbol level,
constant-time via HMAC.

### Threat model
- No secret recovered. A leaking verifier is harmless.
- An adversary who can photograph the card learns ONLY the card's
  fingerprint, which is already public information by design.

---

## 3. Protocol C — SAS (Strong Authentication Sheet)

A challenge-response protocol that requires both the **physical card** AND
the **device** to participate.

### Messages

```
Device ──► User:   Challenge { vault_id, nonce, t_now }
User   ──► Device: (raw photograph of the printed card)
Device       :    S = extract(photo)
                   if not verify_card(S, spinor_local): abort
                   tag = HMAC_SHA3_256(spinor_local, "v1\n" ‖ vault_id
                                       ‖ nonce ‖ S_bytes ‖ INFO_SESSION)
                   session_key = SHA3-512("session_key.v1\n"
                                         ‖ spinor_local ‖ vault_id
                                         ‖ nonce ‖ card_fp(S))[:32]
```

### Properties

| Threat | Outcome |
|--------|---------|
| Stolen card alone | Cannot bind to any device's `spinor_local`; aborts at `verify_card`. |
| Stolen device alone | Refuses to issue a session without a live card scan. |
| Replay of an old (`Challenge`, photograph) pair | TTL gate (`CHALLENGE_TTL_SECONDS`) rejects stale challenges. |
| Side-channel on `tag` | Constant-time `hmac.compare_digest`. |

### Coupling to Eidolon
- `spinor_local` is loaded from secure storage (Keychain/Keystore) or
  re-derived on-the-fly from Phases 1..6 + `machine_lock` (Esoptron
  Phase 3, `vault_migrate`). The implementation is opaque to SAS.

---

## 4. Protocol D — Enrollment by camera, no PC

This is the answer to the on-boarding question: a user joins the
ecosystem by photographing a printed PUBLIC poster with their phone.

### Ceremony

```
1.  fp = card_fp(extract(photo))
2.  e  = phone_csprng(32 bytes)              # never leaves device
3.  device_secret  = HKDF(e, info="identity.private.v1", 32)
4.  public_tag     = HKDF(device_secret, salt=fp,
                          info="identity.public_tag.v1", 16)
5.  shadow_seed    = HKDF(fp || e, info="shadow_hologram.v1", 64)
6.  render local hologram from shadow_seed (GLSL on phone)
```

### Why this is safe AND useful

| Property | Why |
|---------|-----|
| No PC required | All KDFs run on the phone; the camera is the only sensor needed. |
| No leak of issuer secret | The card carries `HKDF(spinor_hash, …)`. Inverting it requires breaking SHA3-512 under HMAC. |
| Two phones, same card → different identities | `device_secret` and `public_tag` depend on per-phone `e`. |
| Same phone, same card → reproducible identity | The KDF chain is deterministic given `(fp, e)`; the phone stores `e` once and reuses it. |
| Two phones, same card → same `card_fp` | The card is a stable, public anchor. Servers can rate-limit per `card_fp`. |
| Same phone, different cards → different identities | `public_tag` mixes `fp` as HKDF salt. |

### The shadow hologram

The `shadow_hologram` is a 64-byte derivation that drives a phone-side
renderer. The reference implementation in `scripts/enroll_from_card.py`
is a static rosette; production deployments would feed it into a GLSL
shader producing an animated parallax artefact. The hologram is purely
cosmetic from a security standpoint, but it is **stable and unique** per
(device, card) pair, which gives the user a recognizable visual
signature they can remember across sessions.

### Multi-device coupling (future work)

A future extension can link several devices to the same `card_fp` via a
group key exchange (e.g. MLS over a private channel). The card then
becomes a "founding moment" anchor shared by an entire device group,
each member retaining its own `device_secret`.

---

## 5. CLI summary

| Goal | Command |
|-----|--------|
| Print a private sheet | `py scripts/print_sheet.py --passphrase "..." --role private --out out/p.png` |
| Print a public card | `py scripts/print_sheet.py --spinor <hex> --role public --out out/c.png` |
| Protocol A | `py scripts/open_vault_from_photo.py photo.jpg --fiducials "…" --mode private` |
| Protocol B | `py scripts/open_vault_from_photo.py photo.jpg --fiducials "…" --mode verify --spinor <hex>` |
| Protocol C | `py scripts/open_vault_from_photo.py photo.jpg --fiducials "…" --mode sas    --spinor <hex>` |
| Protocol D | `py scripts/enroll_from_card.py    photo.jpg --fiducials "…"` |

---

## 5. Protocol F — Cross-machine Migration (NIZK proof)

A vault is bound to a specific machine via `machine_lock`. Migration to a
new device requires proving possession of `master_key` WITHOUT transmitting
it, preventing MITM attacks.

### Messages

```
Target ──► Source: target_machine_lock (via QR scan)
Source      :     challenge = (vault_id, source_lock, target_lock, nonce, t)
                  commitment = HKDF(master_key, salt=nonce, info="commit")
                  ch = SHA3-256(vault_id ‖ source ‖ target ‖ commitment ‖ nonce)
                  response = HKDF(master_key ‖ ch, salt=nonce, info="response")
Source ──► Target: MigrationProof { vault_id, source_lock, target_lock,
                                    nonce, commitment, response, timestamp }
Target      :     recompute commitment & response using master_key
                  if match:
                    machine_bound_key = HKDF(master_key, salt=target_lock, info="bind")
                    session_key = HKDF(master_key ‖ nonce, salt=target_lock, info="session")
```

### Properties

| Threat | Outcome |
|--------|---------|
| MITM intercepts proof | Cannot derive keys without `master_key`; proof is bound to specific `(source, target)`. |
| Replay on different device | `target_lock` check fails; wrong device cannot bind. |
| Stale proof | TTL gate (`CHALLENGE_TTL_SECONDS = 300`) rejects expired challenges. |
| Tampered commitment/response | Constant-time `hmac.compare_digest` check fails. |

### Verification tag

For third-party witnesses (e.g., migration server attestation), a public
`verify_tag = HKDF(master_key, salt=vault_id, info="verify_tag")` can be
embedded in the `.eopx`. Witnesses can attest a valid proof was presented
without learning `master_key`.

### CLI

| Goal | Command |
|------|---------|
| Display target lock | `py scripts/vault_migrate.py show-lock --machine-lock <hex> --qr` |
| Generate proof | `py scripts/vault_migrate.py prove --master-key <hex> --vault-id <hex> --source-lock <hex> --target-lock <hex> --out proof.json` |
| Verify & bind | `py scripts/vault_migrate.py verify --proof proof.json --master-key <hex> --machine-lock <hex>` |

---

## 6. Open items

- Animated GPU hologram on Android/iOS, driven by `shadow_hologram`.
- Hardware-backed `device_secret` via Secure Enclave / StrongBox.
- Full integration with Eidolon `machine_lock` revocation list post-migration.

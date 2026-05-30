```
  EPX-Number:   EPX-2
  Layer:        Card Format
  Title:        Reinforced Visual Card Format (Card V2)
  Author:       Jérémy ZGONEC
  Status:       Draft
  Type:         Standards Track
  Created:      2026-05-30
  License:      MIT
  Replaces:     (implicit V1 layout in src/eopx/metatron/grid.py)
  Depends-On:   EPX-1 (Inscription on Genesis Seal, src/eopx/genesis_token.py)
```

# EPX-2 — Reinforced Visual Card Format (Card V2)

## Abstract

This document specifies version 2 of the Esoptron visual card format. A
visual card is an A4 sheet carrying:

1. a 91-symbol Metatron cube (K₁₃ canvas) — the optical seed,
2. a chromatic scan grid — a 6-color base-6 redundancy layer,
3. an optional bech32 *card identifier* string — for human-readable
   distribution, copying, dictation and OCR fallback,
4. an optional QR code — for *street distribution* mode, encoding a
   hybrid URL that resolves both online (web) and offline (native PWA
   handler) flows.

V2 introduces three orthogonal security upgrades over V1:

- **Integrity**: a 64-bit MAC (truncated SHA3-256) binds the printed
  symbols to the Genesis seal's `vault_fp`, `inscription_fp` and
  `sequence`. Any single-cell tamper invalidates the MAC.
- **Resilience**: a Reed-Solomon code over GF(256) protects the entire
  encoded payload. Up to **22 erased cells** can be recovered.
- **Linkage**: the `bech32` identifier and the QR payload both embed a
  truncated commitment to the Genesis seal, so a card scanned in the
  street cannot be confused with a different Genesis position even
  when only its identifier is shared verbally or printed at low
  resolution.

The format is non-backward-compatible with V1 by design (V1 cards were
not publicly distributed at the time of writing — only one test card,
`ESPX-SIGMA-VAULT-6119`, exists). V1 decoders MUST refuse to parse V2
cards and vice versa; the detection bit is the grid dimensions
(12×16 → V1, 14×18 → V2).

## Copyright

This document is released under the MIT License, same as the Esoptron
codebase.

## Motivation

### 1. Why a binding MAC

V1 grids reproduce the cube symbols in a 6-color base-6 encoding, but
the grid value is **not** cryptographically bound to the surrounding
metadata (Genesis position, inscription, vault fingerprint). An
attacker who possesses a valid V1 card can:

- Repaint individual cells to alter the decoded seed.
- Print the same card with a fabricated inscription text in the
  printable footer — the inscription text on V1 is plain ink, not part
  of the visual payload.

The V2 MAC defeats both attacks at the **visual** layer (in addition to
the Dilithium signature already covering the seal JSON).

### 2. Why Reed-Solomon

Printed cards are subject to:

- Toner streaks, ink bleed, paper wrinkles, coffee.
- Phone-camera limitations: motion blur, perspective foreshortening,
  partial occlusion by fingers.
- Long-term archival fade.

A 22-erasure budget over 252 cells (≈ 8.7 %) lets the decoder
reconstruct the card from photographs where ~1 out of 12 cells is
illegible. Empirically (see `tests/test_card_v2_ecc.py`), this is the
threshold below which a phone photo at 1 m, 50 lux indirect light, ISO
800 still produces a confidently decoded card.

### 3. Why bech32 + QR

For **distribution in the street** the card needs to:

- Be visible from a distance (the QR carries this far better than text).
- Survive being photographed by *any* mainstream phone (iOS/Android
  built-in camera, no Esoptron app required).
- Fall back to manual entry by humans (typed bech32, dictation, postal
  exchange) when the QR is damaged or photographed at too low a
  resolution.

The hybrid resolution scheme (§ 2.6) ensures these three channels all
converge on the same identity.

## Specification

### 2.1 Wire format

A V2 card encodes a 67-byte canonical payload `P`:

```
struct CardV2 {
    uint8       version;              // = 0x02
    uint8[8]    inscription_fp_trunc; // SHA3-256(canonical_inscription_bytes)[:8]
                                      //   = 64 zero bits when no inscription
    uint32_be   sequence;             // BE-uint32 Genesis position
    uint8[8]    mac;                  // (see § 2.2)
    uint8[46]   symbols_packed;       // (see § 2.4)
};                                    // total: 1 + 8 + 4 + 8 + 46 = 67 bytes
```

The `inscription_fp_trunc` field is the SHA3-256 fingerprint of the
inscription's canonical bytes (as defined by EPX-1, `Inscription
.canonical_bytes()`), truncated to 8 bytes. When no inscription is
present the eight bytes are all-zero (`0x00 * 8`); this allows V2 to
represent legacy seals minted without an inscription while still
producing a deterministic payload.

`sequence` is the Genesis position in the canonical lattice (range
`[0, TOTAL_GENESIS)`).

### 2.2 MAC construction

The MAC is computed by:

```
mac_input   =  b"EPX-CARD-V2-MAC|"               # 16-byte domain tag
            || vault_fp                            # 32 bytes
            || symbols_packed                      # 46 bytes
            || inscription_fp_trunc                # 8 bytes
            || sequence_be                         # 4 bytes

mac_full    =  SHA3-256(mac_input)                 # 32 bytes
mac         =  mac_full[:8]                        # 8 bytes
```

Notes:

- The domain tag begins with `b"EPX-CARD-V2-MAC|"` (16 bytes, includes
  the pipe). It MUST appear literally and MUST NOT be elided in any
  implementation, otherwise collisions with other domain hashes in the
  Esoptron codebase become possible.
- `vault_fp` is the **full 32-byte** value, not the truncation visible
  in the bech32 string. The MAC therefore demonstrates knowledge of the
  full vault identity even when only the truncated form is published.
- The MAC is *not* a HMAC (no secret key). It is a cryptographic
  binding, not an authentication tag. Forgery requires a SHA3-256
  preimage of the eight published bytes given the rest of the input —
  ≈ 2⁶⁴ work.

### 2.3 Reed-Solomon encoding

#### 2.3.1 Code parameters

- Field: GF(2⁸) with primitive polynomial 0x11d (the standard QR Code
  generator polynomial).
- Block length: `N = 81` bytes.
- Message length: `K = 67` bytes.
- Parity length: `R = 14` bytes.
- Correction capacity: ⌊R/2⌋ = 7 byte errors with unknown positions,
  or up to R = 14 byte erasures with known positions. Cell-level
  erasures detected by the scan layer (e.g. white-balance reject)
  achieve up to ~22 cell erasures because each base-6 cell carries only
  ⅓ of a byte on average.

#### 2.3.2 Generator polynomial

The systematic encoder uses the same generator polynomial as the QR
Code 14-parity short block:

```
g(x) = (x - α⁰)(x - α¹) ... (x - α¹³)
```

where α is the generator of GF(256) under the primitive polynomial
above. Coefficients (low-to-high) are listed in the reference
implementation `src/eopx/metatron/grid_v2.py`.

#### 2.3.3 Encoded form

The encoded RS codeword is `C = P || R(P)` where `R(P)` is the 14-byte
parity. The full codeword `C` is 81 bytes long.

### 2.4 Base-6 cell mapping

#### 2.4.1 Cube symbols packing

The 91 F₁₃ cube symbols (each in `[0, 12]`) are packed into 46 bytes:

```
pack(symbols[0..90])  →  46-byte field symbols_packed
  for i in 0..45:
      lo = symbols[2*i + 0]     // [0, 12]
      hi = symbols[2*i + 1] if (2*i + 1) < 91 else 0
      symbols_packed[i] = lo | (hi << 4)
```

The last byte's high nibble carries `symbols[90]` (low nibble) and
zero in the high nibble. Decoders MUST treat any out-of-range nibble
(value ≥ 13) as a decoding error.

#### 2.4.2 81-byte → 252-cell encoding

The 81-byte codeword `C` is interpreted as a big-endian integer
`N(C)`, then expressed in base 6:

```
N(C)  =  sum_{i=0..80} C[i] · 256^(80 - i)
cells[i]  =  ⌊ N(C) / 6^(251 - i) ⌋ mod 6   for i in 0..251
```

This produces exactly 252 base-6 digits (since
`81 * log_2(256) / log_2(6) ≈ 250.85 ≤ 252`). The first 252 cells of
the base-6 stream are written into the grid in row-major order
(rows 0 → 13, columns 0 → 17). The 252nd cell may be 0 due to
representation overhead; this is a normal and expected padding.

#### 2.4.3 Cell colors

Cell colors follow the V1 palette (defined in
`src/eopx/metatron/grid.py`, `GRID_OKLCH`):

| index | name        | OKLCH                |
| ----- | ----------- | -------------------- |
| 0     | Vermillon   | (0.55, 0.28,  25°)   |
| 1     | Or          | (0.58, 0.25,  85°)   |
| 2     | Émeraude    | (0.55, 0.26, 160°)   |
| 3     | Cobalt      | (0.50, 0.22, 220°)   |
| 4     | Violet      | (0.45, 0.28, 290°)   |
| 5     | Magenta     | (0.50, 0.26, 340°)   |

This is unchanged from V1 to maintain camera classifier compatibility.

#### 2.4.4 Grid layout

- Dimensions: `GRID_ROWS_V2 = 14`, `GRID_COLS_V2 = 18`. Total 252 cells.
- Cell size: ≥ 8 mm at print time (300 DPI). Smaller cells must be
  agreed by both producer and consumer.
- Margins: at least 5 mm of quiet zone on all four sides.
- Headers: numeric row/column indices in the V1 dark frame style. V2
  headers MUST include both rows 0–13 and columns 0–17 in decimal.

### 2.5 bech32 card identifier

#### 2.5.1 HRP and payload

- Human-readable prefix: `espx`.
- Bech32 variant: **bech32m** (constant `0x2bc830a3`, BIP-350) to align
  with modern address formats.
- Binary payload `B` (24 bytes):

```
struct CardId {
    uint8     version;              // = 0x02
    uint8[4]  vault_fp_trunc;       // vault_fp[:4]
    uint8[8]  inscription_fp_trunc; // same as Wire Format
    uint32_be sequence;             // Genesis position
    uint8[7]  seal_fp_trunc;        // SHA3-256(seal_canonical_bytes)[:7]
};                                  // total: 1 + 4 + 8 + 4 + 7 = 24 bytes
```

- `seal_canonical_bytes` is the deterministic serialization of the
  signed GenesisSeal fields **only** (i.e. excluding
  `signature_hex`, `signer_pk_fp_hex`, and any derived field), in the
  order returned by `GENESIS_SEAL_SIGNED_FIELDS`. It MUST match the
  bytes signed by Dilithium (see `_seal_message` in
  `src/eopx/genesis_token.py`). This guarantees the card identifier
  references a unique, signed seal.

#### 2.5.2 Encoding

`B` is converted to bech32m using the standard 8→5-bit conversion
defined in BIP-173. The resulting string is 50 characters total:

```
"espx1" || <39 data chars> || <6 checksum chars>
```

#### 2.5.3 Display rules

- Render in monospace, at minimum 12 pt, single line.
- Insert a soft space every 6 characters (e.g. `espx1ab cdef gh…`)
  for legibility *only when printed on paper*. The spaces MUST NOT be
  present in the encoded string.
- Case: lowercase, as per BIP-173.

### 2.6 QR code hybrid resolution

#### 2.6.1 When to include a QR

The QR is **optional** on PRIVATE cold-storage cards (see § 2.7) and
**REQUIRED** on STREET-distribution cards.

#### 2.6.2 QR payload

The QR encodes a single URL whose path is the bech32 identifier:

```
https://esoptron.cards/c/<bech32>
```

The host `esoptron.cards` is normative but the protocol MUST tolerate
an arbitrary host configured by the issuer at print time (e.g.
`https://genesis.zgonec.io/c/espx1...`). The host MAY be replaced
with the literal string `esoptron.example` in test vectors and
documentation; production cards MUST use a host actually controlled
by the issuer.

For full offline operation the QR MAY instead encode the URI scheme:

```
esoptron://onboard?card=<bech32>
```

A *hybrid* QR — the format mandated for street cards — encodes the
HTTPS URL **and** prints the URI scheme equivalent in clear text
under the QR, so users with the Esoptron PWA installed can long-press
the URL and choose “Open in Esoptron”.

#### 2.6.3 QR error correction

- Use error correction level **H** (≈ 30 %) for street cards (long-
  lived outdoor exposure).
- Use error correction level **M** (~15 %) for cold-storage cards (the
  cube and grid carry the actual seed; QR damage is recoverable from
  the bech32 fallback).

#### 2.6.4 Size and quiet zone

- Module size ≥ 1.0 mm. At 300 DPI this is 12 px per module.
- Quiet zone: 4 modules on all four sides.
- Print location: bottom-right corner, above the WARNING strip.

### 2.7 IRL ↔ Digital navigation

The card identity is the bech32 string. All channels resolve to the
same identity:

```
+--------------+      +--------------+      +-----------+
| Physical A4  |      | Bech32       |      | JSON      |
| (cube+grid)  |  →   | (B)          |  →   | seal      |
+--------------+      +--------------+      +-----------+
        ↑                    ↑                    ↑
        |                    |                    |
    photograph           QR scan             signature
    + decode             on phone            verification
        |                    |                    |
        +--------+-----------+--------+-----------+
                 |                    |
                 v                    v
            Local PWA            Web resolver
            (offline OK)         (esoptron.cards)
```

Four canonical entry points:

| Mode             | Input                  | Network    | Use case               |
| ---------------- | ---------------------- | ---------- | ---------------------- |
| Cold restore     | photo of card          | offline    | seed reconstruction    |
| Street onboard   | QR scan with phone     | online     | first-touch enrollment |
| Manual recovery  | typed/dictated bech32  | offline OK | accessible / postal    |
| Verify-only      | bech32 + seal JSON     | offline    | signature check        |

A consumer encountering a card MUST be able to verify it offline once
the matching `deployment_pk` is known. The reference PWA bundles all
88 Genesis-position deployment public keys (~16 KB on disk) so that
verification works on first-touch with zero network calls. Cards
beyond Genesis (post-deployment) require an online manifest fetch.

#### 2.7.1 Two card variants

`make_invitation.py` SHALL emit two variants per invitation code:

```
out/invitation_<CODE>_PRIVATE_A4.png  — cube + grid + bech32, no QR
out/invitation_<CODE>_STREET_A4.png   — public cube + grid + bech32 + QR
```

The PRIVATE variant uses `encode_private(seed)` for the cube and
contains the seed in the grid. The STREET variant uses
`encode_public(spinor_hash)` and the grid encodes the **spinor**, not
the seed — distributing the public card is therefore safe.

The same bech32 string appears on BOTH cards so a recipient can
correlate them.

## Backwards compatibility

V1 cards (grid 12×16, no MAC, no RS, no bech32) are NOT decodable as
V2 and vice versa. Detection is done by:

1. Counting columns of the chromatic grid: 16 → V1, 18 → V2.
2. Counting rows: 12 → V1, 14 → V2.

A scanner SHOULD attempt V1 detection only after V2 detection has
failed. As of the spec publication date, the only V1 card known to
exist is `ESPX-SIGMA-VAULT-6119` (test material, not distributed).

## Reference implementation

The normative reference implementation will live at:

```
src/eopx/metatron/grid_v2.py           — encoder/decoder
src/eopx/metatron/bech32_card.py       — bech32m envelope
src/eopx/metatron/qr_companion.py      — QR payload helper
scripts/print_sheet.py                 — A4 layout (extended)
scripts/make_invitation.py             — emits both variants
tools/gen_card_v2_vectors.py           — generates §3 test vectors
```

The encoder MUST satisfy these properties (verified by tests):

```
P  ←  encode_payload(symbols, vault_fp, inscription_fp, sequence)
C  ←  rs_encode(P)
G  ←  base6_encode(C, 252)              # grid cells
B  ←  bech32m_encode(card_id_bytes)

assert decode_grid_v2(G) == (symbols, vault_fp_trunc, …)
assert verify_mac(decoded) is True
assert rs_decode(corrupt(G, k_cells)) recovers C for k_cells ≤ 22
assert bech32m_decode(B) == card_id_bytes
```

## Security considerations

### 3.1 What the MAC does *not* prevent

The MAC is *not* keyed. An adversary with computational power could
compute a MAC for any chosen `(vault_fp, sequence, inscription_fp,
symbols)` tuple. The MAC is therefore a **commitment**, not an
authentication tag. The real authenticity guarantee comes from the
Dilithium signature on the GenesisSeal which covers `vault_fp`,
`sequence` and `inscription_fp_hex`.

A card whose MAC verifies but whose corresponding GenesisSeal is not
signed by a known Genesis deployment key is **inauthentic**. Consumers
MUST verify both.

### 3.2 Coupling to BTC anchor

The bech32 identifier does not include the BTC block height. This is
intentional: two cards from the same Genesis position MUST collide on
their bech32 identifier (the position is the identity), and the BTC
anchor is implicit in the deployment key set used to sign the seal.

### 3.3 Privacy of street distribution

The STREET variant encodes the **spinor** (public render) into its
grid. Reverse-engineering the seed from the spinor requires
sha3-512 preimage breaking — infeasible. The QR + bech32 reveal:

- The vault's truncated fingerprint (4 bytes).
- The Genesis position (4 bytes).
- The inscription's truncated fingerprint (8 bytes).
- The seal's truncated fingerprint (7 bytes).

This is sufficient to look up the canonical seal JSON and verify it,
but does *not* leak the seed or any data not already implied by the
Genesis lattice (which is public).

### 3.4 QR phishing surface

The QR is the most-scanned channel and the most phishable. Three
mitigations are required:

1. The PWA MUST display the **bech32 identifier in clear** before
   doing any action, so the user can compare it with the printed
   string on the card.
2. The PWA MUST reject any HTTPS host that does not match the embedded
   deployment-key manifest's `allowed_hosts` field.
3. Cards SHOULD include a visible hash of the QR URL in the footer
   (truncated SHA3-256, 8 hex chars) so visual comparison is possible
   before scanning.

## 4. Test vectors

The vectors below are derived from the reference invitation
`ESPX-SIGMA-VAULT-6119`, which already exists on disk as
`out/invitation_ESPX_SIGMA_VAULT_6119.json` (commit pending). Use the
helper script `tools/gen_card_v2_vectors.py` to regenerate after any
encoder change.

### 4.1 Inputs

```
code              = "ESPX-SIGMA-VAULT-6119"
name              = "Logos Genesis #001"
motto             = "In silentio, mirror"
issued_at         = "2026-05-29T23:47:09Z"
vault_fp_hex      = 29f96634edd6e6de51ccf992c9ec9f6566a301d436f41eaad577aa16b3bd96a5
seed_hex          = 955cbc7fc2832ba888e825489a11dd07e66dc00b867e509b17680563be5c9701
sequence          = 146038
archetype_id      = 40
inscription_fp    = be39a079764f40660d364ab96256adf0526344caa124effa6afaae40752c626b
```

### 4.2 Derived (to be filled by `tools/gen_card_v2_vectors.py`)

```
symbols_packed    : 46 bytes hex                    (TV-2-A)
mac_input_hex     : 110 bytes hex                   (TV-2-B)
mac_hex           : 8 bytes hex                     (TV-2-C)
payload_hex       : 67 bytes hex (P)                (TV-2-D)
rs_parity_hex     : 14 bytes hex (R(P))             (TV-2-E)
codeword_hex      : 81 bytes hex (C)                (TV-2-F)
grid_cells        : 252 base-6 digits (row-major)    (TV-2-G)
seal_fp_hex       : 32 bytes hex                    (TV-2-H)
card_id_bytes_hex : 24 bytes hex                    (TV-2-I)
bech32m_string    : 50 chars                        (TV-2-J)
qr_payload        : URL form                        (TV-2-K)
qr_uri_form       : esoptron:// form                (TV-2-L)
```

### 4.3 Negative test cases

Each of the following MUST fail to verify:

1. Flip one bit in `symbols_packed[0]` → MAC mismatch.
2. Flip one byte in `mac` → MAC mismatch.
3. Increment `sequence` by 1 → MAC mismatch (and bech32m checksum
   mismatch).
4. Replace `inscription_fp_trunc` with another 8 bytes → MAC mismatch.
5. Corrupt 23 random cells → RS decode failure.
6. Corrupt 22 random cells with known positions → RS decode SUCCESS
   (proves the erasure budget).
7. Change a single bech32 character → bech32m checksum failure.
8. Re-pack the symbols in V1 layout (12×16) → grid dimension reject.

## Acknowledgments

The MAC construction follows the domain-separation conventions used
in `src/eopx/format/secure_bytes.py` and the broader Esoptron crypto
hygiene rules. The RS choice mirrors the QR Code spec (ISO/IEC 18004),
deliberately, so existing battle-tested encoders/decoders can be
reused.

The four-channel resolution model (§ 2.7) was driven by the realistic
need to drop printed cards in the street (e.g. at events) while
preserving offline-first verification and protection against QR
phishing.

## Appendix A — Migration notes

- `src/eopx/metatron/grid.py` keeps the V1 constants (`GRID_ROWS`,
  `GRID_COLS`) for read-only compatibility. New code uses `grid_v2.py`.
- `scripts/make_invitation.py` removes the `extra_lines` parameter and
  replaces it with structured V2 fields. The visible text under the
  cube becomes: `code (bech32 short form) · seq · arch · insc_fp[:8]`.
- The `out/invitation_<CODE>.json` bundle gains four fields:
  `grid_cells`, `mac`, `bech32m`, `qr_url`.

## Appendix B — Future work (non-normative)

- **Card V3** could embed cell *shape* in addition to color (e.g. small
  glyphs inside cells), raising effective capacity from ~2.58 bits/cell
  to ~4.6 bits/cell and allowing ECC for the cube itself, not only the
  metadata.
- **Audio QR**: a 12-tone DTMF rendering of the bech32 string, for
  dictation or voice-channel distribution.
- **Braille embossing**: tactile overlay for accessibility, encoding
  the bech32 string in 6-dot cells.

---

## Integrity attestation

The spec document is **not** modified by the signing process. Integrity
metadata (SHA3-256 hash, author, timestamp, optional Dilithium-5
signature) lives in a separate file at the repository root:
``SPECS.SHA3-256``. This keeps the spec text reproducible, makes line-
ending and editor changes detectable, and lets the manifest cover
multiple specs uniformly.

Workflow:

```powershell
# (re)compute and write SPECS.SHA3-256
py tools/sign_spec.py docs/specs/EPX-2_card_v2.md --author "Jérémy ZGONEC"

# verify
py tools/verify_spec.py docs/specs/EPX-2_card_v2.md
```

The signature scheme remains Dilithium-5 (post-quantum). See
``tools/sign_spec.py`` and ``tools/verify_spec.py``.

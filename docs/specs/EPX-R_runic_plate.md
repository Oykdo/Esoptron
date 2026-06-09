# EPX-R — Runic Lattice Data Plate

**Status:** Draft (spec-first). Owner: Logos Project.
**Class:** New visual canvas behind the existing pattern interface
(`encode_public / encode_private / decode_private / is_in_code / render /
render_seal_revealed / detect`), parallel to the Metatron K₁₃ canvas.

A *plate* is a scannable runic lattice that stores an **encrypted payload**
(typically an AEAD-sealed vault backup or document) as a blocked, interleaved
Reed–Solomon code rendered as a grid of rune glyphs. It is **optical cold
storage**, not a glanceable sigil: at this scale the visual is a data channel,
and security comes from the cipher, not the picture.

---

## 1. Design choice: decouple the *visual alphabet* from the *code field*

The Metatron canvas ties geometry, alphabet, and field together (K₁₃ → 91 F₁₃
symbols). For a high-capacity plate that is the wrong coupling: a large field
(good for long RS blocks) means many glyph states per cell (bad to read).

So EPX-R splits them, exactly as QR does:

- **Visual layer — 16 runes = F₁₆ per cell (4 bits/cell).** Sixteen glyph
  states are easy to discriminate under a scanner/camera → robust reads.
- **Code layer — Reed–Solomon over GF(2⁸).** Battle-tested (QR/Aztec field),
  long blocks (n ≤ 255 symbols). **One code symbol = 2 cells** (4 + 4 bits).

This gives robust runic cells *and* standard long RS blocks, with a clean
mapping `1 GF(2⁸) symbol ↔ 2 F₁₆ cells`.

> Alternative (lab-only): 256 glyph-states/cell (F₂₅₆, 1 symbol = 1 cell)
> doubles density but requires microscopy-grade capture (see §10). Not the
> default.

---

## 2. Geometry — the runic treillis

A square lattice of **M × M cells** on a flat plate, plus:

- **Quiet zone** (blank margin ≥ 4 cells) around the lattice.
- **Fiducials**: three corner anchors (orientation + perspective) and one
  timing track (alternating runes on one row + one column) for cell-grid
  recovery — the runic analogue of QR finder/timing patterns.
- **Format runes** (a small fixed region): version, M, ECC level, interleave
  depth, payload length — itself a tiny high-redundancy RS block so the reader
  can self-configure before decoding the body.
- The remaining cells are the **data field**.

The Sri-Yantra / Flower-of-Life motifs may overlay the lattice as **brand**
(a decorative frame / watermark) without carrying data — the trust and the
bits live in the runic grid, never the ornament (POSITIONING, as for the seal).

---

## 3. Alphabet & field

- **Runes:** a fixed ordered set of 16 glyphs `R[0..15]` (e.g. a curated
  Younger-Futhark-derived set), with a canonical bijection `R[i] ↔ i ∈ F₁₆`.
  Glyphs are chosen for **maximum pairwise visual distance** (low confusion
  under blur/rotation) — this directly sets the per-cell error rate.
- **Field:** `GF(2⁸)` with the standard QR primitive polynomial
  `x⁸ + x⁴ + x³ + x² + 1` (0x11D). Code symbol `s ∈ GF(2⁸)` ↔ cell pair
  `(R[s>>4], R[s & 0xF])`.

---

## 4. Block code — blocked, interleaved Reed–Solomon

A single RS codeword over GF(2⁸) is limited to `n ≤ 255` symbols, so a
megabit plate is necessarily **many blocks, interleaved**:

- Each block is an **`[n, k, d]` RS code, MDS, `d = n − k + 1`** (Singleton).
- Default ECC level: **rate ≈ 0.66** → e.g. `n = 255, k = 169, d = 87`
  (corrects 43 errors or 86 erasures per block).
- **B blocks** tile the payload; symbols are **interleaved** across the plate
  (block-diagonal scatter) so a contiguous physical wound (scratch, coffee
  ring, torn corner) is spread thinly over many blocks.

### Capacity per plate

| Quantity | Formula |
|---|---|
| Cells | `M²` (minus fiducials/format/quiet zone) |
| Code symbols | `cells / 2` |
| Blocks `B` | `⌈code_symbols / n⌉` |
| Useful payload | `B · k · 8` bits |

---

## 5. Theorem 2 (generalized) — decodability of the interleaved plate

**Statement.** Let a plate carry `B` interleaved blocks, each an
`[n, k, d=n−k+1]` Reed–Solomon code over `GF(2⁸)`, with symbol interleaving of
depth `D` (each block's symbols mutually separated by ≥ `D` cells on the
plate). Then:

1. **(Membership)** A read cell-grid is a valid plate **iff**, after
   de-interleaving, every block `cᵢ` satisfies `H · cᵢ = 0`, where `H` is the
   `(n−k)×n` Vandermonde parity-check matrix of the RS code. This is the
   per-block `is_in_code` test.
2. **(Per-block correction)** Each block recovers its `k` data symbols from any
   pattern of `t` errors and `e` erasures with `2t + e ≤ d − 1`.
3. **(Burst/occlusion resilience)** With interleave depth `D`, any single
   contiguous occlusion covering up to `D · (d − 1)` cells damages at most
   `d − 1` symbols **per block** → every block stays within (2), so the **whole
   payload is recovered**.
4. **(Recovery guarantee)** The plate decodes the exact payload whenever, per
   block, `2·errors + erasures ≤ d − 1`.

**Proof sketch.** (1)–(2) are the standard RS facts: an `[n,k]` RS code is MDS
(meets the Singleton bound `d = n−k+1`); the syndrome `S = H·r` is zero iff `r`
is a codeword; Berlekamp–Massey / Welch–Berlekamp corrects up to
`⌊(d−1)/2⌋` errors, and erasure positions reduce the requirement linearly
(`2t + e ≤ d−1`). (3) follows because depth-`D` interleaving maps any
contiguous run of `L ≤ D·(d−1)` damaged cells onto `≤ d−1` symbols of any given
block (no two damaged cells of the same block lie within `D` of each other), so
each block sees `≤ d−1` erasures — within (2). (4) is the union of (2) over all
`B` blocks. ∎

*Erasures vs errors.* The reader marks low-confidence cells (§7) as
**erasures**, which the code corrects at **twice** the rate of unflagged errors
— so calibrated confidence roughly doubles effective robustness.

> A machine-checkable proof (RS-MDS + interleaving lemma) is a follow-up,
> aligned with the project's formal-spec track.

---

## 6. Encoding pipeline

```
payload (vault backup / document)
  → AEAD-seal under the Eidolon vault key            (confidentiality + integrity)
  → frame: magic || version || total_len || crc       (self-describing header)
  → split into B data shards (k symbols each)
  → RS-encode each shard → B codewords (n symbols)
  → interleave codewords across the lattice (depth D)
  → map each GF(2⁸) symbol → 2 runes (F₁₆ cells)
  → place fiducials + format runes + quiet zone
  → render glyph grid (+ optional Sri-Yantra/FoL brand overlay)
```

`render` produces the plate image; `render_seal_revealed` may additionally emit
the EPX-H seal as **brand** (no data). The format region is encoded first and
most redundantly so a reader can bootstrap.

---

## 7. Scan / decode pipeline (`detect`)

```
capture (scanner ≥1200 dpi, or camera)
  → locate fiducials → homography rectify to canonical M×M grid
  → sample each cell → classify to nearest rune (F₁₆) with a confidence score
  → low-confidence cells → ERASURES
  → pair cells → GF(2⁸) symbols → de-interleave → B blocks
  → read format block first (self-configure: M, ECC, D, len)
  → RS-decode each block (errors + erasures)
  → reassemble shards → verify frame CRC → AEAD-open with vault key
```

Confidence calibration (per-cell margin between top-1 and top-2 rune) is the
single biggest robustness lever — it converts ambiguous reads into erasures,
which cost half as much as errors (§5).

---

## 8. Interface mapping (parallel to `metatron`)

| Interface fn | EPX-R behavior |
|---|---|
| `encode_public(spinor)` | render a **public** plate (e.g. a public manifest / brand frame), no secret payload |
| `encode_private(seed)` | seal `seed` (or a vault blob) → blocked-RS → rune grid (the recoverable plate) |
| `decode_private(grid)` | the §7 pipeline → recovered bytes |
| `is_in_code(symbols)` | per-block syndrome test of §5(1) |
| `render(symbols, …)` | glyph-grid renderer |
| `render_seal_revealed(…)` | EPX-H seal as brand overlay (optional) |
| `detect(photo)` | rectify + sample + confidence→erasures (§7) |

`collection.forge` selects EPX-R for a plate-class collection via a `pattern`
field; **anchoring (EPX-T mint, controller sealing, ledger, distribution) is
unchanged.**

---

## 9. Reference parameters

### 9.1 "Vault plate" card (default, scanner-grade)

| Param | Value |
|---|---|
| Capture tier | flatbed scanner ≥ 1200 dpi |
| Cell pitch | 0.2 mm |
| Plate size | ~12 × 12 cm (≈ 615 × 615 cells) |
| Visual alphabet | 16 runes (F₁₆, 4 b/cell) |
| Code | RS over GF(2⁸), `[255,169,87]`, rate ≈ 0.66 |
| Interleave depth | tuned so a ≥ 1 cm² wound is recoverable |
| **Useful payload** | **≈ 1 Mbit (~125 KB)** |

### 9.2 "Archive plate" (10 Mbit, fully worked)

A 10 Mbit (~1.25 MB) plate — e.g. a full encrypted vault plus documents —
using the same block as §9.1:

| Param | Value | Derivation |
|---|---|---|
| Useful payload | 10 Mbit (~1.25 MB) | target |
| Block code | RS `[255,169,87]` / GF(2⁸) | rate ≈ 0.663 |
| Useful / block | 1 352 bits | `169 × 8` |
| Blocks `B` | **7 397** | `⌈10 000 000 / 1 352⌉` |
| Code symbols | 1 886 235 | `B × 255` |
| **Cells** | **≈ 3.77 M** | `× 2` (1 symbol = 2 cells) |
| **Lattice** | **≈ 1 960 × 1 960** | `√cells` + fiducials/format |
| Erasure budget | ≈ 33.7 % of symbols | `B·(d−1)` if perfectly spread |

**Physical realization** (the binding constraint is capture density, not the
algebra):

| Capture tier | Cell pitch | Plate side |
|---|---|---|
| Scanner 2400 dpi | 0.106 mm | **~21 × 21 cm** |
| Scanner 1200 dpi | 0.212 mm | ~41 × 41 cm (A3+ poster) |
| Microscopy 20 µm | 0.020 mm | **~3.9 cm tile** |

**Occlusion behavior.** With 7 397 interleaved blocks, a contiguous wound of a
few cm² maps to **< 1 erased symbol per block** → recovered trivially. The
ceiling is ~⅓ of the plate erased *if* the interleave spreads damage evenly
(depth `D` chosen for the worst-case wound shape).

**Archival variant (more durable).** Drop to rate ≈ 0.5 with RS `[255,127,129]`
(corrects 64 errors **or 128 erasures = 50 % per block**): same 10 Mbit useful,
~2 240 × 2 240 cells (~24 cm @ 2400 dpi). Trades area for survivability — the
right default for long-term cold storage.

### 9.3 Scaling (useful payload, rate ≈ 0.66, F₁₆ cells)

| Target | Cells (~) | M×M | Realistic tier |
|---|---|---|---|
| 1 Mbit | ~379 k | ~615 | scanned card / printed poster |
| 10 Mbit | ~3.8 M | ~1 950 | large scan / microscopy |
| 100 Mbit | ~38 M | ~6 160 | microscopy plate (~11 cm @ 20 µm) |
| 1 Gbit | ~380 M | ~19 500 | lab imaging ~5 µm (~9 cm plate) |

Lab maximum (F₂₅₆, 1 cell/symbol, microscopy) ≈ **2×** these densities.

---

## 10. Security model

- **Capacity ≠ security.** The plate is a channel. Confidentiality and
  integrity come from the **AEAD seal under the Eidolon vault key**, not the
  rune grid. A torn/partial plate that still decodes yields the *ciphertext*;
  without the vault key it reveals nothing.
- **Integrity:** AEAD tag + frame CRC detect tampering/decoding errors before
  use.
- **No secret in the format.** The runic mapping, geometry, and RS parameters
  are **open** (a reader must know them, like QR). Secrecy lives only in the
  key.

---

## 11. IP placement (per `IP-BOUNDARY.md`)

- **Tier 0/1 (open):** the EPX-R *format* — geometry, rune alphabet, RS
  parameters, the decode pipeline, the Theorem-2 property. Open like a barcode
  standard, so any scanner can read a plate.
- **Tier 2 (closed):** any binding of a plate to the **EEP-001 / poly-spinor**
  pipeline (e.g. a seed-deriving or seal step that uses the proprietary
  construction). The plate format stays open; the proprietary engine it may
  carry remains compiled-only.

---

## 12. Open questions

1. Final 16-rune glyph set + measured confusion matrix (drives the per-cell
   error rate, hence the real-world rate ceiling).
2. Interleave pattern (block-diagonal vs spiral) vs occlusion model — pick by
   simulation against scratch/tear/coffee-ring masks.
3. Format-block redundancy level (bootstrap must survive worse damage than the
   body).
4. F₁₆-cell vs F₂₅₆-cell crossover point for the microscopy tier.
5. Whether public plates (`encode_public`) carry the Sri-Yantra/FoL brand by
   default.

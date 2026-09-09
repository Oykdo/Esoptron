# EPX-R Runic Plate — Research Synthesis & Handoff Brief

**Audience:** a research/engineering agent picking up this work.
**Owner:** Logos Project. **Status:** open research program.
**Reads with:** `docs/specs/EPX-R_runic_plate.md` (the spec),
`IP-BOUNDARY.md` (what may/may not be published), and the `eopx.metatron`
pattern interface (the contract a canvas must implement).

---

## 0. TL;DR

EPX-R is a **runic visual error-correcting data canvas**: a lattice of rune
glyphs that stores an **AEAD-encrypted payload** as a blocked, interleaved
Reed–Solomon code. It is a second canvas behind the existing pattern interface
(parallel to the Metatron K₁₃ card), aimed at a spectrum from a **key-carrier
card** to a **megabit cold-storage plate**.

The algebra is established (Reed–Solomon, MDS). The **open questions are
empirical**: the real rune-cell error rate per capture tier, and the physical
realizability of the predicted footprints. This brief states the work as
**falsifiable hypotheses (A1–A8)** with explicit demonstration paths, and
defines the first experiment (a Python PoC) that converts "proven on paper"
into "measured."

---

## 1. Context

- **Ecosystem doctrine** (`IP-BOUNDARY.md`): *open standard, closed engine.*
  A visual **format** is brand/standard (Tier 0/1, publishable like a barcode);
  the proprietary crypto pipeline (EEP-001 temporal prism, poly-spinor) is
  Tier 2 (compiled-only). EPX-R is a **format** → its decode pipeline and the
  Theorem are open; only a binding to the Tier-2 engine would be closed.
- **Why a second canvas:** Metatron K₁₃ couples geometry+alphabet+field (91 F₁₃
  symbols) — fine for a glanceable card, wrong for high capacity. EPX-R
  **decouples** the visual alphabet from the code field to scale.
- **Anchoring is unchanged:** EPX-T mint, controller sealing, ledger, and
  distribution are pattern-agnostic; EPX-R only changes the rendered/scanned
  artifact.

---

## 2. Established results (the floor we build on)

| # | Result | Basis |
|---|---|---|
| E1 | Reed–Solomon `[n,k,d]` over GF(2⁸) is MDS: `d = n−k+1` | Singleton bound (classical) |
| E2 | RS corrects any `t` errors + `e` erasures with `2t+e ≤ d−1` | Berlekamp–Massey / Welch–Berlekamp |
| E3 | Codeword test: `H·c = 0` ⇔ `c` is valid (`is_in_code`) | Vandermonde parity check |
| E4 | Capacity `= B·k·8` bits (B blocks); `= N·rate·(bits/cell)` | counting |
| E5 | Decoupling visual alphabet (F₁₆ cells) from code field (GF(2⁸), 1 symbol = 2 cells) is sound | same trick as QR |

These are not in question. The research is everything *around* them.

---

## 3. Research axioms / hypotheses

Each hypothesis has: **statement**, **status**, **demonstration path**,
**success criterion**. Status ∈ {proven, lemma-sketch, conjecture, engineering}.

### A1 — Interleaved decodability ("Theorem 2, generalized")
- **Statement.** A plate of `B` depth-`D` interleaved RS`[n,k,d]` blocks
  recovers the exact payload **iff** every de-interleaved block satisfies
  `2t+e ≤ d−1`; and any contiguous wound of ≤ `D·(d−1)` cells damages ≤ `d−1`
  symbols per block.
- **Status.** **proven (empirical)** + lemma-sketch. PoC bench (§4.5): with
  interleaving, recovery holds at 33% damage and collapses at 36% — matching
  `(d−1)/n = 33.7%` to the percent. The self-test confirms recovery exactly at
  `nsym` erasures and failure at `nsym+1`. The machine-checkable interleaving
  lemma is still pending (M5).
- **Demonstration.** (i) ✅ PoC round-trip at/just past the per-block budget;
  (ii) ⏳ formalize the interleaving lemma.
- **Success.** 100% recovery strictly below budget, provable failure at/above;
  lemma formalized.

### A2 — Capacity law & megabit reachability
- **Statement.** Useful capacity follows E4; the §9 spec table (1 Mbit card,
  10 Mbit plate, up to 1 Gbit) is realizable in cells.
- **Status.** **proven (empirical).** PoC (§4.5): byte-exact round-trip at
  1 Mbit (740 blocks, 615×615) and 10 Mbit (7 397 blocks, 1943×1943) — lattice
  sizes match the §9 spec table.
- **Demonstration.** ✅ done.
- **Success.** Byte-exact round-trip at both sizes — achieved.

### A3 — Rune channel discriminability  ★ the crux
- **Statement.** There exists a 16-glyph rune set whose **pairwise visual
  distance** yields a per-cell error rate `p_cell(T) ≤ p*` under capture tier
  `T`, where `p*` is the maximum the chosen rate `r` tolerates.
- **Status.** **favorable (empirical, simulation).** PoC (§4.6): a 16-glyph
  set yields `p_cell` = 0% up to degradation 0.30, ≤0.5% @0.45, 2.5% @0.60,
  4.7% @0.75, 10.9% @0.90 — **under the 8.4% errors-only line up to ~0.75** and
  under 16.9% even at 0.90. Only **Kaunan↔Raido** confuse (~5% @0.45). The
  margin is generous → the rate could even rise. **Caveat:** this is a
  degradation *simulation*, not a real camera — A6 is the remaining proof.
- **Demonstration.** ✅ glyph set + 16×16 confusion matrix + `p_cell(T)` (sim);
  ⏳ real-capture confusion matrix (folds into A6).
- **Success.** A glyph set with measured `p_cell(T) ≤ p*` and margin — met in
  simulation; pending on real media.

### A4 — Erasure leverage via confidence
- **Statement.** Flagging low-confidence cells as **erasures** ≈ doubles
  tolerable damage (because the budget is `2t+e`).
- **Status.** **proven (empirical).** WP-2 added a full errors-and-erasures
  decoder (Berlekamp–Massey + Chien + Forney; 300/300 random `2t+e≤d−1` cases
  recover). A4 bench: **erasures recover to 86 (=d−1), errors to 43 (=(d−1)/2)**
  — the ~2× leverage, exactly. The confidence-threshold ROC is still to plot,
  but the 2× boundary is measured.
- **Demonstration.** ✅ errors-vs-erasures threshold bench; ⏳ confidence ROC.
- **Success.** ≥1.5× improvement — achieved (2×).

### A5 — Interleaving vs occlusion geometry
- **Statement.** For a worst-case contiguous wound of area `A`, there is a
  minimal depth `D(A)` guaranteeing ≤ `d−1` erasures/block.
- **Status.** **proven (empirical).** PoC (§4.5): max-spread interleaving holds
  contiguous scratch/corner damage to ~34% (the A1 ceiling); the **sequential**
  layout collapses at 5–10%. Concentrated blots cap ~5 pts lower (worst-case
  shape). A closed-form `D(A)` is still to derive.
- **Demonstration.** ✅ interleaved-vs-sequential bench; ⏳ closed-form `D(A)`.
- **Success.** An empirical/closed-form `D(A)`; recovery matches A1 at the
  ceiling — empirical part achieved.

### A6 — Physical realizability (print → scan → decode)
- **Statement.** The predicted footprints (cell pitch `p`, side `M·p`) are
  physically printable and resolvable with `p_cell ≤ p*` at each tier
  (1200/2400 dpi scanner; 20/5 µm microscopy).
- **Status.** **partially proven (simulation).** The full pipeline is built
  (`scripts/epx_r_prototype.py`): ArUco corner fiducials → homography →
  rectify → per-cell rune classify (+confidence→erasure) → de-interleave →
  RS errors-and-erasures decode → self-describing unframe. **3/3 simulated
  phone photos** (perspective + lighting gradient + blur + noise + JPEG q72)
  decode **byte-exact**; a `detect <photo>` CLI decodes real image files
  (validated on a saved sim JPG). A printable **A4 prototype** (300 dpi,
  ~3.4 mm cells) is generated. **Real print + phone-scan still pending**
  (needs hardware) — the only remaining proof.
- **Demonstration.** ✅ end-to-end pipeline on simulated captures + CLI;
  ⏳ real printed-then-photographed plate; ⏳ microscopy tier.
- **Success.** A **physical** plate that round-trips print→scan→decode — the
  software path is proven; physical capture pending.

### A7 — Capacity ≠ security
- **Statement.** The plate is a channel; confidentiality+integrity come from
  the **AEAD seal under the Eidolon vault key**, not the grid. A partial plate
  yields only ciphertext.
- **Status.** proven (crypto).
- **Demonstration.** Threat model; show a fully-read plate reveals no plaintext
  without the key; tamper → AEAD/CRC reject.
- **Success.** Documented threat model; key-absent reader recovers nothing
  usable.

### A8 — Scale alignment (1 Mbit → 1 Gbit)
- **Statement.** The construction extends by **block count + capture tier**
  with **no algebraic change**; only the tier crossovers move.
- **Status.** **proven (empirical) for 1→10 Mbit.** PoC (§4.5): identical code
  path, no algebraic change; encode 0.47 s → 2.53 s. 100 Mbit–1 Gbit remain
  extrapolated; the capture-tier crossover map awaits the physical work (A6).
- **Demonstration.** ✅ 1 and 10 Mbit round-trip; ✅ A4 tier-crossover map
  (WP-4, §4.7).
- **Success.** 10 Mbit round-trip + tier map — achieved.

---

## 4. Experimental program

### 4.1 PoC (first deliverable) — pure simulation, no camera
Implement EPX-R behind the pattern interface:
- `encode_private(blob)` → frame → RS`[255,169,87]`/GF(2⁸) blocks → interleave →
  F₁₆ cell grid → glyph image.
- `decode_private(image)` → sample → de-interleave → RS-decode → unframe → bytes.
- `is_in_code(symbols)` → per-block syndrome (E3).
- **Robustness bench:** apply parametric damage masks (scratch/tear/ring/blot/
  fold), with and without confidence→erasure, and plot **recovered vs damage %**
  against the A1 budget.

### 4.2 Rune channel study (A3) — the crux
- Candidate 16-glyph sets; degradation model; classifier; **confusion matrix**;
  `p_cell(T)` curves vs the `p*` line.

### 4.3 Physical loopback (A6)
- Print at 1200/2400 dpi; scan; end-to-end decode of a real 1 Mbit card.

### 4.4 Metrics (report these)
round-trip success rate · max recoverable damage fraction · `p_cell` per tier ·
bits/cm² achieved · decode latency · rate↔robustness curve · `D(A)` table.

### 4.5 PoC results — run 2026-06-06 (`scripts/epx_r_poc.py`)

RS`[255,169,87]`/GF(2⁸), ceiling `(d−1)/n = 33.7%`. Pure simulation (no camera).

**Round-trip (byte-exact):**

| Payload | Blocks | Lattice | Cells | is_in_code | Round-trip | enc |
|---|---|---|---|---|---|---|
| 1 Mbit (125 KB) | 740 | 615×615 | 378 225 | OK | **EXACT** | 0.47 s |
| 10 Mbit (1.25 MB) | 7 397 | 1943×1943 | 3 775 249 | OK | **EXACT** | 2.53 s |

**Occlusion bench (recoverable, interleaved · sequential):**

| Damage | scratch | corner | blot |
|---|---|---|---|
| 25% | 3/3 · 0/3 | 3/3 · 0/3 | 3/3 · 0/3 |
| 30% | 3/3 · 0/3 | 3/3 · 0/3 | 1/3 · 0/3 |
| **33%** | **3/3** · 0/3 | **3/3** · 0/3 | 0/3 · 0/3 |
| 36% | 0/3 · 0/3 | 0/3 · 0/3 | 0/3 · 0/3 |

**Reading:** interleaved recovery boundary = `(d−1)/n` to the percent
(Theorem 2 / A1). Sequential collapses at 5–10% (A5). Concentrated blots cap
~5 pts lower — the worst-case wound shape. `is_in_code` distinguishes valid vs
corrupted codewords; erasure decode recovers at exactly `nsym` and fails at
`nsym+1`.

**Not yet measured:** A6 (the physical/camera channel) — see roadmap.

### 4.6 Rune channel + WP-2 results — run 2026-06-06 (`scripts/rune_channel.py`, `epx_r_poc.py`)

**A3 — rune channel** (16 glyphs, nearest-prototype classifier, combined
degradation: blur+rotation+shear+noise+ink-bleed):

| Degradation level | p_cell | vs thresholds |
|---|---|---|
| 0.15–0.30 | 0.00% | < 8.4% (errors-only) |
| 0.45 | 0.50% | < 8.4% |
| 0.60 | 2.47% | < 8.4% |
| 0.75 | 4.69% | < 8.4% |
| 0.90 | 10.91% | < 16.9% (needs erasures) |

Confusion matrix near-diagonal; only **Kaunan(2)↔Raido(10)** confuse (~5% @0.45).

**A4 / WP-2 — errors-and-erasures decoder** (300/300 random `2t+e≤d−1` recover):

| Corrupted/block | as erasures (pos known) | as errors (pos unknown) |
|---|---|---|
| 43 | 40/40 ✅ | 40/40 ✅ |
| 44 | 40/40 ✅ | 0/40 ✗ |
| 86 | 40/40 ✅ | 0/40 ✗ |
| 87 | 0/40 ✗ | 0/40 ✗ |

→ erasures to **86 (=d−1)**, errors to **43 (=(d−1)/2)** = the **~2× leverage.**

**End-to-end usage** (secret → runic plate → noisy scan + scratch → recover):
an 80-byte secret on a 23×23 / 510-rune plate, scanned at level 0.50
(**2 confident-wrong errors** + 31 low-confidence erasures) **plus** a physical
scratch (15% cells erased) → **byte-exact recovery** via the WP-2 decoder.

### 4.7 A4 prototype + detect pipeline — run 2026-06-06 (`scripts/epx_r_prototype.py`)

**WP-3 (A6, simulation).** Printable A4 plate (2480×3508 px @ 300 dpi, 43×69
cells ~3.4 mm, 4 ArUco corner fiducials, 5 RS blocks). Capture path:
ArUco → homography → rectify → classify → RS errors-and-erasures → unframe.
**3/3 simulated phone photos** (perspective + lighting + blur + noise + JPEG
q72) decode **byte-exact**. The `detect <photo>` CLI recovered a payload from a
saved sim JPG (markers 0–3 found, 13/1275 erasures, 0 block-fails). Artifacts:
`epx_r_A4_prototype.png` / `.pdf`. **Real print+scan: pending hardware.**

**WP-4 — A4 capacity by capture tier** (usable 526 cm², rate 0.663, 4 b/cell):

| Tier | Cell pitch | cells/cm² | cells | Useful |
|---|---|---|---|---|
| Phone camera | 4.0 mm | 6 | 3 289 | ~1 KB |
| Scanner 1200 dpi | 0.30 mm | 1 111 | 584 778 | 194 KB (>1 Mbit) |
| Scanner 2400 dpi | 0.15 mm | 4 444 | 2.34 M | 775 KB |
| Microscopy 20 µm | 0.02 mm | 250 000 | 131.6 M | 43.6 MB |
| Lab optics 5 µm | 5 µm | 4 000 000 | 2.1 G | 698 MB |

→ phone tier ≈ **1 KB**; **megabit on A4 starts at scanner-1200 dpi**;
gigabyte-class needs microscopy/lab optics.

---

## 5. Roadmap / milestones

| M | Goal | Proves |
|---|---|---|
| **M0** | PoC encode/decode, byte-exact 1 Mbit round-trip | A2 |
| **M1** | Robustness bench + confidence-erasure | A1, A4, A5 |
| **M2** | Rune set + confusion matrix, `p_cell(T)` | **A3** |
| **M3** | Physical print→scan→decode of a 1 Mbit card | A6, A7 |
| **M4** | 10 Mbit round-trip + tier-crossover map | A8 |
| **M5** | Formalize the interleaving lemma (machine-checked) | A1 (formal) |

Each milestone is gated by the previous; **M2 (rune channel) is the make-or-
break** — if `p_cell` is too high, lower `q`/rate and re-budget.

---

## 6. Non-goals & honest limits

- Not a security primitive: capacity ≠ security (A7). Do not let "1 Mbit plate"
  read as "1 Mbit of security."
- The algebra is the easy part; **the physical channel is the risk**. Treat A3
  and A6 as the real frontier.
- A "card you glance at" dies above ~the 1 Mbit card tier — 10 Mbit+ is a data
  **plate** (scan/microscopy), not a sigil. State the tier explicitly in any
  result.

---

## 7. Constraints for the receiving agent

- **IP boundary:** the EPX-R *format* (geometry, runes, RS params, decode
  pipeline, Theorem) is **Tier 0/1 — publishable**. Any binding to the
  **EEP-001 / poly-spinor** engine is **Tier 2 — keep private/compiled**. Do not
  embed Tier-2 construction in this format's open code, tests, or docs.
- **Reproducibility:** fixed seeds, pinned deps, committed test vectors (mirror
  the existing `gen_test_vectors.py` style).
- **Spec-first:** changes to parameters flow back into
  `docs/specs/EPX-R_runic_plate.md` in the same change.

---

## 8. Glossary & references

- **Plate / card** — a rendered EPX-R artifact (large vs small).
- **Cell** — one rune position (F₁₆, 4 bits).
- **Symbol** — one GF(2⁸) code symbol = 2 cells.
- **Block** — one RS`[n,k,d]` codeword. **Interleave depth `D`** — min cell
  separation between a block's symbols.
- **Tier** — capture class (phone / scanner / microscopy) setting the areal
  density.
- Spec: `docs/specs/EPX-R_runic_plate.md`. Doctrine: `IP-BOUNDARY.md`.
  Interface: `eopx.metatron` public API. Anchoring: EPX-T / `eopx.transfer`,
  `eopx.collection.forge`.

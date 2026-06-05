# EPX-H — Seal Revealed: Cryptographic Hexagram Modulation

| Field           | Value                                            |
| --------------- | ------------------------------------------------ |
| Identifier      | EPX-H                                            |
| Status          | Draft                                            |
| Version         | 2                                                |
| Date            | 2026-05-30                                       |
| Author          | Jérémy ZGONEC                                    |
| Layer           | `eopx.metatron` (rendering extension)            |
| Wire compat     | Additive — does not modify any A-G protocol      |
| Dependencies    | Pillow (rendering); OpenCV only for the camera path |

## Changelog

* **v2** — Replaced the continuous-rotation model (v1) with **discrete star
  selection** (§2.3). The earlier "60° of angular freedom" was geometrically
  unrealisable on K_13's fixed edge set and produced ≈2 bits of real visual
  variation, not 60. v2 also adds the camera-robustness measures **A**
  (exclusion mask, §2.5) and **B** (saturation cap, §3.2), and specifies the
  fiducial path (§5) by reuse of the validated A4 page-corner ArUco frame.
* **v1** — Initial draft (continuous rotation).

## Abstract

EPX-H defines a rendering mode for the Metatron Cube in which the 78 structural
lines are drawn at **variable opacity** derived from the vault's cryptographic
identity. The Seal of Solomon (a hexagram) **emerges** from the pre-existing
geometry: the vault fingerprint selects *which* genuine K_13 hexagram to light
up, and the spinor hash colours its two triangles. The seal is *revealed* from
the cube, never *overlaid* on it.

This approach preserves:

* The 91 F_13 symbols (vertex disks + edge tags) — **byte-for-byte identical**
  to a standard `render()` (§4.4).
* The existing `.eopx` pipeline — `decode_from_photo` and Protocols A-G work
  without modification.
* The validated camera path — the badge reuses the same page-corner ArUco
  fiducials as a normal sheet (§5).

## 1. Motivation

A handover proposal suggested overlaying 7 opaque SVG layers on the cube. Opaque
shapes occult the ArUco fiducials and the F_13 symbol grid, and the approach
required `cairosvg`/`libcairo`.

EPX-H treats the hexagram not as an *addition* but as a **revelation** of a
pattern already present in K_13. Selecting which of the 78 lines to emphasise
and which to suppress yields a unique, vault-bound visual signature without
removing any information-carrying element, using Pillow alone.

Crucially, EPX-H is designed so that **the seal never has to survive the
camera as a measurement**. The decoder reads only the 91 symbols (which it
already handles); the seal's identity is *reproduced* from the decoded data
(§5.3), not recovered from pixel intensities. This is what makes the badge work
with current mobile-phone cameras.

## 2. Geometric foundations

### 2.1 Vertices of K_13

```
v[0]       = center (0, 0)
v[1..6]    = inner hexagon, radius 1,   angles 0, π/3, 2π/3, ..., 5π/3
v[7..12]   = outer hexagon, radius √3,  angles π/6, π/2, ..., 11π/6
```

K_13 is complete: all 78 = C(13,2) vertex pairs are edges.

### 2.2 Hexagram from a ring

A regular hexagram (Star of Solomon) is two interleaved equilateral triangles
inscribed in one circle. On K_13 this requires six vertices at equal radius and
60° apart — which exists on exactly **two** rings:

* **Inner ring** (radius 1): `T_fire = (1,3,5)`, `T_water = (2,4,6)`.
* **Outer ring** (radius √3): `T_fire = (7,9,11)`, `T_water = (8,10,12)`.

Each triangle contributes 3 edges, so each hexagram uses 6 of the 78 K_13
edges. The outer ring is rotated 30° relative to the inner ring.

### 2.3 Discrete star selection (Mesure D)

There is **no continuous rotation**. A continuous angle would place the triangle
points between vertices, off the existing edge set, violating the "revealed, not
added" principle. Instead the vault selects one catalog star and a colour swap:

```python
h           = SHA3-256(b"epx-h.seal_select.v1" ‖ vault_fp)   # 32 B, vault_fp is 32 B
star_index  = h[0] % len(STAR_CONFIGS)     # 0 = inner (0°), 1 = outer (30°)
color_swap  = bool(h[1] & 1)               # exchanges fire/water hues
```

`STAR_CONFIGS` is frozen at:

| Index | Name  | Fire triangle | Water triangle | Points at |
|-------|-------|---------------|----------------|-----------|
| 0     | inner | (1, 3, 5)     | (2, 4, 6)      | 0°        |
| 1     | outer | (7, 9, 11)    | (8, 10, 12)    | 30°       |

The pointing angle (0° / 30°) is the human recognition channel ("my seal points
at 30°"). Geometric entropy from the vault is therefore **≈2 bits**
(star × swap); the dominant visual uniqueness comes from the palette (§3),
which is a function of the vault's public `spinor_hash`.

### 2.4 Line classification

Each of the 78 edges `(i, j)` is classified into one of three tiers:

| Tier | Condition                               | Count | Opacity |
|------|-----------------------------------------|-------|---------|
| Seal | Edge is an edge of the selected star    | 6     | 0.90    |
| Near | Edge shares a vertex with a seal edge   | ≤ 24  | 0.30    |
| Dim  | All other edges                         | rest  | 0.08    |

Seal edges are coloured fire or water depending on which triangle they belong
to; the "Near" tier is a luminous halo; "Dim" is a neutral-grey ghost Metatron.

### 2.5 Exclusion mask (Mesure A)

The decoder (`detect.extract_canonical`) locates each carrier by the **most
colourful cluster** within a window around its canonical position:

* edge tags: a window of `r_tag + 8` px;
* vertices: a search radius of `r_v × 3`, refinement sanity-bounded to `r_v × 2`.

A bright, saturated seal line falling inside such a window competes with the
symbol disk and can corrupt classification — especially for the near-grey
symbols (Obsidienne C=0.02, Ardoise C=0.06, Albâtre C=0.03), which a saturation
cap alone cannot protect because they are themselves low-chroma.

EPX-H therefore renders all structural lines onto a separate RGBA layer and
**punches the layer's alpha to 0** inside every sampling window before
compositing. No seal/near/dim pixel can reach any carrier's search window.

| Region        | Cleared radius                                  | ≥ decoder window |
|---------------|-------------------------------------------------|------------------|
| each edge tag | `r_tag + round(size × 0.014)` (≈27 px @ 1024)   | `r_tag + 8`      |
| each vertex   | `r_v × 2.0`                                      | `r_v × 2` bound  |

## 3. Chromatic derivation

### 3.1 Triangle hues

```python
hue_a = int.from_bytes(spinor_hash[0:2], "big") % 360
hue_b = (hue_a + 180) % 360
hue_fire, hue_water = (hue_b, hue_a) if color_swap else (hue_a, hue_b)
```

Lightness is fixed per tier for contrast: seal 45% (fire) / 55% (water), near
65%, dim 80% (neutral grey).

### 3.2 Saturation cap (Mesure B)

Saturation is **bounded** so that colour bleeding past the exclusion mask under
camera blur or JPEG 4:2:0 chroma subsampling stays weaker than a genuine symbol:

```python
saturation = 45 + (spinor_hash[2] % 16)    # [45, 60] %   (SEAL_MAX_SATURATION = 60)
```

Mesure B is a *secondary* defence; Mesure A (§2.5) is the primary guarantee.

### 3.3 Determinism

The same `(vault_fp, spinor_hash)` always produces the same star, swap, palette,
and image bytes.

## 4. Rendering pipeline

### 4.1 Function signature

```python
def render_seal_revealed(
    symbols: Sequence[int],       # 91 F_13 symbols
    vault_fp: bytes,              # 32 B vault fingerprint (selects star + swap)
    spinor_hash: bytes,           # ≥3 B spinor hash (colour palette)
    size: int = 1024,
    star_override: Optional[int] = None,   # force a star index, for tests
) -> Image.Image:
```

### 4.2 Layer order (Pillow, no SVG)

1. White background.
2. **Seal layer (RGBA)**: all 78 edges drawn by tier (dim/near/seal) with
   per-line alpha, then the alpha is multiplied by the exclusion mask (§2.5)
   and composited onto the background.
3. **Edge tags**: the 78 coloured symbol disks — identical draw calls to
   `render.render()`.
4. **Vertex disks + glyphs**: the 13 coloured rings with glyphs — identical
   draw calls to `render.render()`.

Steps 3-4 are byte-for-byte the same as the standard renderer (§4.4).

### 4.3 Opacity

Lines are drawn on an RGBA canvas with explicit per-line alpha; the alpha
channel is then masked (`ImageChops.multiply`) and `alpha_composite`d onto the
opaque white background, giving a deterministic RGB result.

### 4.4 Symbol preservation

Because the seal lives only in the line layer and is masked away from every
sampling window, the interiors of the 13 vertex disks and 78 edge tags are
**pixel-identical** to a standard `render()` of the same `size` (verified in
`tests/test_seal_reveal.py::TestSymbolPreservation`).

## 5. Fiducials and the camera path

### 5.1 The cube alone is not scannable

A bare cube PNG carries no fiducials. The validated camera path lives on the
**A4 sheet** (`scripts/print_sheet.py`): the cube is centred inside 4
page-corner ArUco markers (DICT_4X4_50, IDs 0-3) plus a chromatic scan grid.
`eopx.metatron.aruco.autodetect_cube` detects those markers, rectifies the
page, crops the cube, and runs `extract_canonical`.

### 5.2 Badge = seal cube in the validated frame

EPX-H does **not** invent a new fiducial scheme. `make_sheet()` accepts a
`cube_renderer` hook; the badge passes a closure wrapping
`render_seal_revealed`, leaving the page-corner ArUco fiducials, grid, and
detection pipeline untouched. `scripts/eopx_badge.py` is the CLI entry point.

The seal star's edges are all among inner (1-6) or outer (7-12) cube vertices,
so the seal never touches the page-corner fiducials.

### 5.3 Verification of the seal

A holder/verifier who knows the vault's public identity:

1. decodes the 91 symbols through the normal pipeline (`.eopx` / ArUco);
2. recovers `vault_fp` and `spinor_hash` from the vault's public record;
3. **re-renders** the expected seal locally and compares.

This is the correct verification model: the seal is *reproduced*, never
*measured* off the photo. Camera white-balance and tone-mapping destroy absolute
hue/intensity, so any scheme that measured line intensities from the JPEG would
be unreliable — EPX-H deliberately does not do this. The seal is a
human-recognition + deterministic-re-render channel; cryptographic trust remains
with the symbol channel and the `.eopx` chunk signature (Protocol B).

## 6. Constants (frozen at v2)

| Constant                | Value                          |
| ----------------------- | ------------------------------ |
| `SEAL_DOMAIN`           | `b"epx-h.seal_select.v1"`     |
| `SEAL_EDGE_WIDTH`       | `4`                            |
| `NEAR_EDGE_WIDTH`       | `2`                            |
| `DIM_EDGE_WIDTH`        | `2`                            |
| `SEAL_ALPHA`            | `0.90`                         |
| `NEAR_ALPHA`            | `0.30`                         |
| `DIM_ALPHA`             | `0.08`                         |
| `SEAL_SAT_BASE`         | `45`                           |
| `SEAL_SAT_SPAN`         | `16` (→ `SEAL_MAX_SATURATION = 60`) |
| `TAG_CLEAR_PAD_FRAC`    | `0.014`                        |
| `VERTEX_CLEAR_MULT`     | `2.0`                          |
| `DEFAULT_SEAL_SIZE`     | `1024`                         |
| `STAR_CONFIGS`          | inner(1,3,5/2,4,6,0°), outer(7,9,11/8,10,12,30°) |

## 7. Test vectors

### 7.1 Determinism
Two calls with the same `(symbols, vault_fp, spinor_hash, size)` MUST produce
bit-identical PNG bytes.

### 7.2 Star selection
`select_star` is deterministic, in `[0, len(STAR_CONFIGS))`, rejects a
non-32-byte `vault_fp`, and over 50 distinct vaults exercises both catalog
stars.

### 7.3 Symbol preservation
The interiors of the 13 vertex disks and 78 edge tags MUST be pixel-identical to
a standard `render()` of the same size.

### 7.4 Exclusion mask (Mesure A)
`_build_protection_mask` MUST return 0 at every tag centre, at the tag
search-window edge (`r_tag + 8`), at every vertex centre, and at `r_v` from each
vertex; and MUST retain some 255 pixels.

### 7.5 Saturation cap (Mesure B)
Over 64 distinct spinors, every fire/water/near colour MUST have HSL saturation
≤ `SEAL_MAX_SATURATION` (+ a small round-trip margin).

### 7.6 Fiducial loopback
A seal badge rendered via `make_sheet(cube_renderer=…)` MUST decode through
`autodetect_cube → extract_canonical` and recover **no fewer** matching symbols
than the equivalent plain cube (the seal adds zero classification errors), and
MUST recover ≥86/91 on the noise-free synthetic sheet
(`tests/test_seal_badge_loopback.py`).

## 8. File manifest

| File                                  | Status   | Purpose                          |
| ------------------------------------- | -------- | -------------------------------- |
| `src/eopx/metatron/seal_reveal.py`    | created  | Rendering module (A+B+D)         |
| `scripts/eopx_badge.py`               | created  | Badge CLI                        |
| `tests/test_seal_reveal.py`           | created  | Unit tests                       |
| `tests/test_seal_badge_loopback.py`   | created  | Fiducial end-to-end loopback     |
| `src/eopx/metatron/__init__.py`       | modified | Export `render_seal_revealed`    |
| `scripts/print_sheet.py`              | modified | `make_sheet(cube_renderer=…)` hook |

## 9. References

- Esoptron Whitepaper I — Metatron Visual Encoding
- Esoptron `graph.py` — K_13 vertex/edge geometry
- Esoptron `render.py` — deterministic PNG renderer
- Esoptron `aruco.py` / `print_sheet.py` — page-corner ArUco fiducial frame
- Esoptron `detect.py` — colour-cluster carrier sampling

---

*This document is normative for `version = 2`. The seal revealed is not added to
the mirror — it was always there, waiting for the vault to name the angle.*

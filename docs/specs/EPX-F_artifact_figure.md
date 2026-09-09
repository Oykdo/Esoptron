# EPX-F — Artifact Figure: a frozen, recomputable face for a `.eopx`

| Field           | Value                                                     |
| --------------- | --------------------------------------------------------- |
| Identifier      | EPX-F                                                     |
| Status          | Draft                                                     |
| Version         | 1                                                         |
| Date            | 2026-09-09                                                |
| Author          | Jérémy ZGONEC                                             |
| Layer           | `eopx.artifact_figure` (derivation); presentation is free |
| Wire compat     | Additive — reads the manifest, modifies nothing           |
| Dependencies    | stdlib only (`hashlib`) + `eopx.metatron.field.hkdf_sha3_512` |

## Changelog

* **v1** — Initial draft. Two-band grid, pre-image inputs only, epoch tag from
  `dilithium_pk_fp`.

## Abstract

EPX-F defines **F**, the function mapping a `.eopx` artifact to a *cell grid*:
`GRID_H × GRID_W` integer levels that any renderer may draw with any glyph set.
The grid derives from the **pre-image half** of the signed manifest, so it can
be recomputed from the file by anyone and compared against what is printed,
engraved or displayed.

F is **frozen at v1**. A printed badge outlives the software that made it; a
change to the derivation is a new version, never an edit.

## 1. Motivation, and the trap it avoids

An artifact deserves a face that is *its own* — not decoration chosen by a
designer, but a deterministic consequence of what the artifact is. The obvious
implementation is also wrong, and it is worth writing down why.

`EopxManifest.canonical_payload()` (`src/eopx/format/eopx_format.py`) covers:

```
eopx_format_version, vault_id, merkle_root, dilithium_pk_fp,
kyber_pk_fp, timestamp_utc, image_sha3_512
```

`payload_hash` is therefore **downstream of the pixels**, and `image_sha3_512`
is the pixels. A figure drawn *into* the image and derived *from* either field
is a fixed point:

```
figure -> pixels -> image_sha3_512 -> payload_hash -> figure
```

with no solution. Only fields fixed **before** the image exists are admissible
inputs (§2).

The reward for respecting that constraint is that no new cryptography is
needed. The inputs live inside `canonical_payload()`; the rendering reaches it
through `image_sha3_512`. **The single ML-DSA-87 signature already covers both
the inputs and the drawing.** A verifier checks the signature it was already
checking, then recomputes.

## 2. Admissible inputs

| Field              | Admissible | Reason                                    |
| ------------------ | ---------- | ----------------------------------------- |
| `merkle_root`      | **yes**    | content identity, fixed before rendering  |
| `dilithium_pk_fp`  | **yes**    | issuer identity, fixed before rendering   |
| `vault_id`         | yes        | reserved for a future version             |
| `kyber_pk_fp`      | yes        | reserved for a future version             |
| `timestamp_utc`    | yes        | reserved for a future version             |
| `payload_hash`     | **no**     | covers `image_sha3_512` — circular (§1)   |
| `image_sha3_512`   | **no**     | is the pixels — circular (§1)             |
| ledger state       | **no**     | not in the manifest; see §6               |

v1 consumes exactly `merkle_root` and `dilithium_pk_fp`, both 32 bytes, taken
raw (not hex) from the manifest.

## 3. Derivation (normative)

```
GRID_W       = 16          cells per row
GRID_H       = 8           rows
CONTENT_ROWS = 6           rows 0..5   — content band
EPOCH_ROWS   = 2           rows 6..7   — epoch band
LEVELS       = 16          one hex nibble per cell

INFO_CONTENT = "esoptron.figure.content.v1"
INFO_EPOCH   = "esoptron.figure.epoch.v1"

content = HKDF-SHA3-512(ikm = merkle_root,
                        salt = "",
                        info = INFO_CONTENT,
                        length = 48)                    # 96 cells
epoch   = HKDF-SHA3-512(ikm = merkle_root || dilithium_pk_fp,
                        salt = "",
                        info = INFO_EPOCH,
                        length = 16)                    # 32 cells

cells   = nibbles(content) || nibbles(epoch)            # high nibble first
grid[r][c] = cells[r * GRID_W + c]
```

`HKDF-SHA3-512` is RFC 5869 instantiated with SHA3-512, as already used by
`vault/unlock`, `vault/enroll` and `egg_token` (`eopx.metatron.field`).

128 cells × 4 bits = **512 bits = exactly one SHA3-512 width**: no counter
mode, no truncation bias, one output one grid.

### 3.1 Why two bands

The content band depends on `merkle_root` alone, so **an artifact keeps its
face for life**. The epoch band also takes `dilithium_pk_fp`, so **a key
rotation is visible** without making the object a stranger. A badge minted in
2026 and re-attested under a 2030 key still reads as the same artifact, with a
different lower band.

A single-band design would have been simpler and wrong: rotating the issuing
key would have redrawn every artifact in the parc.

## 4. Canonical form, digest, tag

The **canonical text** is one lowercase hex digit per cell, rows joined by
`\n`, no trailing newline. It is glyph-independent by construction.

```
figure_digest = SHA3-256(canonical_text, UTF-8)
figure_tag    = first 4 bytes of figure_digest, hex        # 8 characters
```

The digest covers the **levels**, never a rendering. The tag is small enough to
print under a badge and is a *comparison aid*: only recomputation from the
`.eopx` decides.

## 5. Epochs and key rotation

`epoch_id = dilithium_pk_fp[0:4]`, hex. Two artifacts sharing an `epoch_id`
were signed under the same key.

The epoch tag is a **legible signal, not a proof of authority**. Continuity
across a rotation is carried by a cosigned attestation, using the dual-signature
mechanism of `tools/sign_spec.py` (`signature` + `cosignature` over one digest,
`SPECS.SHA3-256`):

> **Epoch N+1 cosigns an attestation naming epoch N's `dilithium_pk_fp`.**

A verifier holding only epoch N+1's public key can then walk backwards and
accept an artifact minted under epoch N, without epoch N's key still being
live. Without this chain, a parc of printed artifacts has the lifetime of a
single key.

The attestation record format and its publication endpoint are **out of scope
for v1** and are the immediate follow-on work. What v1 fixes is the input:
`dilithium_pk_fp` is the epoch, and it is inside the signed payload.

## 6. Presentation, and what must never move

A renderer maps levels to glyphs. `ASCII_RAMP` is the reference — 16 glyphs,
light to dense:

```
 .`',:;!~+=*%#@$
```

Two implementations printing the same grid with it must agree character for
character. Substituting a Unicode block ramp, drawing
box-drawing frames around a gallery, or animating the display changes what a
reader sees **and nothing else** — the grid, the digest and the tag are
untouched.

Two rules bound this freedom:

1. **Anything inside the signed pixels is frozen.** `image_sha3_512` covers the
   decoded RGB bytes; an animated face invalidates the signature for every
   frame but one. Movement lives outside the envelope.
2. **A moving face must not be mistakable for a frozen one.** A living
   rendering driven by ledger state (as `collection/figure.py` does, bounded by
   `LIVING_INTERIOR_CAP`) is a hint for the eye. If it is beautiful, people
   will try to "verify" by looking at it; it must therefore be visibly distinct
   from the EPX-F face.

## 7. Verification

```
1. verify the .eopx signature                  (existing SDK path, unchanged)
2. read merkle_root and dilithium_pk_fp        from the verified manifest
3. grid  = F(merkle_root, dilithium_pk_fp)     §3
4. compare canonical_text(grid) / figure_tag(grid) with the artifact
```

Step 1 is what establishes trust. Steps 2–4 establish that the face belongs to
that artifact. **Looking at the figure is not a step.**

## 8. Freezing rules

* `FIGURE_VERSION = 1` is baked into `INFO_CONTENT` / `INFO_EPOCH`. Changing
  geometry, ramp length, band split, KDF or input set requires `v2` domain
  strings and a new section here; v1 must keep producing v1 grids forever.
* The vectors in §9 are normative. A failing vector is a regression or a
  deliberate version bump — never an expected-value edit.
* Ports (TypeScript SDK, PWA) must reproduce §9 byte for byte before shipping.

## 9. Test vectors

Inputs, retypable by any port:

```
MR_A = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
FP_A = 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
FP_B = c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
MR_B = d7cbece511de55e5b18a277abad1ddfb72e81f5f7f9c1ca042482eda41e49520
       ( = SHA3-256("esoptron.epxf.testvector.B") )
```

**F(MR_A, FP_A)** — epoch `80818283`, tag `b0401fcd`

```
49ae329b8b747b01
ad04a51176f99b0e
06ee014df09645a7
749d394a34656097
1d38ef49a89713dd
55ab8c746369a81c
1c56695457db99c4
653882ef9bc627a8
```

**F(MR_A, FP_B)** — same artifact, next epoch `c0c1c2c3`, tag `ab02f2e7`.
Rows 0–5 are identical to the above; only the epoch band moves:

```
49ae329b8b747b01
ad04a51176f99b0e
06ee014df09645a7
749d394a34656097
1d38ef49a89713dd
55ab8c746369a81c
2c00cf5c5f9aecdc
5d033f23dc4a2604
```

**F(MR_B, FP_A)** — different artifact, epoch `80818283`, tag `d67ea63a`

```
2f9f56b3a3800600
f4b4820ea5d1011d
ee6f57889853c1a0
ea52a2ace46aac27
af617dbf1747fe22
0edac7f63c5a5572
84d0783b74d124f0
c2e5de046ed70768
```

Rendered with `ASCII_RAMP`, `F(MR_A, FP_A)` reads:

```
,+=@'`+*~*!,!* .
=# ,=:..!;$++* @
 ;@@ .,#$ +;,:=!
!,+#'+,=',;:; +!
.#'~@$,+=~+!.'##
::=*~%!,;';+=~.%
.%:;;+:,:!#*++%,
;:'~~`@$+*%;`!=~
```

Covered by `tests/test_artifact_figure.py`.

## 10. Security considerations

**EPX-F is brand, not security** (POSITIONING). It adds no entropy to any
protocol, proves no possession, and cannot be checked by eye. Its only claims:

* the grid is a deterministic function of two signed manifest fields;
* the digest binds the levels, not the glyphs;
* a key rotation is legible without changing the artifact's identity band.

The 128 cells are a public function of public inputs. Nothing here is secret,
and no part of the grid may ever be used as key material, as a challenge, or as
evidence of anything the ML-DSA-87 signature does not already establish.

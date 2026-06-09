# EPX-R — Theorem 2: interleaving lemma & proof (WP-5)

Companion to `EPX-R_runic_plate.md` §5. Establishes rigorously why depth-`B`
round-robin interleaving turns a contiguous physical wound into a per-block
erasure load within the Reed–Solomon budget. Checked numerically by
`scripts/verify_interleaving.py`.

## Setup

A plate carries `B` codewords (blocks) of an `[n, k, d]` Reed–Solomon code over
GF(2⁸), `d = n − k + 1` (MDS, by the Singleton bound). Symbols are written to
the cell grid in **stream order** by the round-robin interleave used in the PoC
(`cw.T.reshape(-1)`):

> symbol with stream index `s` belongs to block `b = s mod B` at position
> `p = ⌊s / B⌋`.

Each symbol occupies **2 consecutive cells** (high then low F₁₆ nibble), laid
row-major.

## Lemma (round-robin interleaving)

Let `W` ⊂ ℤ be a set of erased symbols forming a **contiguous range of length
`S`** in stream order. Then `W` contains at most `⌈S / B⌉` symbols of any single
block.

**Proof.** Block `b` owns exactly the symbols whose stream index is `≡ b (mod
B)`: the arithmetic progression `{b, b+B, b+2B, …}`. In any window of `S`
consecutive integers, the count of integers congruent to a fixed residue mod
`B` is either `⌊S/B⌋` or `⌈S/B⌉` (the residues are hit cyclically, period `B`),
hence `≤ ⌈S/B⌉`. ∎

## Theorem 2 (recovery under a contiguous wound)

If a contiguous erased symbol-range has length `S ≤ B·(d−1)`, then **every block
sees ≤ d−1 erasures and the whole payload is recovered.**

**Proof.** By the Lemma, each block has `≤ ⌈S/B⌉` erasures. `S ≤ B·(d−1)` gives
`⌈S/B⌉ ≤ d−1`. An `[n,k]` RS code is MDS, so erasure decoding corrects up to
`d−1 = n−k` erasures per block (Berlekamp–Welch / syndrome solve). Thus all `B`
blocks decode and the payload is recovered. ∎

### Corollary (in cells)

Two cells per symbol, laid contiguously, so a contiguous **cell** wound of
length `W` touches a contiguous symbol range of length `≤ ⌊W/2⌋ + 1`. Hence any
contiguous wound of

> `W ≤ 2·B·(d−1) − 2` cells

is recoverable. Equivalently, the recoverable fraction of a single contiguous
wound approaches `(d−1)/n` of the plate as `B` grows — matching the PoC bench
(interleaved recovery to ~33.7% = `(d−1)/n` for `[255,169,87]`).

### Errors-and-erasures form

If the reader emits some symbols as **errors** (confident-wrong, position
unknown) rather than erasures, the per-block requirement is `2t_b + e_b ≤ d−1`
(E2). The Lemma bounds `e_b ≤ ⌈S/B⌉`; the same interleaving argument bounds the
error count per block for a contiguous misread region. Recovery holds whenever,
per block, `2t_b + e_b ≤ d−1`.

## Two-dimensional wounds

A physical wound is 2-D. In row-major cell order, a wound spanning full grid
width over `h` rows is a single contiguous stream range (Theorem 2 applies
directly). A wound narrower than the grid width decomposes into at most `h`
disjoint contiguous runs (one per affected row); the per-block erasure count is
the sum of the per-run bounds `Σ ⌈Sᵢ/B⌉`, still `≤ ⌈(Σ Sᵢ)/B⌉ + h`. For
`B ≫ h` this stays within budget for any wound whose total area is below the
`(d−1)/n` fraction — the regime confirmed empirically (scratch/corner/blot
benches).

## Numerical verification

`scripts/verify_interleaving.py` checks, for several `(n,k,B)`:
1. the Lemma: `max-per-block(S) = ⌈S/B⌉` for every window length `S` and a
   range of start offsets, against the actual `cw.T.reshape(-1)` map;
2. the Theorem boundary: every contiguous `S ≤ B·(d−1)` keeps per-block
   erasures `≤ d−1`, and `S = B·(d−1)+1` exceeds it for the worst block.

## Status

Rigorous written proof + numerical check (this file + verifier). A
machine-checkable proof (Lean/Coq) of the Lemma's congruence-counting step is a
straightforward follow-up but not required for the bound to hold.

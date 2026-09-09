#!/usr/bin/env python3
"""EPX-R WP-5 — numerical verification of the interleaving lemma & Theorem 2.

Round-robin map (cw.T.reshape(-1)): stream index s -> block b = s mod B.

Checks:
  (1) Lemma: in any contiguous window of length S, the per-block count equals
      ceil(S/B). Verified by an O(B) closed form, anchored by brute force on
      small windows over many start offsets.
  (2) Theorem 2 boundary: S = B*(d-1) gives max d-1 per block; S = B*(d-1)+1
      overflows exactly one block to d.

Run:  py -3.11 scripts/verify_interleaving.py   (instant, pure stdlib)
"""

from __future__ import annotations

import math


def fast_counts(S, st, B):
    """O(B) per-block counts for window [st, st+S), residue b = s mod B."""
    base, rem = divmod(S, B)
    c = [base] * B
    for i in range(rem):
        c[(st + i) % B] += 1
    return c


def brute_counts(S, st, B):
    """O(S) ground truth, for small windows only."""
    c = [0] * B
    for s in range(st, st + S):
        c[s % B] += 1
    return c


def check_lemma(B, n):
    starts = (0, 1, B // 3, B - 1, B, 2 * B + 1, 5 * B + 3)
    # (a) brute-anchor the closed form on small absolute windows, many starts
    for S in list(range(0, 260)) + [B - 1, B, B + 1, 2 * B, 2 * B + 1, 3 * B]:
        for st in starts:
            if fast_counts(S, st, B) != brute_counts(S, st, B):
                return False, ("brute", S, st)
            if max(fast_counts(S, st, B)) != (math.ceil(S / B) if S else 0):
                return False, ("formula", S, st)
    # (b) formula consistency at large representative windows (O(B) each)
    total = B * n
    for S in (total // 4, total // 2, total - 1, total):
        if max(fast_counts(S, 0, B)) != math.ceil(S / B):
            return False, ("large", S)
    return True, None


def check_boundary(B, n, k):
    nsym = n - k                          # d-1
    at = max(fast_counts(B * nsym, 0, B))         # S = B*(d-1)
    over = max(fast_counts(B * nsym + 1, 0, B))   # S = B*(d-1)+1
    return at, over, nsym


if __name__ == "__main__":
    n, k = 255, 169
    print("[verify] interleaving lemma + Theorem 2 boundary "
          "(round-robin, s -> s mod B)\n")
    print(f"  RS[{n},{k}], d-1 = {n-k}")
    print("    B    | lemma | S=B(d-1) max/blk | S=B(d-1)+1 max/blk | recoverable cells | OK")
    allok = True
    for B in [5, 16, 740, 7397]:
        ok_l, info = check_lemma(B, n)
        at, over, nsym = check_boundary(B, n, k)
        ok = ok_l and at == nsym and over == nsym + 1
        allok &= ok
        cells = 2 * B * nsym - 2
        print(f"  {B:6d} | {'OK' if ok_l else f'FAIL{info}':^5s} | {at:^16d} | "
              f"{over:^18d} | {cells:>15,d}  | {'OK' if ok else 'FAIL'}")
    print(f"\n  Lemma: per-block count = ceil(S/B). Theorem 2: S <= B*(d-1) "
          f"=> <= d-1/block => recover.")
    print(f"  ALL CHECKS {'PASSED' if allok else 'FAILED'}.")

"""Reed-Solomon RS(13, 10) over F_13, interleaved x7 -> (91, 70).

Whitepaper II, sections 2.2 to 2.4.

Construction:
    Message m in F_13^10. Polynomial P(X) = sum_{j=0..9} m_j * X^j.
    Codeword c in F_13^13: c[i] = P(i) for i in {0, 1, ..., 12}.

The code is systematic on the first 10 positions iff we interpret c[0..9]
as the message itself (true when P interpolates through (0, m_0), ..., (9, m_9)
-- which is what we enforce in block_encode below).

Distance d = n - k + 1 = 4 (Singleton bound, MDS).
Erasure capacity per block = d - 1 = 3.
Error capacity per block    = floor((d-1)/2) = 1.

Seven blocks are interleaved across the 91 carriers of K_13 (13 vertices
plus 78 edges) so that a local burst of damage affects at most one symbol
per block.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

from . import field as F

BLOCK_N = 13                  # codeword length per block
BLOCK_K = 10                  # message symbols per block
NUM_BLOCKS = 7                # 7 interleaved blocks
TOTAL_N = BLOCK_N * NUM_BLOCKS  # 91 carriers
TOTAL_K = BLOCK_K * NUM_BLOCKS  # 70 message symbols
BLOCK_D = BLOCK_N - BLOCK_K + 1  # = 4
EVAL_POINTS = tuple(range(BLOCK_N))  # 0, 1, ..., 12


# ---------------------------------------------------------------------------
# Polynomial helpers in F_13
# ---------------------------------------------------------------------------

def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Horner evaluation of a polynomial in F_13."""
    acc = 0
    for c in reversed(coeffs):
        acc = F.add(F.mul(acc, x), c)
    return acc


def _lagrange_interpolate(points: Sequence[int], values: Sequence[int]) -> List[int]:
    """Compute the unique polynomial coefficients (degree < len(points))
    interpolating the given (x_i, y_i) over F_13.

    Returns coefficients in ascending degree order: [a_0, a_1, ..., a_{n-1}].
    """
    if len(points) != len(values):
        raise ValueError("points and values must have equal length")
    n = len(points)
    if len({p % F.Q for p in points}) != n:
        raise ValueError("evaluation points must be distinct in F_13")

    # Lagrange basis: P(X) = sum_i y_i * L_i(X)
    # where L_i(X) = prod_{j != i} (X - x_j) / (x_i - x_j)
    result = [0] * n
    for i, (xi, yi) in enumerate(zip(points, values)):
        # numerator polynomial prod_{j != i} (X - x_j)
        num = [1]
        for j, xj in enumerate(points):
            if j == i:
                continue
            new_num = [0] * (len(num) + 1)
            for k, c in enumerate(num):
                new_num[k] = F.add(new_num[k], F.mul(c, F.sub(0, xj)))
                new_num[k + 1] = F.add(new_num[k + 1], c)
            num = new_num
        # denominator prod_{j != i} (x_i - x_j)
        denom = 1
        for j, xj in enumerate(points):
            if j == i:
                continue
            denom = F.mul(denom, F.sub(xi, xj))
        inv_denom = F.inv(denom)
        scale = F.mul(yi, inv_denom)
        for k, c in enumerate(num):
            result[k] = F.add(result[k], F.mul(c, scale))
    return result


# ---------------------------------------------------------------------------
# Block-level encoding / decoding
# ---------------------------------------------------------------------------

def block_encode(message: Sequence[int]) -> List[int]:
    """Encode a 10-symbol message into a 13-symbol codeword."""
    if len(message) != BLOCK_K:
        raise ValueError(f"message must be {BLOCK_K} symbols")
    if any((s < 0 or s >= F.Q) for s in message):
        raise ValueError("symbols must be in F_13")

    # Polynomial that interpolates (0, m_0), ..., (9, m_9).
    coeffs = _lagrange_interpolate(list(range(BLOCK_K)), list(message))
    return [_eval_poly(coeffs, x) for x in EVAL_POINTS]


def block_decode(codeword: Sequence[int],
                 erasures: Optional[Iterable[int]] = None) -> List[int]:
    """Decode a 13-symbol codeword back to its 10-symbol message.

    erasures: optional iterable of positions (0..12) flagged as unreliable.
    Supports both erasure-only (up to 3) and error+erasure decoding.
    With distance d=4 the budget is: 2*t + e <= 3, i.e. at most
    t=1 error + e=1 erasure, or t=0 errors + e=3 erasures.

    The error-correction path uses the PGZ (Peterson-Gorenstein-Zierler)
    algorithm over F_13 to locate and correct up to 1 unknown error.
    """
    if len(codeword) != BLOCK_N:
        raise ValueError(f"codeword must be {BLOCK_N} symbols")

    erased = set(erasures) if erasures is not None else set()
    if any(p < 0 or p >= BLOCK_N for p in erased):
        raise ValueError("erasure positions out of range")
    e = len(erased)

    # First try: erasure-only decode (fast path).
    if e <= BLOCK_D - 1:
        try:
            return _erasure_decode(codeword, erased)
        except ValueError:
            pass  # fall through to error+erasure decode

    # Second try: error+erasure decode.
    # Budget: 2*t + e <= BLOCK_D - 1 = 3.
    # With d=4 the only meaningful t is 1 (t=2 would need e=0 which
    # exceeds d-1).  Try t=1 if e <= 1, or t=0 if e <= 3.
    for t in range(min(2, (BLOCK_D - 1 - e) // 2), -1, -1):
        if 2 * t + e > BLOCK_D - 1:
            continue
        if t == 0:
            try:
                return _erasure_decode(codeword, erased)
            except ValueError:
                continue
        # t >= 1: use PGZ to find error positions.
        try:
            return _error_erasure_decode(codeword, erased, t)
        except ValueError:
            continue

    raise ValueError(
        f"cannot decode: e={e} erasures + unknown errors exceed "
        f"distance d={BLOCK_D}"
    )


def _erasure_decode(codeword: Sequence[int],
                    erased: set[int]) -> List[int]:
    """Pure-erasure decode: interpolate through non-erased positions
    and verify consistency."""
    reliable = [p for p in range(BLOCK_N) if p not in erased]
    if len(reliable) < BLOCK_K:
        raise ValueError("not enough reliable positions")
    pts = reliable[:BLOCK_K]
    vals = [codeword[p] for p in pts]
    coeffs = _lagrange_interpolate(pts, vals)

    for p in reliable[BLOCK_K:]:
        if _eval_poly(coeffs, p) != codeword[p]:
            raise ValueError(
                f"codeword inconsistent at position {p}: residual error"
            )

    return [_eval_poly(coeffs, x) for x in EVAL_POINTS[:BLOCK_K]]


def _syndrome(codeword: Sequence[int]) -> List[int]:
    """Compute the (BLOCK_N - BLOCK_K) = 3 syndrome symbols S_1, S_2, S_3."""
    return [_eval_poly(codeword, F.pow_(F.ALPHA, j))
            for j in range(1, BLOCK_D)]


def _error_erasure_decode(codeword: Sequence[int],
                          erased: set[int],
                          t: int) -> List[int]:
    """Brute-force error+erasure decode over F_13.

    For RS(13,10) with d=4 and small n=13, brute-force is practical:
    try every combination of t unknown error positions among the
    non-erased carriers, treat them all as erasures, decode, and
    verify that the result re-encodes to match the received codeword
    at ALL non-erased, non-error positions.
    """
    from itertools import combinations

    non_erased = [p for p in range(BLOCK_N) if p not in erased]
    # Try t=1 then t=2 etc. For d=4 only t=1 is realistic.
    for actual_t in range(1, t + 1):
        if 2 * actual_t + len(erased) > BLOCK_D - 1:
            continue
        for error_positions in combinations(non_erased, actual_t):
            combined = erased | set(error_positions)
            if len(combined) > BLOCK_D - 1:
                continue
            try:
                result = _erasure_decode(list(codeword), combined)
            except ValueError:
                continue
            # Verify: re-encode and check ALL positions NOT in combined.
            re_encoded = block_encode(result)
            # Positions not in combined must match the received codeword.
            ok = True
            for p in range(BLOCK_N):
                if p in combined:
                    continue
                if re_encoded[p] != codeword[p]:
                    ok = False
                    break
            if ok:
                return result
    raise ValueError("PGZ error+erasure decode failed: no consistent candidate")


def is_block_codeword(codeword: Sequence[int]) -> bool:
    """Theorem 2 test for a single 13-symbol block.

    A vector lies in the RS(13, 10) code iff the polynomial interpolating
    its first 10 entries (degree < 10) also matches its last 3 entries.
    """
    if len(codeword) != BLOCK_N:
        return False
    if any((s < 0 or s >= F.Q) for s in codeword):
        return False
    coeffs = _lagrange_interpolate(list(range(BLOCK_K)),
                                   list(codeword[:BLOCK_K]))
    return all(_eval_poly(coeffs, p) == codeword[p]
               for p in range(BLOCK_K, BLOCK_N))


# ---------------------------------------------------------------------------
# Full 91-symbol interleaved code
# ---------------------------------------------------------------------------

def encode(message: Sequence[int]) -> List[int]:
    """Encode 70 message symbols into a 91-symbol interleaved codeword.

    Layout: block b stores its codeword c_b at positions
        i * NUM_BLOCKS + b   for i in 0..12.
    This interleaving spreads any local burst across all 7 blocks.
    """
    if len(message) != TOTAL_K:
        raise ValueError(f"message must be {TOTAL_K} symbols")

    blocks = [block_encode(message[b * BLOCK_K:(b + 1) * BLOCK_K])
              for b in range(NUM_BLOCKS)]
    interleaved = [0] * TOTAL_N
    for b in range(NUM_BLOCKS):
        for i in range(BLOCK_N):
            interleaved[i * NUM_BLOCKS + b] = blocks[b][i]
    return interleaved


def decode(codeword: Sequence[int],
           erasures: Optional[Iterable[int]] = None) -> List[int]:
    """Decode 91 symbols (possibly with erasures) back to 70 message symbols.

    Uses an iterative strategy per block:
      1. Try decode with no erasures (PGZ corrects up to t=1 error).
      2. If that fails, try with erasures (up to 3 per block).
      3. If that fails, progressively add the worst-confidence positions
         as erasures and retry with t=0 (pure erasure decode).
    """
    if len(codeword) != TOTAL_N:
        raise ValueError(f"codeword must be {TOTAL_N} symbols")
    erased_global = set(erasures) if erasures is not None else set()

    message: List[int] = []
    for b in range(NUM_BLOCKS):
        block = [codeword[i * NUM_BLOCKS + b] for i in range(BLOCK_N)]
        block_erasures = {
            i for i in range(BLOCK_N)
            if (i * NUM_BLOCKS + b) in erased_global
        }
        msg = block_decode_iterative(block, block_erasures)
        message.extend(msg)
    return message


def block_decode_iterative(codeword: Sequence[int],
                           erasures: Optional[set[int]] = None) -> List[int]:
    """Iterative block decoder that tries progressively more aggressive
    strategies until one succeeds.

    Strategy order:
      1. Pure error correction (no erasures) - handles up to t=1.
      2. Declared erasures only - handles e<=3 with no unknown errors.
      3. Declared erasures + PGZ t=1 - handles e<=1 + t=1.
      4. If still failing, progressively treat the worst-offending
         non-erased positions as erasures (up to budget).
    """
    erased = set(erasures) if erasures is not None else set()
    e = len(erased)

    # Strategy 1: pure error correction, no erasures.
    if e == 0:
        try:
            return _error_erasure_decode(codeword, set(), t=1)
        except ValueError:
            pass

    # Strategy 2: erasure-only decode (up to 3 erasures).
    if e <= BLOCK_D - 1:
        try:
            return _erasure_decode(codeword, erased)
        except ValueError:
            pass

    # Strategy 3: erasure + error (e<=1, t=1).
    if e <= 1:
        try:
            return _error_erasure_decode(codeword, erased, t=1)
        except ValueError:
            pass

    # Strategy 4: too many declared erasures, or residual errors remain.
    # Try progressive relaxation: keep only the most-confident erasures
    # and let PGZ handle the rest as errors.
    # Also try ignoring ALL erasures and using pure error correction.
    try:
        return _error_erasure_decode(codeword, set(), t=1)
    except ValueError:
        pass

    # If e > 3: trim to top-3 erasures (by distance, which we don't have
    # here, so just keep the first 3) and retry.
    if e > BLOCK_D - 1:
        trimmed = set(list(erased)[:BLOCK_D - 1])
        try:
            return _erasure_decode(codeword, trimmed)
        except ValueError:
            pass
        try:
            return _error_erasure_decode(codeword, set(), t=1)
        except ValueError:
            pass

    raise ValueError(
        f"iterative decode failed: e={e} erasures, all strategies exhausted"
    )


def is_in_code(codeword: Sequence[int]) -> bool:
    """Theorem 2 test for the full 91-symbol vector.

    True iff every interleaved RS(13, 10) block lies in its block code.
    Probability for a uniformly random F_13^91 vector: 13^-21 ~= 2^-77.8.
    """
    if len(codeword) != TOTAL_N:
        return False
    for b in range(NUM_BLOCKS):
        block = [codeword[i * NUM_BLOCKS + b] for i in range(BLOCK_N)]
        if not is_block_codeword(block):
            return False
    return True

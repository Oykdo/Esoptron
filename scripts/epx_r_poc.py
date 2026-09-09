#!/usr/bin/env python3
"""EPX-R proof-of-concept — runic-plate blocked/interleaved Reed-Solomon.

Validates the EPX-R spec (docs/specs/EPX-R_runic_plate.md) by simulation:

  * encode_private(blob)  -> B interleaved RS[255,169,87]/GF(2^8) blocks
                             -> F_16 rune-cell grid (M x M of nibble values)
  * decode_private(grid)  -> byte-exact round-trip
  * is_in_code(block)     -> per-block syndrome test (H.c == 0)
  * robustness bench      -> scratch / corner-tear / blot masks, WITH vs
                             WITHOUT interleaving, measured recoverable %
                             against the Theorem-2 ceiling (d-1)/n = 33.7%.

Pure stdlib + numpy. The AEAD seal is orthogonal to the channel and is
out of scope here (this proves the *code*, not the cipher).
"""

from __future__ import annotations

import itertools
import struct
import time
import zlib
import numpy as np

# --------------------------------------------------------------------------- #
# GF(2^8), primitive polynomial 0x11D (the QR/Aztec field)
# --------------------------------------------------------------------------- #
PRIM = 0x11D
_exp = [0] * 512
_log = [0] * 256
_x = 1
for _i in range(255):
    _exp[_i] = _x
    _log[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= PRIM
for _i in range(255, 512):
    _exp[_i] = _exp[_i - 255]

EXP = np.array(_exp, dtype=np.int32)
LOG = np.array(_log, dtype=np.int32)


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _exp[_log[a] + _log[b]]


def gf_pow(a: int, p: int) -> int:
    if a == 0:
        return 1 if p == 0 else 0
    return _exp[(_log[a] * p) % 255]


def gf_inv(a: int) -> int:
    return _exp[255 - _log[a]]


def gf_mul_vec(scalar: int, vec: np.ndarray) -> np.ndarray:
    """Vectorised scalar * vector over GF(2^8) (vec uint8 -> uint8)."""
    out = np.zeros_like(vec)
    if scalar == 0:
        return out
    nz = vec != 0
    out[nz] = EXP[(LOG[scalar] + LOG[vec[nz]]) % 255]
    return out


def gf_solve(A, b):
    """Solve A x = b over GF(2^8) by Gaussian elimination (A: e x e)."""
    e = len(b)
    M = [list(A[i]) + [b[i]] for i in range(e)]
    for col in range(e):
        piv = next((r for r in range(col, e) if M[r][col] != 0), None)
        if piv is None:
            raise ValueError("singular")
        M[col], M[piv] = M[piv], M[col]
        inv = gf_inv(M[col][col])
        M[col] = [gf_mul(v, inv) for v in M[col]]
        for r in range(e):
            if r != col and M[r][col] != 0:
                f = M[r][col]
                M[r] = [M[r][c] ^ gf_mul(f, M[col][c]) for c in range(e + 1)]
    return [M[i][e] for i in range(e)]


# --------------------------------------------------------------------------- #
# Reed-Solomon [n, k] over GF(2^8), generator roots a^0 .. a^(nsym-1)
# --------------------------------------------------------------------------- #
class RS:
    def __init__(self, n: int = 255, k: int = 169):
        assert n <= 255
        self.n, self.k, self.nsym = n, k, n - k
        g = [1]
        for i in range(self.nsym):
            g = self._poly_mul(g, [1, gf_pow(2, i)])
        self.gen = g  # length nsym+1, gen[0]=1

    @staticmethod
    def _poly_mul(p, q):
        r = [0] * (len(p) + len(q) - 1)
        for i, pi in enumerate(p):
            if pi:
                for j, qj in enumerate(q):
                    r[i + j] ^= gf_mul(pi, qj)
        return r

    # ---- vectorised systematic encode of B blocks at once -------------- #
    def encode_blocks(self, msgs: np.ndarray) -> np.ndarray:
        """msgs: uint8 [B, k] -> codewords uint8 [B, n] (systematic)."""
        B = msgs.shape[0]
        out = np.zeros((B, self.n), dtype=np.uint8)
        out[:, : self.k] = msgs
        gen = self.gen
        for i in range(self.k):
            coef = out[:, i].copy()
            for j in range(1, self.nsym + 1):
                out[:, i + j] ^= gf_mul_vec(gen[j], coef)
        out[:, : self.k] = msgs  # restore systematic part (out[k:] = parity)
        return out

    # ---- single-codeword helpers --------------------------------------- #
    def _eval(self, cw, x: int) -> int:
        acc = 0
        for v in cw:
            acc = gf_mul(acc, x) ^ int(v)
        return acc

    def syndromes(self, cw):
        return [self._eval(cw, gf_pow(2, j)) for j in range(self.nsym)]

    def is_in_code(self, cw) -> bool:
        return all(s == 0 for s in self.syndromes(cw))

    def decode_erasures(self, cw, erased):
        """Recover a codeword given known erasure positions.

        Solvable iff len(erased) <= nsym (Theorem 2). Returns the repaired
        codeword; raises if the per-block budget is exceeded.
        """
        e = len(erased)
        if e == 0:
            return cw
        if e > self.nsym:
            raise ValueError("erasures exceed d-1 budget")
        recv = list(cw)
        for p in erased:
            recv[p] = 0
        # Only the nsym root-syndromes (j < nsym) isolate the erasure sum:
        #   S_j = sum_{p in E} c_p * (a^{n-1-p})^j  ,  j = 0..e-1
        S = [self._eval(recv, gf_pow(2, j)) for j in range(e)]
        nodes = [gf_pow(2, (self.n - 1 - p) % 255) for p in erased]
        V = [[gf_pow(nodes[t], j) for t in range(e)] for j in range(e)]
        x = gf_solve(V, S)
        out = list(cw)
        for t, p in enumerate(erased):
            out[p] = x[t]
        return out

    # ---- WP-2: full errors-and-erasures decode (2t + e <= d-1) ---------- #
    def decode(self, received, erased=None):
        erased = list(erased) if erased else []
        return rs_correct_msg(list(received), self.nsym, erased)


# --------------------------------------------------------------------------- #
# WP-2 — errors-and-erasures Reed-Solomon decode (Berlekamp-Massey + Forney)
# Ported from the public-domain "Reed-Solomon for coders" reference, adapted to
# this module's GF and big-endian (coef[0] = highest power) convention.
# --------------------------------------------------------------------------- #
class ReedSolomonError(Exception):
    pass


def gf_div(a, b):
    return gf_mul(a, gf_inv(b))


def gf_poly_mul(p, q):
    r = [0] * (len(p) + len(q) - 1)
    for j in range(len(q)):
        for i in range(len(p)):
            r[i + j] ^= gf_mul(p[i], q[j])
    return r


def gf_poly_add(p, q):
    r = [0] * max(len(p), len(q))
    for i in range(len(p)):
        r[i + len(r) - len(p)] = p[i]
    for i in range(len(q)):
        r[i + len(r) - len(q)] ^= q[i]
    return r


def gf_poly_scale(p, x):
    return [gf_mul(c, x) for c in p]


def gf_poly_eval(p, x):
    y = p[0]
    for i in range(1, len(p)):
        y = gf_mul(y, x) ^ p[i]
    return y


def gf_poly_div(dividend, divisor):
    out = list(dividend)
    for i in range(len(dividend) - (len(divisor) - 1)):
        coef = out[i]
        if coef != 0:
            for j in range(1, len(divisor)):
                if divisor[j] != 0:
                    out[i + j] ^= gf_mul(divisor[j], coef)
    sep = -(len(divisor) - 1)
    return out[:sep], out[sep:]


def rs_calc_syndromes(msg, nsym):
    return [0] + [gf_poly_eval(msg, gf_pow(2, i)) for i in range(nsym)]


def rs_find_errata_locator(e_pos):
    e_loc = [1]
    for i in e_pos:
        e_loc = gf_poly_mul(e_loc, gf_poly_add([1], [gf_pow(2, i), 0]))
    return e_loc


def rs_find_error_evaluator(synd, err_loc, nsym):
    _, rem = gf_poly_div(gf_poly_mul(synd, err_loc), [1] + [0] * (nsym + 1))
    return rem


def rs_correct_errata(msg_in, synd, err_pos):
    coef_pos = [len(msg_in) - 1 - p for p in err_pos]
    err_loc = rs_find_errata_locator(coef_pos)
    err_eval = rs_find_error_evaluator(synd[::-1], err_loc, len(err_loc) - 1)[::-1]
    X = [gf_pow(2, -(255 - cp)) for cp in coef_pos]
    E = [0] * len(msg_in)
    for i, Xi in enumerate(X):
        Xi_inv = gf_inv(Xi)
        prime = 1
        for j in range(len(X)):
            if j != i:
                prime = gf_mul(prime, 1 ^ gf_mul(Xi_inv, X[j]))
        y = gf_poly_eval(err_eval[::-1], Xi_inv)
        y = gf_mul(gf_pow(Xi, 1), y)
        if prime == 0:
            raise ReedSolomonError("errata locator derivative is zero")
        E[err_pos[i]] = gf_div(y, prime)
    return gf_poly_add(msg_in, E)


def rs_find_error_locator(synd, nsym, erase_count=0):
    err_loc = [1]
    old_loc = [1]
    synd_shift = len(synd) - nsym if len(synd) > nsym else 0
    for i in range(nsym - erase_count):
        K = i + synd_shift
        delta = synd[K]
        for j in range(1, len(err_loc)):
            delta ^= gf_mul(err_loc[-(j + 1)], synd[K - j])
        old_loc = old_loc + [0]
        if delta != 0:
            if len(old_loc) > len(err_loc):
                new_loc = gf_poly_scale(old_loc, delta)
                old_loc = gf_poly_scale(err_loc, gf_inv(delta))
                err_loc = new_loc
            err_loc = gf_poly_add(err_loc, gf_poly_scale(old_loc, delta))
    err_loc = list(itertools.dropwhile(lambda c: c == 0, err_loc))
    errs = len(err_loc) - 1
    if (errs - erase_count) * 2 + erase_count > nsym:
        raise ReedSolomonError("too many errors to correct")
    return err_loc


def rs_find_errors(err_loc, nmess):
    errs = len(err_loc) - 1
    err_pos = [nmess - 1 - i for i in range(nmess)
               if gf_poly_eval(err_loc, gf_pow(2, i)) == 0]
    if len(err_pos) != errs:
        raise ReedSolomonError("could not locate errors (Chien)")
    return err_pos


def rs_forney_syndromes(synd, pos, nmess):
    erase_rev = [nmess - 1 - p for p in pos]
    fsynd = list(synd[1:])
    for i in range(len(pos)):
        x = gf_pow(2, erase_rev[i])
        for j in range(len(fsynd) - 1):
            fsynd[j] = gf_mul(fsynd[j], x) ^ fsynd[j + 1]
    return fsynd


def rs_correct_msg(msg_out, nsym, erase_pos):
    if len(msg_out) > 255:
        raise ValueError("message too long")
    if len(erase_pos) > nsym:
        raise ReedSolomonError("too many erasures to correct")
    for e in erase_pos:
        msg_out[e] = 0
    synd = rs_calc_syndromes(msg_out, nsym)
    if max(synd) == 0:
        return msg_out
    fsynd = rs_forney_syndromes(synd, erase_pos, len(msg_out))
    err_loc = rs_find_error_locator(fsynd, nsym, erase_count=len(erase_pos))
    err_pos = rs_find_errors(err_loc[::-1], len(msg_out))
    msg_out = rs_correct_errata(msg_out, synd, erase_pos + err_pos)
    if max(rs_calc_syndromes(msg_out, nsym)) > 0:
        raise ReedSolomonError("could not correct message")
    return msg_out


# --------------------------------------------------------------------------- #
# Plate: framing -> blocks -> interleave -> F_16 cell grid
# --------------------------------------------------------------------------- #
MAGIC = b"EPXR"


def _frame(payload: bytes) -> bytes:
    head = MAGIC + struct.pack(">BI", 1, len(payload))
    body = head + payload
    return body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def _unframe(body: bytes) -> bytes:
    crc = struct.unpack(">I", body[-4:])[0]
    if zlib.crc32(body[:-4]) & 0xFFFFFFFF != crc:
        raise ValueError("CRC mismatch")
    assert body[:4] == MAGIC
    (_, ln) = struct.unpack(">BI", body[4:9])
    return body[9 : 9 + ln]


def encode_private(blob: bytes, rs: RS, interleave: bool = True):
    """blob -> (grid MxM of nibbles, meta) ; the runic plate."""
    framed = _frame(blob)
    B = (len(framed) + rs.k - 1) // rs.k
    buf = framed + b"\x00" * (B * rs.k - len(framed))
    msgs = np.frombuffer(buf, dtype=np.uint8).reshape(B, rs.k)
    cw = rs.encode_blocks(msgs)  # [B, n]

    # interleave symbols across blocks (max spread) or lay sequentially
    if interleave:
        stream = cw.T.reshape(-1)          # order: pos-major -> cycles blocks
    else:
        stream = cw.reshape(-1)            # block-major -> contiguous per block
    # each symbol byte -> 2 nibble cells
    cells = np.empty(stream.size * 2, dtype=np.uint8)
    cells[0::2] = stream >> 4
    cells[1::2] = stream & 0x0F
    M = int(np.ceil(np.sqrt(cells.size)))
    grid = np.zeros(M * M, dtype=np.uint8)
    grid[: cells.size] = cells
    meta = dict(B=B, n=rs.n, M=M, ncells=cells.size, interleave=interleave,
                framed_len=len(framed))
    return grid.reshape(M, M), meta


def decode_private(grid: np.ndarray, rs: RS, meta: dict) -> bytes:
    B, n, M = meta["B"], meta["n"], meta["M"]
    erased_mask = meta.get("erased")  # optional MxM bool of erased cells
    cells = grid.reshape(-1)[: meta["ncells"]]
    cell_erased = (
        erased_mask.reshape(-1)[: meta["ncells"]]
        if erased_mask is not None else None
    )
    # nibbles -> symbol bytes ; a symbol is erased if either nibble is erased
    syms = (cells[0::2].astype(np.uint8) << 4) | cells[1::2]
    if cell_erased is not None:
        sym_erased = cell_erased[0::2] | cell_erased[1::2]
    else:
        sym_erased = np.zeros(syms.size, dtype=bool)

    if meta["interleave"]:
        cw = syms.reshape(n, B).T.copy()
        ce = sym_erased.reshape(n, B).T
    else:
        cw = syms.reshape(B, n).copy()
        ce = sym_erased.reshape(B, n)

    out = np.empty((B, rs.k), dtype=np.uint8)
    failed = 0
    for b in range(B):
        erased = np.nonzero(ce[b])[0].tolist()
        blk = cw[b].tolist()
        if not erased and max(rs_calc_syndromes(blk, rs.nsym)) == 0:
            out[b] = cw[b, : rs.k]          # clean block, fast path
            continue
        try:
            rep = rs.decode(blk, erased)    # errors AND erasures (WP-2)
            out[b] = rep[: rs.k]
        except (ReedSolomonError, ValueError):
            failed += 1
            out[b] = cw[b, : rs.k]          # over budget -> will fail CRC
    if failed:
        raise PlateUndecodable(failed, B)
    framed = out.reshape(-1).tobytes()[: meta["framed_len"]]
    return _unframe(framed)


class PlateUndecodable(Exception):
    def __init__(self, failed, total):
        super().__init__(f"{failed}/{total} blocks over budget")
        self.failed, self.total = failed, total


# --------------------------------------------------------------------------- #
# Damage masks on the M x M cell grid (mark cells erased)
# --------------------------------------------------------------------------- #
def mask_scratch(M, frac, rng):
    """Horizontal band(s) covering ~frac of the grid (contiguous burst)."""
    em = np.zeros((M, M), dtype=bool)
    rows = max(1, int(round(frac * M)))
    start = rng.integers(0, max(1, M - rows))
    em[start : start + rows, :] = True
    return em


def mask_corner(M, frac, rng):
    """A corner tear: a square block in a random corner."""
    em = np.zeros((M, M), dtype=bool)
    side = int(round(np.sqrt(frac) * M))
    side = min(M, max(1, side))
    corner = rng.integers(0, 4)
    if corner == 0:
        em[:side, :side] = True
    elif corner == 1:
        em[:side, M - side:] = True
    elif corner == 2:
        em[M - side:, :side] = True
    else:
        em[M - side:, M - side:] = True
    return em


def mask_blots(M, frac, rng, n_blots=6):
    """Several random circular coffee-ring blots totalling ~frac."""
    em = np.zeros((M, M), dtype=bool)
    target = frac * M * M
    yy, xx = np.mgrid[0:M, 0:M]
    placed = 0
    guard = 0
    while placed < target and guard < 200:
        guard += 1
        r = max(1, int(np.sqrt(target / n_blots / np.pi)))
        cy, cx = rng.integers(0, M), rng.integers(0, M)
        disk = (yy - cy) ** 2 + (xx - cx) ** 2 <= r * r
        em |= disk
        placed = em.sum()
    return em


MASKS = {"scratch": mask_scratch, "corner": mask_corner, "blot": mask_blots}


# --------------------------------------------------------------------------- #
# Experiments
# --------------------------------------------------------------------------- #
def self_test(rs: RS):
    rng = np.random.default_rng(1)
    msg = rng.integers(0, 256, size=rs.k, dtype=np.uint8)
    cw = rs.encode_blocks(msg.reshape(1, rs.k))[0].tolist()
    assert rs.is_in_code(cw), "valid codeword failed is_in_code"
    bad = list(cw); bad[0] ^= 1
    assert not rs.is_in_code(bad), "corrupted codeword passed is_in_code"
    # erasures exactly at the budget recover; one over the budget fails
    pos = rng.choice(rs.n, size=rs.nsym, replace=False).tolist()
    dmg = list(cw)
    for p in pos:
        dmg[p] = 0
    rep = rs.decode_erasures(dmg, pos)
    assert rep == cw, "erasure decode at budget failed"
    over = rng.choice(rs.n, size=rs.nsym + 1, replace=False).tolist()
    try:
        rs.decode_erasures([0] * rs.n, over)
        raise AssertionError("decode over budget did not raise")
    except ValueError:
        pass
    print(f"[self-test] OK  RS[{rs.n},{rs.k},{rs.nsym+1}]  "
          f"ceiling (d-1)/n = {rs.nsym/rs.n:.3%}")


def roundtrip(rs: RS, payload: bytes, interleave=True, verify_syndromes=64):
    t0 = time.time()
    grid, meta = encode_private(payload, rs, interleave=interleave)
    t_enc = time.time() - t0
    # is_in_code on a sample of blocks
    cw_stream = (grid.reshape(-1)[: meta["ncells"]])
    syms = (cw_stream[0::2].astype(np.uint8) << 4) | cw_stream[1::2]
    cw = (syms.reshape(meta["n"], meta["B"]).T if interleave
          else syms.reshape(meta["B"], meta["n"]))
    nchk = min(verify_syndromes, meta["B"])
    ok = all(rs.is_in_code(cw[b].tolist()) for b in range(nchk))
    t0 = time.time()
    out = decode_private(grid, rs, meta)
    t_dec = time.time() - t0
    exact = out == payload
    print(f"  payload={len(payload):>9,d}B  B={meta['B']:>5d}  "
          f"M={meta['M']:>5d} ({meta['M']*meta['M']:,d} cells)  "
          f"is_in_code[{nchk}]={'OK' if ok else 'FAIL'}  "
          f"round-trip={'EXACT' if exact else 'MISMATCH'}  "
          f"enc={t_enc:.2f}s dec={t_dec:.2f}s")
    return exact and ok


def bench(rs: RS, B=160, trials=3):
    rng = np.random.default_rng(7)
    payload = rng.integers(0, 256, size=B * rs.k - 16, dtype=np.uint8).tobytes()
    levels = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.33, 0.36, 0.40]
    ceil = rs.nsym / rs.n
    print(f"\n[bench] B={B}  ceiling (d-1)/n = {ceil:.1%}   "
          f"(recoverable cell-damage %, success over {trials} trials)")
    header = "  damage% |" + "".join(f" {m:^17s}|" for m in MASKS)
    print(header)
    print("          |" + "".join(
        f" {'interlv':>7s} {'seq':>7s} |" for _ in MASKS))
    for frac in levels:
        row = f"  {frac*100:5.0f}%  |"
        for mname, mfn in MASKS.items():
            res = {}
            for il in (True, False):
                grid, meta = encode_private(payload, rs, interleave=il)
                ok = 0
                for tr in range(trials):
                    em = mfn(meta["M"], frac, np.random.default_rng(100 + tr))
                    meta2 = dict(meta); meta2["erased"] = em
                    try:
                        out = decode_private(grid, rs, meta2)
                        ok += int(out == payload)
                    except PlateUndecodable:
                        pass
                res[il] = ok
            row += f" {res[True]:>3d}/{trials:<3d} {res[False]:>3d}/{trials:<3d} |"
        print(row)
    print(f"  -> interleaving holds recovery up to ~{ceil:.0%} for contiguous "
          f"damage; sequential collapses far earlier.")


def test_full_decoder(rs: RS, trials=300):
    """Random errors+erasures within 2t+e <= nsym must recover exactly."""
    rng = np.random.default_rng(3)
    ok = 0
    for _ in range(trials):
        msg = rng.integers(0, 256, size=rs.k, dtype=np.uint8)
        cw = rs.encode_blocks(msg.reshape(1, rs.k))[0].tolist()
        e = int(rng.integers(0, rs.nsym + 1))
        t = int(rng.integers(0, (rs.nsym - e) // 2 + 1))
        pos = rng.choice(rs.n, size=e + t, replace=False).tolist()
        er, errp = pos[:e], pos[e:]
        rec = list(cw)
        for p in er:
            rec[p] = int(rng.integers(0, 256))
        for p in errp:
            v = int(rng.integers(0, 256))
            while v == rec[p]:
                v = int(rng.integers(0, 256))
            rec[p] = v
        try:
            if rs.decode(rec, er) == cw:
                ok += 1
        except ReedSolomonError:
            pass
    print(f"[full-decoder] {ok}/{trials} random (2t+e<=d-1) cases recovered "
          f"{'OK' if ok == trials else 'FAIL'}")


def bench_a4(rs: RS, trials=40):
    """A4: erasures (known positions) recover ~2x more than errors."""
    rng = np.random.default_rng(5)
    msg = rng.integers(0, 256, size=rs.k, dtype=np.uint8)
    cw = rs.encode_blocks(msg.reshape(1, rs.k))[0].tolist()
    print(f"\n[A4] erasure leverage  (n={rs.n}, k={rs.k}, d-1={rs.nsym}; "
          f"errors need 2t<=d-1 -> t<={rs.nsym//2})")
    print("  corrupted/block | as ERASURES (pos known) | as ERRORS (pos unknown)")
    for m in [40, 43, 44, 60, 80, 86, 87]:
        er_ok = err_ok = 0
        for _ in range(trials):
            pos = rng.choice(rs.n, size=m, replace=False).tolist()
            rec = list(cw)
            for p in pos:
                v = int(rng.integers(0, 256))
                while v == rec[p]:
                    v = int(rng.integers(0, 256))
                rec[p] = v
            try:
                if rs.decode(rec, pos) == cw:
                    er_ok += 1
            except ReedSolomonError:
                pass
            try:
                if rs.decode(rec, []) == cw:
                    err_ok += 1
            except ReedSolomonError:
                pass
        print(f"  {m:>15d} | {er_ok:>3d}/{trials:<3d} {'OK' if er_ok==trials else '--':<6s}"
              f"        | {err_ok:>3d}/{trials:<3d} {'OK' if err_ok==trials else '--'}")
    print(f"  -> erasures recover to ~{rs.nsym}; errors to ~{rs.nsym//2}  =>  ~2x (A4).")


if __name__ == "__main__":
    rs = RS(255, 169)               # [255,169,87], rate 0.663
    self_test(rs)
    test_full_decoder(rs)
    bench_a4(rs)
    print("\n[round-trip 1 Mbit]")
    rng = np.random.default_rng(42)
    roundtrip(rs, rng.integers(0, 256, size=125_000, dtype=np.uint8).tobytes())

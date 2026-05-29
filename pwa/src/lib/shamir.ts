/**
 * Shamir secret sharing over GF(2^8) with the Rijndael polynomial 0x11B.
 *
 * Pure TypeScript port of ``eopx.format.shamir`` — same log/antilog
 * tables, same polynomial encoding, same Lagrange reconstruction. The
 * randomness for split() comes from ``crypto.getRandomValues``.
 *
 * Split with ``split(secret, k, n)`` always returns indices ``1..n``;
 * combine with ``combine(shares)`` reconstructs the secret if at least
 * ``k`` distinct shares are supplied. Fewer than ``k`` shares produce
 * garbage — pair this with the AEAD layer in ``recovery.ts`` to detect
 * insufficient input.
 */

export type Share = { index: number; bytes: Uint8Array };

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

function mulNaive(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

(function initTables() {
  const g = 0x03;
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x = mulNaive(x, g);
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

export function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

export function gfInv(a: number): number {
  if (a === 0) throw new Error("0 has no inverse in GF(2^8)");
  return EXP[255 - LOG[a]];
}

export function gfDiv(a: number, b: number): number {
  if (a === 0) return 0;
  if (b === 0) throw new Error("division by zero in GF(2^8)");
  // (LOG[a] - LOG[b]) mod 255 — handle the negative branch like Python's %
  let d = LOG[a] - LOG[b];
  if (d < 0) d += 255;
  return EXP[d];
}

function evalPoly(coeffs: ArrayLike<number>, x: number): number {
  let acc = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    acc = gfMul(acc, x) ^ coeffs[i];
  }
  return acc & 0xff;
}

/**
 * Split a secret into ``n`` shares; any ``k`` recover it.
 *
 * The optional ``randomCoeff`` lets test code inject deterministic
 * coefficients (used to verify parity against pre-computed Python
 * vectors). Production callers must leave it undefined.
 */
export function split(
  secret: Uint8Array,
  k: number,
  n: number,
  randomCoeff?: (pos: number, j: number) => number,
): Share[] {
  if (!(secret instanceof Uint8Array) || secret.length === 0)
    throw new Error("secret must be non-empty bytes");
  if (!(1 <= k && k <= n)) throw new Error(`need 1 <= k <= n, got k=${k}, n=${n}`);
  if (n > 255) throw new Error("n must be <= 255 for GF(2^8) Shamir");

  const L = secret.length;
  const shares: Uint8Array[] = [];
  for (let i = 0; i < n; i++) shares.push(new Uint8Array(L));

  const randBuf = randomCoeff ? null : new Uint8Array(k - 1);
  for (let pos = 0; pos < L; pos++) {
    if (randBuf) crypto.getRandomValues(randBuf);
    const coeffs = new Uint8Array(k);
    coeffs[0] = secret[pos];
    for (let j = 1; j < k; j++) {
      coeffs[j] = randomCoeff
        ? randomCoeff(pos, j) & 0xff
        : (randBuf as Uint8Array)[j - 1];
    }
    for (let i = 1; i <= n; i++) {
      shares[i - 1][pos] = evalPoly(coeffs, i);
    }
  }
  return shares.map((b, i) => ({ index: i + 1, bytes: b }));
}

/** Lagrange-interpolate the secret from ``shares.length`` shares at x=0. */
export function combine(shares: Share[]): Uint8Array {
  if (shares.length === 0)
    throw new Error("at least one share is required");
  const L = shares[0].bytes.length;
  const indices = shares.map((s) => s.index);
  if (new Set(indices).size !== indices.length)
    throw new Error("share indices must be distinct");
  if (indices.some((i) => i < 1 || i > 255))
    throw new Error("share indices must lie in 1..255");
  if (shares.some((s) => s.bytes.length !== L))
    throw new Error("all shares must have equal length");

  const coeffs0: number[] = [];
  for (let i = 0; i < indices.length; i++) {
    const xi = indices[i];
    let num = 1;
    let den = 1;
    for (let j = 0; j < indices.length; j++) {
      if (j === i) continue;
      const xj = indices[j];
      num = gfMul(num, xj);
      den = gfMul(den, xi ^ xj);
    }
    coeffs0.push(gfDiv(num, den));
  }

  const out = new Uint8Array(L);
  for (let pos = 0; pos < L; pos++) {
    let acc = 0;
    for (let i = 0; i < shares.length; i++) {
      acc ^= gfMul(shares[i].bytes[pos], coeffs0[i]);
    }
    out[pos] = acc;
  }
  return out;
}

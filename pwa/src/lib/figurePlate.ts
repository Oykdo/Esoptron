/**
 * EPX-F §6 — TypeScript port of ``eopx.figure_plate``.
 *
 * Everything here *reads* a grid, never defines one. The grid and its digest
 * live in {@link ./artifactFigure} and do not know this module exists: swapping
 * a ramp, framing a plate or animating a display changes what a person sees and
 * nothing a verifier checks.
 *
 * One guard is deliberate and load-bearing. A **frozen** plate is drawn with a
 * solid frame and prints its tag, because the tag is exactly what a reader may
 * compare against a recomputation. A **living** plate — one whose cells drift
 * with ledger state — is drawn with a dashed frame and **prints no tag at all**.
 * A moving face must never be mistakable for the artifact's identity, and the
 * cheapest way to guarantee that is to make it impossible to compare.
 */

import { sha3_256_ } from "./crypto";
import {
  ASCII_RAMP,
  GRID_H,
  GRID_W,
  LEVELS,
  figureTag,
  renderRows,
} from "./artifactFigure";

/**
 * Block-element ramp, ordered by ink coverage. Ties are broken by *shape*
 * rather than weight, which gives the face texture instead of a flat gradient.
 *
 * Perceptual, not metric: terminals disagree on the exact rendering of these
 * code points, and several are East-Asian *ambiguous* width. Use
 * {@link ASCII_RAMP} when byte-exact column alignment matters more than looks.
 */
export const UNICODE_RAMP = " ░▖▗▘▝▒▚▞▌▐▀▄▓▉█";

/** Max cells a living rendering may perturb. The drift is a hint for the eye;
 *  it is not part of the artifact's face and never enters a digest. */
export const LIVING_CELL_CAP = 5;

type Frame = readonly [string, string, string, string, string, string, string, string];

/** corners, edges, and the tees that separate the grid from its caption */
const FRAMES: Record<string, Frame> = {
  solid: ["┌", "┐", "└", "┘", "─", "│", "├", "┤"],
  dashed: ["┌", "┐", "└", "┘", "╌", "╎", "├", "┤"],
  ascii: ["+", "+", "+", "+", "-", "|", "+", "+"],
};

/** Code-point length, so a ramp of astral glyphs still measures as one per
 *  cell — the same unit Python's ``len(str)`` uses for these strings. */
function width(s: string): number {
  return Array.from(s).length;
}

/**
 * Centre ``s`` in ``w`` columns, matching CPython's ``str.center`` exactly.
 *
 * CPython does not split the padding naively: it adds one extra column on the
 * **left** when the margin and the target width are both odd
 * (``left = marg // 2 + (marg & width & 1)``), so ``"ab".center(5)`` is
 * ``"  ab "`` and not ``" ab  "``. A port that halves the margin agrees with
 * Python on every even case and drifts by one column on the odd ones — which
 * is exactly the kind of difference that survives review and then makes two
 * plates of the same artifact look subtly unlike each other.
 */
function center(s: string, w: number): string {
  const n = width(s);
  if (n >= w) return s;
  const marg = w - n;
  const left = Math.floor(marg / 2) + (marg & w & 1);
  return " ".repeat(left) + s + " ".repeat(marg - left);
}

function frame(rows: string[], style: string, caption: string[]): string {
  const [tl, tr, bl, br, h, v, ml, mr] = FRAMES[style];
  const w = Math.max(...rows.map(width), ...caption.map(width));
  const out: string[] = [tl + h.repeat(w + 2) + tr];
  // The grid is centred rather than left-aligned: a long caption widens the
  // frame, and a figure pinned to the left edge of that frame reads as a
  // layout accident.
  for (const r of rows) out.push(`${v} ${center(r, w)} ${v}`);
  if (caption.length > 0) {
    out.push(ml + h.repeat(w + 2) + mr);
    for (const c of caption) out.push(`${v} ${center(c, w)} ${v}`);
  }
  out.push(bl + h.repeat(w + 2) + br);
  return out.join("\n");
}

function epochLine(epoch: string, tag: string): string {
  if (epoch && tag) return `epoch ${epoch} · ${tag}`;
  if (tag) return tag;
  return epoch ? `epoch ${epoch}` : "";
}

export interface PlateOptions {
  title?: string;
  epoch?: string;
  ramp?: string;
  asciiFrame?: boolean;
}

/**
 * The artifact's frozen face, framed, with its tag printed underneath.
 *
 * The tag is the whole point of the caption: a reader recomputes
 * ``F(merkle_root, dilithium_pk_fp)`` from the `.eopx` and compares those eight
 * characters. Looking at the picture proves nothing.
 */
export function plate(
  grid: ReadonlyArray<ReadonlyArray<number>>,
  opts: PlateOptions = {},
): string {
  const { title = "", epoch = "", ramp = UNICODE_RAMP, asciiFrame = false } = opts;
  const rows = renderRows(grid, ramp);
  const caption = [title, epochLine(epoch, figureTag(grid))].filter((c) => c !== "");
  return frame(rows, asciiFrame ? "ascii" : "solid", caption);
}

/**
 * ``grid`` with at most ``min(activity, cap)`` cells perturbed by state.
 *
 * Deterministic in ``stateBytes``, so two viewers of the same ledger state see
 * the same shimmer. The result is **not** the artifact's face: it has no tag,
 * and feeding it to ``figureDigest`` is a category error.
 */
export function livingRows(
  grid: ReadonlyArray<ReadonlyArray<number>>,
  stateBytes: Uint8Array,
  activity: number,
  cap: number = LIVING_CELL_CAP,
): number[][] {
  const out = grid.map((row) => [...row]);
  const n = Math.min(cap, Math.max(0, activity));
  if (n === 0) return out;
  const tail = sha3_256_(stateBytes);
  const cells = GRID_W * GRID_H;
  for (let k = 0; k < n; k += 1) {
    const idx = tail[k] % cells;
    out[Math.floor(idx / GRID_W)][idx % GRID_W] = tail[k + 8] % LEVELS;
  }
  return out;
}

export interface LivingPlateOptions extends PlateOptions {
  stateBytes: Uint8Array;
  activity: number;
}

/**
 * The artifact *now*: dashed frame, and deliberately **no tag**.
 *
 * The missing tag is the safety property, not an omission — there is nothing
 * here a reader could mistake for something to compare.
 */
export function livingPlate(
  grid: ReadonlyArray<ReadonlyArray<number>>,
  opts: LivingPlateOptions,
): string {
  const {
    stateBytes,
    activity,
    title = "",
    epoch = "",
    ramp = UNICODE_RAMP,
    asciiFrame = false,
  } = opts;
  const rows = renderRows(livingRows(grid, stateBytes, activity), ramp);
  const caption = [title, epoch ? `epoch ${epoch} · living` : "living"].filter(
    (c) => c !== "",
  );
  return frame(rows, asciiFrame ? "ascii" : "dashed", caption);
}

/**
 * ``count`` successive living renderings, for an animated display.
 *
 * Frame *i* is driven by ``stateBytes`` plus the frame index, so the whole
 * sequence is reproducible from the same ledger state — an animation, not a
 * random walk. Frames live entirely outside the signature envelope: a moving
 * face changes pixels, and ``image_sha3_512`` covers pixels.
 */
export function frames(
  grid: ReadonlyArray<ReadonlyArray<number>>,
  stateBytes: Uint8Array,
  count: number = 8,
  activity: number = LIVING_CELL_CAP,
  ramp: string = UNICODE_RAMP,
): string[][] {
  const out: string[][] = [];
  for (let i = 0; i < count; i += 1) {
    const suffix = new Uint8Array(4);
    new DataView(suffix.buffer).setUint32(0, i, false); // big-endian, as Python
    const seed = new Uint8Array(stateBytes.length + 4);
    seed.set(stateBytes, 0);
    seed.set(suffix, stateBytes.length);
    out.push(renderRows(livingRows(grid, seed, activity), ramp));
  }
  return out;
}

/**
 * Lay finished plates side by side, top-aligned, padded to equal height.
 *
 * Column alignment is computed in code points. With {@link UNICODE_RAMP} in a
 * terminal that renders block elements as double-width, the columns will drift
 * — pass ``asciiFrame`` and {@link ASCII_RAMP} to {@link plate} when alignment
 * must be exact.
 */
export function gallery(plates: ReadonlyArray<string>, gap: number = 2): string {
  if (plates.length === 0) return "";
  const blocks = plates.map((p) => p.split("\n"));
  const height = Math.max(...blocks.map((b) => b.length));
  const padded = blocks.map((block) => {
    const w = Math.max(...block.map(width));
    const lines = block.map((line) => line + " ".repeat(w - width(line)));
    while (lines.length < height) lines.push(" ".repeat(w));
    return lines;
  });
  const sep = " ".repeat(gap);
  const out: string[] = [];
  for (let i = 0; i < height; i += 1) out.push(padded.map((col) => col[i]).join(sep));
  return out.join("\n");
}

/**
 * ``[columns, rows]`` a framed plate occupies — for laying out a page.
 *
 * The caption widens the frame when it is longer than the grid, so the caption
 * has to be part of the question. Code points, not display columns.
 */
export function plateSize(
  title: string = "",
  epoch: string = "",
  tag: string = "",
): [number, number] {
  const caption = [title, epochLine(epoch, tag)].filter((c) => c !== "");
  const w = Math.max(GRID_W, ...caption.map(width)) + 4;
  const h = GRID_H + 2 + (caption.length > 0 ? caption.length + 1 : 0);
  return [w, h];
}

/** Return why ``ramp`` is unusable, or ``null`` if it is fine. */
export function checkRamp(ramp: string): string | null {
  const glyphs = Array.from(ramp);
  if (glyphs.length !== LEVELS) {
    return `ramp must have exactly ${LEVELS} glyphs, got ${glyphs.length}`;
  }
  if (new Set(glyphs).size !== LEVELS) {
    return "ramp glyphs must be distinct (two levels would look alike)";
  }
  return null;
}

export { ASCII_RAMP };

import { JSX } from "react";

/**
 * Bespoke line glyphs for the twelve Codex relics — one per archetype, in a
 * single minimal stroke style. They inherit `currentColor` (set to the relic's
 * seal colour by `.relic-icon`), so each card tints its own glyph.
 */
const GLYPHS: Record<string, JSX.Element> = {
  // The First Mirror — an oval glass on a stand, with a glint.
  speculum_primum: (
    <>
      <ellipse cx="12" cy="9" rx="6" ry="7" />
      <path d="M9 6a4 5 0 0 1 4-1" opacity="0.55" />
      <path d="M12 16v4M8.5 20h7" />
    </>
  ),
  // The Keystone — a key: ring bow, shaft, teeth.
  clavis: (
    <>
      <circle cx="12" cy="6" r="3" />
      <path d="M12 9v11M12 20h3M12 17h2" />
    </>
  ),
  // The Stolen Ember — a four-point spark.
  scintilla: (
    <path
      d="M12 2l1.6 8.4L22 12l-8.4 1.6L12 22l-1.6-8.4L2 12l8.4-1.6z"
      fill="currentColor"
      stroke="none"
    />
  ),
  // The Tide — twin waves.
  unda: (
    <>
      <path d="M2 13q2.5-4 5 0t5 0 5 0" />
      <path d="M2 17q2.5-4 5 0t5 0 5 0" opacity="0.5" />
    </>
  ),
  // The Loom — a frame, warp threads, a weft bar.
  stamen: (
    <>
      <rect x="5" y="4" width="14" height="16" rx="1" />
      <path d="M9 4v16M12 4v16M15 4v16" opacity="0.55" />
      <path d="M5 12h14" strokeWidth="2" />
    </>
  ),
  // The Lantern — ring, body, base.
  lucerna: (
    <>
      <path d="M10 3h4" />
      <path d="M9 6h6l1 2v8l-1 2H9l-1-2V8z" />
      <path d="M12 9v6" opacity="0.55" />
      <path d="M10 20h4" />
    </>
  ),
  // The Hollow Crown — three points, a band, a jewel.
  corona_cava: (
    <>
      <path d="M4 17l1.5-9L9 13l3-6 3 6 3.5-5L20 17z" />
      <path d="M4 17h16" />
      <circle cx="12" cy="7" r="0.9" fill="currentColor" stroke="none" />
    </>
  ),
  // The Mask — a face with two eyes.
  persona: (
    <>
      <path d="M6 7q6-2 12 0 1 8-6 12Q5 15 6 7z" />
      <circle cx="9.5" cy="11" r="1" fill="currentColor" stroke="none" />
      <circle cx="14.5" cy="11" r="1" fill="currentColor" stroke="none" />
    </>
  ),
  // The Hearth — an arch with a flame.
  focus: (
    <>
      <path d="M5 20v-9a7 7 0 0 1 14 0v9" />
      <path
        d="M12 18c-1.8 0-3-1.3-3-3 0-1.8 1.5-2.3 1.2-4 1.3.8 1.8 1.8 1.8 2.8.8-.4.8-1.3.8-2.2 1 1.3 1.4 2.6 1.4 3.6 0 1.7-1.2 3-3 3z"
        fill="currentColor"
        stroke="none"
      />
    </>
  ),
  // The Threshold — a doorway, inner leaf, knob.
  limen: (
    <>
      <path d="M5 21V10a7 7 0 0 1 14 0v11" />
      <path d="M9 21v-10a3 3 0 0 1 6 0v10" />
      <circle cx="13.5" cy="15" r="0.7" fill="currentColor" stroke="none" />
    </>
  ),
  // The Phoenix — spread wings rising, body, tail.
  phoenix: (
    <>
      <path
        d="M3 13C7 9 9 11 12 7c3 4 5 2 9 6-4-1-6 1-9-2-3 3-5 1-9 2z"
        fill="currentColor"
        stroke="none"
        opacity="0.9"
      />
      <path d="M12 11v6M10 19q2-2 4 0" />
    </>
  ),
  // The Watchword — an inscribed tile.
  tessera: (
    <>
      <rect x="5" y="5" width="14" height="14" rx="2" />
      <path d="M8.5 10h7M8.5 12.5h7M8.5 15h4" opacity="0.7" />
    </>
  ),
};

export function RelicGlyph({ relic }: { relic: string }) {
  const inner = GLYPHS[relic];
  return (
    <svg
      className="relic-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {inner ?? <circle cx="12" cy="12" r="7" />}
    </svg>
  );
}

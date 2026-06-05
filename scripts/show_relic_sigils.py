"""Print the figurative ASCII figure of every Codex relic (or one).

Each relic is drawn as the object it is (mirror, key, ember...), with a
deterministic, fingerprint-derived interior. Brand only, never security.

    py scripts/show_relic_sigils.py                 # all 12
    py scripts/show_relic_sigils.py speculum_primum  # just one
"""

from __future__ import annotations

import sys

from eopx.collection import CODEX, CODEX_BY_KEY, render_relic_figure


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        relic = CODEX_BY_KEY.get(argv[1])
        if relic is None:
            print(f"unknown relic '{argv[1]}'", file=sys.stderr)
            return 2
        relics = [relic]
    else:
        relics = sorted(CODEX, key=lambda r: r.rank)

    for relic in relics:
        print()
        print(f"  #{relic.rank} {relic.name} — {relic.title}")
        for line in render_relic_figure(relic).splitlines():
            print("  " + line)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

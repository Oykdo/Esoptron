#!/usr/bin/env python3
"""Benchmark Argon2id profiles for Esoptron recovery shares.

Helps an operator pick the right ``ESOPTRON_ARGON2_PROFILE`` for the target
device (laptop, phone, low-power tablet).

Usage::

    py scripts/argon2_bench.py
    py scripts/argon2_bench.py --profile mobile
    py scripts/argon2_bench.py --target-ms 5000   # tune for a max latency
"""

from __future__ import annotations

import argparse
import secrets
import sys
import time
from pathlib import Path

# Allow running from a checkout without installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from eopx.recovery import (
    ARGON2_PROFILES,
    _argon2id,
    _argon2_params_for,
)


def bench_once(kind: str, profile: str, *, password_len: int = 8) -> float:
    params = _argon2_params_for(kind, profile)
    password = secrets.token_bytes(password_len)
    salt = secrets.token_bytes(16)
    t0 = time.perf_counter()
    _argon2id(password, salt, **params)
    return (time.perf_counter() - t0) * 1000.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile", choices=sorted(ARGON2_PROFILES), default=None,
        help="benchmark one profile (default: all)",
    )
    parser.add_argument(
        "--repeats", type=int, default=3,
        help="number of timed runs per (profile, kind) pair",
    )
    parser.add_argument(
        "--target-ms", type=float, default=None,
        help="recommend the strongest profile staying under this latency",
    )
    args = parser.parse_args()

    profiles = [args.profile] if args.profile else sorted(ARGON2_PROFILES)
    kinds = ("card_pin", "passphrase")

    print(f"{'profile':<12} {'kind':<12} {'mem':>8} {'t':>4} {'avg_ms':>10}")
    print("-" * 50)
    results: dict[tuple[str, str], float] = {}
    for prof in profiles:
        for kind in kinds:
            params = _argon2_params_for(kind, prof)
            samples = [bench_once(kind, prof) for _ in range(args.repeats)]
            avg = sum(samples) / len(samples)
            results[(prof, kind)] = avg
            mem_mib = params["memory_cost"] // 1024
            print(
                f"{prof:<12} {kind:<12} {mem_mib:>5} MiB "
                f"{params['time_cost']:>4} {avg:>10.1f}"
            )

    if args.target_ms is not None:
        print()
        print(f"Recommendation for target ≤ {args.target_ms:.0f} ms per share:")
        for kind in kinds:
            ok = [
                prof for prof in profiles
                if results[(prof, kind)] <= args.target_ms
            ]
            if not ok:
                print(f"  {kind}: none of the profiles fit; consider tuning.")
            else:
                # Pick the strongest profile that still fits.
                strongest = max(
                    ok, key=lambda p: ARGON2_PROFILES[p][kind]["memory_cost"]
                )
                print(
                    f"  {kind}: {strongest} "
                    f"({results[(strongest, kind)]:.0f} ms)"
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())

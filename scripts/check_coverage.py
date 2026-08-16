#!/usr/bin/env python3
"""Enforce per-file coverage floors against a cargo-llvm-cov JSON export.

# Why this exists rather than `--fail-under-lines`

cargo-llvm-cov can fail a run on a *workspace* threshold, which is the wrong
instrument here. CLAUDE.md Phase 1 sets its bar on one file — "100% branch
coverage on `imt.rs`" — and a workspace average lets that file rot while the
number stays green.

# Why a ratchet rather than the stated 100%

The Phase 1 criterion was never measured when the phase was called done. It is
not met: see PLAN.md. Asserting 100% now would start this job red on day one,
which trains everyone to ignore it. So the floors below are set at the measured
values and can only be raised. Lowering one is a deliberate, reviewable edit,
which is the property that matters.

Usage:
    cargo +nightly llvm-cov --workspace --branch --json --output-path cov.json
    python3 scripts/check_coverage.py cov.json
"""

from __future__ import annotations

import json
import sys

# Measured 2026-08-16 with `cargo +nightly llvm-cov --workspace --branch`.
# Raise when coverage improves; never lower one without saying why in the PR.
#
# Floors sit at the measured value truncated to one decimal. That buffer is
# deliberate: `--branch` instrumentation shifts region counts slightly between
# nightly releases, and a ratchet that fails on third-decimal drift gets
# disabled within a week.
#
# Numbers here are only comparable to a `--branch` run. A stable-toolchain run
# reports different region counts for the same code — measuring hash.rs at
# 99.13% rather than 97.83% — so do not transplant figures between the two.
#
# Keys are repo-relative path suffixes, matched against llvm-cov's absolute
# filenames, so this works regardless of checkout location.
FILE_FLOORS: dict[str, dict[str, float]] = {
    # The load-bearing file. CLAUDE.md Phase 1 wants 100% *branch* coverage
    # here. It is at 41/48. The gap is 7 branches — tracked in PLAN.md, and
    # small enough to close deliberately rather than by drift.
    "crates/zutreexo-accumulator/src/imt.rs": {
        "regions": 96.0,
        "lines": 95.6,
        "branches": 85.4,
    },
    # Deserialization runs on attacker-supplied bytes, so it gets its own floor
    # rather than hiding inside the workspace average. Two upstream defects
    # surfaced here before any fuzzer ran; see docs/design.md D13.
    "crates/zutreexo-accumulator/src/proof.rs": {
        "regions": 96.7,
        "lines": 97.6,
        "branches": 85.0,
    },
    # Block application also runs on attacker-supplied data. The floor is low
    # because the code is new; stage 2b's harness should raise it.
    "crates/zutreexo-chain/src/block_apply.rs": {
        "regions": 89.5,
        "lines": 80.3,
        "branches": 77.2,
    },
    # Domain separation is consensus-critical and cheap to cover fully.
    "crates/zutreexo-accumulator/src/hash.rs": {
        "regions": 97.8,
        "lines": 100.0,
    },
}

WORKSPACE_FLOORS: dict[str, float] = {
    "regions": 94.2,
    "lines": 93.4,
    "branches": 84.8,
}


def percent(summary: dict, key: str) -> float | None:
    """Percentage for one metric, or None when the metric does not apply.

    llvm-cov reports `0/0 = 0.0%` for a file with no branch regions at all,
    which is indistinguishable from "every branch missed" if you only read the
    percentage. Treating that as a failure would flag files that are correct by
    construction, so a zero denominator reads as absent rather than as zero.
    """
    block = summary.get(key)
    if not isinstance(block, dict):
        return None
    if block.get("count") in (0, None):
        return None
    value = block.get("percent")
    return float(value) if isinstance(value, (int, float)) else None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <llvm-cov-export.json>", file=sys.stderr)
        return 2

    try:
        with open(argv[1], encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read coverage export: {exc}", file=sys.stderr)
        return 2

    try:
        data = report["data"][0]
    except (KeyError, IndexError, TypeError):
        print("error: unexpected llvm-cov export shape", file=sys.stderr)
        return 2

    failures: list[str] = []

    # ---- per-file floors ----
    matched: set[str] = set()
    for entry in data.get("files", []):
        filename = entry.get("filename", "")
        summary = entry.get("summary", {})
        for suffix, floors in FILE_FLOORS.items():
            if not filename.endswith(suffix):
                continue
            matched.add(suffix)

            reported = []
            for metric in ("regions", "lines", "functions", "branches"):
                actual = percent(summary, metric)
                if actual is None:
                    reported.append(f"{metric} n/a")
                    continue
                reported.append(f"{metric} {actual:.2f}%")
                floor = floors.get(metric)
                if floor is not None and actual + 1e-9 < floor:
                    failures.append(
                        f"{suffix}: {metric} {actual:.2f}% "
                        f"below floor {floor:.2f}%"
                    )

            # A floor on a metric the file does not report would silently never
            # fire, so say so rather than passing quietly.
            for metric in floors:
                if percent(summary, metric) is None:
                    failures.append(
                        f"{suffix}: floor set on '{metric}', "
                        f"but llvm-cov reports no such data"
                    )

            print(f"  {suffix}: {', '.join(reported)}")

    for suffix in FILE_FLOORS:
        if suffix not in matched:
            # A floor pointing at a file that no longer exists silently stops
            # enforcing anything, which is worse than a loud failure.
            failures.append(f"{suffix}: no coverage data — was the file moved?")

    # ---- workspace floor ----
    totals = data.get("totals", {})
    print("  workspace total:", end=" ")
    parts = []
    for metric in ("regions", "lines", "functions", "branches"):
        actual = percent(totals, metric)
        if actual is None:
            continue
        parts.append(f"{metric} {actual:.2f}%")
        floor = WORKSPACE_FLOORS.get(metric)
        if floor is not None and actual + 1e-9 < floor:
            failures.append(
                f"workspace: {metric} {actual:.2f}% below floor {floor:.2f}%"
            )
    print(", ".join(parts))

    if failures:
        print("\ncoverage floors not met:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print(
            "\nIf this is a deliberate reduction, lower the floor in "
            "scripts/check_coverage.py in the same PR and say why.",
            file=sys.stderr,
        )
        return 1

    print("\nall coverage floors met")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

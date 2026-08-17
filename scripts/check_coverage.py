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

# Always clean first

`llvm-cov` merges every `.profraw` it finds, including ones left by an earlier
build of different code. The output is not obviously wrong — `covered` stays
correct while `notcovered` fills up with regions from binaries that no longer
exist — so it reads as a sudden, catastrophic regression.

Measured locally without cleaning: `imt.rs` 57% (really 96%), `proof.rs` 64%
(really 98%), `utreexo.rs` 52% (really 92%). Believing those numbers would have
meant lowering the floors by forty points and discarding the gate entirely.

The tell is `covered` holding steady while the denominator grows.

Usage:
    cargo llvm-cov clean --workspace
    cargo +nightly llvm-cov --workspace --branch --json --output-path cov.json
    python3 scripts/check_coverage.py cov.json
"""

from __future__ import annotations

import json
import sys

# Measured with `cargo +nightly llvm-cov --workspace --branch`. Raise when
# coverage improves; never lower one without saying why in the PR.
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
#
# These floors describe **what CI can actually measure**, which is not what a
# developer's machine measures. Only `fixtures/nu5-orchard.jsonl` is committed;
# the other three slices are 63 MB and stay gitignored. Every test touching
# zutreexo-chain is gated on a fixture, so a run with more fixtures present
# scores higher — block_apply.rs reads 88.37% here and 90.12% with all four.
#
# Calibrate against the committed fixture only. Raising a floor to a number seen
# locally would fail every CI run, which is how these were wrong to begin with.
FILE_FLOORS: dict[str, dict[str, float]] = {
    # The load-bearing file. CLAUDE.md Phase 1 wants 100% *branch* coverage
    # here; it is at 58/70. Stage 2c raised both the numerator and the
    # denominator by adding `undo_insert`.
    "crates/zutreexo-accumulator/src/imt.rs": {
        "regions": 96.8,
        "lines": 96.4,
        "min_branches": 56,  # measured 58/70
    },
    # Deserialization runs on attacker-supplied bytes, so it gets its own floor
    # rather than hiding inside the workspace average.
    "crates/zutreexo-accumulator/src/proof.rs": {
        "regions": 97.7,
        "lines": 97.9,
        "min_branches": 14,  # measured 16-17/20, varies — see below
    },
    # Domain separation is consensus-critical and cheap to cover fully.
    "crates/zutreexo-accumulator/src/hash.rs": {
        "regions": 99.5,
        "lines": 100.0,
    },
    # Carries the tagged node-hash encoding whose absence corrupted every
    # forest snapshot until stage 2c (docs/design.md D19). Floored so that
    # regression cannot recur unnoticed.
    "crates/zutreexo-accumulator/src/utreexo.rs": {
        "regions": 92.3,
        "lines": 90.5,
    },
    # The three below are the reason the committed fixture exists. Each one
    # measured 0.00% before it, because their only tests are fixture-gated.
    "crates/zutreexo-chain/src/block_apply.rs": {
        "regions": 93.0,
        "lines": 86.1,
        "min_branches": 15,  # measured 17/22
    },
    "crates/zutreexo-chain/src/extract.rs": {
        "regions": 87.4,
        "lines": 88.0,
        "min_branches": 2,  # measured 2/2
    },
    "crates/zutreexo-chain/src/pool.rs": {
        "regions": 83.7,
        "lines": 80.4,
    },
    # Reorg rollback. The invariant it serves is byte-identical state after an
    # unwind, so a silent gap here is the expensive kind.
    "crates/zutreexo-chain/src/rollback.rs": {
        "regions": 92.9,
        "lines": 95.7,
        "min_branches": 27,  # measured 29/32
    },
    # The differential harness and the reorg fuzzer. Test infrastructure, but
    # also the project's primary correctness signal (CLAUDE.md §5 rule 2): a
    # silent regression in either disables what catches everything else.
    "crates/zutreexo-testkit/src/harness.rs": {
        "regions": 80.2,
        "lines": 80.5,
        "min_branches": 32,  # measured 34/52
    },
    "crates/zutreexo-testkit/src/reorg.rs": {
        "regions": 88.7,
        "lines": 85.7,
        "min_branches": 28,  # measured 30/38
    },
    # The oracles themselves. If these rot, every tier built on them weakens
    # without anything going red.
    "crates/zutreexo-testkit/src/state.rs": {
        "regions": 96.6,
        "lines": 93.4,
        "min_branches": 11,  # measured 13/14
    },
    "crates/zutreexo-testkit/src/naive.rs": {
        "regions": 99.2,
        "lines": 99.2,
        "min_branches": 16,  # measured 18/20
    },
    "crates/zutreexo-testkit/src/checkpoints.rs": {
        "regions": 95.4,
        "lines": 97.3,
    },
}

# Measured 93.48 / 92.22 / 80.37 in the CI profile at stage 2c, after
# `cargo llvm-cov clean`. Every per-file figure rose from 2b; the workspace
# total rose with them.
WORKSPACE_FLOORS: dict[str, float] = {
    "regions": 93.1,
    "lines": 91.9,
    # Percentage, not a count: the workspace denominator grows as code is added,
    # so an absolute floor here would have to be edited on every commit. Carries
    # extra tolerance for the branch jitter described below.
    "branches": 78.5,
}

# ---------------------------------------------------------------------------
# Why branch floors are absolute counts while region and line floors are
# percentages.
#
# Branch coverage here is **not deterministic between runs**. The property
# suites drive `proof.rs` and `imt.rs` with proptest, which seeds a fresh RNG
# on every run, so which bounds-check branches get exercised varies. Measured
# back to back on identical source, `proof.rs` reported 17/20 and then 16/20
# — while its region and line coverage were byte-identical at 96.70% and
# 97.70% both times. Regions and lines are stable; branches are not.
#
# On a 20-branch denominator a single branch is five percentage points, so a
# zero-tolerance percentage ratchet on branches would fail CI at random. That
# is worse than no check: a gate that cries wolf gets switched off, and it
# would take the stable region and line ratchets down with it.
#
# So branch floors are absolute covered-counts set about two branches below the
# observed minimum, which absorbs the jitter while still catching a real
# regression — losing three or more branches is not noise. Region and line
# floors stay strict, because they have been verified stable across runs.
#
# If branch coverage is ever needed as a hard gate (CLAUDE.md Phase 1 asks for
# 100% on imt.rs), the fix is to make the run deterministic — a fixed proptest
# seed, or a separate non-randomised suite — not to tighten these numbers.
# ---------------------------------------------------------------------------


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


def unexercised(summary: dict) -> bool:
    """True when the file was compiled but no test ever entered it.

    Distinguishing this from "poorly covered" matters, because the cause and the
    fix are completely different. A file at 40% needs more tests written. A file
    at *exactly* zero regions and zero functions was never reached at all, which
    in this repo has one overwhelmingly likely cause: every test that touches
    `zutreexo-chain` is gated on a fixture being present, and `fixtures/*.jsonl`
    is gitignored.

    Reporting that as "0.00% below floor 89.50%" reads as a coverage regression
    and sends you looking for the wrong thing. It happened, and it cost real
    time, so the tool says which it is.
    """
    for key in ("regions", "functions"):
        block = summary.get(key)
        if not isinstance(block, dict):
            return False
        if not block.get("count"):
            return False
        if block.get("covered"):
            return False
    return True


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

            # Diagnose "never ran" before comparing against floors, so the
            # message names the cause instead of three derived symptoms.
            if unexercised(summary):
                failures.append(
                    f"{suffix}: NEVER EXECUTED (0 of "
                    f"{summary['regions']['count']} regions, 0 of "
                    f"{summary['functions']['count']} functions).\n"
                    f"      This is a missing test environment, not a coverage "
                    f"regression. Every test touching zutreexo-chain is gated "
                    f"on a fixture;\n"
                    f"      check that fixtures/nu5-orchard.jsonl is present — "
                    f"the other slices are gitignored by design."
                )
                print(f"  {suffix}: NEVER EXECUTED")
                continue

            reported = []
            for metric in ("regions", "lines", "functions"):
                actual = percent(summary, metric)
                if actual is None:
                    reported.append(f"{metric} n/a")
                    continue
                reported.append(f"{metric} {actual:.2f}%")
                floor = floors.get(metric)
                if floor is not None and actual + 1e-9 < floor:
                    failures.append(
                        f"{suffix}: {metric} {actual:.2f}% below floor {floor:.2f}%"
                    )

            # Branches: absolute counts, for the jitter reason documented above.
            block = summary.get("branches") or {}
            total = block.get("count") or 0
            covered = block.get("covered") or 0
            if total:
                reported.append(f"branches {covered}/{total}")
                minimum = floors.get("min_branches")
                if minimum is not None and covered < minimum:
                    failures.append(
                        f"{suffix}: {covered}/{total} branches covered, "
                        f"floor is {int(minimum)}"
                    )
            else:
                reported.append("branches n/a")
                if "min_branches" in floors:
                    failures.append(
                        f"{suffix}: floor set on 'min_branches', "
                        f"but llvm-cov reports no branch data"
                    )

            # A floor on a metric the file does not report would silently never
            # fire, so say so rather than passing quietly.
            for metric in floors:
                if metric == "min_branches":
                    continue
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

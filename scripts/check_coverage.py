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
    # Phase 1's definition of done, and the only file in the workspace whose
    # branch floor is *exact* rather than set a couple below the observed
    # minimum.
    #
    # It can be exact because `tests/imt_branches.rs` is deterministic — fixed
    # inputs, named expected errors, no generation — so this figure does not
    # move between runs the way the proptest-driven files do. That was the
    # blocker recorded in PLAN.md: a gate on a number that wanders gets
    # switched off, and takes the stable ratchets with it.
    #
    # 83 of 88. The five missing sides are defensive guards no public call can
    # reach; they are enumerated in CLAUDE.md's amended Phase 1 DoD, and
    # deleting them to reach 88 would trade a real safety net for a number.
    # If this ever reads above 83, something became reachable that was not —
    # find out what before raising the floor.
    "crates/zutreexo-accumulator/src/imt.rs": {
        "regions": 97.4,
        "lines": 98.3,
        "min_branches": 83,  # exact: 83/88, five unreachable guards excluded
    },
    # The prefix-cohort construction (D37). Same reasoning as `proof.rs`: it
    # decodes bridge-supplied bytes and its `resolve` runs on a cohort a hostile
    # bridge chose the contents of, so it is gated on its own rather than
    # averaged away.
    #
    # 46 of 56 branches. The uncovered sides are `CorruptTree` guards on a tree
    # whose value index disagrees with its leaf vector, which no public mutator
    # can produce -- the same class enumerated in CLAUDE.md's amended Phase 1
    # DoD for `imt.rs`, and kept for the same reason.
    "crates/zutreexo-accumulator/src/cohort.rs": {
        "regions": 96.8,
        "lines": 97.2,
        "min_branches": 44,  # measured 46/56
    },
    # The sorted cohort tree (D38). Gated on its own for the same reason as
    # `cohort.rs`: it decodes bridge-supplied bytes, and it is a *second*
    # structure over the same nullifier set, which is where a silent
    # disagreement would live.
    #
    # 35 of 40 branches. The uncovered sides are `depth_for`'s overflow guard --
    # unreachable without a Vec of more than 2^32 values -- and the pad
    # fallbacks in the fold, which fire only for a tree shallower than any this
    # builds. Kept for the reason CLAUDE.md's amended Phase 1 DoD gives: a guard
    # that fails loudly beats a number.
    "crates/zutreexo-accumulator/src/sorted.rs": {
        "regions": 98.0,
        "lines": 97.8,
        "min_branches": 33,  # measured 35/40
    },
    # Deserialization runs on attacker-supplied bytes, so it gets its own floor
    # rather than hiding inside the workspace average.
    #
    # Lowered 98.7 -> 98.6 on 2026-08-28, with the reason enumerated rather
    # than the number simply moved. The sorted-cohort codec (D38) added ~200
    # regions, one of which is provably dead: `reader.hash()?` inside the value
    # loop. The count guard establishes `remaining >= 32 * value_count` before
    # the loop, each iteration consumes exactly 32, so the read cannot fail --
    # yet dropping the `?` would mean an unchecked read, which is worse than an
    # uncovered one. Same trade CLAUDE.md's amended Phase 1 DoD makes for
    # `imt.rs`: a guard that cannot fire beats a number.
    "crates/zutreexo-accumulator/src/proof.rs": {
        "regions": 98.6,
        "lines": 99.6,
        "min_branches": 26,  # measured 29/32
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
    # Phase 3's on-disk snapshot format. It earns an entry rather than being
    # absorbed into the workspace average because deserialising a file someone
    # else wrote is the crate's only untrusted-input surface, and an
    # unexercised arm there is a parser accepting something it should refuse.
    #
    # The floor started life 4 points lower. `load` verifies magic and checksum
    # before calling `decode`, so every structural check inside `decode` is
    # unreachable by any edit that disturbs the payload — the checksum fires
    # first. Three tests were written believing otherwise and passed on
    # ChecksumMismatch while the arms they were named for never ran. This gate
    # is what surfaced it: green tests, zero coverage, directly above each
    # other. Reaching those arms needs a forged file that reseals a valid
    # checksum over an edited payload, which is also the realistic adversary.
    "crates/zutreexo-chain/src/store.rs": {
        "regions": 89.1,
        "lines": 88.6,
        "min_branches": 18,  # measured 20/24
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
    # Stage 2d's zebrad RPC client (BlockStream/RpcSource/FixtureSource).
    # Exercised against a real TCP server in the test module — a background
    # thread standing in for zebrad — rather than against the network, so this
    # runs the same in CI as anywhere else.
    "crates/zutreexo-testkit/src/source.rs": {
        "regions": 93.7,
        "lines": 96.7,
        "min_branches": 10,  # measured 12/16
    },
    # Stage 2d's genesis-to-tip replay binary. This is an operational entry
    # point, not library code: `main` parses env vars, opens a TCP connection
    # to a live, synced `zebrad`, and drives a run that takes on the order of
    # a day. No test environment has that node, so this can never be
    # exercised the way a fixture-gated file eventually is — it is not a
    # "missing fixture", it is structurally out of reach for the automated
    # suite. `never_measured` records that explicitly instead of letting the
    # workspace average absorb it silently. The logic worth covering (RPC
    # framing, response parsing, block ordering) lives in source.rs instead,
    # which this binary only calls.
    "crates/zutreexo-testkit/src/bin/genesis_replay.rs": {
        "never_measured": (
            "operational entry point — needs a live synced zebrad, which no "
            "test environment has. See src/source.rs for the logic this "
            "binary drives, covered there instead."
        ),
    },
    # Phase 4a's two measurement binaries. Same category as genesis_replay: they
    # drive a live node for hours and produce numbers for docs/benchmarks.md,
    # and the logic worth covering lives in the libraries they call
    # (bundle.rs, zutreexo-csn) which are gated above.
    "crates/zutreexo-testkit/src/bin/csn_replay.rs": {
        "never_measured": (
            "operational entry point — replays mainnet from a live zebrad in "
            "bridge/compact-node lockstep. The transition it drives is covered "
            "by zutreexo-csn/tests/lockstep.rs."
        ),
    },
    "crates/zutreexo-testkit/src/bin/gap_cost.rs": {
        "never_measured": (
            "operational entry point — samples a live zebrad to measure wallet "
            "sync cost against gap length. Reporting only; it computes no state."
        ),
    },
    "crates/zutreexo-testkit/src/bin/cohort_cost.rs": {
        "never_measured": (
            "operational entry point — builds a 50.4M-leaf tree at production "
            "depth to measure prefix-cohort cost (D37). 21 GB and three "
            "minutes; reporting only, it computes no state the workspace "
            "depends on. The construction it measures is covered by "
            "zutreexo-accumulator's cohort tests."
        ),
    },
    "crates/zutreexo-testkit/src/bin/pool_cohorts.rs": {
        "never_measured": (
            "operational entry point — builds a sorted tree per pool at real "
            "mainnet nullifier counts to answer whether every pool reaches the "
            "anonymity target (D39). 5.8 GB; reporting only. Its one piece of "
            "logic, `widest_prefix`, has unit tests inside the binary."
        ),
    },
    # Phase 5b's shadow runner. Same category again, and more so than the
    # others: it follows the *live* chain tip for hours and its most
    # interesting path — reorg recovery — fires only when mainnet reorgs, which
    # no test environment can arrange. The compact node's half of that claim is
    # covered by zutreexo-csn/tests/reorg.rs, and the block-hash and JSON
    # oracle plumbing lives in src/source.rs.
    #
    # PLAN.md records that shadow.rs's own `unwind` is untested in anger. This
    # entry is why that has to be said out loud rather than inferred from a
    # coverage number.
    # Phase 6's DoS measurement. Same category: it loads a 6 GB tip snapshot and
    # times proof generation against 27.5M real outputs, which no test
    # environment can do. The proof paths it times are covered in
    # zutreexo-accumulator.
    "crates/zutreexo-testkit/src/bin/dos_cost.rs": {
        "never_measured": (
            "operational entry point — measures per-proof cost against a "
            "loaded mainnet snapshot. Reporting only; it computes no state."
        ),
    },
    "crates/zutreexo-testkit/src/bin/shadow.rs": {
        "never_measured": (
            "operational entry point — follows a live zebrad at chain tip. Its "
            "reorg path needs mainnet to reorg. The compact-node rollback it "
            "relies on is covered by zutreexo-csn/tests/reorg.rs."
        ),
    },
    # Phase 4a. The bundle format is what a bridge serves and a compact node
    # consumes, so its decoder is an untrusted-input surface like store.rs.
    "crates/zutreexo-chain/src/bundle.rs": {
        "regions": 96.5,
        "lines": 94.7,
        "min_branches": 11,  # measured 13/14
    },
    # The compact state node itself: the one component that decides whether a
    # roots-only node accepts a block. Every rejection path here is a defence
    # against a hostile bridge.
    "crates/zutreexo-csn/src/lib.rs": {
        "regions": 86.3,
        "lines": 77.4,
        "min_branches": 20,  # measured 22/28
    },
    # Phase 4b's bridge. `wire.rs` decodes bytes a client sent and `server.rs`
    # decodes an HTTP request from one, so both are untrusted-input surfaces on
    # the same footing as store.rs and bundle.rs. `lib.rs` is the retention and
    # proof-serving logic behind them.
    #
    # These floors are lower than the codec files above and deliberately so:
    # the uncovered remainder is mostly i/o error paths that need a socket to
    # fail in a specific way mid-write, which is a fault-injection harness this
    # phase did not build. What is covered is every path a peer can reach by
    # sending bytes.
    "crates/zutreexo-bridge/src/wire.rs": {
        "regions": 96.3,
        "lines": 91.3,
        "min_branches": 6,  # measured 8/8
    },
    # Phase 6 raised regions and lowered lines here, and both moved for the same
    # reason: the hardening in D34 added code whose *happy* paths are all tested
    # (timeouts, the total deadline, the response cap, rate limiting) and whose
    # error edges are i/o failures — `set_read_timeout` returning Err,
    # `write_all` failing mid-header, `accept` failing. Those need a socket to
    # fail on demand, which is the fault-injection harness the comment above
    # already says this phase did not build.
    #
    # Regions ratcheted up 88.3 -> 89.5 (measured 89.58) to lock in the gain.
    # Lines lowered 92.5 -> 91.9 (measured 91.98): a deliberate reduction,
    # declared here in the same change per this file's own rule rather than
    # worked around.
    "crates/zutreexo-bridge/src/server.rs": {
        "regions": 89.5,
        "lines": 91.9,
        "min_branches": 13,  # measured 22/24
    },
    "crates/zutreexo-bridge/src/lib.rs": {
        "regions": 86.9,
        "lines": 88.7,
        "min_branches": 4,  # measured 4/4
    },
}

# Measured 93.59 / 92.66 / 83.97 in the CI profile at Phase 4b, after
# `cargo llvm-cov clean`, over the workspace excluding never-measured files
# (see the calculation in `main`).
#
# Up again from Phase 4a's 93.29 / 92.17 / 81.38, and the branch figure most of
# all, because Phase 4b's additions are decoders and decoders were given
# adversarial tests rather than round-trip tests alone. One of those found a
# denial-of-service hole in code that had shipped two phases earlier
# (`docs/design.md` D29), which is the argument for keeping this ratchet
# pointed upward rather than lowering it whenever new code lands slightly below
# the mean.
#
WORKSPACE_FLOORS: dict[str, float] = {
    "regions": 93.5,
    "lines": 92.6,
    # Percentage, not a count: the workspace denominator grows as code is added,
    # so an absolute floor here would have to be edited on every commit. Set
    # 0.3 below the measurement rather than at the usual one-decimal truncation,
    # because this is the one workspace metric the jitter described below can
    # move, and a flaky gate gets switched off.
    "branches": 83.6,
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


def _assert_no_duplicate_floors() -> None:
    """Fail loudly if a path is listed twice in FLOORS.

    A duplicate key in a Python dict literal is not an error: the last one
    silently wins. That is exactly what happened on 2026-08-22 — `gap_cost.rs`
    was already registered as never-measured and a second, identical entry was
    added below it. Nothing complained, and the only reason it was noticed was
    an unrelated grep.

    The failure mode is worse than untidiness. A later entry with *different*
    floors would silently replace the earlier one, quietly lowering a gate that
    still looked present in the file.
    """
    import ast

    with open(__file__, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys = [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        seen: set[str] = set()
        for key in keys:
            if key in seen:
                raise SystemExit(f"check_coverage.py lists {key!r} twice; the second entry silently wins")
            seen.add(key)


def main(argv: list[str]) -> int:
    _assert_no_duplicate_floors()
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

            # Structurally unmeasurable (e.g. needs a live node no test
            # environment has) is a different claim from "never ran in this
            # particular run" — it never gets a fixture to be gated on, so it
            # is reported and skipped rather than routed through the
            # unexercised()/floor checks below, neither of which apply.
            reason = floors.get("never_measured")
            if reason is not None:
                print(f"  {suffix}: NOT MEASURED BY DESIGN — {reason}")
                continue

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
    #
    # Computed here rather than read from llvm-cov's own `totals`, because the
    # `never_measured` files have to come out of it.
    #
    # They are structurally unmeasurable — operational binaries that need a live
    # synced node — so every region in them is a permanent zero that no test can
    # ever raise. Leaving them in does not make the gate stricter, it makes it
    # meaningless: each new binary drags the average down, the floor gets
    # lowered to match, and the lowered floor no longer constrains the code that
    # *is* testable. That already happened once, and by Phase 4a three such
    # binaries contributed 957 regions of guaranteed 0%, pulling the workspace
    # from 93.3% to 83.4%.
    #
    # Excluding them means the floor tracks what tests can actually influence.
    # The raw figure is still printed, so nothing is hidden.
    never = {
        suffix
        for suffix, floors in FILE_FLOORS.items()
        if floors.get("never_measured") is not None
    }
    accumulated: dict[str, list[int]] = {
        metric: [0, 0] for metric in ("regions", "lines", "functions", "branches")
    }
    excluded = 0
    for entry in data.get("files", []):
        filename = entry.get("filename", "")
        if any(filename.endswith(suffix) for suffix in never):
            excluded += 1
            continue
        summary = entry.get("summary", {})
        for metric, pair in accumulated.items():
            block = summary.get(metric)
            if not isinstance(block, dict):
                continue
            pair[0] += block.get("covered") or 0
            pair[1] += block.get("count") or 0

    print(f"  workspace total ({excluded} never-measured files excluded):", end=" ")
    parts = []
    for metric in ("regions", "lines", "functions", "branches"):
        covered, total = accumulated[metric]
        if not total:
            continue
        actual = 100.0 * covered / total
        parts.append(f"{metric} {actual:.2f}%")
        floor = WORKSPACE_FLOORS.get(metric)
        if floor is not None and actual + 1e-9 < floor:
            failures.append(
                f"workspace: {metric} {actual:.2f}% below floor {floor:.2f}%"
            )
    print(", ".join(parts))

    raw = data.get("totals", {})
    raw_parts = [
        f"{metric} {value:.2f}%"
        for metric in ("regions", "lines", "functions", "branches")
        if (value := percent(raw, metric)) is not None
    ]
    print("  (including them: " + ", ".join(raw_parts) + ")")

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

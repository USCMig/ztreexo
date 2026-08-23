#!/usr/bin/env python3
"""Report per-target fuzz saturation, to budget the next run from data.

`docs/design.md` D36: the 2026-08-22 run gave five targets the same wall clock
and four of them saturated in under two hours, so ~99% of four cores' budget
went to confirming that nothing new was being found. Time-to-saturation spans
nearly four orders of magnitude across these targets, which is why a single
`-max_total_time` for all of them cannot be right.

This reads the libFuzzer logs a run leaves in `fuzz-runs/` and answers the two
questions needed to schedule the next one:

  * which targets are saturated, and how much budget went in after they were;
  * how long each took to reach its last discovery, which is the unit to
    budget in.

Works on a run in progress -- it reads logs, not processes -- so it can also be
used to decide whether to cut a run short.

Usage:
    scripts/fuzz_saturation.py [--logs fuzz-runs] [--elapsed-hours H]

`--elapsed-hours` converts execution counts to wall time. Without it the report
gives execution counts only, which is exact; with it, times are estimates that
assume a roughly constant execution rate.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# "#1285649323\tNEW    cov: 810 ft: 2824 corp: 284/97Kb ..."
STAT = re.compile(r"^#(\d+)\s+(\w+)\s+cov:\s*(\d+)\s+ft:\s*(\d+)")
# "INFO: Loaded 1 modules   (735 inline 8-bit counters): ..."
EDGES = re.compile(r"\((\d+) inline 8-bit counters\)")

# Logs that are not a fuzz target's.
SKIP = {"build", "driver"}


@dataclass
class Target:
    name: str
    instrumented: int | None
    inited_cov: int | None
    inited_ft: int | None
    final_exec: int
    final_cov: int
    final_ft: int
    last_new_exec: int | None  # None => never found a new edge
    new_count: int

    @property
    def edges_gained(self) -> int | None:
        if self.inited_cov is None:
            return None
        return self.final_cov - self.inited_cov

    @property
    def saturated_at(self) -> int:
        """Execution count of the last new edge; 0 if it never found one."""
        return self.last_new_exec or 0

    @property
    def wasted_fraction(self) -> float:
        """Share of executions that ran after the last new edge."""
        if self.final_exec == 0:
            return 0.0
        return (self.final_exec - self.saturated_at) / self.final_exec


def parse(path: Path) -> Target | None:
    return parse_lines(path.stem, path.read_text(errors="replace").splitlines())


def parse_lines(name: str, lines: list[str]) -> Target | None:
    instrumented = inited_cov = inited_ft = None
    final_exec = final_cov = final_ft = 0
    last_new_exec = None
    new_count = 0
    best_cov = 0

    for line in lines:
        if instrumented is None:
            m = EDGES.search(line)
            if m:
                instrumented = int(m.group(1))
        m = STAT.match(line)
        if not m:
            continue
        execs, kind, cov, ft = int(m.group(1)), m.group(2), int(m.group(3)), int(m.group(4))
        # Lines are emitted in execution order, so last one wins.
        final_exec, final_cov, final_ft = execs, cov, ft
        if kind == "INITED":
            # The baseline: what the seed corpus already reached. Not a find.
            inited_cov, inited_ft = cov, ft
            best_cov = cov
            continue
        if kind == "NEW":
            new_count += 1
        # A NEW line reports a new *feature*; it is a new **edge** only when
        # `cov` actually moved. Counting features as discoveries is exactly what
        # makes a saturated target look busy, so track the high-water mark of
        # `cov` across every stat line rather than trusting the NEW label.
        if cov > best_cov:
            best_cov = cov
            last_new_exec = execs

    if final_exec == 0:
        return None
    return Target(
        name=name,
        instrumented=instrumented,
        inited_cov=inited_cov,
        inited_ft=inited_ft,
        final_exec=final_exec,
        final_cov=final_cov,
        final_ft=final_ft,
        last_new_exec=last_new_exec,
        new_count=new_count,
    )


def _assert_new_lines_are_not_treated_as_edges() -> None:
    """The distinction this whole script exists to make.

    libFuzzer prints `NEW` for a new *feature* (an edge-count bucket), not only
    for a new edge. A target whose coverage never moves still prints `NEW` and
    looks productive -- which is how the first draft of D36's table reported
    `nonmembership_decode` saturating at "~2.1 h" when the true answer is never.

    Reading the last `NEW` line gives the wrong answer here; reading the
    high-water mark of `cov` gives the right one. Guarded on every run because
    the two are easy to conflate again.
    """
    saturated = [
        "INFO: Loaded 1 modules   (500 inline 8-bit counters): 500 [0x0, 0x1),",
        "#19\tINITED cov: 323 ft: 934 corp: 67/11Kb exec/s: 0 rss: 58Mb",
        "#1000\tNEW    cov: 323 ft: 940 corp: 68/11Kb lim: 4096 exec/s: 500 rss: 60Mb",
        "#900000000\tNEW    cov: 323 ft: 945 corp: 69/11Kb lim: 4096 exec/s: 500 rss: 60Mb",
        "#2147483648\tpulse  cov: 323 ft: 945 corp: 69/11Kb lim: 4096 exec/s: 500 rss: 60Mb",
    ]
    t = parse_lines("saturated", saturated)
    assert t is not None, "synthetic log should parse"
    assert t.new_count == 2, f"expected 2 NEW lines, got {t.new_count}"
    assert t.edges_gained == 0, f"coverage never moved, got {t.edges_gained:+d}"
    assert t.last_new_exec is None, (
        f"two NEW lines but no new edge: last_new_exec should be None, "
        f"got {t.last_new_exec} -- features are being counted as edges"
    )
    assert t.wasted_fraction == 1.0, t.wasted_fraction

    # And the converse: a target that really does gain an edge is reported.
    productive = saturated[:3] + [
        "#5000000\tNEW    cov: 340 ft: 950 corp: 70/11Kb lim: 4096 exec/s: 500 rss: 60Mb",
        "#10000000\tpulse  cov: 340 ft: 950 corp: 70/11Kb lim: 4096 exec/s: 500 rss: 60Mb",
    ]
    t = parse_lines("productive", productive)
    assert t is not None
    assert t.edges_gained == 17, t.edges_gained
    assert t.last_new_exec == 5000000, t.last_new_exec
    assert abs(t.wasted_fraction - 0.5) < 1e-9, t.wasted_fraction


def human_time(hours: float) -> str:
    if hours < 1 / 60:
        return "<1 min"
    if hours < 1:
        return f"{hours * 60:.0f} min"
    if hours < 48:
        return f"{hours:.1f} h"
    return f"{hours / 24:.1f} d"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--logs", default="fuzz-runs", type=Path)
    ap.add_argument(
        "--elapsed-hours",
        type=float,
        default=None,
        help="wall-clock hours the run has been going, to estimate times",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="run the parser self-check and exit; needs no logs, for CI",
    )
    args = ap.parse_args()

    _assert_new_lines_are_not_treated_as_edges()
    if args.self_test:
        print("fuzz_saturation: self-check passed")
        return 0

    if not args.logs.is_dir():
        print(f"no log directory at {args.logs}", file=sys.stderr)
        return 2

    targets = []
    for path in sorted(args.logs.glob("*.log")):
        if path.stem in SKIP:
            continue
        t = parse(path)
        if t is not None:
            targets.append(t)

    if not targets:
        print(f"no target logs with stat lines in {args.logs}", file=sys.stderr)
        return 2

    # Busiest first: the target still finding things is the one to budget for.
    targets.sort(key=lambda t: (-(t.edges_gained or 0), t.name))

    e = args.elapsed_hours
    print(f"{'target':<24} {'edges':>13} {'last new edge':>16} {'after it':>10}")
    print("-" * 66)
    total_exec = 0
    total_gained = 0
    for t in targets:
        total_exec += t.final_exec
        gained = t.edges_gained
        total_gained += gained or 0
        if t.inited_cov is None:
            edges = f"{t.final_cov} (no INITED)"
        else:
            edges = f"{t.inited_cov}->{t.final_cov} ({gained:+d})"
        if t.last_new_exec is None:
            when = "never"
        elif e is not None:
            when = human_time(e * t.last_new_exec / t.final_exec)
        else:
            when = f"#{t.last_new_exec:,}"
        print(f"{t.name:<24} {edges:>13} {when:>16} {t.wasted_fraction:>9.1%}")

    print("-" * 66)
    print(f"{len(targets)} targets, {total_exec:,} executions, {total_gained} new edges")

    saturated = [t for t in targets if (t.edges_gained or 0) == 0]
    if saturated:
        print()
        print("Saturated -- gained no edges. These need seeds or a structured")
        print("generator, not more hours (D36):")
        for t in saturated:
            print(f"  {t.name}: {t.final_exec:,} executions, still at {t.final_cov} edges")

    # The scheduling rule from D36: run 10x past the last discovery.
    print()
    print("Suggested budget for the next run (10x time-to-last-discovery):")
    for t in targets:
        if t.last_new_exec is None:
            print(f"  {t.name:<24} minutes -- re-seed instead")
        elif e is not None:
            hours = 10 * e * t.last_new_exec / t.final_exec
            print(f"  {t.name:<24} {human_time(hours)}")
        else:
            print(f"  {t.name:<24} {10 * t.last_new_exec:,} executions")
    if e is None:
        print()
        print("(pass --elapsed-hours to get these as times)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

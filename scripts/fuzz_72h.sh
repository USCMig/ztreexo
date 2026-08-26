#!/usr/bin/env bash
#
# Phase 6: the long fuzz run.
#
# # Budgets are per target, not one clock for all of them
#
# The 2026-08-22 run gave all five targets the same 72 hours. `docs/design.md`
# D36 records what that bought: 206 billion executions, 34 new edges, and 31 of
# them in `bundle_decode`. Three targets never reached an edge their seed corpus
# had not already reached, and `utxo_proof_decode` found its three at execution
# 101. Four of five cores spent three days confirming saturation.
#
# `bundle_decode` was the opposite problem. It found edges at 19.7 h, 66.3 h and
# **71.5 h** — the last one with twenty-five minutes left on the clock. It was
# still discovering when the run was cut off, so 72 h was too short for it and
# far too long for everything else, at the same time.
#
# Hence two budgets below. Note what the split is really saying: for a saturated
# target more hours is the wrong lever entirely, and its budget here buys crash
# coverage, not code coverage. Widening *that* needs better seeds or a
# structured `Arbitrary` generator (D36), which is a code change, not a flag.
#
# Re-derive these numbers after any run — the script prints the analysis at the
# end, or run `scripts/fuzz_saturation.py` by hand against `fuzz-runs/`.
#
# # Which targets, and why not all seven
#
# `forest_decode` and `snapshot_decode` are excluded. Both reach
# `MemForest::deserialize`, which panics on a malformed node-type field and
# overflows the stack on deeply nested input (`docs/design.md` D33).
# `UtxoForest::from_bytes` contains the panic with `catch_unwind` — but not the
# overflow, which aborts rather than unwinds — and libfuzzer-sys installs a
# panic hook that aborts before unwinding anyway, so under the fuzzer both
# targets die within seconds.
#
# The fork fix for both bugs is written and verified (D33). These two go back in
# once it is pushed and the pin in `Cargo.toml` moves to it.
#
# Usage: nohup scripts/fuzz_72h.sh > fuzz-runs/driver.log 2>&1 &

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ZUTREEXO_FUZZ_OUT:-$REPO/fuzz-runs}"
RSS_MB="${ZUTREEXO_FUZZ_RSS_MB:-4096}"

# Still finding edges at 71.5 h, so give it days and the spare cores.
#
# `-fork=N` rather than `-jobs=N -workers=N`, for two measured reasons: `-jobs`
# writes each worker's output to `fuzz-<n>.log` in the *current directory*
# (dropping stray files in the repo root) and leaves the main log carrying only
# one worker's numbers, so the analysis at the end would silently under-report.
# Fork mode keeps one stream and merges the workers' corpora, which is the
# actual point of running them together.
#
# Measured on this box: 2 forks took `bundle_decode` from ~18k to ~40k exec/s,
# so throughput scales close to linearly. Coverage discovery does not —
# independent workers duplicate each other's exploration — so read this as
# "more executions", not "8x sooner to the next edge".
LONG_SECS="${ZUTREEXO_FUZZ_LONG_SECS:-604800}"    # 7 d
LONG_WORKERS="${ZUTREEXO_FUZZ_WORKERS:-8}"

# Saturated within minutes. This budget is for crash-hunting; at these rates it
# is still tens of billions of executions each.
SHORT_SECS="${ZUTREEXO_FUZZ_SHORT_SECS:-86400}"   # 24 h

# target:seconds:workers
TARGETS=(
  "bundle_decode:$LONG_SECS:$LONG_WORKERS"
  "utxo_proof_decode:$SHORT_SECS:1"
  "compact_state_decode:$SHORT_SECS:1"
  "wire_request_decode:$SHORT_SECS:1"
  "nonmembership_decode:$SHORT_SECS:1"
)

mkdir -p "$OUT"
cd "$REPO"
say() { echo "[$(date -Is)] $*"; }

say "building ${#TARGETS[@]} targets"
for spec in "${TARGETS[@]}"; do
  t="${spec%%:*}"
  rustup run nightly cargo fuzz build "$t" >> "$OUT/build.log" 2>&1 || {
    say "BUILD FAILED for $t — see $OUT/build.log"; exit 1; }
done
say "built"

for spec in "${TARGETS[@]}"; do
  IFS=: read -r t secs workers <<< "$spec"
  say "launching $t for ${secs}s with ${workers} worker(s)"
  parallel=()
  if [ "$workers" -gt 1 ]; then
    parallel=(-fork="$workers")
  fi
  nohup nice -n 10 rustup run nightly cargo fuzz run "$t" -- \
      -max_total_time="$secs" \
      -rss_limit_mb="$RSS_MB" \
      -print_final_stats=1 \
      "${parallel[@]}" \
    > "$OUT/$t.log" 2>&1 &
  echo "$!" > "$OUT/$t.pid"
done

say "all launched; waiting"
wait
say "all targets finished"

for spec in "${TARGETS[@]}"; do
  t="${spec%%:*}"
  # `ls | grep -c .` returns 1 when the count is zero, so a `|| echo 0` fallback
  # appends a *second* line and the log reads "artifacts=0\n0". wc -l does not.
  crashes=$(ls -1 "$REPO/fuzz/artifacts/$t"/ 2>/dev/null | wc -l)
  # Sequential runs report a `stat::` block; fork mode does not, so fall back to
  # the running count on its last line.
  execs=$(grep -oE 'stat::number_of_executed_units: *[0-9]+' "$OUT/$t.log" | grep -oE '[0-9]+$' | tail -1)
  if [ -z "$execs" ]; then
    execs=$(grep -oE '^#[0-9]+:' "$OUT/$t.log" | tail -1 | tr -cd '0-9')
  fi
  say "$t: artifacts=$crashes execs=${execs:-unknown}"
done

# The point of the run is the analysis, so do not make anyone remember to run
# it. Reads the logs just written; needs no flags once a run has finished.
say "saturation analysis"
python3 "$REPO/scripts/fuzz_saturation.py" --logs "$OUT" || true

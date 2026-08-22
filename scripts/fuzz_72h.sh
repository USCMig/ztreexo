#!/usr/bin/env bash
#
# Phase 6: the 72-hour fuzz run.
#
# # Which targets, and why not all seven
#
# `forest_decode` and `snapshot_decode` are excluded. Both reach
# `MemForest::deserialize`, which **panics** on a malformed node-type field
# (`docs/design.md` D33). `UtxoForest::from_bytes` now contains that panic with
# `catch_unwind`, which protects production — but libfuzzer-sys installs a panic
# hook that aborts the process *before* unwinding, so under the fuzzer the
# containment is invisible and both targets die within seconds.
#
# Including them would burn 72 hours re-finding one known bug. They go back in
# once the fork returns an error instead; the pin is D25 and the patch is ready.
#
# # Parallelism
#
# Five targets, one process each, on a 12-core box, niced so an interactive
# session stays usable. libFuzzer keeps its own corpus per target and they do
# not contend.
#
# Usage: nohup scripts/fuzz_72h.sh > fuzz-runs/driver.log 2>&1 &

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ZUTREEXO_FUZZ_OUT:-$REPO/fuzz-runs}"
SECS="${ZUTREEXO_FUZZ_SECS:-259200}"   # 72 h
RSS_MB="${ZUTREEXO_FUZZ_RSS_MB:-4096}"

TARGETS=(
  bundle_decode
  utxo_proof_decode
  compact_state_decode
  wire_request_decode
  nonmembership_decode
)

mkdir -p "$OUT"
cd "$REPO"
say() { echo "[$(date -Is)] $*"; }

say "building ${#TARGETS[@]} targets"
for t in "${TARGETS[@]}"; do
  rustup run nightly cargo fuzz build "$t" >> "$OUT/build.log" 2>&1 || {
    say "BUILD FAILED for $t — see $OUT/build.log"; exit 1; }
done
say "built"

for t in "${TARGETS[@]}"; do
  say "launching $t for ${SECS}s"
  nohup nice -n 10 rustup run nightly cargo fuzz run "$t" -- \
      -max_total_time="$SECS" \
      -rss_limit_mb="$RSS_MB" \
      -print_final_stats=1 \
    > "$OUT/$t.log" 2>&1 &
  echo "$!" > "$OUT/$t.pid"
done

say "all launched; waiting"
wait
say "all targets finished"

for t in "${TARGETS[@]}"; do
  crashes=$(ls "$REPO/fuzz/artifacts/$t"/ 2>/dev/null | grep -c . || echo 0)
  execs=$(grep -oE 'stat::number_of_executed_units: *[0-9]+' "$OUT/$t.log" | grep -oE '[0-9]+$' | tail -1)
  say "$t: artifacts=$crashes execs=${execs:-unknown}"
done

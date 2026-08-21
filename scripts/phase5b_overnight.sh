#!/usr/bin/env bash
#
# Phase 5b: the three long runs, chained, so a night produces all of them.
#
# Sequenced rather than parallel because run 2 and run 3 each need a snapshot
# run 1 produces, and because their resident sets (roughly 17 GiB and 33 GiB)
# do not comfortably coexist on a 62 GiB machine that is also hosting the
# zebrad they read from.
#
#   1. genesis -> tip, no proofs, snapshotting at 1,700,000 and at tip.
#      This is the expensive pass and it is done once. ~7 h.
#   2. compact-node lockstep across the sandblasting window, resumed from the
#      1.7M snapshot so the transparent forest is real. Stage 2d measured 9
#      blk/s here against 1,568 at tip, so this is where the p99 lives. ~1 h.
#   3. shadow the live tip from the tip snapshot. ~10 h for 500 blocks at
#      Zcash's 75 s target spacing.
#
# Run 2 is allowed to fail without taking run 3 with it: run 3 carries a
# CLAUDE.md definition-of-done item and run 2 is a measurement.
#
# Usage:  nohup scripts/phase5b_overnight.sh > /dev/null 2>&1 &
# Watch:  tail -f <OUT_DIR>/*.log

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNAP_DIR="${ZUTREEXO_SNAP_DIR:-$HOME/zutreexo-snapshots}"
OUT_DIR="${ZUTREEXO_OUT_DIR:-$REPO/phase5b-runs}"
RPC="${ZUTREEXO_RPC:-127.0.0.1:8232}"

SANDBLAST_FROM=1700000
SANDBLAST_TO=1710000
SHADOW_BLOCKS="${ZUTREEXO_SHADOW_BLOCKS:-500}"

mkdir -p "$SNAP_DIR" "$OUT_DIR"
cd "$REPO"

say() { echo "[$(date -Is)] $*"; }

say "building release binaries"
cargo build --release -p zutreexo-testkit --bins 2>&1 | tail -3
BIN="$REPO/target/release"

# ---------------------------------------------------------------- run 1 ----
say "RUN 1: genesis -> tip, snapshotting at $SANDBLAST_FROM and at tip"
ZUTREEXO_RPC="$RPC" \
ZUTREEXO_REPORT_EVERY=100000 \
ZUTREEXO_SAVE_AT="$SANDBLAST_FROM:$SNAP_DIR/h$SANDBLAST_FROM.snap" \
ZUTREEXO_SAVE="$SNAP_DIR/tip.snap" \
  "$BIN/genesis_replay" > "$OUT_DIR/1-genesis-replay.log" 2>&1
RUN1=$?
say "RUN 1 exited $RUN1"

if [ $RUN1 -ne 0 ]; then
  say "RUN 1 failed; runs 2 and 3 both depend on its snapshots. Stopping."
  exit 1
fi

# ---------------------------------------------------------------- run 2 ----
if [ -f "$SNAP_DIR/h$SANDBLAST_FROM.snap" ]; then
  say "RUN 2: compact-node lockstep over $SANDBLAST_FROM..$SANDBLAST_TO"
  ZUTREEXO_RPC="$RPC" \
  ZUTREEXO_RESUME="$SNAP_DIR/h$SANDBLAST_FROM.snap" \
  ZUTREEXO_END="$SANDBLAST_TO" \
  ZUTREEXO_REPORT_EVERY=2000 \
    "$BIN/csn_replay" > "$OUT_DIR/2-sandblasting-lockstep.log" 2>&1
  say "RUN 2 exited $?"
else
  say "RUN 2 skipped: no snapshot at $SANDBLAST_FROM"
fi

# ---------------------------------------------------------------- run 3 ----
if [ -f "$SNAP_DIR/tip.snap" ]; then
  say "RUN 3: shadowing live tip for $SHADOW_BLOCKS blocks"
  ZUTREEXO_RPC="$RPC" \
  ZUTREEXO_RESUME="$SNAP_DIR/tip.snap" \
  ZUTREEXO_SHADOW_BLOCKS="$SHADOW_BLOCKS" \
  ZUTREEXO_SHADOW_LOG="$OUT_DIR/3-shadow.jsonl" \
    "$BIN/shadow" > "$OUT_DIR/3-shadow.log" 2>&1
  say "RUN 3 exited $?"
else
  say "RUN 3 skipped: no snapshot at tip"
fi

say "all runs finished; logs in $OUT_DIR"

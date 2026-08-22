#!/usr/bin/env bash
#
# Runs Phase 5b's steps 2 and 3 once an already-running genesis replay exits.
#
# # Why this exists separately
#
# `phase5b_overnight.sh` was edited while it was running. Bash reads a script
# incrementally and tracks a byte offset into the file, so editing one mid-run
# makes it resume at the wrong bytes when the current command returns — the
# edit shifted lines above the resume point, which is the case that corrupts.
# The replay itself was never at risk (it is a separate process holding its own
# fds), so the fix is to detach the supervisor rather than restart six hours of
# work.
#
# Takes the replay's PID and waits for it, rather than re-launching it.
#
# Usage: nohup scripts/phase5b_after_replay.sh <replay-pid> &

set -uo pipefail

REPLAY_PID="${1:?usage: phase5b_after_replay.sh <replay-pid>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNAP_DIR="${ZUTREEXO_SNAP_DIR:-$HOME/zutreexo-snapshots}"
OUT_DIR="${ZUTREEXO_OUT_DIR:-$REPO/phase5b-runs}"
RPC="${ZUTREEXO_RPC:-127.0.0.1:8232}"
BIN="$REPO/target/release"

SANDBLAST_FROM=1700000
SANDBLAST_TO=1760000
SHADOW_BLOCKS="${ZUTREEXO_SHADOW_BLOCKS:-500}"

mkdir -p "$SNAP_DIR" "$OUT_DIR"
cd "$REPO"
say() { echo "[$(date -Is)] $*"; }

say "waiting for replay pid $REPLAY_PID"
while kill -0 "$REPLAY_PID" 2>/dev/null; do sleep 60; done
say "replay pid $REPLAY_PID has exited"

if [ ! -f "$SNAP_DIR/tip.snap" ]; then
  say "no tip snapshot — the replay did not finish cleanly. Stopping."
  say "check $OUT_DIR/1-genesis-replay.log"
  exit 1
fi

# ---------------------------------------------------------------- run 2 ----
if [ -f "$SNAP_DIR/h$SANDBLAST_FROM.snap" ]; then
  say "RUN 2: compact-node lockstep over $SANDBLAST_FROM..$SANDBLAST_TO"
  ZUTREEXO_RPC="$RPC" \
  ZUTREEXO_RESUME="$SNAP_DIR/h$SANDBLAST_FROM.snap" \
  ZUTREEXO_END="$SANDBLAST_TO" \
  ZUTREEXO_REPORT_EVERY=5000 \
    "$BIN/csn_replay" > "$OUT_DIR/2-sandblasting-lockstep.log" 2>&1
  say "RUN 2 exited $?"
else
  say "RUN 2 skipped: no snapshot at $SANDBLAST_FROM"
fi

# ---------------------------------------------------------------- run 3 ----
say "RUN 3: following live tip for $SHADOW_BLOCKS blocks (catch-up not counted)"
ZUTREEXO_RPC="$RPC" \
ZUTREEXO_RESUME="$SNAP_DIR/tip.snap" \
ZUTREEXO_SHADOW_BLOCKS="$SHADOW_BLOCKS" \
ZUTREEXO_SHADOW_LOG="$OUT_DIR/3-shadow.jsonl" \
  "$BIN/shadow" > "$OUT_DIR/3-shadow.log" 2>&1
say "RUN 3 exited $?"

say "all runs finished; logs in $OUT_DIR"

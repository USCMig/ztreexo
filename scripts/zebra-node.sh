#!/usr/bin/env bash
#
# Driver for the Dockerised Zebra node that zutreexo benchmarks and
# differential-tests against (CLAUDE.md Phase 0, and the Zebra oracle in
# Phase 2).
#
# Usage:
#   scripts/zebra-node.sh up                 start the node (detached)
#   scripts/zebra-node.sh down               stop it, cleanly
#   scripts/zebra-node.sh restart
#   scripts/zebra-node.sh status             tip height, peers, disk, RSS
#   scripts/zebra-node.sh logs [-f]
#   scripts/zebra-node.sh rpc METHOD [PARAMS_JSON]
#   scripts/zebra-node.sh wait-sync [--timeout SECONDS]
#   scripts/zebra-node.sh watch [--interval S] [--out FILE]
#   scripts/zebra-node.sh state-dir          print the host state path
#   scripts/zebra-node.sh nuke               delete the chain state (asks first)
#
# `watch` is the one that feeds Phase 0 item 3: it samples height, RSS and
# on-disk bytes into a CSV, so IBD wall-clock and peak RSS are recorded rather
# than recalled.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$REPO_ROOT/docker"
COMPOSE_FILE="$COMPOSE_DIR/docker-compose.yml"
CONTAINER="ztreexo-zebrad"

# Mirror the defaults in docker-compose.yml so this script can report the same
# paths and ports without parsing YAML.
[[ -f "$COMPOSE_DIR/.env" ]] && set -a && . "$COMPOSE_DIR/.env" && set +a
STATE_DIR="${ZEBRA_STATE_DIR:-$HOME/.local/share/ztreexo/zebra}"
RPC_PORT="${ZEBRA_RPC_PORT:-8232}"
HEALTH_PORT="${ZEBRA_HEALTH_PORT:-8080}"
RPC_URL="http://127.0.0.1:${RPC_PORT}"
HEALTH_URL="http://127.0.0.1:${HEALTH_PORT}"

die() { echo "error: $*" >&2; exit 1; }

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

need() { command -v "$1" >/dev/null || die "missing required tool: $1"; }

# --------------------------------------------------------------------- rpc

rpc() {
  local method="$1"
  local params="${2:-[]}"
  curl -fsS --max-time 120 \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":\"zutreexo\",\"method\":\"${method}\",\"params\":${params}}" \
    "$RPC_URL"
}

# Returns .result, or fails loudly with the JSON-RPC error attached.
rpc_result() {
  local raw
  raw="$(rpc "$@")" || die "RPC call to $RPC_URL failed — is the node up? (scripts/zebra-node.sh status)"
  if [[ "$(jq -r 'has("error") and (.error != null)' <<<"$raw")" == "true" ]]; then
    die "zebrad returned an error for '$1': $(jq -c '.error' <<<"$raw")"
  fi
  jq '.result' <<<"$raw"
}

# --------------------------------------------------------------------- cmds

cmd_up() {
  need docker
  mkdir -p "$STATE_DIR"

  local avail_gb
  avail_gb="$(df -BG --output=avail "$STATE_DIR" | tail -1 | tr -dc '0-9')"
  if [[ -n "$avail_gb" && "$avail_gb" -lt 600 ]]; then
    echo "WARNING: only ${avail_gb} GB free at $STATE_DIR." >&2
    echo "         A synced mainnet Zebra state is several hundred GB and grows." >&2
  fi

  echo "==> state dir: $STATE_DIR"
  compose up -d "$@"
  echo
  echo "RPC:    $RPC_URL   (loopback only, no auth — see docker/zebrad.toml)"
  echo "Health: $HEALTH_URL/healthy and $HEALTH_URL/ready"
  echo
  echo "Initial sync takes many hours. Follow it with:"
  echo "  scripts/zebra-node.sh logs -f"
  echo "  scripts/zebra-node.sh watch --out docs/ibd-$(date -u +%Y%m%d).csv"
}

cmd_down() {
  # stop_grace_period in the compose file gives RocksDB time to flush; passing
  # a matching -t here stops the CLI's own 10s default from cutting it short.
  compose stop -t 300
  compose down
}

cmd_restart() { cmd_down; cmd_up; }

cmd_logs() { compose logs "$@" zebrad; }

cmd_shell() { docker exec -it "$CONTAINER" bash; }

cmd_state_dir() { echo "$STATE_DIR"; }

cmd_rpc() {
  need curl; need jq
  [[ $# -ge 1 ]] || die "usage: zebra-node.sh rpc METHOD [PARAMS_JSON]"
  rpc_result "$1" "${2:-[]}"
}

# Host-side RSS of the zebrad process. The container does not use a private PID
# namespace view from the host's perspective, so the process is visible in
# /proc — which is also how scripts/measure_baseline.sh finds it.
zebrad_rss_kb() {
  local pid
  pid="$(pgrep -x zebrad | head -1)" || { echo ""; return; }
  awk '/VmRSS/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo ""
}

cmd_status() {
  need docker; need curl; need jq

  local state
  state="$(docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}' \
            "$CONTAINER" 2>/dev/null || echo "absent -")"
  echo "container:  $state"
  echo "state dir:  $STATE_DIR"

  if [[ -d "$STATE_DIR" ]]; then
    echo "disk:       $(du -sh "$STATE_DIR" 2>/dev/null | cut -f1)"
  fi

  local rss_kb
  rss_kb="$(zebrad_rss_kb)"
  [[ -n "$rss_kb" ]] && echo "rss:        $((rss_kb / 1024)) MiB"

  local info
  if ! info="$(rpc getblockchaininfo 2>/dev/null | jq -e '.result' 2>/dev/null)"; then
    echo "rpc:        unreachable at $RPC_URL"
    return 0
  fi

  # `estimatedheight` is Zebra's guess at the network tip; `blocks` is where we
  # actually are. Their difference is the honest remaining-work number.
  jq -r '
    "chain:      \(.chain)",
    "height:     \(.blocks)",
    "est. tip:   \(.estimatedheight // "?")",
    "progress:   \((.verificationprogress // 0) * 100 | floor)%"
  ' <<<"$info"

  local behind
  behind="$(jq -r '(.estimatedheight // .blocks) - .blocks' <<<"$info")"
  echo "behind:     $behind blocks"

  local peers
  peers="$(rpc getpeerinfo 2>/dev/null | jq -r '.result | length' 2>/dev/null || echo "?")"
  echo "peers:      $peers"

  local ready
  ready="$(curl -fsS --max-time 5 "$HEALTH_URL/ready" >/dev/null 2>&1 && echo yes || echo no)"
  echo "ready:      $ready"

  # Value pools are the cheapest sanity check that the shielded side of the
  # state is real, and Phase 0 records them anyway.
  jq -r 'if .valuePools then "pools:      " + ([.valuePools[] | "\(.id)=\(.chainValue)"] | join(" ")) else empty end' <<<"$info"
}

cmd_wait_sync() {
  need curl
  local timeout=0 start elapsed
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --timeout) timeout="$2"; shift 2 ;;
      *) die "unknown argument: $1" ;;
    esac
  done

  start="$(date +%s)"
  echo "waiting for $HEALTH_URL/ready ..."
  while true; do
    if curl -fsS --max-time 5 "$HEALTH_URL/ready" >/dev/null 2>&1; then
      echo "node is synced to tip after $(( $(date +%s) - start ))s"
      return 0
    fi
    elapsed=$(( $(date +%s) - start ))
    if [[ "$timeout" -gt 0 && "$elapsed" -ge "$timeout" ]]; then
      die "still not ready after ${elapsed}s"
    fi
    # One line per poll would be unreadable over a multi-hour IBD.
    if (( elapsed % 300 < 30 )); then
      local h
      h="$(rpc getblockchaininfo 2>/dev/null | jq -r '.result.blocks // "?"' 2>/dev/null || echo "?")"
      printf '  [%6ds] height %s\n' "$elapsed" "$h"
    fi
    # Cap the poll interval at whatever is left on the deadline, so a short
    # --timeout is honoured when it expires rather than 30s later.
    local nap=30
    if [[ "$timeout" -gt 0 && $(( timeout - elapsed )) -lt "$nap" ]]; then
      nap=$(( timeout - elapsed ))
      (( nap < 1 )) && nap=1
    fi
    sleep "$nap"
  done
}

cmd_watch() {
  need curl; need jq
  local interval=60 out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --interval) interval="$2"; shift 2 ;;
      --out)      out="$2"; shift 2 ;;
      *) die "unknown argument: $1" ;;
    esac
  done

  local header="unix_time,elapsed_s,height,est_tip,peers,rss_kb,state_bytes"
  if [[ -n "$out" ]]; then
    mkdir -p "$(dirname "$out")"
    [[ -s "$out" ]] || echo "$header" >"$out"
    echo "appending to $out every ${interval}s; Ctrl-C to stop"
  else
    echo "$header"
  fi

  local start; start="$(date +%s)"
  while true; do
    local now info height est peers rss bytes row
    now="$(date +%s)"
    info="$(rpc getblockchaininfo 2>/dev/null | jq -c '.result' 2>/dev/null || echo '{}')"
    height="$(jq -r '.blocks // ""' <<<"$info")"
    est="$(jq -r '.estimatedheight // ""' <<<"$info")"
    peers="$(rpc getpeerinfo 2>/dev/null | jq -r '.result | length' 2>/dev/null || echo "")"
    rss="$(zebrad_rss_kb)"
    bytes="$(du -sb "$STATE_DIR" 2>/dev/null | cut -f1 || echo "")"
    row="$now,$((now - start)),$height,$est,$peers,$rss,$bytes"
    if [[ -n "$out" ]]; then echo "$row" >>"$out"; else echo "$row"; fi
    sleep "$interval"
  done
}

cmd_nuke() {
  echo "This deletes $STATE_DIR — a full re-sync from genesis, many hours."
  read -r -p "Type the word 'resync' to confirm: " reply
  [[ "$reply" == "resync" ]] || { echo "aborted"; exit 1; }
  compose down 2>/dev/null || true
  rm -rf "${STATE_DIR:?}"/*
  echo "state cleared."
}

# -------------------------------------------------------------------- main

[[ $# -ge 1 ]] || { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

sub="$1"; shift
case "$sub" in
  up)         cmd_up "$@" ;;
  down|stop)  cmd_down ;;
  restart)    cmd_restart ;;
  logs)       cmd_logs "$@" ;;
  shell)      cmd_shell ;;
  status)     cmd_status ;;
  rpc)        cmd_rpc "$@" ;;
  wait-sync)  cmd_wait_sync "$@" ;;
  watch)      cmd_watch "$@" ;;
  state-dir)  cmd_state_dir ;;
  nuke)       cmd_nuke ;;
  -h|--help)  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//' ;;
  *)          die "unknown subcommand: $sub (try --help)" ;;
esac

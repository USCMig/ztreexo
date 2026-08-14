#!/usr/bin/env bash
#
# Phase 0 baseline measurement (CLAUDE.md Phase 0).
#
# Answers, against a synced mainnet zebrad:
#   1. size of the transparent UTXO set, each pool's nullifier set, and each
#      note commitment tree — counts and on-disk bytes;
#   2. per-block rate of transparent inputs/outputs and nullifiers per pool;
#   3. steady-state disk and RSS of the node itself.
#
# Every later performance claim is measured against what this prints. Output is
# a markdown table appended to docs/benchmarks.md plus a machine-readable JSON
# blob, so a rerun can be diffed against a previous one.
#
# Usage:
#   scripts/measure_baseline.sh [--rpc URL] [--out DIR] [--sample-blocks N]
#                               [--state-dir DIR] [--allow-unsynced]
#
# Requirements: a synced zebrad with JSON-RPC enabled, plus curl and jq.
#
# Run against zebrad 6.3.0 at mainnet tip (height 3,444,699) on 2026-08-12.
# Results in docs/benchmarks.md. Two things that run did NOT resolve, and that
# a rerun still will not:
#
#   * The transparent UTXO set count. Zebra does not implement
#     `gettxoutsetinfo` ("Method not found"), and no other RPC reports it.
#     Getting it needs either a full-history scan or a read-only open of
#     Zebra's RocksDB `utxo_by_out_loc` column family.
#   * The Sprout nullifier rate. Sprout is drained; a 1000-block sample at tip
#     contains no Sprout spends at all, so the rate is reported as unverified
#     rather than as zero. `vjoinsplit` is nonetheless the correct field — it
#     was confirmed against early-chain blocks, where it counts non-zero.

set -euo pipefail

RPC_URL="${ZEBRA_RPC_URL:-http://127.0.0.1:8232}"
OUT_DIR="docs"
SAMPLE_BLOCKS=1000
ZEBRA_STATE_DIR="${ZEBRA_STATE_DIR:-}"
SYNCED=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc)            RPC_URL="$2"; shift 2 ;;
    --out)            OUT_DIR="$2"; shift 2 ;;
    --sample-blocks)  SAMPLE_BLOCKS="$2"; shift 2 ;;
    --state-dir)      ZEBRA_STATE_DIR="$2"; shift 2 ;;
    --allow-unsynced) ALLOWED_LAG=999999999; SYNCED=false; shift ;;
    -h|--help)        sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for tool in curl jq; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

# Ironwood activated here as part of NU6.3 (CLAUDE.md §7).
IRONWOOD_ACTIVATION=3428143
# Other activation heights, used to slice the fixture corpus.
SAPLING_ACTIVATION=419200
NU5_ACTIVATION=1687104
# The 2022-23 sandblasting window: the pathological high-output-count case, and
# real rather than synthetic.
SANDBLAST_START=1700000
SANDBLAST_END=2000000

rpc() {
  local method="$1"; shift
  local params="${1:-[]}"
  curl -fsS --max-time 60 \
    --data "{\"jsonrpc\":\"2.0\",\"id\":\"zutreexo\",\"method\":\"$method\",\"params\":$params}" \
    -H 'content-type: application/json' \
    "$RPC_URL" | jq -e '.result'
}

echo "==> checking node at $RPC_URL"
if ! INFO="$(rpc getblockchaininfo)"; then
  cat >&2 <<EOF
Could not reach zebrad at $RPC_URL.

Start a synced node with JSON-RPC enabled, e.g. in zebrad.toml:

  [rpc]
  listen_addr = "127.0.0.1:8232"

then rerun, or pass --rpc.
EOF
  exit 1
fi

TIP_HEIGHT="$(jq -r '.blocks' <<<"$INFO")"
CHAIN="$(jq -r '.chain' <<<"$INFO")"
echo "    chain=$CHAIN tip=$TIP_HEIGHT"

if [[ "$TIP_HEIGHT" -lt "$IRONWOOD_ACTIVATION" ]]; then
  echo "WARNING: tip is below Ironwood activation ($IRONWOOD_ACTIVATION)." >&2
  echo "         Ironwood pool figures will be empty." >&2
fi

# A baseline taken from a partially-synced node is not a baseline, it is a
# number that looks like one. Refuse by default rather than emit it: the whole
# point of this file is that later claims are measured against it, and an
# under-synced run would poison the IMT capacity ceiling in docs/design.md D3.
EST_HEIGHT="$(jq -r '.estimatedheight // 0' <<<"$INFO")"
BEHIND=$(( EST_HEIGHT > TIP_HEIGHT ? EST_HEIGHT - TIP_HEIGHT : 0 ))
if [[ "$BEHIND" -gt "${ALLOWED_LAG:-100}" ]]; then
  PROGRESS="$(jq -r '(.verificationprogress // 0) * 100 | floor' <<<"$INFO")"
  cat >&2 <<EOF

REFUSING TO MEASURE: node is $BEHIND blocks behind the estimated tip
($TIP_HEIGHT of $EST_HEIGHT, ~${PROGRESS}% verified).

Initial sync from genesis takes many hours. Wait for it:

  scripts/zebra-node.sh wait-sync

Meanwhile the IBD wall-clock and RSS baseline is only capturable *during*
sync — if no sampler is running, start one now, because that measurement
cannot be recovered afterwards:

  scripts/zebra-node.sh watch --interval 60 --out docs/ibd-baseline.csv

To override anyway (fixture capture at low heights, or a smoke test of this
script), re-run with --allow-unsynced. The output is then marked
"synced": false and must not be quoted as a baseline.
EOF
  exit 1
fi

# ---------------------------------------------------------------- section 1
# Sizes. Zcash exposes pool value totals via getblockchaininfo's valuePools,
# but *not* nullifier counts — nothing in the RPC surface reports those,
# because no consensus rule needs them. They have to come from a scan.

echo "==> 1/3 state sizes"

VALUE_POOLS="$(jq -c '.valuePools // []' <<<"$INFO")"

# z_gettreestate returns each pool's frontier, not a commitment count. The
# `finalState` hex is the serialized incremental-merkle-tree frontier — a few
# hundred bytes regardless of how many notes the tree holds — so its length
# says nothing about tree size. It is captured anyway because it pins the
# frontier and root we would have to reproduce, and because a changed byte
# length across releases is worth noticing.
#
# The commitment *count* is not exposed by any RPC. It is derived instead from
# the per-block shielded-output scan in section 2.
TREESTATE="$(rpc z_gettreestate "[\"$TIP_HEIGHT\"]" || echo '{}')"
TREESTATE_SUMMARY="$(jq -c '
  to_entries
  | map(select(.value | type == "object" and has("commitments")))
  | map({
      key: .key,
      value: {
        final_root: (.value.commitments.finalRoot // null),
        frontier_bytes: ((.value.commitments.finalState // "") | length / 2)
      }
    })
  | from_entries' <<<"$TREESTATE")"

# On-disk footprint. The state directory is the honest number for "what a node
# must keep"; per-column-family breakdown needs rocksdb tooling and is left to
# a follow-up.
DISK_BYTES="null"
if [[ -n "$ZEBRA_STATE_DIR" && -d "$ZEBRA_STATE_DIR" ]]; then
  DISK_BYTES="$(du -sb "$ZEBRA_STATE_DIR" | cut -f1)"
else
  echo "    (pass --state-dir for on-disk bytes)"
fi

RSS_KB="null"
if PID="$(pgrep -x zebrad | head -1)"; then
  RSS_KB="$(awk '/VmRSS/ {print $2}' "/proc/$PID/status" 2>/dev/null || echo null)"
fi

# ---------------------------------------------------------------- section 2
# Per-block rates. Sampled rather than exhaustive: a full scan of 3.4M blocks
# over JSON-RPC takes many hours, and the rate estimate does not need it.

echo "==> 2/3 per-block rates over $SAMPLE_BLOCKS blocks"

RATES_JSON="$(
  python3 - "$RPC_URL" "$TIP_HEIGHT" "$SAMPLE_BLOCKS" "$VALUE_POOLS" <<'PYTHON'
import json, sys, urllib.request

rpc_url, tip, sample = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
value_pools = json.loads(sys.argv[4]) if len(sys.argv) > 4 else []

def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": "z", "method": method,
                       "params": params}).encode()
    req = urllib.request.Request(rpc_url, data=body,
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["result"]

# Candidate JSON field names per pool, most likely first.
#
# Verification status against zebrad 6.3.0, sampled at heights 7141-7200:
#
#   sprout    CONFIRMED. `vjoinsplit` present and non-empty; 196 nullifiers
#             counted across 60 blocks, so the path is exercised, not just
#             present.
#   sapling   CONFIRMED by key presence. `vShieldedSpend` is emitted on every
#             transaction, including v1, as an empty array.
#   orchard   CONFIRMED by key presence. `orchard` is emitted unconditionally
#             as `{actions: [], valueBalance, valueBalanceZat}`, so
#             `orchard.actions` is the right path.
#   ironwood  UNVERIFIED. No `ironwood` key appears on any transaction in the
#             sample — but every sampled transaction predates the pool by
#             three million blocks, so that proves nothing. Note that Zebra
#             6.3.0 does know the pool: `getblockchaininfo.valuePools`
#             includes an `ironwood` entry and the upgrade table lists NU6.3
#             at height 3,428,143. What is unknown is only how an
#             Ironwood-bearing transaction is rendered, and that cannot be
#             learned until the node syncs past that height.
#
# A wrong name here does not throw. It silently counts zero, and a zero
# nullifier rate would feed straight into the IMT capacity ceiling and make it
# look far safer than it is. The cross-check at the bottom turns that silent
# zero into an explicit "unverified", which is why `ironwood` will be flagged
# on the first real run: the pool holds value at tip.
#
# `lockbox` also appears in valuePools. It is a value pool with no nullifiers
# (the NU6 development-fund lockbox), so it is deliberately absent below.
POOL_FIELDS = {
    "sprout":   [("vjoinsplit", 2), ("vJoinSplit", 2), ("joinsplits", 2)],
    "sapling":  [("vShieldedSpend", 1), ("vShieldedSpends", 1)],
    "orchard":  [("orchard.actions", 1), ("vActionsOrchard", 1)],
    "ironwood": [("ironwood.actions", 1), ("vActionsIronwood", 1)],
}

def dig(tx, path):
    """Follows a dotted path, returning a list or None if any step is absent."""
    node = tx
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, list) else None

totals = {"blocks": 0, "txs": 0, "t_in": 0, "t_out": 0,
          "sprout": 0, "sapling": 0, "orchard": 0, "ironwood": 0}

# Note commitments created, per pool. The commitment tree is the structure
# zutreexo deliberately leaves alone (CLAUDE.md §2), but its growth rate is
# part of the Phase 0 baseline, and no RPC reports the tree's size.
#
# Orchard and Ironwood actions carry exactly one nullifier and one commitment
# each, so the same array serves both counts. Sapling separates them, and each
# Sprout JoinSplit carries two of each.
COMMITMENT_FIELDS = {
    "sprout":   [("vjoinsplit", 2), ("vJoinSplit", 2), ("joinsplits", 2)],
    "sapling":  [("vShieldedOutput", 1), ("vShieldedOutputs", 1)],
    "orchard":  [("orchard.actions", 1), ("vActionsOrchard", 1)],
    "ironwood": [("ironwood.actions", 1), ("vActionsIronwood", 1)],
}
commitments = {"sprout": 0, "sapling": 0, "orchard": 0, "ironwood": 0}
# Which candidate actually matched, so the operator learns the real names.
matched_field = {}
# Union of every key seen on a tx object, for the same reason.
seen_keys = set()
shielded_versions = 0

start = max(1, tip - sample + 1)
for height in range(start, tip + 1):
    try:
        block = rpc("getblock", [str(height), 2])
    except Exception as exc:                      # noqa: BLE001
        print(f"warn: height {height}: {exc}", file=sys.stderr)
        continue

    totals["blocks"] += 1
    for tx in block.get("tx", []):
        totals["txs"] += 1
        seen_keys.update(tx.keys())
        totals["t_in"] += len(tx.get("vin", []))
        totals["t_out"] += len(tx.get("vout", []))

        # v4 carries Sapling and Sprout; v5 carries Orchard. A transaction at
        # these versions may still be purely transparent, so this is only a
        # hint — but a sample with zero of them means the sample says nothing
        # about shielded rates either way.
        if tx.get("version", 0) >= 4:
            shielded_versions += 1

        for pool, candidates in POOL_FIELDS.items():
            for path, per_item in candidates:
                items = dig(tx, path)
                if items is not None:
                    totals[pool] += per_item * len(items)
                    if items:
                        matched_field[pool] = path
                    break

        for pool, candidates in COMMITMENT_FIELDS.items():
            for path, per_item in candidates:
                items = dig(tx, path)
                if items is not None:
                    commitments[pool] += per_item * len(items)
                    break

blocks = max(1, totals["blocks"])
per_block = {k: v / blocks for k, v in totals.items() if k != "blocks"}
commitments_per_block = {k: v / blocks for k, v in commitments.items()}

# --- the cross-check ------------------------------------------------------
#
# `getblockchaininfo`'s valuePools is computed by consensus, independently of
# how transactions are rendered as JSON. If a pool holds value but the scan
# found no nullifiers for it, either the sample genuinely contains no spends
# from that pool, or the field name above is wrong. Those two are
# indistinguishable from the counts alone, so both are reported as unverified
# rather than as zero.
pool_has_value = {
    p.get("id"): (p.get("chainValueZat") or 0) > 0 for p in value_pools
}
warnings = []
unverified = []
for pool in ("sprout", "sapling", "orchard", "ironwood"):
    if totals[pool] == 0 and pool_has_value.get(pool):
        unverified.append(pool)
        warnings.append(
            f"pool '{pool}' holds value on-chain but the {blocks}-block sample "
            f"counted zero nullifiers. Either no {pool} spends occurred in this "
            f"range, or none of {[c[0] for c in POOL_FIELDS[pool]]} is the "
            f"field Zebra actually emits. Treat this rate as UNKNOWN, not zero."
        )

if shielded_versions == 0:
    warnings.append(
        f"no transaction at version >= 4 in the sample (heights {start}-{tip}); "
        "this range predates shielded activity, so every pool rate below is "
        "structurally zero and says nothing about mainnet."
    )

for w in warnings:
    print(f"warn: {w}", file=sys.stderr)

print(json.dumps({
    "range": [start, tip],
    "totals": totals,
    "per_block": per_block,
    "commitments_total": commitments,
    "commitments_per_block": commitments_per_block,
    "field_names_matched": matched_field,
    "pools_unverified": unverified,
    "tx_keys_observed": sorted(seen_keys),
    "warnings": warnings,
}, indent=2))
PYTHON
)"

# ---------------------------------------------------------------- section 3
# Fixture corpus. CLAUDE.md Phase 0 asks for these slices to be captured while
# a synced node is in front of us, so CI never needs a validator.

echo "==> 3/3 fixture corpus manifest"

# Anchored to the repo, not to --out: fixtures are corpus data with a committed
# manifest, and they belong in one known place regardless of where a given run
# writes its report.
FIXTURE_DIR="${FIXTURE_DIR:-$(cd "$(dirname "$0")/.." && pwd)/fixtures}"
mkdir -p "$FIXTURE_DIR"
SKIPPED_FIXTURES=()

capture_slice() {
  local name="$1" start="$2" count="$3"
  local target="$FIXTURE_DIR/$name.jsonl"
  local last=$((start + count - 1))

  # Skipped rather than attempted: below the tip these heights do not exist
  # yet, and hammering the RPC to collect a row of identical errors buries the
  # one fact worth reporting.
  if [[ "$last" -gt "$TIP_HEIGHT" ]]; then
    echo "    $name: SKIPPED (needs height $last, node is at $TIP_HEIGHT)"
    SKIPPED_FIXTURES+=("$name")
    return 0
  fi

  echo "    $name: heights $start..$last"
  : >"$target"
  for ((h = start; h <= last; h++)); do
    rpc getblock "[\"$h\", 0]" >>"$target" || {
      echo "      failed at height $h" >&2; break; }
  done
}

SLICE_LEN="${FIXTURE_SLICE_LEN:-200}"
capture_slice sapling-activation  "$SAPLING_ACTIVATION"  "$SLICE_LEN"
capture_slice nu5-orchard         "$NU5_ACTIVATION"      "$SLICE_LEN"
capture_slice sandblasting        "$SANDBLAST_START"     "$SLICE_LEN"
capture_slice ironwood-activation "$IRONWOOD_ACTIVATION" "$SLICE_LEN"

(
  cd "$FIXTURE_DIR"
  sha256sum ./*.jsonl >MANIFEST.sha256 2>/dev/null || true
)

# ---------------------------------------------------------------------------

REPORT="$OUT_DIR/baseline-$(date -u +%Y%m%dT%H%M%SZ).json"
jq -n \
  --arg chain "$CHAIN" \
  --argjson synced "$SYNCED" \
  --argjson tip "$TIP_HEIGHT" \
  --argjson value_pools "$VALUE_POOLS" \
  --argjson rates "$RATES_JSON" \
  --argjson treestate "$TREESTATE_SUMMARY" \
  --argjson disk_bytes "$DISK_BYTES" \
  --argjson rss_kb "$RSS_KB" \
  '{
     measured_at: (now | todate),
     synced: $synced,
     chain: $chain,
     tip_height: $tip,
     value_pools: $value_pools,
     treestate: $treestate,
     rates: $rates,
     node: { state_dir_bytes: $disk_bytes, rss_kb: $rss_kb }
   }' >"$REPORT"

echo
echo "wrote $REPORT"
echo "fixtures in $FIXTURE_DIR (manifest: MANIFEST.sha256)"
if [[ ${#SKIPPED_FIXTURES[@]} -gt 0 ]]; then
  echo "NOT captured (node not yet synced past them): ${SKIPPED_FIXTURES[*]}"
  echo "Rerun after sync completes; the corpus is incomplete until then."
fi
echo
echo "Next: fold these numbers into docs/benchmarks.md, and revisit the IMT"
echo "capacity ceiling in docs/design.md D3 against the measured growth rate."

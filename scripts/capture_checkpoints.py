#!/usr/bin/env python3
"""Capture the validator oracle: per-slice counts as *zebrad* reports them.

# What this is for

CLAUDE.md Phase 2 requires two oracles, and this produces the second one. The
naive model catches accumulator bugs. It cannot catch *parsing* bugs, because a
naive model and a real accumulator fed the same bad parse will agree with each
other and both be wrong. Only something that read the bytes by an independent
route can catch that.

That route is `zebrad`'s own JSON rendering. Our parser goes
raw block bytes -> `zebra_chain` consensus deserializer -> counts. This script
goes the same raw bytes -> zebrad's RPC serializer -> JSON -> counts. Agreement
means the parse is right, not merely self-consistent.

# Why the output is committed

CI has no synced node and never will. Running this writes a small JSON file per
slice into `crates/zutreexo-testkit/checkpoints/`, which the harness loads
offline. Re-run it only when the fixtures are re-captured or the parser changes
in a way that should move these numbers -- and if it does move them, find out
why before committing the new ones.

Usage:
    python3 scripts/capture_checkpoints.py                # all slices
    python3 scripts/capture_checkpoints.py ironwood-activation
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

RPC_URL = os.environ.get("ZEBRA_RPC_URL", "http://127.0.0.1:8232")

# Heights must stay in step with `capture_slice` in scripts/measure_baseline.sh.
SLICE_LEN = int(os.environ.get("FIXTURE_SLICE_LEN", "200"))
SLICES: dict[str, int] = {
    "sapling-activation": 419200,
    "nu5-orchard": 1687104,
    "sandblasting": 1700000,
    "ironwood-activation": 3428143,
}

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(REPO, "crates", "zutreexo-testkit", "checkpoints")


def rpc(method: str, params: list) -> dict:
    body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params})
    request = urllib.request.Request(
        RPC_URL,
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        payload = json.load(response)
    if payload.get("error"):
        raise RuntimeError(f"{method} failed: {payload['error']}")
    return payload["result"]


def count_block(height: int) -> dict[str, int]:
    """Counts one block the way zebrad's JSON describes it.

    Every field read here is chosen to be an *independent* statement of the same
    fact our deserializer extracts, not a restatement of it:

    * Sprout -- each JoinSplit reveals exactly two nullifiers and creates
      exactly two commitments, so `len(vjoinsplit) * 2` for both.
    * Sapling -- spends and outputs are separate arrays, so the two counts
      differ. That difference is useful: it is the control proving the
      Orchard/Ironwood equality below is a real constraint rather than an
      artifact of counting one array twice.
    * Orchard and Ironwood -- an action carries one nullifier and one
      commitment, so both counts equal the action count.
    * Transparent -- `vin` entries carrying a `coinbase` key reference no prior
      output and are not spends, which is exactly the exclusion our extractor
      makes.
    """
    block = rpc("getblock", [str(height), 2])
    counts = {
        "sprout_nullifiers": 0,
        "sapling_nullifiers": 0,
        "orchard_nullifiers": 0,
        "ironwood_nullifiers": 0,
        "sprout_commitments": 0,
        "sapling_commitments": 0,
        "orchard_commitments": 0,
        "ironwood_commitments": 0,
        "transparent_spends": 0,
        "transparent_creates": 0,
        "transactions": 0,
    }

    for tx in block.get("tx", []):
        counts["transactions"] += 1

        joinsplits = len(tx.get("vjoinsplit") or [])
        counts["sprout_nullifiers"] += joinsplits * 2
        counts["sprout_commitments"] += joinsplits * 2

        counts["sapling_nullifiers"] += len(tx.get("vShieldedSpend") or [])
        counts["sapling_commitments"] += len(tx.get("vShieldedOutput") or [])

        orchard_actions = len((tx.get("orchard") or {}).get("actions") or [])
        counts["orchard_nullifiers"] += orchard_actions
        counts["orchard_commitments"] += orchard_actions

        ironwood_actions = len((tx.get("ironwood") or {}).get("actions") or [])
        counts["ironwood_nullifiers"] += ironwood_actions
        counts["ironwood_commitments"] += ironwood_actions

        for vin in tx.get("vin") or []:
            if "coinbase" not in vin:
                counts["transparent_spends"] += 1
        counts["transparent_creates"] += len(tx.get("vout") or [])

    return counts


def capture(name: str, start: int) -> dict:
    end = start + SLICE_LEN - 1
    print(f"  {name}: heights {start}..{end}", flush=True)

    totals: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for counts in pool.map(count_block, range(start, end + 1)):
            for key, value in counts.items():
                totals[key] = totals.get(key, 0) + value

    return {
        "slice": name,
        "start_height": start,
        "end_height": end,
        "blocks": SLICE_LEN,
        "source": "zebrad getblock <height> 2",
        "captured_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "totals": dict(sorted(totals.items())),
    }


def main(argv: list[str]) -> int:
    wanted = argv[1:] or list(SLICES)
    unknown = [name for name in wanted if name not in SLICES]
    if unknown:
        print(f"error: unknown slice(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"known: {', '.join(SLICES)}", file=sys.stderr)
        return 2

    try:
        info = rpc("getblockchaininfo", [])
    except (urllib.error.URLError, OSError, RuntimeError) as exc:
        print(f"error: cannot reach zebrad at {RPC_URL}: {exc}", file=sys.stderr)
        return 2

    tip = info.get("blocks", 0)
    print(f"node at height {tip}")

    os.makedirs(OUT_DIR, exist_ok=True)
    for name in wanted:
        start = SLICES[name]
        end = start + SLICE_LEN - 1
        if end > tip:
            print(f"  {name}: SKIPPED (needs {end}, node at {tip})")
            continue
        record = capture(name, start)
        path = os.path.join(OUT_DIR, f"{name}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"    wrote {os.path.relpath(path, REPO)}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

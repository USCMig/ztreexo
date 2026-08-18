# Benchmarks

Two kinds of number live here, and conflating them would be the easiest way to
mislead:

* **Phase 1 micro-benchmarks** — measured, reproducible, below. They say what
  the accumulator primitives cost.
* **Phase 0 baselines** — measured 2026-08-12 at mainnet tip. They say what
  today's node costs, and every claim about whether this project is worth doing
  is a comparison against them.

Nothing here is yet a claim that zutreexo is faster than anything end to end.
The Phase 1 numbers are primitive costs; the comparison that matters is Phase 5.

---

## Phase 0 — baselines: MEASURED 2026-08-12

Against `zebrad 6.3.0`, mainnet, synced to height **3,444,700**
(`verificationprogress` 1.0), 16,557 blocks past Ironwood activation. Raw
output: `docs/baseline-20260812T004142Z.json`. Host is the same machine as the
Phase 1 benchmarks below.

### Node cost today — what zutreexo has to beat

| Measurement | Value |
|---|---|
| Initial block download, genesis to tip | **19.4 h** |
| Peak RSS during IBD | **5.07 GiB** |
| Steady-state RSS at tip | 4.70 GiB |
| Total state on disk | **298 GB** |
| Peers during IBD | median 10, max 31 |

Sampled every 60 s into `docs/ibd-baseline.csv` — 1,422 samples over 24.2 h, of
which the first 1,136 (19.44 h) cover IBD and the remainder are steady state at
tip. Sync averaged 49.2 blocks/s; the first hour ran near 9 blocks/s, so
early-sync rate is not representative of the whole. 156 of the 1,136 IBD
samples (14%) recorded zero peers — churn that did not stall the sync, but
worth watching if a rerun is slower.

### Per-block rates at tip (1,000-block sample, heights 3,443,701–3,444,700)

| Quantity | Per block | Sample total |
|---|---|---|
| Transactions | 4.619 | 4,619 |
| Transparent inputs | 7.118 | 7,118 |
| Transparent outputs | 5.716 | 5,716 |
| Sapling nullifiers | 0.138 | 138 |
| Orchard nullifiers | **6.192** | 6,192 |
| Ironwood nullifiers | **2.934** | 2,934 |
| Sprout nullifiers | *unverified* | 0 |
| **Total shielded nullifiers** | **9.264** | 9,264 |

Note commitments created per block: Sapling 0.330, Orchard 6.192, Ironwood
2.934. Orchard and Ironwood actions carry one nullifier and one commitment
each, so those two columns coincide by construction.

**Sprout reads as unverified, not zero.** The 1,000-block sample contains no
Sprout spends — the pool is legacy and drained — so the scan cannot distinguish
"no activity" from "wrong field name". The cross-check reports it as unknown by
design. `vjoinsplit` *is* the correct field: it counted 196 nullifiers over 60
blocks at heights 7,141–7,200.

**Orchard still out-spends Ironwood roughly 2:1.** Ironwood is the larger pool
by value, but Orchard is withdraw-only, and withdrawals are exactly what
produce nullifiers. Expect Orchard's rate to decay toward zero as it drains and
Ironwood's to absorb it, so the long-run per-pool steady state is closer to the
combined 9.1/block landing in one tree.

### Transparent UTXO set: not growing

Transparent inputs (7.118/block) exceed outputs (5.716/block). Roughly one
input per block is a coinbase, which spends nothing, so real spends are ~6.1/block
against 5.7 outputs — **the transparent UTXO set is approximately flat, not
growing.**

That matters for the question Phase 5 is meant to settle. Utreexo's storage
saving is proportional to the set it replaces; if that set is in steady state,
the saving does not compound, while the proof bandwidth is paid on every block
forever. Combined with the upstream defect in `docs/design.md` D10, the case
for shipping the transparent forest is weaker after this measurement than
before it.

### Still not measured

**The transparent UTXO set count.** Zebra does not implement `gettxoutsetinfo`
(`-32601 Method not found`), and no other RPC reports it. Getting the exact
count needs either a full-history scan or a read-only open of Zebra's RocksDB
`utxo_by_out_loc` column family. Left undone rather than estimated.

**Commitment tree sizes.** `z_gettreestate` returns each pool's *frontier*, not
a count — 418 B (Sapling), 322 B (Orchard), 354 B (Ironwood), which is
frontier serialization and independent of tree size. Roots are recorded in the
JSON. Commitment counts would come from the same full scan as above.

### Fixture corpus

Captured, 200 blocks per slice, raw block hex:

| Slice | Heights | Size |
|---|---|---|
| Sapling activation | 419,200–419,399 | 4.3 MB |
| NU5 / Orchard | 1,687,104–1,687,303 | 1.9 MB |
| Sandblasting | 1,700,000–1,700,199 | 2.1 MB |
| Ironwood activation | 3,428,143–3,428,342 | 59.3 MB |

65 MB total. `fixtures/MANIFEST.sha256` is committed; the `.jsonl` files are
gitignored and belong in LFS or a bucket. Regenerate with
`scripts/measure_baseline.sh`.

The Ironwood slice is 14× the size of the NU5 slice for the same block count —
activation-window blocks are dense.

---

## Phase 0 — how the measurement is guarded

The node is defined in `docker/` — a pinned `zfnd/zebra` mainnet container,
driven by `scripts/zebra-node.sh`. RPC is on `127.0.0.1:8232`; the `8234` in
`docker/.env` is the **P2P** port, moved off 8233 because another container
holds it.

`scripts/measure_baseline.sh` refuses to run against an under-synced node
rather than emitting a plausible-looking number; `--allow-unsynced` overrides
it and marks the output `"synced": false`. Reproduce with:

```bash
scripts/measure_baseline.sh --state-dir "$(scripts/zebra-node.sh state-dir)"
```

### RPC field verification

The per-block nullifier rate is read out of `getblock` verbosity 2. Zcash RPC
field naming has drifted across implementations, and a wrong name here does not
error — it silently counts **zero**, which would flow straight into the IMT
capacity ceiling and make it look far safer than it is. Status against
zebrad 6.3.0:

| Pool | Field | Status |
|---|---|---|
| Sprout | `vjoinsplit` (×2 per JoinSplit) | **confirmed** — 196 nullifiers over 60 blocks at heights 7,141–7,200 |
| Sapling | `vShieldedSpend` | **confirmed** — 138 nullifiers in the tip sample |
| Orchard | `orchard.actions` | **confirmed** — 6,192 nullifiers in the tip sample |
| Ironwood | `ironwood.actions` | **confirmed** — 2,934 nullifiers in the tip sample |

All four resolved. Ironwood matched the first candidate guess, but only the
post-activation run could establish that.

The script cross-checks each pool's counted nullifiers against its
`valuePools` balance, which is computed by consensus and independent of JSON
naming. A pool holding value but counting zero nullifiers is reported in
`pools_unverified` rather than as a rate of zero — which is what happened to
Sprout, correctly.

`lockbox` also appears in `valuePools`; it is the NU6 development-fund pool and
has no nullifiers, so it is deliberately not tracked.

### CLAUDE.md Phase 0 checklist

| Measurement | Status |
|---|---|
| Transparent UTXO set: on-disk bytes | measured (298 GB total state; per-CF breakdown outstanding) |
| Transparent UTXO set: count | **outstanding** — no RPC exposes it |
| Nullifier set per pool: rate | measured |
| Nullifier set per pool: absolute count | **outstanding** — needs a full scan |
| Note commitment tree: creation rate | measured |
| Note commitment tree: absolute size | **outstanding** — frontier only via RPC |
| Per-block transparent inputs/outputs | measured |
| Per-block nullifiers revealed, per pool | measured (Sprout unverified — drained) |
| Zebra IBD wall-clock and peak RSS | measured |
| Fixture corpus + manifest | captured |

The outstanding rows all reduce to one task: a full-history scan, or a
read-only open of Zebra's RocksDB. They are absolute *stocks*; the capacity
question in D3 turns on *flows*, which are measured.

Both decisions that waited on Phase 0 can now be taken:

1. **The IMT capacity ceiling** (`docs/design.md` D3). Measured — and it
   disproved the original headroom claim. See the correction there; a depth
   decision is now open and must be settled before Phase 3.
2. **Whether the transparent forest is worth shipping.** The measured UTXO set
   is approximately flat (above), which weakens the case.

Re-running the whole thing from a cold node:

```bash
scripts/zebra-node.sh up                 # start the node (docker/README.md)
# IBD wall-clock and RSS are only capturable *during* sync, not afterwards:
scripts/zebra-node.sh watch --interval 60 --out docs/ibd-baseline.csv &
scripts/zebra-node.sh wait-sync          # ~19 h from genesis on this host
scripts/measure_baseline.sh --state-dir "$(scripts/zebra-node.sh state-dir)"
```

The same run captures the fixture corpus listed above, so CI never needs a
validator.

---

## Phase 1 — accumulator micro-benchmarks

```bash
cargo bench -p zutreexo-accumulator
```

**Machine:** 12th Gen Intel Core i5-12450H, 12 threads, 62 GiB RAM,
`rustc` 1.92.0, release profile with `overflow-checks = true`.
Single-threaded throughout. Criterion reports [lower, estimate, upper]; the
estimate is quoted below.

### Nullifier IMT — the numbers that matter

At the default depth, which is **40** as of 2026-08-14 (`docs/design.md` D3).
Depth-32 figures are kept alongside because the depth decision was taken partway
through and the comparison is the evidence for what it cost.

| Operation | 10⁴ nullifiers | 10⁶ nullifiers | Scaling in set size |
|---|---|---|---|
| `insert` (d40) | 22.7 µs | 25.2 µs | ~flat |
| `prove_non_membership` (d40) | 2.97 µs | 3.03 µs | `O(log n)` map lookup |
| `verify_non_membership` (d40) | **5.17 µs** | **5.15 µs** | **none** |
| *`insert` (d32)* | *18.1 µs* | *21.1 µs* | *~flat* |
| *`prove_non_membership` (d32)* | *1.27 µs* | *2.68 µs* | *`O(log n)`* |
| *`verify_non_membership` (d32)* | *4.14 µs* | *4.13 µs* | *none* |

Moving from depth 32 to 40 cost +25% on verification and +20% on insertion —
matching the prediction from the per-level cost, since eight more levels is
eight more hash compressions. **The flatness survived**, which is the property
the whole design rests on: verification still does not care how many nullifiers
exist.

**Verification is flat across a hundred-fold increase in set size.** That is the
whole design claim on the shielded side, and it is the number Phase 5's headline
result rests on: a wallet resuming after a long absence pays `O(log n)` per note
regardless of how long it was away, where today it scans every block's revealed
nullifiers and pays linearly in the gap.

The residual growth in `insert` and `prove` is the `BTreeMap` lookup that finds
the low leaf, not Merkle work. The tree is fixed-depth, so the hashing is 32 or
64 compressions whatever `n` is.

### Verification cost is linear in depth, and nothing else

| Depth | Capacity | `verify_non_membership` | ns per level |
|---|---|---|---|
| 16 | 65,536 | 2.11 µs | 132 |
| 24 | 16.8 M | 3.09 µs | 129 |
| 32 | 4.29 G | 4.07 µs | 127 |
| 40 | 1.10 T | 5.07 µs | 127 |

Two things follow. First, ~127 ns per level is one BLAKE2b-256 compression, so
verification is doing exactly the work it should and no more. Second, this is
why the 10⁸ column is reportable without building a 10⁸-element tree: the proof
shape at depth 32 is identical whether the tree holds ten values or four
billion, so 4.07 µs *is* the 10⁸ figure.

### Proof sizes — the cost side

| Depth | Non-membership | Insertion |
|---|---|---|
| 16 | 594 B | 1,115 B |
| 24 | 850 B | 1,627 B |
| 32 | **1,106 B** | **2,139 B** |
| 40 | 1,362 B | 2,651 B |

Canonical encoding, version byte included. An insertion proof carries two
sibling paths — the low leaf's and the append position's — hence roughly double.

Bandwidth is the honest cost of this design, and these are the raw
per-proof figures rather than a per-block total. What a node actually downloads
depends on nullifiers per block, which is a Phase 0 measurement, and on
deduplication across proofs sharing internal nodes, which is a Phase 4 one.
**Do not extrapolate a bandwidth overhead from this table alone.**

Decode plus re-encode of a depth-32 non-membership proof: 500 ns.

Empty-tree root computation at depth 32, done once at startup per pool: 8.11 µs.

### Transparent Utreexo

| Set size | `prove_single` | `verify_single` | `verify_batch` (~64 targets) |
|---|---|---|---|
| 10³ | 1.03 µs | 1.93 µs | 60.0 µs |
| 10⁴ | 1.44 µs | 2.76 µs | 103.8 µs |
| 10⁵ | 2.04 µs | 3.45 µs | — |

**These are additions-only, and that is not a methodological choice.**
`rustreexo` 0.6.0 cannot generate a valid inclusion proof for a leaf whose
sibling has been deleted (`docs/design.md` D10), so a delete-inclusive benchmark
would be timing a path that does not work. Delete costs, and the batch-proof
deduplication saving Phase 4 needs, go in once that is resolved.

### What is deliberately absent

* **`insert` and `prove` at 10⁸.** The in-memory tree holds every leaf and every
  populated internal node — roughly 20 GB at that size. That is what Phase 3's
  on-disk representation is for. `ZUTREEXO_BENCH_HUGE=1 cargo bench` runs it on
  a machine with the memory. A fabricated number would be worse than none.
* **Anything resembling wall-clock wallet sync.** Wallet sync is dominated by
  trial decryption, which no accumulator changes (CLAUDE.md §2.2). Benchmarking
  against Slipstream's or Warp Sync's figures would produce an unimpressive
  result for a reason unrelated to whether this design is sound.
* **Per-block validation latency, peak RSS, steady-state disk.** Phase 5, and
  meaningless before the Phase 0 baseline exists.

### Reproducing

```bash
cargo bench -p zutreexo-accumulator                       # everything above
cargo bench -p zutreexo-accumulator -- imt/verify         # the headline only
ZUTREEXO_BENCH_HUGE=1 cargo bench -p zutreexo-accumulator # adds the 10^8 case
```

Benchmark inputs come from a seeded xorshift generator, never from system
entropy or time, so runs are comparable across machines and dates (CLAUDE.md §5
rule 5).

---

## Stage 2d — genesis-forward replay, 2026-08-18

`cargo run --release -p zutreexo-testkit --bin genesis_replay`, depth 40,
against a synced zebrad at tip 3,451,769.

**Blocks 0..1,950,000 applied with zero errors** — 56% of chain history,
including Sapling activation, NU5/Orchard activation, and the 2022–23
sandblasting era. The run stopped on its 24 GiB memory ceiling, not on a fault.

| height | unspent outputs | sprout | sapling | orchard | RSS | rate |
|---|---|---|---|---|---|---|
| 100,000 | 13,637,623 | 302,178 | 0 | 0 | 7.2 GiB | 1265 blk/s |
| 300,000 | 28,203,068 | 911,208 | 0 | 0 | 16.2 GiB | 253 blk/s |
| 500,000 | 21,632,152 | 1,326,758 | 26,973 | 0 | 17.3 GiB | 875 blk/s |
| 1,000,000 | 17,214,940 | 1,533,458 | 302,300 | 0 | 17.3 GiB | 1450 blk/s |
| 1,700,000 | 21,180,838 | 1,545,080 | 831,673 | 296 | 17.4 GiB | 1524 blk/s |
| 1,800,000 | 20,164,946 | 1,545,100 | 1,352,874 | 4,522,350 | 17.8 GiB | 9 blk/s |
| 1,900,000 | 14,837,461 | 1,545,186 | 1,411,280 | 23,120,491 | 20.6 GiB | 15 blk/s |
| 1,950,000 | 15,009,468 | 1,545,196 | 1,430,900 | 31,962,354 | 24.0 GiB | — |

Total wall clock 361 minutes. Fetching is not the constraint: RPC serves ~2,000
blocks/s at eight workers, so the whole chain downloads in about half an hour.

### The transparent UTXO set is large, which cuts against a Phase 5 expectation

**Closes a Phase 0 gap** — Zebra does not implement `gettxoutsetinfo`, so this
had never been measured.

The set peaks near **28.2M unspent outputs around height 300,000** and settles
around 15–21M. Early history is dominated by mining-pool payout transactions:
blocks near height 20,000 average **257 outputs each**, a net +233 UTXOs per
block. That was verified against the node directly rather than trusted, because
13.6M unspent outputs at height 100,000 did not look credible.

CLAUDE.md Phase 5 anticipates that "Zcash's transparent UTXO set is far smaller
than Bitcoin's, so the transparent-side Utreexo storage win may not justify its
proof bandwidth". At 15–28M outputs that expectation looks doubtful — Bitcoin's
own set is of the same order. **Phase 5 should test this rather than assume it,
and the answer may now favour keeping the transparent forest.**

At **553 bytes per unspent output** the transparent side dominates memory
entirely; the nullifier trees are a rounding error beside it until Orchard
arrives.

### Orchard nullifier growth is 20× the rate Phase 0 extrapolated from

Orchard opens at NU5 (height 1,687,104) and reaches **31.96M nullifiers by
height 1,950,000** — about 121 per block sustained across the sandblasting
period, against the **6.192/block** measured at tip in Phase 0.

This does not invalidate the depth-40 decision (D3): 2^40 absorbs it with room
to spare, and the asymmetry argument that chose 40 over 32 is only strengthened.
It does show the tip rate is a poor basis for extrapolation. A sustained 121/
block would exhaust depth 32 in roughly 84 years rather than the 1,648 that D3's
tip-rate figure implies — still survivable, but the twenty-fold gap between a
quiet period and an attack period is the number to reason with.

**It also corrects a Phase 0 estimate.** Phase 0 put full-history nullifier
memory at 4.6–8.5 GiB from 327 B/nullifier. Orchard alone already exceeds the
implied count at 56% of the chain.

### Throughput collapses under sandblasting

1,265 blk/s at height 100,000; **9 blk/s** through the sandblasting window. Two
causes compound: ~121 nullifier insertions per block at depth 40, each touching
two 40-node Merkle paths, and B-tree operations over a growing state.

Relevant to Phase 5's per-block validation latency, and a reminder that p50 over
quiet history would badly misrepresent the p99 a real node must survive.

### What this run does not establish

The cold-rebuild check ran **5 times and was skipped 75 times** — it is capped
at 200,000 nullifiers per pool and the pools outgrow that quickly. Drift
detection over long replays is therefore weak, and stays weak until there is a
rebuild strategy that scales. Small-scale coverage in 2b and 2c is unaffected.

Reaching tip needs either more memory headroom or a leaner UTXO index; at 553
bytes per output, storing the precomputed leaf hash instead of the whole
`UtxoLeaf` would cut the dominant term by roughly an order of magnitude, at the
cost of rollback needing another source for the leaf contents.

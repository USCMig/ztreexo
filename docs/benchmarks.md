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

## Stage 2d — genesis-to-tip replay, 2026-08-18

`cargo run --release -p zutreexo-testkit --bin genesis_replay`, depth 40,
against a synced zebrad at tip 3,452,735.

**All 3,452,736 blocks applied from genesis with zero errors.** 7h02m wall
clock, peak RSS 32.7 GiB. 71 from-scratch root rebuilds, all matching the
incremental roots.

That satisfies the amended Phase 2 definition of done. It is a substantive
claim rather than an absence of evidence: the IMT rejects duplicate nullifiers
and the applier rejects unresolvable spends, so a mis-parsed nullifier would
collide and a mis-parsed outpoint would fail to resolve. Neither happened across
54.1M nullifiers and 3.45M blocks.

A first attempt stopped at height 1,950,000 on a 24 GiB ceiling. The numbers
below match that run exactly at every shared checkpoint, which is unplanned but
welcome evidence of determinism.

### Final state at tip

| | count |
|---|---|
| unspent transparent outputs | 27,529,579 |
| Sprout nullifiers | 1,547,198 |
| Sapling nullifiers | 2,129,852 |
| Orchard nullifiers | 50,392,547 |
| Ironwood nullifiers | 70,380 |
| **total nullifiers** | **54,139,977** |

The transparent forest holds 12 perfect trees.

### Growth, and where the cost lives

| height | unspent outputs | orchard | RSS | rate |
|---|---|---|---|---|
| 100,000 | 13,637,623 | 0 | 7.2 GiB | 1,222 blk/s |
| 300,000 | 28,203,068 | 0 | 16.3 GiB | 253 blk/s |
| 1,700,000 | 21,180,838 | 296 | 17.4 GiB | 1,507 blk/s |
| 1,800,000 | 20,164,946 | 4,522,350 | 17.9 GiB | **9 blk/s** |
| 1,900,000 | 14,837,461 | 23,120,491 | 20.8 GiB | 15 blk/s |
| 2,100,000 | 15,384,937 | 46,996,381 | 29.5 GiB | 84 blk/s |
| 2,700,000 | 28,326,522 | 48,941,510 | 33.3 GiB | 762 blk/s |
| 3,452,735 | 27,529,579 | 50,392,547 | 32.7 GiB | 1,568 blk/s |

Throughput spans **9 to 1,568 blocks/s — a 165× range** — and memory climbs from
17 GiB to 32 GiB almost entirely between heights 1.7M and 2.1M, which is Orchard
going from 296 nullifiers to 47 million.

**For Phase 5 this is the headline, not the average.** A p50 taken over quiet
history understates the p99 a node must survive by more than two orders of
magnitude. Report per-block latency as a distribution over the sandblasting
window, not as a mean over all history.

Fetching is never the constraint: RPC serves ~2,000 blocks/s at eight workers,
so the whole chain downloads in about half an hour.

### The transparent UTXO set is not small

**Closes a Phase 0 gap** — Zebra does not implement `gettxoutsetinfo`, so this
had never been measured.

27.5M unspent outputs at tip, having peaked at 28.3M and dipped to 14.8M
mid-history. Early blocks average 257 outputs each (mining-pool payouts), which
was verified against the node rather than trusted, because 13.6M unspent at
height 100,000 did not look credible.

CLAUDE.md Phase 5 anticipates that "Zcash's transparent UTXO set is far smaller
than Bitcoin's, so the transparent-side Utreexo storage win may not justify its
proof bandwidth". At 27.5M outputs it is the same order of magnitude as
Bitcoin's. **That expectation should be tested, not assumed, and the answer may
now favour keeping the transparent forest.**

At roughly 550 bytes per unspent output the transparent index dominates memory
for the first half of history; Orchard overtakes it after NU5.

### Phase 0 corrections

**Nullifier volume was underestimated 2–3×.** Phase 0 put full-history nullifier
memory at 4.6–8.5 GiB from 327 B/nullifier. The real total is 54.1M nullifiers.
Depth 40 still absorbs this with enormous margin — 2^40 is 1.1e12, so the set is
0.005% of capacity — and the asymmetry argument behind D3 is only strengthened.

**The tip rate is a poor basis for extrapolation.** Orchard averaged ~121
nullifiers/block through sandblasting against the 6.192/block measured at tip:
a twenty-fold gap between a quiet period and an attack period. Any capacity
projection should use the attack rate.

**Ironwood confirms Phase 0 independently.** 70,380 nullifiers over the 24,592
blocks since activation at 3,428,143 is 2.86/block, against 2.934/block measured
separately at tip.

### Cold rebuild coverage

71 rebuilds performed, 73 skipped for exceeding the cap. The skips are Orchard
and Sapling in later history; every pool was checked repeatedly before it grew
past the ceiling.

This became affordable only after replacing the rebuild algorithm. Replaying
every insertion via `from_values` costs `2 * depth` hashes per value — 80 at
depth 40, so 4 billion hashes for Orchard at tip. `IndexedMerkleTree::
rebuild_root` folds the tree a level at a time instead, roughly three hashes per
value, about **27× cheaper**. That moved the practical ceiling from 200,000
values to tens of millions, taking the check from 5 rebuilds on the first run to
71 here.

It is also a stronger check: successor links are rebuilt by sorting the values
rather than copied from the stored leaves, so it catches a stale `next_value` or
`next_index` as well as a stale internal node.

---

## Phase 3 — snapshots, 2026-08-19

Measured on real mainnet state: a genesis replay to height 250,000, saved and
reloaded.

| | |
|---|---|
| replay to height 250,000 | **10.1 min** |
| snapshot written | **3.85 GB in 12.5 s** |
| snapshot loaded | **21.5 s** |
| **speedup, replay → load** | **28×** |
| unspent outputs at that height | 23,358,418 |
| peak RSS, replay | 12.4 GiB |
| peak RSS, load | 12.7 GiB |

All four nullifier roots after loading are byte-identical to the roots the
replay produced. Speed without that would be worthless, so it is checked rather
than assumed.

Extrapolating to tip — 27.5M unspent outputs and 54.1M nullifiers — a full
snapshot should be roughly 6 GB, against a 7-hour replay.

### Where the bytes go

Nullifiers cost 32 bytes each on disk against roughly 600 in memory, because
only the values are stored and everything else is rederived (`docs/design.md`
D22). At height 250,000 the transparent index dominates completely: 23.4M
outputs against 0.72M nullifiers.

That ratio inverts after NU5. At tip the nullifier side is 54.1M against 27.5M
outputs, but the nullifiers still cost less on disk than in memory by a factor
of nearly twenty, whereas the UTXO index is stored close to its in-memory size.

**A snapshot does not reduce the working set.** Loading 3.85 GB produced 12.7
GiB resident — very close to what the replay itself used, which is the point:
the format is a faithful round trip, not a compression scheme. Cutting the
32.7 GiB tip footprint needs the `UtxoLeaf`-to-leaf-hash change, which is
separate work.

### Crash consistency

`tests/crash.rs`, release build, 25 rounds per configuration:

| writer | kills | target intact | damaged |
|---|---|---|---|
| atomic (temp + fsync + rename) | 25 | **25** | 0 |
| non-atomic control (direct write) | 25 | ~5 | **~20** |

7 of the 25 atomic rounds left a temp file behind, confirming the kill landed
between `create` and `rename` rather than outside the write window.

The control exists because 25 clean kills look identical whether the writer is
atomic or the kills never landed on a write — which is exactly what the first
version of this harness did, and it passed. See `docs/design.md` D23.

---

## Phase 4a — proof bundles: what a compact node downloads, 2026-08-20

Measured by `crates/zutreexo-testkit/src/bin/csn_replay.rs` against a synced
`zebrad` 6.3.0 at mainnet tip. Every block is applied twice — once by a bridge
holding full state, once by a compact node holding only roots — and the roots
are compared after each. A divergence aborts the run, so these describe a
protocol that verified, not one that merely serialised.

```
ZUTREEXO_RPC=127.0.0.1:8232 ZUTREEXO_END=150000 \
  cargo run --release -p zutreexo-testkit --bin csn_replay
```

### Heights 0–150,000, depth 40

| | |
|---|---|
| blocks | 150,001 |
| elapsed | 628.9 s (239 blk/s at the end) |
| transparent spends | 16,898,753 |
| nullifiers | 449,698 |
| block bytes | 4,250,648,599 |
| bundle bytes | 7,248,205,320 |
| **proof overhead** | **170.5%** |

**This is the bad number, and it is worse than it first looked.** A compact node
downloads 1.7× as much in proofs as it does in blocks. Bitcoin's Utreexo
simulations saw roughly a quarter more download; this is nearly seven times
that.

**It also gets worse with height, which is the more important finding:**

| through height | overhead |
|---|---|
| 25,000 | 100.9% |
| 50,000 | 109.0% |
| 75,000 | 122.5% |
| 100,000 | 131.5% |
| 125,000 | 175.3% |
| 150,000 | 170.5% |

A single number would have hidden this. The trend is what matters, because it
says the cost is not a fixed tax — it tracks the growth of the transparent UTXO
set, which Phase 0 measured at 27.5M outputs at tip against the ~1.2M reached by
height 150,000. Extrapolating from six points across 4% of the chain would be
irresponsible, so no figure for tip is offered here; what is claimed is the
direction, and the direction is unfavourable.

### Where the bytes go

| component | bytes | share |
|---|---|---|
| **Utreexo inclusion proofs** | **4,733,477,880** | **65.3%** |
| spent leaf contents | 1,318,208,796 | 18.2% |
| nullifier insertion proofs | 1,192,149,398 | 16.4% |

**Two predictions were wrong here, and the correction is the useful part.**
`bundle.rs`'s first draft called the spent leaf contents "the single largest
term". They are the smallest. And an earlier run over heights 0–20,000 put
nullifier proofs at 40.5% and Utreexo proofs at 32.0% — the opposite ordering —
which was an artefact of the early chain having few transparent spends. Over
150,000 blocks there are 16.9M transparent spends against 450k nullifiers, and
the transparent side dominates by a factor of four.

The lesson is about the measurement, not the design: a 20,000-block range looked
like plenty and gave a confidently wrong answer about which half of the system
to optimise.

### Batching, over 12,471 blocks with two or more inputs (heights 0–20,000)

| | bytes |
|---|---|
| one proof per input | 1,005,753,525 |
| one batched proof | 146,646,288 |
| **saving** | **85.4%** |

CLAUDE.md Phase 4 asks for proof aggregation and predicts that inputs in the
same block share internal nodes. They do, and it is worth far more than
expected. `rustreexo`'s `Proof` is natively multi-target, so this is a property
of the type rather than an optimisation layered on top — the work was measuring
it, not building it. Given that the Utreexo term is now known to dominate, this
85.4% is the difference between an unattractive design and an unusable one.

**This measurement was wrong once and said so.** The first version proved each
input individually *after* applying the block, by which time the leaves are
deleted and every `prove` fails. It skipped all 12,471 blocks and printed "no
block in this range had two or more provable inputs" over a range holding 1.6
million spends. It reported that rather than a plausible number, which is the
only reason it was caught. Enabling it costs roughly double the runtime, so it
is behind `ZUTREEXO_MEASURE_BATCHING=1` and the 150,000-block run above does not
include it.

### An optimisation available but not taken

Over heights 0–20,000, **71.4% of the sibling hashes in nullifier proofs**
(4,027,481 of 5,641,440) are the canonical empty-subtree hash for their level. A
depth-40 tree holding 70,518 nullifiers is overwhelmingly empty, so above
roughly `log2(leaf_count)` every sibling on a path is a value both sides derive
from the pool's domain separator and the level. That is 128,879,392 of the
186,943,218 bytes spent on nullifier proofs in that range.

A bitmap of which siblings are non-empty would remove most of it. But the
nullifier term is only 16.4% of the bundle over the longer range, so this is
worth roughly 11% of the total — useful, not decisive. **The 65.3% sitting in
Utreexo proofs is where the work belongs**, and that is a question about
`rustreexo`'s proof encoding rather than ours.

Both are wire-format changes and belong with the Phase 4b transport, before the
format has clients. Neither has been implemented or measured at the new size;
the percentages above are projections from a byte census.

### What this does not measure

The headline Phase 5 result is **nullifier-check cost against gap length** for a
*wallet* — one `O(log n)` non-membership proof per note against scanning every
block since last sync. That is a different query by a different actor, and
nothing here bears on it. These numbers are the cost of a compact node doing
initial block download, which is the axis where an accumulator is most exposed.

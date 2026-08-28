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
clock, RSS 32.7 GiB at tip. 71 from-scratch root rebuilds, all matching the
incremental roots.

> **Corrected 2026-08-22.** This read "peak RSS 32.7 GiB". It was the *final*
> `VmRSS`, not a peak — the binary was reading the wrong field and the table
> below already contradicted it at height 2,700,000. Phase 5b re-ran the same
> replay reading `VmHWM` and measured a true peak of **40.6 GiB**, 24% higher.
> The 32.7 GiB figure reproduced exactly as the final `VmRSS`, which is how the
> mistake was identified rather than merely suspected.

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

---

## Phase 5a — the headline: nullifier-check cost against gap length, 2026-08-20

CLAUDE.md Phase 5 calls this "the headline result". Measured by
`crates/zutreexo-testkit/src/bin/gap_cost.rs` over the most recent 400,001
blocks — heights 3,054,402 to 3,454,402, roughly a year at 75 s/block.

```
ZUTREEXO_RPC=127.0.0.1:8232 ZUTREEXO_GAP_BLOCKS=400000 \
  cargo run --release -p zutreexo-testkit --bin gap_cost
```

| | |
|---|---|
| nullifiers revealed | 1,349,457 (3.4 per block) |
| nullifier bytes | 43,182,624 |
| compact-block bytes | 293,557,540 |
| **nullifiers as a share of a compact sync** | **14.7%** |
| non-membership proof, depth 40 | **1,362 bytes** |
| sparse-path variant (projected) | 631 bytes |

### The answer depends on which question is asked, so both are reported

**Framing A — the wallet only wants spend status.** A watch-only balance, or
the check before attempting a spend. Scanning is `O(gap)`; proofs are `O(notes)`
and flat.

| gap (blocks) | nullifiers | scan bytes | 1 note | 10 notes | 100 notes |
|---|---|---|---|---|---|
| 10 | 57 | 1,824 | proofs 1.3× | scan 7.5× | scan 74.7× |
| 100 | 839 | 26,848 | proofs 19.7× | proofs 2.0× | scan 5.1× |
| 1,000 | 9,094 | 291,008 | proofs 213.7× | proofs 21.4× | proofs 2.1× |
| 10,000 | 68,448 | 2,190,336 | proofs 1,608× | proofs 161× | proofs 16.1× |
| 100,000 | 458,491 | 14,671,712 | proofs 10,772× | proofs 1,077× | proofs 108× |
| 400,000 | 1,349,457 | 43,182,624 | proofs 31,705× | proofs 3,170× | proofs 317× |

Crossovers at the measured rate:

| wallet | proofs win beyond | in time |
|---|---|---|
| 1 note | 13 blocks | ~16 minutes |
| 10 notes | 126 blocks | ~2.6 hours |
| 100 notes | 1,262 blocks | ~26 hours |

**The claim in CLAUDE.md holds, and decisively.** Any wallet offline longer
than about a day is better off with proofs even holding 100 notes, and a
year-long gap favours them by two to four orders of magnitude. This is the
result the project was built to find.

> **Read this table with `docs/design.md` D35 attached (added 2026-08-22).**
> Phase 6's privacy review concludes that **this exact query cannot be made
> privately.** Asking a bridge about a specific nullifier hands over a value
> only the note's owner could compute, and batching several links those notes
> to one wallet. Decoys do not fix it: when the note is later spent the real
> nullifier appears on-chain and the anonymity set collapses to one.
>
> So the numbers above are a *bandwidth* measurement of a query a
> privacy-conscious Zcash wallet should not make. Together with the trust
> caveat below, that is two independent reasons the headline is weaker than
> 31,705× suggests. The compact-node results in Phases 4 and 5b are unaffected;
> they request by height and leak nothing.

**Framing B — the wallet is doing a full sync.** It also wants notes *received*
during the gap, which needs trial decryption, which needs the compact block for
every block in the gap regardless. The nullifiers are already inside that
download, so proofs do not replace it — they are added to it, and dropping the
nullifiers from the wire is the only saving available.

| gap | compact sync | nullifiers within it | best case saving |
|---|---|---|---|
| 1,000 | 1,573,740 B | 291,008 B | 18.5% |
| 10,000 | 11,901,048 B | 2,190,336 B | 18.4% |
| 100,000 | 85,072,000 B | 14,671,712 B | 17.2% |
| 400,000 | 293,557,504 B | 43,182,624 B | 14.7% |

**At most 14.7% of the bytes over a year-long gap, and 0% of the trial
decryption**, which §2.2 already identifies as the dominant cost and which no
accumulator changes. For short gaps with many notes it is a net *loss*: at a
10-block gap a 100-note wallet adds 134,376 bytes to save 1,824.

So the honest summary is that the accumulator transforms one question and
barely touches the other. Framing A is a real capability that does not exist
today. Framing B — "how long does my wallet take to sync" — is essentially
unaffected, and any presentation of these numbers that quotes the 31,705×
without saying so is choosing the flattering question.

### Re-measured across three eras, 2026-08-22

[D32](design.md) concluded that a figure measured over one slice of chain
history is not a property of the design, after Phase 4b's 73.0%
transparent-bandwidth share turned out to describe 2011 and inverted when
measured anywhere else. Its closing note flagged this result as needing the
same check, since it was taken over the most recent 400,001 blocks only.

Checked. `gap_cost` now takes `ZUTREEXO_GAP_END`, so any era can be sampled.
**All figures below use the sparse 637-byte proof** — see the correction note.

| 400,000-block window | nullifiers/block | share of a compact sync | 1 note | 10 notes | 100 notes |
|---|---|---|---|---|---|
| **1,000,000–1,400,000** — Sapling era, pre-NU5 | 0.7 | 7.0% | 13,201× | 1,320× | 132× |
| **1,350,000–1,750,000** — sandblasting | 5.3 | **3.1%** | **107,371×** | 10,737× | 1,074× |
| **3,057,000–3,457,000** — tip | 3.4 | 14.8% | 69,040× | 6,904× | 690× |

Crossovers, same basis:

| wallet | pre-NU5 | sandblasting | tip |
|---|---|---|---|
| 1 note | 30 blocks | 4 blocks | 6 blocks |
| 10 notes | 303 blocks | 37 blocks | 58 blocks |
| 100 notes | 3,030 blocks (~63 h) | 373 blocks (~7.8 h) | 579 blocks (~12 h) |

**The direction holds in every era; the magnitude spans a factor of eight.**
Proofs win in all three, and a wallet offline more than about a day is better
off with them everywhere. The spread tracks shielded activity almost exactly —
scanning cost is linear in nullifiers revealed, a proof costs the same either
way, so 0.7 per block versus 5.3 is most of the difference.

Unlike D32's case this is **not** an inversion. The claim CLAUDE.md set out to
test survives being measured somewhere else, which is precisely what the 73.0%
did not.

**Framing A and Framing B move in opposite directions**, which is the finding
worth keeping from the third row. The sandblasting era is the *best* case for
proofs against scanning (107,371×) and simultaneously the *worst* case for
dropping nullifiers from a full sync (3.1%, against 14.8% at tip) — because
sandblasted blocks are enormous, so the nullifiers inside them are a small
share of bytes a syncing wallet must fetch regardless. An era that flatters one
framing penalises the other.

> **Correction, same day.** The first version of this section compared
> pre-NU5's 13,201× against Phase 5a's 31,705× and concluded the advantage was
> "about 2.4× smaller". **Those two numbers are on different bases.** Phase 5a
> predates the sparse encoding and used the dense 1,362-byte proof; `gap_cost`
> now reports the 637-byte sparse one. On a single basis the tip figure is
> 69,040× and the real spread is 5.2×, not 2.4×.
>
> Caught by re-measuring tip alongside the other two and getting a crossover of
> 6 blocks where Phase 5a's table said 13 — a ratio of 2.14, which is exactly
> 1362/637. Comparing a new measurement against an old one without checking
> they were taken the same way is the same error D32 is about, one level down:
> not the wrong era, the wrong units.

### The trust caveat, which is not a footnote

A non-membership proof is only meaningful against a **trusted root**, and
nothing commits accumulator roots to the Zcash chain today. That is the Phase 7
hard fork. Without it a wallet takes the root from the bridge — and a wallet
that trusts a bridge for the root could simply ask "is this nullifier spent?"
and be told, with no accumulator involved at all.

The proof is not worthless in the meantime. Roots are a few hundred bytes, so a
wallet can fetch them from several independent bridges and compare, reducing
the trust from "this bridge is honest" to "these bridges are not all colluding",
and any bridge that serves a proof against a root it also published can be
caught. But that is materially weaker than trustlessness, and **the framing A
numbers above measure bandwidth, not trust.** They do not establish that the
scheme is worth deploying before Phase 7; they establish that if the roots can
be trusted, the bandwidth argument is overwhelming.

### Sparse paths matter more here than for block download

A depth-40 tree holding 2^25.7 nullifiers is mostly empty, so 631 of the 1,362
bytes are empty-subtree hashes both sides can derive. Implementing that halves
every crossover above: a 100-note wallet would break even at roughly 585 blocks
instead of 1,262. Unlike the Phase 4a case — where the compressible term was
only 16.4% of the bundle and the Utreexo proofs dominated — here the proof *is*
the whole cost, so the optimisation is worth its full 53.7%.

---

## Phase 5b — storage, latency, and a shadow at the live tip, 2026-08-22

Three runs, chained overnight by `scripts/phase5b_overnight.sh` and
`scripts/phase5b_after_replay.sh` against a synced `zebrad` 6.3.0:

1. genesis to tip, snapshotting at 1,700,000 and at tip — **7h09m**, 3,455,225
   blocks, zero apply errors;
2. bridge/compact-node lockstep over **60,000 blocks** of the sandblasting ramp
   (1,700,000–1,760,000), resumed from the 1.7M snapshot so the transparent
   forest is real — **88 min**, zero divergences;
3. shadowing the live tip — **12h39m**, **500 blocks followed at tip** plus 521
   of catch-up, **zero divergences, zero parse disagreements**.

### The storage side, which had never been measured

CLAUDE.md Phase 5 asks for "peak RSS and steady-state disk for a validating
node", to be weighed against the proof bandwidth. Until Phase 5b there was no
figure at all, because a compact node's state had only ever lived in memory and
nothing serialised it.

| | bridge (full state) | compact node |
|---|---|---|
| steady resident at tip | **31.7 GiB** | 693 B |
| peak resident, tip-following | **37.5 GiB** | — |
| peak resident, genesis replay | **40.6 GiB** | — |
| on disk | 6.25 GB snapshot | **469–789 B** |
| reorg history, 512 blocks | forest + outpoint index | **324 KB** |

**Roughly 49 million to one** at the observed 693 B, and it does not grow with
the chain: the state is roots and counters, so its size varies only with the
number of perfect trees in the forest — which is why it moved between 469 and
789 bytes over 1,021 consecutive blocks rather than climbing.

### A correction: peak RSS was understated

The genesis replay reported **peak 40.6 GiB (`VmHWM`)** against the **32.7 GiB**
published for stage 2d — **24% higher**. The old line read `VmRSS`, the
*current* resident size, at the end of the run, and labelled it "peak"; this
run's final `VmRSS` was 32.7 GiB, reproducing the published figure exactly and
confirming that is what it had always been measuring.

Stage 2d's own table already contradicted it, showing 33.3 GiB at height
2,700,000 against the 32.7 GiB printed at tip — a peak cannot be below a value
the same run logged earlier. The binary now reads `VmHWM`.

Stage 2d's other numbers reproduced exactly at every shared checkpoint —
28,203,068 unspent outputs at 300,000, 21,180,838 and Orchard 296 at 1,700,000 —
which is a determinism check nobody had to write.

### Per-block validation latency

CLAUDE.md Phase 5 asks for p50 and p99. Reported as quantiles because stage 2d
measured a 165× throughput spread across mainnet history and concluded a mean
"understates the p99 a node must survive by more than two orders of magnitude".

**Sandblasting ramp, 60,000 blocks (heights 1,700,000–1,760,000):**

| | p50 | p99 | max | mean |
|---|---|---|---|---|
| bridge apply + prove | 0.265 ms | 14.990 ms | 93.757 ms | 1.094 ms |
| bundle encode + decode | 0.022 ms | 0.428 ms | 2.414 ms | 0.041 ms |
| **compact node verify** | **0.164 ms** | **10.781 ms** | **29.724 ms** | 0.750 ms |

**Live tip, 1,021 blocks (heights 3,455,225–3,456,245):**

| | p50 | p99 | max |
|---|---|---|---|
| bridge apply + prove | 0.453 ms | 4.835 ms | 32.684 ms |
| **compact node verify** | **0.267 ms** | **2.648 ms** | **19.537 ms** |

The compact node is **1.7× cheaper at p50 and 1.8× at p99** at tip, and 1.6×/1.4×
across the sandblasting ramp. Modest — and it should be read as modest. The
compact node still verifies a proof per spend and per nullifier; what it saves is
holding the set, not the arithmetic over it. The tail matters more than the
median either way: p99 is 11× p50 at tip and 57× across the ramp.

### The finding that changes the narrow-or-keep argument

**Proof overhead depends overwhelmingly on which era you measure, and the
composition inverts.**

| measured over | proof overhead | Utreexo share | nullifier share |
|---|---|---|---|
| heights 0–150,000 (Phase 4b) | **152.6%** | **73.0%** | ~27% |
| heights 1.70M–1.76M (sandblasting) | **8.3%** | **9.5%** | **87.1%** |
| live tip, 1,021 blocks | **38.4%** | — | — |

Phase 4a and 4b measured heights 0–150,000 and found 73.0% of bundle bytes in
Utreexo inclusion proofs, rising with height. `PLAN.md` recorded that as the
third of three independent signals that the transparent forest should be
dropped.

**That reading does not survive being measured anywhere else.** Early blocks are
tiny and almost purely transparent, so proofs dominate them; a sandblasted block
averages 471 KB and the whole bundle is 8.3% of it. On the modern chain the
Utreexo proofs are under a tenth of a bundle and the nullifier proofs are seven
eighths of it.

So the transparent forest is **not** where the bandwidth goes, and the case for
dropping it is much weaker than Phase 4b made it look. The earlier figure was
not wrong; it was a measurement of 2011, presented as a property of the design.

Sparse paths (D28) saved 60.2% of nullifier proof bytes over the ramp, against
68.6% measured at heights 0–20,000.

### Shadow mode: what it did and did not establish

500 blocks followed at the live tip, plus 521 of catch-up, over 12h39m. Every
block applied through both paths and the roots compared byte for byte; every
block's parse compared against `zebrad`'s own JSON, field for field. **Zero
divergences, zero parse disagreements, zero errors of any kind across 1,021
blocks.**

**Zero reorgs occurred.** That was the expected outcome for a window this size
and it is stated plainly rather than left to be inferred from a clean summary:
the composed reorg path in `shadow.rs` — find the fork, reload the bridge
snapshot, replay the common prefix, restore the compact state — **has still
never run against a real fork.** Its parts are tested (`shadow_fork.rs`,
`zutreexo-csn/tests/reorg.rs`); their composition is not. See `PLAN.md`.

The run is also an external shadow rather than a flag inside Zebra, which is
narrower than CLAUDE.md Phase 5's wording asks for. `docs/design.md` D30 records
why.

### A measurement bug found in the run's own output

The per-block JSONL logged `began_bridge.elapsed()` a second time at write
time, which measures from the start instant to *now* rather than the duration
that was recorded — so it captured bridge-apply plus the codec plus the compact
verify plus the root comparisons. It inflated the bridge p50 by 82%, the p99 by
57%, and the max from 33 ms to 53 ms. The in-memory summary was correct
throughout, and the tables above use it.

It was caught by the two disagreeing. A single source would have published the
inflated figures, and they flattered the design — the compact node looked 2.4×
cheaper at p50 rather than 1.7×.

---

## Phase 4b — sparse proof paths, re-measured, 2026-08-20

`docs/design.md` D28 changed the wire format: sibling hashes that are the
canonical empty-subtree value for their level are replaced by a cleared bit in
a presence bitmap and rebuilt by the decoder. Phase 4a projected the saving from
a byte census; these are the measurements.

### The wallet proof — where it matters most

| | bytes |
|---|---|
| dense (Phase 4a) | 1,362 |
| **sparse (now)** | **637** |
| saved | **53.2%** |

Projected at 631; the extra six bytes are the pool, depth and height the
response now carries explicitly.

> **Correction, 2026-08-28 — this table describes a tree 768× too small.**
>
> The 637 bytes were measured against a **65,536-leaf** tree. The tool's comment
> justified that as "putting the occupied levels well below the depth, which is
> the regime the whole chain is in", and **that reasoning is wrong**: the sparse
> encoding omits siblings equal to the empty-subtree hash, so the count of
> *non-empty* siblings is `log2(occupied)` and has nothing to do with the gap
> between occupancy and depth. The proof grows a flat 32 bytes per doubling:
>
> | occupied leaves | sparse proof |
> |---|---|
> | 65,536 (2^16) | 637 B |
> | 1,000,000 | 733 B |
> | 8,000,000 | 829 B |
> | **50,392,547 — Orchard** | **925 B** |
>
> So 637 B is right for **Ironwood** (70,380 nullifiers, genuinely a 2^16-scale
> tree) and wrong for **Orchard**, which is the pool most notes are in. The
> 53.2% saving against dense is unaffected — both forms grow together — but every
> ratio computed from 637 B was overstated by 925/637 = **1.452×**. Corrected in
> the Phase 5a tables below. `gap_cost` now takes the leaf count as a parameter
> rather than hardcoding either figure. See `docs/design.md` D37.

### The compact-node bundle — heights 0–150,000

| | Phase 4a | Phase 4b |
|---|---|---|
| bundle bytes | 7,248,205,320 | 6,485,997,123 |
| **proof overhead** | **170.5%** | **152.6%** |
| nullifier proofs | 1,192,149,398 | 431,589,992 (**63.8%** saved) |

66.4% of sibling hashes over this range were derivable — 764,606,688 bytes
never sent.

### The composition moved, and that is the finding

| component | Phase 4a | Phase 4b |
|---|---|---|
| **Utreexo inclusion proofs** | 65.3% | **73.0%** |
| spent leaf contents | 18.2% | 20.3% |
| nullifier proofs | 16.4% | **6.7%** |

The nullifier side is now nearly free — 6.7% of the bundle — and the transparent
side is 93.3% of it. Compressing the shielded half worked and moved the problem
without shrinking it much: overhead fell by 18 points and remains six times
Bitcoin's Utreexo figure.

**So the transparent forest is where the remaining cost lives, and there is no
equivalent trick available for it.** The empty-subtree compression works because
an indexed Merkle tree at depth 40 is mostly empty and its filler is derivable.
A Utreexo forest is dense by construction — that is the whole point of the
forest-of-perfect-trees design — so its proofs carry no derivable filler to
remove. Any further reduction has to come from `rustreexo`'s proof encoding or
from not serving transparent proofs at all.

CLAUDE.md Phase 5 anticipates that conclusion: *"If the measurements say that,
narrow the project to the nullifier accumulator and drop the transparent forest
rather than shipping both out of sunk cost."* Three measurements now point the
same way — 27.5M transparent outputs at tip against Phase 0's expectation of a
much smaller set, 73.0% of proof bandwidth, and an overhead that rises with
height. **That decision is not taken here**, because Phase 5b's storage and
latency numbers are the other half of it and have not been measured, but the
evidence is accumulating in one direction and should be read as such.

### What did not change

Batching still saves 85.4%; it is orthogonal to path compression and already
inside every figure above. The `ZUTREEXO_MEASURE_BATCHING=1` runs are unaffected.

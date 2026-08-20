# Project: `zutreexo` — Accumulator-Based State Compression for Zcash

> **Rev 2 (2026-08-10).** Changes from rev 1, after reading
> `github.com/zodl-inc/slipstream` and confirming Ironwood's status:
> added §2.2 (Slipstream is complementary orchestration, not a competitor — and
> its benchmark axis is the wrong one for us); added an AGPL licensing decision
> to §3 that must be made before any code is written; rewrote Phase 2's test
> section around a concrete two-oracle harness; retargeted Phase 5's benchmarks
> at nullifier-check cost rather than wall-clock sync; and updated §7 — Ironwood
> is resolved, but NU7's possible 3× block-time change and Tachyon's PIR work
> are new risks that need answering in Phase 0.

> **How to use this file:** drop it in the repo root as `CLAUDE.md` (or paste it as
> the opening message of a Claude Code session). It is written to be executed
> phase-by-phase. Each phase has an explicit **Definition of Done**; do not advance
> until the DoD passes. Ask before deviating from the accumulator choices in §2 —
> they are load-bearing and were selected for correctness reasons, not convenience.

---

## 1. Goal and non-goals

**Goal.** Reduce the persistent, random-access state a Zcash validating node must
hold, from "full transparent UTXO set + full nullifier set" to "a few kilobytes of
accumulator roots," without weakening consensus and without leaking which shielded
note was spent.

**In scope**
- A Rust accumulator library covering Zcash's three state structures.
- A *bridge node* that replays chain history and serves membership /
  non-membership proofs to lightweight peers.
- A *compact state node* (CSN) that validates blocks holding only roots + proofs.
- Differential testing against Zebra's canonical state.
- A ZIP draft, only if and when Phase 5 measurements justify it.

**Explicitly out of scope (for now)**
- Any consensus change. Phases 0–5 are consensus-neutral by construction: proofs
  are supplied out-of-band by bridge nodes, not embedded in transactions.
  Embedding proofs in the transaction format is a hard fork and is Phase 7, gated
  on real benchmarks.
- Changing the shielded circuits. We do not touch Sapling/Orchard/Ironwood proving
  systems.
- Wallet-side sync UX. Related but separate (see `lightwalletd`/Zaino/Tachyon work).

---

## 2. The central design decision — read this before writing code

Zcash is **not** one UTXO set. It has three structures with different algebra, and
the single most common way to get this project wrong is to apply Utreexo uniformly
to all three.

| Structure | Operations needed | Correct primitive | Rationale |
|---|---|---|---|
| Transparent UTXO set (t-addrs) | insert + **delete** + membership | **Utreexo forest** (`rustreexo`) | Identical to Bitcoin. Utreexo's forest-of-perfect-trees design exists precisely to make deletion cheap. Direct port. |
| Nullifier set (per shielded pool) | insert + **non-membership** | **Indexed Merkle Tree (IMT)** | ⚠️ See below. |
| Note commitment tree (per pool) | append-only + membership-in-zk | **Leave as-is** (`incrementalmerkletree`/`bridgetree`) | Already an append-only frontier; membership is proven *inside* the zk-SNARK. Utreexo adds nothing and would break the circuit. |

### 2.1 Why the nullifier set must NOT use a plain Utreexo forest or MMR

A Utreexo forest — and an MMR, and any unordered hash accumulator — proves
**membership only**. Nullifier checking requires the opposite: proving a nullifier
has **never** appeared. There is no way to prove absence from an unordered
accumulator without holding the entire set, which defeats the purpose.

The fix is an **Indexed Merkle Tree** (a.k.a. nullifier tree, as used in Aztec):
each leaf stores `(value, next_value, next_index)`, keeping the set sorted by value
via a linked list threaded through the leaves. Non-membership of `x` is proven by
exhibiting the "low leaf" `L` where `L.value < x < L.next_value` and giving a
standard Merkle path to `L`. Insertion updates `L` and appends a new leaf — two
Merkle path updates, `O(log n)`.

**If an agent proposes "just use Utreexo with deletion disabled" for nullifiers,
reject it.** That is the known failure mode of this design.

### 2.2 What this project is NOT competing with

Resolved by reading `github.com/zodl-inc/slipstream` directly. **ZODL Slipstream
is orchestration, not cryptography, and it is complementary to this project.**
Its own README describes the design as "upstream brain, Slipstream body": every
cryptographic and wallet-logic decision is delegated to *unmodified*
`librustzcash` crates (`zcash_client_backend`, `zcash_client_sqlite`,
`shardtree`, `sapling`) published on crates.io. Slipstream owns only parallel
block fetch with a device-RAM-scaled byte budget, a sparse in-memory commitment
tree with checkpoint-downgrade, a write-behind persistence lane,
spend-before-sync ordering, tip-following, mempool, and a Tor transport policy.
No accumulator, no protocol change, no consensus surface.

Its published v0.5 numbers against stock ZcashLightClientKit on one real wallet:
~20 s vs 22:30 on an M4 (~70×), 43 s vs 16:55 on an iPhone A18, 4:43 vs 1:04:26
on a 2016 iPad. A 2019 wallet spanning ~2.4M blocks including the 2022–23
sandblasting era restores in 51 minutes on M4.

**Do not benchmark zutreexo against those numbers.** They measure wall-clock
wallet sync, which is dominated by trial decryption — a cost no accumulator
changes, because learning that a note is yours requires attempting decryption
and nothing else will do. Measuring zutreexo on that axis guarantees an
unimpressive result for a reason unrelated to whether the design is sound. See
Phase 5 for the axes that actually apply.

One signal worth noting from that repo: Slipstream ships a **parked GPU
Sinsemilla kernel** (`gpuhash`, off by default). ZODL considered
GPU-accelerating commitment-tree hashing, which corroborates that tree/witness
hashing — not only decryption — is a live bottleneck. That is the structure §2
says to leave alone; the existing incremental-frontier and parallel-rebuild
approaches are the right answers there.

### 2.3 Multiple pools

There is one nullifier set per shielded pool, and Zcash currently has several
active or draining (Sprout, Sapling, Orchard — now withdraw-only post-Ironwood —
and Ironwood). The design must be **per-pool parameterized from day one**: a
`PoolId` enum, one IMT instance per pool, roots committed independently. Do not
hardcode a single nullifier tree; the Orchard→Ironwood migration means at least
two are live simultaneously.

---

## 3. Repository layout

```
zutreexo/
├── CLAUDE.md                      # this file
├── Cargo.toml                     # workspace
├── crates/
│   ├── zutreexo-accumulator/      # Phase 1 — pure, no chain deps
│   │   ├── src/utreexo.rs         #   thin typed wrapper over rustreexo
│   │   ├── src/imt.rs             #   indexed Merkle tree (nullifiers)
│   │   ├── src/hash.rs            #   domain-separated hashers (BLAKE2b)
│   │   └── src/proof.rs           #   serializable proof types
│   ├── zutreexo-chain/            # Phase 2 — chain semantics
│   │   ├── src/pool.rs            #   PoolId, per-pool state
│   │   ├── src/block_apply.rs     #   deterministic state transition fn
│   │   └── src/rollback.rs        #   reorg handling / undo blocks
│   ├── zutreexo-bridge/           # Phase 4 — proof-serving node
│   ├── zutreexo-csn/              # Phase 5 — compact state node
│   └── zutreexo-testkit/          # fixtures, differential harness, fuzz targets
└── docs/
    ├── design.md
    ├── benchmarks.md
    └── zip-draft.md               # Phase 7 only
```

**Dependency policy.** Use `rustreexo` for the transparent accumulator rather than
reimplementing it. Use `zcash_primitives` / `zcash_protocol` for consensus types
(nullifiers, outpoints, network params). Use `zebra-chain` and `zebra-state` as
the source of truth for replay. Do not vendor consensus-critical logic.

---

## 4. Phased plan

### Phase 0 — Spike and instrument (est. 1 week)

Build nothing permanent. Answer these with measurements, written into
`docs/benchmarks.md`:

1. Current mainnet size of: transparent UTXO set (count + on-disk bytes),
   each pool's nullifier set (count + bytes), each note commitment tree.
2. Per-block rate of: transparent inputs/outputs, nullifiers revealed per pool.
3. Baseline Zebra IBD wall-clock and peak RSS on the target hardware.

Also, while zebrad is synced and in front of you, **capture the fixture corpus**
the harness will need in Phase 2, so CI never requires a validator. Slices worth
having: Sapling activation, NU5/Orchard activation, the 2022–23 sandblasting
window (the pathological high-output-count case, and real rather than
synthetic), and Ironwood activation at 3,428,143.

**DoD:** a reproducible script (`scripts/measure_baseline.sh`) plus a committed
table. Every later performance claim is measured against these numbers. Fixture
corpus captured and stored (LFS or bucket), with a committed manifest.

---

### Phase 1 — Accumulator core (est. 2–3 weeks)

Pure library. No chain, no I/O, no network.

**Build**
- `utreexo.rs`: typed wrapper — `insert(&[Hash])`, `delete(&[Proof])`,
  `roots() -> Vec<Hash>`, `verify(&Proof, &[Hash]) -> bool`.
- `imt.rs`: indexed Merkle tree with
  `insert(value) -> InsertionProof`,
  `prove_non_membership(value) -> NonMembershipProof`,
  `verify_non_membership(...)`, `root()`.
  Handle the sentinel low-leaf at `value = 0` and the max-value edge case.
- `hash.rs`: BLAKE2b-256 with **distinct personalization strings per structure and
  per pool** (e.g. `ZUtxoAccum__`, `ZNullIMT_Orch`). Domain separation is
  mandatory — cross-structure collisions are a consensus bug.

**Test**
- Property tests (`proptest`) — the core invariants:
  - insert-then-prove always verifies;
  - non-membership proof fails for any inserted value, succeeds for any absent one;
  - inserting a duplicate is rejected;
  - root after applying operations in a batch == root after applying them one at a
    time;
  - delete-then-prove fails (transparent accumulator).
- Deterministic vectors checked into `testkit` so later refactors can't drift.

**DoD:** 100% branch coverage on `imt.rs`; proptests green at 10k cases; a
`cargo bench` harness exists for insert/prove/verify at set sizes 10⁴, 10⁶, 10⁸.

---

### Phase 2 — Chain state transition (est. 3–4 weeks)

**Build** `block_apply.rs`: a single pure function

```rust
fn apply_block(
    state: &mut ChainAccumulators,
    block: &Block,
    proofs: &BlockProofBundle,
) -> Result<StateDelta, ApplyError>
```

Order of operations per block, and it must be exactly this, deterministically:

1. For each transparent input: verify Utreexo inclusion proof → delete leaf.
2. For each transparent output: compute leaf hash (commit to outpoint **and**
   scriptPubKey **and** amount **and** coinbase-ness/height — mirror
   `rustreexo`'s Bitcoin leaf construction, adapted) → insert.
3. For each shielded pool, for each nullifier revealed: verify non-membership
   against that pool's IMT → insert → update root.
4. For each shielded pool, for each note commitment: append to the existing
   frontier (unchanged behavior; we only track the root to cross-check).
5. Emit `StateDelta` containing all pre-images needed to undo the block.

**Also build** `rollback.rs`. Reorgs are the single most under-tested area of
accumulator work. Undo must restore bit-identical roots. Utreexo deletion is not
naturally invertible — you must persist the deleted leaves and their positions in
the `StateDelta`.

**Test — build the harness in `zutreexo-testkit` (skeleton already drafted; see
the companion `zutreexo-harness/` files).** The design is **two oracles, because
they catch different bug classes and neither alone is sufficient**:

1. **`NaiveState`** — a deliberately dumb `BTreeMap`/`BTreeSet` model of the
   chain state. Catches accumulator bugs. It must share **zero code** with
   `zutreexo-accumulator`, or the two can be wrong in the same way. Never
   optimise this file; the moment it gets clever it stops being an oracle.
2. **The validator** — Zebra's `z_gettreestate`. Catches *parsing* bugs, where
   both models agree because both were fed the same garbage. Only overlaps on
   note commitment trees, but that overlap is enough.

Three comparison tiers, cheap to expensive:
- **every block:** counts only (UTXO count, per-pool nullifier counts). O(1),
  catches a dropped output instantly.
- **every N blocks:** incremental roots vs roots **recomputed cold** from the
  naive state. This is the load-bearing check — it proves the incremental path
  has not drifted from a from-scratch computation, which is the failure mode
  that accumulates silently over a million-block replay and surfaces only when
  someone cannot spend. `N` is a knob: 1000 for throughput, 1 when bisecting.
- **at checkpoints:** cross-check against the validator.

Plus reorg fuzzing, which is where accumulator implementations actually break:
Utreexo deletion is not naturally invertible, so undo requires the deleted
leaves *and* their positions in the `StateDelta`, and it is very easy to keep
almost enough. The invariant is total — `apply(A..N)`, undo to `K`, apply the
divergent `K..M` must produce **byte-identical** roots to a cold replay of the
final chain. Do not soften this to "equivalent" or "same balance"; the
comparison being mechanical is the entire value of the harness.

Two non-negotiable harness behaviours:
- **Dump a repro before propagating any error.** A divergence you cannot replay
  offline is one you will not fix.
- **Every divergence becomes a permanent seed** in the fuzzer's regression
  corpus, added and confirmed failing *before* the fix.

**DoD (amended 2026-08-17, stage 2d — see below):** a genesis-to-tip replay
completes with zero apply errors; parse agreement with `zebrad` at checkpoints
sampled across all history; incremental roots equal a from-scratch rebuild at
those checkpoints; two replays byte-identical. Reorg fuzzer runs 10⁶ randomized
reorgs with zero divergence — **met, stage 2c**. Every past divergence present
as a passing seed.

> **Why this was amended.** The original wording was *"bit-exact agreement with
> Zebra at every checkpoint from genesis to tip."* That comparison does not
> exist: **Zebra computes none of the roots this project computes.**
> `z_gettreestate` returns commitment-tree roots only, §2 deliberately leaves
> those trees alone, there is no nullifier-root RPC because no other
> implementation maintains one, and Zebra does not implement
> `gettxoutsetinfo`. The criterion was unmeetable as written, not merely hard.
>
> The amendment is **narrower**, not looser, and keeps Zebra as the oracle for
> everything Zebra can actually oracle — the parse. What replaces the root
> comparison is the observation that **mainnet is its own oracle**: the IMT
> rejects duplicate nullifiers and the applier rejects unresolvable spends, so a
> clean genesis-forward replay is a substantive claim. A mis-parsed nullifier
> collides; a mis-parsed outpoint fails to resolve. Neither survives 3.45M
> blocks quietly.
>
> **Explicitly not claimed:** bit-exact root agreement with any other
> implementation. Nothing else computes these roots. Matching Zebra's
> commitment-tree `finalRoot` was considered and rejected — it would test
> `incrementalmerkletree` against Zebra while exercising none of this project's
> accumulator, and §2 puts those trees out of scope.
>
> This changes no research claim. The headline result is Phase 5's
> nullifier-check cost against gap length, which is a benchmark; correctness of
> the state transition is what this DoD buys, and the amended form buys it.
> Reasoning and measurements in `PLAN.md`.

---

### Phase 3 — Persistence and snapshots (est. 2 weeks)

- On-disk format for the Utreexo *pollard* (partial forest) and the IMT.
- Versioned, with an explicit format version byte and a migration path.
- Snapshot export/import so a new node can bootstrap from a trusted-but-verifiable
  state at height H, then validate forward.
- Crash-consistency: fsync discipline, torn-write recovery, tested with a
  kill-at-random-syscall harness.

**DoD:** kill -9 at any point during block application leaves the store recoverable
to a consistent height with no root divergence.

---

### Phase 4 — Bridge node (est. 3–4 weeks)

The bridge holds the **full** forest and full IMTs and serves proofs. This is the
component that makes the whole thing usable without a consensus change.

- Maintains complete accumulator state alongside a Zebra node.
- gRPC/JSON-RPC service:
  - `GetUtxoInclusionProofs(outpoints) -> proofs`
  - `GetNullifierNonMembershipProof(pool, nullifier) -> proof`
  - `GetBlockProofBundle(height) -> BlockProofBundle` (batched, for CSNs doing IBD)
  - `GetAccumulatorRoots(height) -> roots`
- **Integrate with Zaino rather than forking `lightwalletd`.** Zaino is the Rust
  indexer the ecosystem is converging on and already reads Zebra's state directly;
  expose the above as an additional Zaino service surface if the maintainers are
  receptive, otherwise as a standalone sidecar with the same transport.
- Batch proof aggregation: Utreexo proofs for inputs in the same block share
  internal nodes; deduplicate before serialization. Measure the savings.

**DoD:** a CSN can complete IBD to tip using only headers + blocks + bridge-served
proofs, ending with roots identical to the bridge's.

---

### Phase 5 — Compact state node and measurement (est. 3 weeks)

- `zutreexo-csn`: validates the chain holding only roots + a pollard cache.
- Run behind a **shadow-mode feature flag** against a normal Zebra node: both
  validate every block, results compared, any disagreement is a hard failure and a
  loud log line. Never let the accumulator path gate consensus during this phase.
- Fill in `docs/benchmarks.md`, versus the Phase 0 baseline. **Measure on the
  axes where an accumulator can actually win** (see §2.2 for why wall-clock
  wallet sync is the wrong axis):
  - **nullifier-check cost as a function of gap length** — the headline result.
    Today a wallet learns its notes were spent by scanning every block's
    revealed nullifiers, which is linear in the gap since last sync. An IMT
    non-membership proof is O(log n) per note, *independent of chain length*.
    Plot both against gap length; the crossover point is the finding.
  - peak RSS and steady-state disk for a validating node;
  - per-block validation latency (p50/p99);
  - **bandwidth overhead from proofs** — the cost side of the trade. Bitcoin's
    Utreexo work saw roughly a quarter more download in early simulations;
    Zcash's number will differ and must be measured, not assumed.
  - IBD wall-clock, reported for completeness but *not* as the headline.

**DoD:** honest numbers published, including the cases where this is *worse* than
the status quo. If the bandwidth overhead exceeds the storage saving for realistic
node operators, say so in the doc and stop — that is a valid outcome.

Expect this specifically: Zcash's transparent UTXO set is far smaller than
Bitcoin's, so the transparent-side Utreexo storage win may not justify its proof
bandwidth. **The nullifier IMT is where the durable value most likely lives.** If
the measurements say that, narrow the project to the nullifier accumulator and
drop the transparent forest rather than shipping both out of sunk cost.

---

### Phase 6 — Adversarial review (est. 2–3 weeks)

- Fuzz all deserialization paths (`cargo-fuzz`): malformed proofs, oversized
  batches, IMT leaves with inconsistent `next_index`, duplicate nullifiers.
- Explicit DoS analysis: cost to a bridge node of a peer requesting proofs for
  every UTXO; rate limiting and proof-size caps.
- **Privacy review, the Zcash-specific one:** confirm that nothing in the proof
  request pattern reveals which note a wallet is spending. A wallet asking a bridge
  for a *specific* nullifier's non-membership proof is a metadata leak. Mitigations
  to evaluate: batching with decoys, oblivious retrieval, or having wallets only
  ever request proofs for nullifiers they are about to publish anyway (which is
  already public). Write the conclusion into `docs/design.md` regardless of
  outcome.
- External review request to Zcash Foundation / ZODL / Shielded Labs before any
  consensus proposal.

**DoD:** fuzzers run 72h clean; privacy analysis written and reviewed by someone
outside the project.

---

### Phase 7 — ZIP draft (gated, only if Phases 5–6 justify it)

Embedding proofs in transactions is a hard fork. Only draft this if the measured
benefit is real and the privacy review is clean. Content: leaf-hash definition,
proof serialization, activation height, and the migration story for the
Orchard→Ironwood dual-nullifier-set period.

---

## 5. Standing engineering rules for this repo

1. **Consensus-neutral until Phase 7.** If a change would alter what blocks a node
   accepts, stop and flag it.
2. **Differential testing is the primary correctness signal.** Zebra is the oracle.
   A green unit test suite with a divergent root is a failure.
3. **No unwrap/panic in accumulator or apply paths.** Return typed errors; a panic
   in block application is a remote crash vector.
4. **Every hash gets a domain separator.** No exceptions.
5. **Determinism.** No `HashMap` iteration order, no floats, no system time, in any
   path that touches a root.
6. **Benchmarks accompany optimizations.** No "this should be faster" commits.
7. When uncertain about Zcash protocol semantics, consult the Zcash Protocol
   Specification and the relevant ZIP directly — do not infer from Bitcoin
   analogy. The nullifier/commitment-tree distinction (§2) is exactly the kind of
   thing Bitcoin intuition gets wrong.

---

## 6. Suggested opening prompts for the Claude Code session

- *"Read CLAUDE.md. Set up the Cargo workspace per §3, with empty crates and CI
  (fmt, clippy -D warnings, test, cargo-deny). Don't implement logic yet."*
- *"Implement `crates/zutreexo-accumulator/src/imt.rs` per §2.1 with the full
  proptest suite from Phase 1. Start with the data structure and the
  non-membership proof; ask me before choosing the tree depth strategy
  (fixed-depth sparse vs. growable)."*
- *"Write the Phase 0 measurement script against a local Zebra node and fill in
  docs/benchmarks.md. Then capture the fixture corpus listed in Phase 0."*
- *"Implement `apply_block` per Phase 2 step order exactly. Then wire up
  `zutreexo-testkit` from the drafted harness files — two oracles, three
  comparison tiers, repro dumps before error propagation."*
- *"Read REVIEWING.md in github.com/zodl-inc/slipstream and write
  docs/prior-art.md: what their golden-oracle / semantic_diff and darkside
  oracle discipline does that our harness doesn't yet. Ideas only — we are not
  linking AGPL code (see §3)."*

---

## 7. Known open questions to resolve early

- **IMT depth.** Fixed-depth (simpler proofs, capacity ceiling) vs. growable
  (no ceiling, more complex root updates). Nullifier sets grow forever, so a fixed
  depth needs a defensible ceiling — compute it from Phase 0's growth rate. **Note
  the moving target below before fixing a number.**
- **⚠️ NU7 may change the growth rate out from under you.** A coinholder vote on
  NU7 scope, led by Project Tachyon and Valar Group, opens late August 2026 and
  includes **3× faster block times**. That would roughly triple the rate at which
  nullifier sets grow, directly invalidating any IMT capacity ceiling derived from
  current-rate extrapolation. Derive the ceiling from *transactions*, not blocks,
  and add explicit headroom. Check the vote outcome before Phase 3 persistence
  freezes the on-disk format.
- **Does Tachyon subsume this?** Delivering Tachyon was described as the
  ecosystem's next major protocol priority at the 2026 Summer ZODL Summit, and
  private information retrieval (PIR) was a summit topic. If PIR gives wallets
  private nullifier queries with a better privacy story than bridge-served
  non-membership proofs, it may subsume this project's main use case. **Resolve
  this in Phase 0, not Phase 6** — it is the single question most likely to make
  the whole effort redundant.
- **Leaf hash contents for transparent UTXOs.** Must commit to enough that a proof
  can't be replayed for a different output. Mirror Bitcoin's Utreexo leaf design
  but confirm against Zcash's transparent tx format and coinbase maturity rules.
- **Sprout.** Small, legacy, but nonzero. Decide early whether to include it or
  explicitly exclude and document why.
- **Ironwood — resolved, but confirm before fixing `PoolId`.** Ironwood activated
  on schedule at block height 3,428,143 as part of NU6.3, introducing a new
  formally verified shielded pool that reuses a patched circuit while restricting
  Orchard to withdrawals only (removal of funds remains discretionary, so Orchard
  will drain slowly rather than empty). Ironwood has since overtaken Orchard as
  the largest shielded pool. So: **both Orchard and Ironwood nullifier sets are
  live and will remain so indefinitely.** The per-pool parameterisation in §2.3 is
  mandatory, not defensive.

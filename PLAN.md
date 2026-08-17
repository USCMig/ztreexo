# Plan

The authoritative phase definitions — scope, rationale, and Definition of Done —
live in [`CLAUDE.md`](CLAUDE.md). This file is the *operational* view: what is
done, what is in flight, which branch it lives on, and what is known to be
blocked. When the two disagree, `CLAUDE.md` wins and this file is stale.

## Branching

Phases run two to four weeks and are strictly sequential, so a branch per phase
would leave `main` stale for a month while producing a merge that is a
formality. Instead:

* **One branch per _stage_** — `phase-2b-harness`, `phase-2c-rollback` — sized
  at days to a week, which is a reviewable unit.
* **A tag at each phase boundary** — `phase-1-complete`, `phase-2-complete`. A
  tag is a better completion marker than a branch: immutable, permanent, and it
  does not have to be kept alive.
* **`main` is protected.** Changes land by pull request with
  `fmt / clippy / test` and `cargo-deny` green. `proptest 10k` is deliberately
  *not* a required check — it is gated on `schedule || workflow_dispatch`, so it
  is skipped on pull requests, and GitHub never considers a skipped required
  check satisfied.

Naming: `phase-<n><stage>-<topic>` for plan work, `chore/<topic>` for
infrastructure, `fix/<topic>` for defects.

## Status

| Phase | Scope | Branch | Status |
|---|---|---|---|
| 0 | Baseline measurement, fixture capture | — | **complete** — mainnet tip 2026-08-12, [`docs/benchmarks.md`](docs/benchmarks.md) |
| 1 | Accumulator core: Utreexo wrapper + IMT | — | **complete for the IMT**; transparent side blocked upstream, and one DoD item unmet (below) |
| 2a | Block ingestion, `apply_block` | — | **complete** — real mainnet blocks parse and apply, parser cross-checked against the node |
| 2b | Differential harness: two oracles, three tiers | `phase-2b-harness` | **complete** — all four slices agree with both oracles; each tier proven by fault injection |
| 2c | `rollback.rs`, reorg fuzzing | `phase-2c-rollback` | **complete** — 10⁶ randomised reorgs, zero divergence, byte-identical to cold replay |
| 2d | Genesis-forward replay | `phase-2d-replay` | not started |
| 3 | Persistence, snapshots, crash consistency | — | not started |
| 4 | Bridge node (proof serving) | — | not started |
| 5 | Compact state node, published benchmarks | — | not started |
| 6 | Fuzzing, DoS analysis, privacy review | — | not started |
| 7 | ZIP draft — gated on 5 and 6 | — | not started |

## Known gaps, carried deliberately

These are open and tracked here rather than discovered later.

**Phase 1 DoD is not met, and by more than it first appeared.** It requires
*"100% branch coverage on `imt.rs`"*. That criterion had never been measured
when the phase was called done, because *branch* coverage needs a nightly
toolchain — stable rejects `-Z coverage-options=branch`.

Measured 2026-08-16 on nightly:

| `imt.rs` | covered | total | % |
|---|---|---|---|
| regions | 1027 | 1069 | 96.07% |
| lines | 592 | 619 | 95.64% |
| functions | 65 | 68 | 95.59% |
| **branches** | **41** | **48** | **85.42%** |

The region figure was flattering it. The real gap against the DoD is **7
uncovered branches** — which is small enough to close deliberately, and is the
right way to read it rather than as a percentage.

`scripts/check_coverage.py` enforces per-file floors so coverage can only
improve, and the CI job runs on nightly for the same reason.

**Branch coverage is not reproducible between runs**, which constrains how hard
that gate can be pushed. The property suites drive `proof.rs` and `imt.rs`
through proptest, which seeds a fresh RNG each run, so which bounds-check
branches get exercised varies: measured back to back on identical source,
`proof.rs` reported 17/20 and then 16/20, while its region and line coverage
were byte-identical both times. On a 20-branch denominator one branch is five
percentage points, so a zero-tolerance branch ratchet would fail CI at random —
and a gate that cries wolf gets switched off, taking the stable region and line
ratchets with it. Branch floors are therefore absolute covered-counts set about
two branches below the observed minimum; regions and lines stay strict.

**Making the Phase 1 DoD enforceable therefore needs a deterministic run**, not
a tighter threshold: a fixed proptest seed, or a separate non-randomised suite
for `imt.rs`. That is the actual prerequisite for closing the seven branches,
and it is not blocking stage 2b.

**CI had never executed the `zutreexo-chain` crate, and nobody noticed.**
Discovered 2026-08-16 when the coverage job first ran on GitHub. Every test that
touches that crate is gated on a fixture being present, and `fixtures/*.jsonl`
was entirely gitignored — 65 MB of raw block hex that never reaches a runner.
So the tests skipped, silently and greenly, exactly as written.

Measured effect:

| | no fixtures (what CI did) | committed fixture | all four, local |
|---|---|---|---|
| `block_apply.rs` | **0.00%** | 88.37% | 90.12% |
| `extract.rs` | **0.00%** | 80.49% | 90.85% |
| `chain/pool.rs` | **0.00%** | 63.96% | 74.77% |
| workspace | 74.50% | 93.34% | 93.62% |

Fixed by committing `fixtures/nu5-orchard.jsonl` — at 1.85 MB the smallest
slice, and it recovers 18 of the 19.1 available points for 2.8% of the bytes.
The rest stay ignored; `ironwood-activation` alone is 59.3 MB because those
blocks average 89.6 KB. Those three now earn their place as differential
breadth — Sprout activity, sandblasting's pathological output counts,
Ironwood — rather than as coverage, and run locally and in the nightly sweep.

Two lessons folded back into the tooling. `check_coverage.py` now reports a file
at zero regions *and* zero functions as **NEVER EXECUTED** with the fixture
named, because reading it as "0.00% below floor 89.50%" sends you looking for a
coverage regression that is not there. And every floored file in
`zutreexo-chain` is floored individually, so a fixture going missing again fails
by name rather than as a diffuse drop in the workspace total.

**Coverage floors describe what CI can measure, not what a laptop can.** A local
run with all four fixtures scores higher than CI ever will. Calibrate against
the committed fixture only — raising a floor to a locally-observed number fails
every CI run, which is precisely how these were wrong to begin with.

**A latent Phase 1 serialisation bug survived until stage 2c.**
`ZcashNodeHash::write` emitted a bare 32 bytes and `read` returned `Some`
unconditionally — byte-symmetric, but losing the variant, so `Empty` came back
as `Some([0; 32])`. `MemForest`'s reader skips children for empty branches, so
resurrecting one as `Some` sent it hunting for children that were never written.

It was invisible for two phases because **nothing serialised a forest** until
rollback needed a snapshot, and it would have corrupted any snapshot of a forest
that had ever seen a deletion. Found by the reorg fuzzer at iteration 16,310 of
seed 1; fixed with a tagged encoding matching upstream, and pinned by regression
tests. `docs/design.md` D19.

The general lesson, worth carrying into Phase 3: **a serialisation format that
nothing round-trips is not tested, whatever the unit tests say.** Phase 3
freezes the on-disk format, so every type it persists needs an explicit
round-trip test before that happens — not merely an encoder and a decoder that
look symmetric.

**The transparent side is blocked upstream.** `rustreexo` 0.6.0 generates
invalid inclusion proofs for any leaf whose sibling has been deleted, reproduced
with stock upstream types. Pinned in
[`crates/zutreexo-accumulator/tests/upstream_rustreexo.rs`](crates/zutreexo-accumulator/tests/upstream_rustreexo.rs),
which fails loudly if upstream fixes it. Analysis in
[`docs/design.md`](docs/design.md) D10. The nullifier IMT is unaffected.

**Tier 2 of the harness cannot run at `DEFAULT_DEPTH`.** The naive oracle
materialises all `2^depth` leaves by design — walking a sparse path is exactly
the cleverness that would let it share the accumulator's bugs — so
`MAX_NAIVE_DEPTH` is 16. Differential replay runs at depth 14, which is sound
because depth is a parameter and structural agreement at 14 is the same
statement as at 40.

Depth 14 is a floor, not a preference: capacity is `2^depth` leaves **per
pool**, and the Ironwood slice alone reveals 5,838 Orchard nullifiers in 200
blocks. At depth 12 the Orchard tree fills at block 130 and both sides begin
rejecting in lockstep — agreement rather than divergence, so not an error, and
it initially looked like a clean short pass. The harness now reports a truncated
replay explicitly and a test pins that behaviour.

Two consequences carry forward:

* **On 2d.** Even 2^16 is only about 65,000 nullifiers, roughly 7,000 blocks at
  current rates, so a genesis-forward replay cannot carry tier 2 across its
  whole span. 2d needs windowed cold rebuilds, or an oracle that is sparse
  without becoming clever.
* **On cost.** The oracle rebuilds successor pointers by linear search, so a
  cold root is `O(n²)` in accumulated nullifiers — that, not tree depth,
  dominates runtime. Hence the default of a rebuild every 10 blocks with the
  strict every-block setting moved to the nightly sweep; see `docs/design.md`
  D16.

**No independent naive Utreexo.** The shielded side has a true second
implementation; the transparent side has only an unspent-outpoint set, which
feeds the count tier and nothing more. A genuine independent forest would mean
bit-matching whichever deletion variant upstream implements, and getting that
wrong yields false divergences — an oracle that cries wolf is worse than none.
Deferred while the transparent side is blocked anyway; see `docs/design.md` D15.
Partially offset by tier 3, which now cross-checks transparent spend and output
counts against the node across all four slices.

## Ordering constraints

* ~~**2c depends on undo primitives that do not exist.**~~ **Done.**
  `IndexedMerkleTree::undo_insert` exists and is exact. Forest undo turned out
  to be *impossible* as a delta — `rustreexo` has no positional reinsert — so
  the transparent side rolls back by snapshot and replay instead. See
  `docs/design.md` D18.
* **2d needs a block source abstraction.** Streaming 3.4M blocks cannot run
  through the fixture loader currently living in a test helper; it needs a real
  component with RPC and fixture backends.
* **Phase 3 freezes the on-disk format**, so the IMT depth decision had to land
  first. It has — depth 40, [`docs/design.md`](docs/design.md) D3.
* **NU7 may move the ground under Phase 3.** A coinholder vote opening late
  August 2026 includes 3× faster block times, which would triple nullifier
  growth. Ceilings are derived from transaction counts rather than block counts
  for this reason, but check the outcome before the persistence format freezes.

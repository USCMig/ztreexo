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
| 2b | Differential harness: two oracles, three tiers | `phase-2b-harness` | **in progress** |
| 2c | `rollback.rs`, reorg fuzzing | `phase-2c-rollback` | not started |
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

`scripts/check_coverage.py` now enforces per-file floors at the measured values,
so coverage can only improve; the CI job runs on nightly for the same reason.
Closing the seven branches is tracked separately and is not blocking stage 2b.

**The transparent side is blocked upstream.** `rustreexo` 0.6.0 generates
invalid inclusion proofs for any leaf whose sibling has been deleted, reproduced
with stock upstream types. Pinned in
[`crates/zutreexo-accumulator/tests/upstream_rustreexo.rs`](crates/zutreexo-accumulator/tests/upstream_rustreexo.rs),
which fails loudly if upstream fixes it. Analysis in
[`docs/design.md`](docs/design.md) D10. The nullifier IMT is unaffected.

**Tier 2 of the harness cannot run at `DEFAULT_DEPTH`.** The naive oracle
materialises all `2^depth` leaves by design — walking a sparse path is exactly
the cleverness that would let it share the accumulator's bugs — so
`MAX_NAIVE_DEPTH` is 16. Differential replay therefore runs at depth 16, which
is sound because depth is a parameter and structural agreement at 16 is the same
statement as at 40. The consequence lands on **2d**: 2^16 leaves is roughly
65,000 nullifiers, about 7,000 blocks at current rates, so a genesis-forward
replay cannot carry tier 2 across its whole span. 2d needs a different strategy
for that tier — windowed cold rebuilds, or an oracle that is sparse without
becoming clever.

**No independent naive Utreexo.** The shielded side has a true second
implementation; the transparent side does not. Its cold-rebuild tier replays the
op log through a second `rustreexo` instance, which catches state corruption and
drift in the long-lived instance but *shares code*, so it cannot catch an
algorithm bug. Building a genuine independent forest means bit-matching whichever
deletion variant upstream implements, and getting that wrong yields false
divergences. Deferred while the transparent side is blocked anyway.

## Ordering constraints

* **2c depends on undo primitives that do not exist.** `StateDelta` already
  carries the right preimages, but nothing consumes them — there is no
  `IndexedMerkleTree::undo_insert` and no forest undo. Those are the first thing
  2c builds.
* **2d needs a block source abstraction.** Streaming 3.4M blocks cannot run
  through the fixture loader currently living in a test helper; it needs a real
  component with RPC and fixture backends.
* **Phase 3 freezes the on-disk format**, so the IMT depth decision had to land
  first. It has — depth 40, [`docs/design.md`](docs/design.md) D3.
* **NU7 may move the ground under Phase 3.** A coinholder vote opening late
  August 2026 includes 3× faster block times, which would triple nullifier
  growth. Ceilings are derived from transaction counts rather than block counts
  for this reason, but check the outcome before the persistence format freezes.

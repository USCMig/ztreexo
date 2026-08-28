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
| 1 | Accumulator core: Utreexo wrapper + IMT | — | **complete** — DoD met as amended 2026-08-22: 100% of *reachable* branches on `imt.rs` (83/88, five unreachable guards enumerated in [`CLAUDE.md`](CLAUDE.md)), reproducible run to run. Transparent side was blocked upstream, now unpinned via a fork ([D25](docs/design.md)) |
| 2a | Block ingestion, `apply_block` | — | **complete** — real mainnet blocks parse and apply, parser cross-checked against the node |
| 2b | Differential harness: two oracles, three tiers | `phase-2b-harness` | **complete** — all four slices agree with both oracles; each tier proven by fault injection |
| 2c | `rollback.rs`, reorg fuzzing | `phase-2c-rollback` | **complete** — 10⁶ randomised reorgs, zero divergence, byte-identical to cold replay |
| 2d | Genesis-forward replay | `phase-2d-replay` | **complete** — all 3,452,736 blocks applied from genesis with zero errors, 7h02m, RSS at tip 32.7 GiB (the run's own table shows 33.3 GiB earlier; the binary was printing current RSS labelled "peak" and now reads `VmHWM`) |
| 3 | Persistence, snapshots, crash consistency | `phase-3-persistence` | **complete** — DoD met: 25 SIGKILLs mid-save, store intact every time, with a non-atomic control proving the harness detects corruption. Merged `main` 2026-08-20; the merge's coverage run found three snapshot tests passing for the wrong reason ([D24](docs/design.md)) |
| 4a | Proof bundle + compact state node verification core | `phase-4a-bundle` | **complete** — a roots-only node tracks the bridge byte-for-byte over real mainnet blocks; bandwidth measured and it is unflattering ([`docs/benchmarks.md`](docs/benchmarks.md)) |
| 4b | Sparse wire format, bridge service, served IBD | `phase-4a-bundle` | **complete** — Phase 4 DoD met over a real socket; sparse paths cut wallet proofs 53.2% and bundle overhead 170.5% to 152.6%. Not gRPC ([D27](docs/design.md)) |
| 5a | Headline measurement: nullifier-check cost vs gap length | `phase-4a-bundle` | **complete** — the claim holds decisively for spend-status queries (317x to 31,705x at a year's gap) and barely at all for full sync (<=14.7% of bytes, 0% of trial decryption) |
| 5b | Shadow-mode CSN against Zebra, remaining Phase 5 axes | `phase-5b-shadow` | **complete** — storage measured at last (31.7 GiB vs 693 B, ~49M:1), latency p50/p99 over 60k sandblasting blocks and 1,021 at tip, and 500 blocks shadowed at the live tip with zero divergences. Reverses the narrow-or-keep direction: **keep the transparent forest** (below). Shadow is external to Zebra ([D30](docs/design.md)); reorg recovery is a queue for a compact node ([D31](docs/design.md)) |
| 6 | Fuzzing, DoS analysis, privacy review | `phase-6-adversarial` | **in progress** — **72 h fuzz run complete 2026-08-25: 206 billion executions, zero crashes across all 5 targets**, so the DoD's fuzzing half is met for those five; two excluded on an upstream panic ([D33](docs/design.md)) — the fork fix is written and verified against all five crash artifacts but **not pushed**, and writing it turned up a second, worse bug in the same function: unbounded recursion overflows the stack on ~4 MB of input, which aborts rather than unwinds, so the `catch_unwind` D33 relied on never covered it. Bridge hardened: slowloris was total denial from one idle socket, now closed ([D34](docs/design.md)). **Privacy review complete and negative** — Phase 5a's headline query cannot be made privately ([D35](docs/design.md)). External review dropped (below). **Fuzz budgeting was wrong in both directions**: three targets gained zero edges in the whole run and `utxo_proof_decode` found its last at execution 101, while `bundle_decode` was **still finding edges 25 minutes before the clock ran out**. `scripts/fuzz_72h.sh` now budgets per target (7 d + `-fork=8` for `bundle_decode`, 24 h for the rest) and runs `scripts/fuzz_saturation.py` itself ([D36](docs/design.md)) |
| 6b | Prefix cohorts: can the headline query be made private? | `phase-6b-prefix-cohort` | **step 1 complete** — the one mitigation [D35](docs/design.md) left standing is built and measured. At Orchard's real 50.4M nullifiers a 16-bit prefix gives a **768-member anonymity set for 449.7 KB**, 498× a single proof and still 98× cheaper than scanning a year. Path dedup is worth 35.2%, not the ~20% predicted. **Found that the published sparse proof size was measured on a tree 768× too small**, overstating every Phase 5a ratio by 1.452×; all three eras re-measured ([D37](docs/design.md)). Step 2 — the value-ordered layout — not started, and it touches a Phase 3-frozen structure |
| 7 | ZIP draft — gated on 5 and 6 | — | **gated shut** — CLAUDE.md requires "the measured benefit is real **and** the privacy review is clean". [D35](docs/design.md) is negative, so the gate holds. Phase 6b is the attempt to change that |

## Known gaps, carried deliberately

These are open and tracked here rather than discovered later.

**Phase 6's deserialisation fuzzing should not wait for Phase 6.** A three-line
bit-flip loop written to raise a coverage number found a denial-of-service hole
in our own proof-header guard within seconds ([D29](docs/design.md)) — a
declared hash count of 2^32+1 reaching `with_capacity` and aborting the process
on a 141 GB allocation. The assumption that D13 was purely an upstream problem
to wait out was wrong: the wrapper written to contain it did not. Every decoder
added from here should get a bit-flip and truncation sweep at the time it is
written, not at Phase 6.

**Phase 6's external-review DoD is dropped, deliberately.** CLAUDE.md Phase 6
requires the privacy analysis be "reviewed by someone outside the project" and
an "external review request to Zcash Foundation / ZODL / Shielded Labs before
any consensus proposal". Neither is something this repo can satisfy on its own,
and both only bind before a consensus proposal — which this project is not
making. Dropped on 2026-08-22 the way the Tachyon gate was, rather than left to
hold Phase 6 open forever. The analysis is written and stands on its own
([D35](docs/design.md)); the team will seek outside eyes as availability allows.

**Reorg handling is tested in three of its four parts.** Taken separately,
because they need different things to test them:

| part | covered by | needs a real reorg? |
|---|---|---|
| compact node restores a kept state and stays byte-identical to a cold replay | `zutreexo-csn/tests/reorg.rs` | no |
| deciding *where* to unwind to | `zutreexo-testkit/tests/shadow_fork.rs` | no |
| reload the bridge snapshot, replay the common prefix | `load` + `apply_block`, covered elsewhere | no |
| **the three composed, against a chain that forked** | **`zutreexo-testkit/tests/shadow_reorg.rs`** | **no — closed 2026-08-22** |

`shadow.rs` calls `shadow::find_fork` rather than keeping its own copy, so the
tested walk is the one that runs. The `reorg.rs` invariant is CLAUDE.md Phase
2's unsoftened: apply branch A, restore to the fork, apply divergent branch B,
end **byte-identical** to a node that only ever saw the final chain — with both
blindness checks confirmed firing.

**Closed with the scripted stub**, which this file previously identified as the
only one of the three options that belongs in CI. `unwind` moved into
`zutreexo_testkit::shadow` behind a `ChainView` trait, so a test can drive it
with a node scripted to fork. The trait returns `BlockSummary` rather than block
bytes deliberately: deserialisation is covered thoroughly elsewhere, and
requiring it here would mean fabricating consensus-encoded blocks for two
divergent chains to exercise a path that never touches a byte.

Six cases, including the invariant that matters — apply branch A, unwind, apply
branch B, end **byte-identical** to a node that only ever saw the final chain —
plus a no-op control and a refusal when the fork predates the snapshot.

Both blindness checks fire. Making `unwind` rewind unconditionally fails the
no-op control. And the cold-replay comparison turned out to pass whether or not
the branches differed, so the test now asserts the fixture *is* a reorg;
confirmed by setting branch B's salt equal to A's, which nothing else in the
file notices.

**Still true:** mainnet has never reorged under a shadow run. The 500-block run
of 2026-08-22 saw zero in 12h39m. What is now tested is that the code handles
one correctly when it comes.

**A full node's reorg data does not fit at tip, which is itself a finding.**
`RollbackJournal` was built in stage 2c and is the wrong tool at mainnet tip:
`record` clones the whole outpoint index, measured at **14 MiB per block** in a
smoke run, which extrapolates to ~15 GiB for one retained snapshot against 27.5M
outputs. The shadow runner reloads and replays instead. See
[D31](docs/design.md) — the asymmetry with the compact node's few hundred bytes
is an argument for the design, not merely a harness detail.

**The case for dropping the transparent forest has collapsed, and it was a
measurement artifact.** This entry previously read "the evidence is now
three-deep", resting on Phase 4a/4b putting **73.0%** of proof bandwidth in
Utreexo inclusion proofs, rising with height.

Phase 5b measured the same thing in two other eras and the composition inverts:

| measured over | proof overhead | Utreexo share | nullifier share |
|---|---|---|---|
| heights 0–150,000 | 152.6% | **73.0%** | ~27% |
| heights 1.70M–1.76M | 8.3% | **9.5%** | **87.1%** |
| live tip | 38.4% | — | — |

Phases 4a and 4b only ever measured heights 0–150,000. Those blocks are tiny and
almost purely transparent, so proofs dominate them; a sandblasted block averages
471 KB and the entire bundle is 8.3% of it. On the modern chain Utreexo proofs
are under a tenth of a bundle.

The 73.0% was never wrong — it was a property of 2011 presented as a property of
the design. Of the three signals, one (27.5M outputs at tip) stands, one
(73.0% of bandwidth) is withdrawn, and the third ("overhead rises with height")
is contradicted outright: overhead at tip is 38.4% against 152.6% early.

**So: keep the transparent forest.** Narrowing to the nullifier accumulator
would drop the cheap half and keep the expensive one. `docs/benchmarks.md`
Phase 5b has the numbers.

The general lesson, which cost this project a nearly-taken decision: **a figure
measured over one slice of chain history is not a property of the design.**
Every bandwidth or composition number in these docs should name its height
range, and several did not.

**A bridge cannot be multi-threaded as built.** `ChainAccumulators` is not
`Send` because `rustreexo`'s `MemForest` is `Rc`/`Weak` with interior
mutability — the same root cause as mit-dci/rustreexo#151. Concurrency has to
come from owning the state on one thread and passing requests over a channel.
The server has no TLS, auth, rate limiting or proof-size caps either; bind it to
loopback until Phase 6.

**The headline result is real but gated on Phase 7.** A non-membership proof is
only meaningful against a trusted root, and nothing commits accumulator roots to
the chain today. A wallet that trusts a bridge for the root could just ask the
bridge whether the nullifier is spent and skip the accumulator entirely.
Multi-bridge root comparison weakens the trust assumption without removing it.
So the 31,705x in [`docs/benchmarks.md`](docs/benchmarks.md) measures bandwidth,
not trust, and does not by itself justify deployment before the fork.

**The compact-node bandwidth overhead is 170% and rising with height.** A
compact node downloads 1.7x as much in proofs as in blocks over heights
0–150,000, against roughly 25% for Bitcoin's Utreexo simulations — and the
figure climbs from 100.9% at height 25,000 to 170.5% at 150,000 as the
transparent UTXO set grows. **65.3% of that is Utreexo inclusion proofs**, so
that is where any optimisation belongs; the derivable empty-subtree hashes in
nullifier proofs are worth only about 11% of the bundle. Both are wire-format
changes and belong with the Phase 4b transport, before the format has clients.
See [`docs/benchmarks.md`](docs/benchmarks.md).

This is the measurement CLAUDE.md Phase 5 anticipated might sink the design, and
it arrived early and negative. It is not yet a verdict: the 85.4% saving from
batching is already counted in the 170%, the sparse-path encodings are not, and
the wallet-side nullifier query — the actual headline claim — is untouched by
any of it.

**`rustreexo` is pinned to a fork.** The D10 fix (upstream PR #152) is not
merged. `tests/upstream_rustreexo.rs` asserts the fixed behaviour, so losing the
pin fails loudly rather than silently reintroducing invalid proofs. Drop the
pin when upstream merges. mit-dci/rustreexo#151 is still open and still worked
around.

**Every check inside `decode` is reachable only through a forged file.** `load`
verifies magic and checksum before calling `decode`, so the checksum masks every
structural check behind it. Three Phase 3 tests were written without noticing
and passed on `ChecksumMismatch` while the arms they named never executed; the
coverage floor caught it, not the suite. Fixed, mutation-checked, and written up
as D24. **Carried forward: Phase 6's deserialisation fuzzing must reseal a valid
checksum over each mutated payload, or it will spend its entire budget bouncing
off the checksum and report a clean run having tested nothing.**

**Phase 1's DoD is met, as amended — closed 2026-08-22.** It had been open
since Phase 1, requiring *"100% branch coverage on `imt.rs`"*, a criterion never
measured when the phase was called done because *branch* coverage needs nightly.
First measured 2026-08-16 at **41/48, 85.42%**.

The blocker was never effort. Branch coverage moved between identical runs,
because the property suites reseed each time: `proof.rs` reported 17/20 and then
16/20 on byte-identical source while its region and line figures were the same
to the digit. A ratchet against a wandering number fails at random, and a gate
that cries wolf gets switched off, taking the stable ratchets with it.

Fixed by `crates/zutreexo-accumulator/tests/imt_branches.rs`: 27 deterministic
cases — fixed inputs, named expected errors, nothing generated — covering every
path a caller reaches by getting something wrong. The happy paths stay with
proptest, which is what it is for.

| `imt.rs` | before | after |
|---|---|---|
| regions | 96.07% | **97.41%** |
| lines | 95.64% | **98.33%** |
| branches | 75/88 | **83/88** |

Measured twice back to back: **identical**. That is what makes the gate
enforceable, and `imt.rs`'s branch floor is now **exact** rather than set a
couple below the observed minimum — the only such floor in the workspace.

**The remaining five sides are unreachable through the public API**, not merely
untested, so the DoD is amended in `CLAUDE.md` to *100% of reachable branches*,
following the precedent set when Phase 2's DoD turned out to name a comparison
that did not exist. Each is enumerated there. Deleting them to reach 88 would
trade a real safety net for a number: they exist so a refactor that breaks an
invariant fails loudly instead of computing a wrong root.

Two were checked rather than assumed. `verify_insertion`'s capacity guard is
*shadowed* — the append index equals `leaf_count`, so a count past capacity is
an index past capacity and `check_path` rejects first; measured at depths 1, 2
and 3. And `undo_insert`'s `next_index` disjunct is unreachable because one leaf
points at any given value, while its `next_value` sibling **is** reachable and
now has its own test, since short-circuit evaluation means one test cannot cover
both.

**Branch floors elsewhere remain absolute covered-counts set about two below
the observed minimum**, because every other floored file is still driven by
proptest and still wanders. Regions and lines stay strict everywhere.

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

**`apply_block` mishandled intra-block spends, and a test defended the bug.**
A transaction may spend an output created by an earlier transaction in the same
block; mainnet block 572 does. `block_apply.rs` ordered all deletions before all
insertions and documented that as *preventing* it, "which Zcash consensus
forbids" — false, a Bitcoin analogy applied backwards (CLAUDE.md §5 rule 7).

Three things kept it alive for three stages, and each is worth carrying forward:

* **A tolerance absorbed it.** Every fixture replay in 2a–2c ran with
  `allow_unknown_spends`, added for the legitimate reason that windowed replays
  start mid-chain. It counted intra-block spends as pre-window spends. Treat any
  "ignore what we cannot resolve" option as capable of hiding a different bug
  than the one it was added for.
* **A test encoded the false rule.** The naive oracle asserted
  `a_block_cannot_spend_what_it_creates`. An oracle that encodes a wrong rule
  does not merely fail to catch the bug — it defends it.
* **Only the strict path found it.** The genesis replay cannot use the
  tolerance, and hit it after 572 blocks.

Fixed by cancellation (`docs/design.md` D21), pinned by
`crates/zutreexo-chain/tests/intra_block_spend.rs`, which runs in milliseconds
where the discovery took six hours.

**Phase 2 is complete.** The amended DoD is met: genesis-to-tip with zero apply
errors, 71 from-scratch rebuilds all matching, parse agreement with `zebrad` at
checkpoints (2b), and two runs byte-identical at every shared checkpoint. Peak
memory 32.7 GiB — the first attempt stopped at 56% on a 24 GiB ceiling, so the
headroom mattered.

**Memory is the constraint on doing this routinely.** 32.7 GiB is fine for an
occasional verification run and not fine for CI or a laptop. At roughly 550
bytes per unspent output the transparent index dominates early history; storing
the precomputed leaf hash rather than the whole `UtxoLeaf` would cut that by
about an order of magnitude, at the cost of rollback needing another source for
leaf contents. Worth doing before Phase 3 freezes an on-disk format that will
inherit the same shape.

**A snapshot does not shrink the working set, only the startup cost.** Loading
a 3.85 GB snapshot produces 12.7 GiB resident — essentially what the replay used.
That is the format being a faithful round trip rather than a compression scheme,
and it is correct, but it means the 32.7 GiB tip footprint is untouched. The
`UtxoLeaf`-to-leaf-hash change would cut the dominant term by roughly an order of
magnitude. Phase 3 was the natural moment for it and it was **not** done, so the
on-disk format now encodes whole leaves; changing that later means a format
version bump and a migration, which is exactly what the version byte is for.

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

# zutreexo design decisions

Living record of decisions that are load-bearing, in the sense that reversing
one invalidates work already done. Each entry states the decision, the date, the
reasoning, and what would change it.

Phase status is tracked in `README.md`. Measurements live in
`docs/benchmarks.md`.

---

## D1 — Licence: MIT OR Apache-2.0, and no AGPL linkage

**Decided 2026-08-10.** CLAUDE.md §3 required this before any code was written.

zutreexo is dual-licensed MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`),
matching `librustzcash`, Zebra, and `rustreexo`. It is the Rust-ecosystem norm
and imposes nothing on downstream integrators.

**zutreexo does not link ZODL Slipstream.** Slipstream is AGPL-3.0-only
(copyright Znewco, Inc. d/b/a ZODL), with commercial licences sold separately
and a carve-out reserving App Store distribution to official Zodl builds.
Linking it — even only to reuse its block-fetch layer — would relicense this
entire project as AGPL, including for users interacting with it over a network,
which for a bridge node is the normal case rather than an edge case.

There is also little to reuse. Slipstream operates at a different layer: it is
wallet-sync orchestration delegating every cryptographic decision to unmodified
`librustzcash` crates, with no accumulator and no protocol surface. The overlap
with an accumulator library is close to nil.

Reading Slipstream's source for ideas is not linking. Copying its code is.
`deny.toml` enforces the boundary so an accidental `cargo add` fails CI rather
than review.

**What would change this:** nothing short of a decision to accept AGPL for the
whole project, which would need to be deliberate and recorded here.

---

## D2 — Nullifiers use an indexed Merkle tree, not Utreexo

**Decided in CLAUDE.md §2.1; restated here because it is the decision most
likely to be re-litigated by someone new.**

A Utreexo forest, a Merkle mountain range, and every other unordered hash
accumulator prove *membership*. Nullifier checking needs the opposite: proving a
nullifier has never appeared. Absence cannot be proven from an unordered
accumulator without holding the entire set, which defeats the purpose.

An indexed Merkle tree keeps the set sorted by threading a linked list through
the leaves: each leaf holds `(value, next_value, next_index)`. Non-membership of
`x` is a Merkle path to the *low leaf* `L` with `L.value < x < L.next_value`.
Because the list has no gaps, a value strictly between a leaf and its successor
cannot be in the tree.

"Just use Utreexo with deletion disabled" is the known failure mode. It answers
a different question than the one nullifier checking asks.

---

## D3 — Indexed Merkle tree depth: fixed, parameterised, default 32

**Decided 2026-08-10.** CLAUDE.md §7 listed this as an open question.

Depth is fixed at construction rather than growable. Consequences:

* Every proof is exactly `depth` siblings — 1 KiB at depth 32. Constant proof
  size is much easier to specify in a future ZIP than one varying with chain
  height, and it removes "what depth was the tree at height H" from the
  verifier's problem entirely.
* One code path for every insertion. A growable tree needs a second root-update
  path for the grow step, which is a rare branch in a consensus-critical
  function — the worst combination.
* A capacity ceiling of `2^depth`, which has to be defensible.

**The default of 32 gives 4.29e9 leaves per pool.**

The ceiling is derived from **transaction throughput, not block count**, which
is what makes it robust to the NU7 vote. Three-times faster blocks triple the
block rate; they do not triple the number of shielded spends, which is bounded
by demand rather than by block spacing. That part of the original reasoning
survives measurement.

### Correction, 2026-08-12: the headroom claim was wrong

This entry originally asserted that "even a sustained thousand-fold increase in
spend volume over today leaves decades of headroom." **Phase 0 disproves that.**

Measured at mainnet tip (`docs/benchmarks.md`): Orchard reveals 6.192
nullifiers per block, Ironwood 2.934, Sapling 0.138 — 9.264 shielded nullifiers
per block combined. At a 75-second target that is 420,768 blocks per year.

Time for the fastest-filling pool (Orchard) to exhaust depth 32:

| Spend volume | Years to fill |
|---|---|
| today's rate | 1,648 |
| 10× | 165 |
| 100× | **16.5** |
| 1000× | **1.65** |

A thousand-fold increase fills it in under two years, not decades. The claim was
off by roughly three orders of magnitude, and it was wrong in the unsafe
direction. It came from reasoning about the *stock* of existing nullifiers
(tens of millions against 4.29e9) instead of the *flow*, which is what actually
fills an append-only tree.

Two further corrections to the picture:

* If NU7 triples block rate *and* volume triples with it, 100× growth exhausts
  depth 32 in **5.5 years**.
* Orchard is withdraw-only and draining, so its rate should decay toward zero
  while Ironwood absorbs it. The long-run steady state is closer to the full
  9.264/block landing in a single tree: 1,102 years at today's rate, 11 years
  at 100×.

### Resolved 2026-08-14: depth 40

`DEFAULT_DEPTH` is now **40**. Reasoning below; the decision was taken on the
measured numbers rather than deferred to Phase 3.



Depth 32 is comfortable for realistic growth — 165 years even at a sustained
tenfold increase — but 100× sustained adoption puts the ceiling inside the
plausible lifetime of a consensus format, and an append-only tree never
reclaims space.

The cost of more depth is bounded and known (`docs/benchmarks.md`):

| Depth | Capacity | Proof | Verify | Orchard @100× |
|---|---|---|---|---|
| 32 | 4.29e9 | 1,106 B | 4.07 µs | 16.5 yr |
| 36 | 6.87e10 | ~1,234 B | ~4.6 µs | 264 yr |
| 40 | 1.10e12 | 1,362 B | 5.07 µs | 4,220 yr |

Depth 40 costs +23% proof bytes and +25% verification for 256× the capacity.
The asymmetry favours depth: overshooting costs a fixed bandwidth premium
forever, while undershooting costs a hard consensus migration under time
pressure.

**Chosen: 40.** The deciding argument is that asymmetry. 16.5 years of headroom
under a plausible-if-optimistic adoption scenario is not enough margin for a
format that can only be changed by a network upgrade, and 1.1e12 leaves removes
the question entirely rather than deferring it.

If Phase 5 finds proof bandwidth dominating the result, 36 remains available as
a compromise (16× depth-32 capacity for +12.5% bytes) — but changing it then
means regenerating every pinned root, so treat 40 as settled unless a
measurement forces it.

Depth is a constructor parameter, so a pool needing more can be instantiated
deeper without touching the algebra. Different depths produce different roots,
so this is a per-pool launch decision, not a migration.

---

## D4 — Value ordering is big-endian over the canonical nullifier encoding

Values are compared as big-endian 256-bit unsigned integers over the 32-byte
nullifier serialization. `[u8; 32]`'s derived lexicographic `Ord` is exactly
that, which is why `Value` can derive its ordering rather than hand-rolling it.

The choice is arbitrary in the sense that little-endian would work equally well;
it is *not* arbitrary in the sense that it is consensus-visible. Two
implementations disagreeing here produce different roots from the same set.

---

## D5 — `Value::ZERO` is a reserved sentinel

Leaf 0 always holds `(0, 0, 0)`. All-zero is never insertable, which frees it to
mean "no successor" in `next_value`.

A real all-zero nullifier is cryptographically unreachable, but the code rejects
it explicitly rather than relying on that. Relying on an improbability is how a
consensus bug gets written.

---

## D6 — Every hash is domain-separated by structure, pool, and node role

CLAUDE.md §5 rule 4, implemented in `crates/zutreexo-accumulator/src/hash.rs`.

BLAKE2b personalization is 16 bytes and enters the parameter block rather than
the message, so two personalizations are independent functions. Every separator
fills all 16 bytes — a short one is silently zero-padded, which would make two
"different" separators equal if they shared a prefix.

| Structure | Layout | Example |
|---|---|---|
| Transparent Utreexo | `"ZUtxoAccum" ‖ "__" ‖ role(4)` | `ZUtxoAccum__Leaf` |
| Nullifier IMT | `"ZNullIMT" ‖ pool(4) ‖ role(4)` | `ZNullIMTOrchLeaf` |

Pool tags: `Sprt`, `Sapl`, `Orch`, `Iron`. Roles: `Leaf`, `Node`, `Empt`.

The empty leaf gets its own separator rather than reusing all-zero bytes, so no
populated leaf can collide with an unoccupied position whatever its contents.

These strings are consensus-visible and must never change.
`crates/zutreexo-testkit/src/vectors.rs` pins the resulting digests.

---

## D7 — Sprout is included

CLAUDE.md §7 asked for an explicit decision. `PoolId` has a `Sprout` variant.

It is legacy and small, but its nullifier set is nonzero and permanent, and a
replay from genesis has to account for it. Excluding it would make the chain
crate unable to represent real history in order to save one enum variant. The
per-pool parameterisation means the cost of including it is one more tag.

---

## D8 — `PoolId` lives in the accumulator crate

CLAUDE.md §3 places `pool.rs` in `zutreexo-chain`. `PoolId` itself is defined in
`zutreexo-accumulator` instead, because the hash domain separators are
pool-specific and domain separation is a Phase 1 concern; the accumulator crate
cannot depend on the chain crate to learn what a pool is.

`zutreexo-chain` re-exports it, so chain code has one obvious import.
Per-pool *chain state* still lands in `zutreexo-chain::pool` in Phase 2.

---

## D9 — Transparent leaves commit to the whole output plus its context

`UtxoLeaf` hashes `txid ‖ vout ‖ height ‖ is_coinbase ‖ value ‖ len(script) ‖
script`, all fixed-width or length-prefixed so the preimage admits exactly one
parse.

Rationale, following CLAUDE.md §7:

* **Outpoint** alone is insufficient — outpoints can recur across chains and
  across a rollback-and-remine.
* **Value and script** stop a proof for a dust output being replayed for a
  large one.
* **Height and coinbase flag** because coinbase maturity is a consensus rule and
  a node holding no UTXO set has nowhere else to learn either fact.

**Not final.** This mirrors Bitcoin's Utreexo leaf design and must be confirmed
against the Zcash transparent transaction format and Zcash's own coinbase rules
before Phase 3 freezes anything — CLAUDE.md §5 rule 7 warns specifically against
inferring from Bitcoin analogy.

---

## D10 — Upstream blocker: `rustreexo` 0.6.0 cannot prove after deletions

**Found 2026-08-10 by the Phase 1 differential suite. This is the most important
open item in the project.**

`rustreexo` 0.6.0 generates *invalid inclusion proofs* for any leaf whose
sibling has been deleted. Reproduced with stock upstream types
(`MemForest`/`Stump`/`BitcoinNodeHash`), so it is not caused by our
`ZcashNodeHash` or our domain separation:

```
add 8 leaves        → every leaf proves and verifies
delete leaf 0       → forest and stump roots still agree
prove leaf 3        → verifies (its sibling is untouched)
prove leaf 1        → prove() returns Ok, verification fails:
                      InvalidProof(MissingSibling(9))
```

In canonical Utreexo a surviving sibling is promoted one row when its partner is
deleted, and its proof becomes one node shorter. `MemForest::prove` appears to
keep reporting the leaf's original position, so verification asks for a sibling
no longer on the path.

`Pollard`, the other full-forest type, is worse: after a deletion it cannot
generate a proof for an *unaffected* leaf either, failing with
`"Could not upgrade node, this is probably a bug"`. **Switching structures is
not the fix.**

State tracking is unaffected — `MemForest` and `Stump` roots stay identical
through arbitrary add/delete sequences. It is proof *generation* that is broken.

**Why it matters.** Spending one of two adjacent outputs is routine, so on
mainnet this fires constantly. A bridge node cannot serve transparent inclusion
proofs across blocks, which blocks the transparent half of Phase 4.

**Pinned, not worked around.** `crates/zutreexo-accumulator/tests/upstream_rustreexo.rs`
asserts the defective behaviour on purpose. Those tests fail when upstream fixes
it, which is the signal to delete the file and restore full property coverage in
`tests/properties.rs`.

**Options, in preference order:**

1. Report upstream and wait. Cheapest if it lands.
2. Implement the forest ourselves. Contradicts CLAUDE.md §3's dependency policy,
   and it is the part of the design with the least novelty — a poor use of
   effort.
3. **Drop the transparent forest.** CLAUDE.md Phase 5 already anticipates this:
   Zcash's transparent UTXO set is far smaller than Bitcoin's, so the
   transparent-side storage win may not justify its proof bandwidth, and "the
   nullifier IMT is where the durable value most likely lives."

This finding is evidence for option 3, but not proof of it — the decision should
be made on Phase 0/Phase 5 measurements, not on the inconvenience of a
dependency. Recording it here so the argument is not re-derived from scratch
later.

### Resolved 2026-08-14: keep the transparent forest

**Decision: the transparent side stays in scope.** Option 1 (report upstream and
work around) rather than option 3 (drop it).

The Phase 0 measurement showed the transparent UTXO set is flat *in aggregate*,
and I read that as weakening the case. The counter-argument, which is better
than mine: **centralised exchanges deal almost exclusively in transparent
funds.** Shielded adoption is growing, but exchange flow is the dominant source
of transparent transactions and it is not going away in any near-term horizon —
so transparent throughput stays high even while the *net* set size holds steady.

That reframes the flat-set finding. A flat set means the storage saving does not
compound, which is a real limit on the upside. It does not mean the transparent
side is idle: a high spend rate against a steady-state set is exactly the
workload Utreexo's cheap-deletion design was built for, and it is the case worth
exercising.

Consequences:

* The upstream defect above moves from "reason to drop the feature" to "blocker
  to route around." Options, in order: report it upstream, and if that stalls,
  either pin a working revision or implement the forest ourselves.
* The transparent-side property coverage in `tests/properties.rs` stays narrowed
  until the defect is resolved, and `tests/upstream_rustreexo.rs` remains the
  alarm.
* Phase 5 still measures both halves honestly and separately. Keeping the
  transparent forest in scope is not a commitment to shipping it.

The nullifier IMT, which is the part that carries the project's claimed value,
is entirely unaffected: it depends on nothing but `blake2b_simd`.

---

## D13 — Upstream: `rustreexo` proof decoding is an unbounded allocation

**Found 2026-08-10 by the 10,000-case property sweep. Fixed at our boundary;
still present upstream.**

`rustreexo::proof::Proof::deserialize` reads a `u64` length prefix and passes it
directly to `Vec::with_capacity` without checking it against the available
input:

```rust
let targets_len = read_u64(&mut buf)? as usize;
let mut targets = Vec::with_capacity(targets_len);   // unbounded
```

Eight attacker-chosen bytes therefore buy an allocation of any size. The
property test `decoders_never_panic`, feeding arbitrary bytes to every decoder,
aborted the test process outright:

```
memory allocation of 3728591668636114096 bytes failed
```

3,728,591,668,636,114,096 is exactly 466,073,958,579,514,262 × 8 — a declared
target count multiplied by the eight bytes each target occupies.

**Severity.** This is a remote denial of service in any node that decodes a
peer-supplied proof, which is exactly what a compact state node does. It needs
no valid proof, no accumulator state, and no more than nine bytes on the wire.
It is a more immediately dangerous defect than D10, which merely does not work.

**Fixed here.** `decode_utxo_proof` now validates the header before
`rustreexo` sees the bytes, in `proof::validate_utxo_proof_header`. The check is
structural rather than a magic cap: targets are 8 bytes each and hashes 32, so
the declared counts must be satisfiable by the input that actually arrived. The
hash count is checked for exact fit, which also makes the encoding canonical.
The regression case is pinned in `proof::tests::hostile_utxo_proof_length_does_not_allocate`.

**What this says about the plan.** CLAUDE.md Phase 6 schedules
deserialization fuzzing for late in the project. Two decoder defects surfaced in
Phase 1 from a property test and a differential suite, before any fuzzer ran.
Both were in the dependency rather than in our code, which is the argument for
running `cargo-fuzz` against the decode paths as soon as they exist rather than
holding it for Phase 6. The always-on `decoders_never_panic` property is a
cheap standing version of the same thing and should stay.

Neither this nor D10 touches the nullifier IMT.

---

## D11 — Two accumulator views, full and compact

Each structure has a proof-generating type and a proof-verifying type:

| | Full (bridge node) | Compact (CSN) |
|---|---|---|
| Transparent | `UtxoForest` | `UtxoRoots` |
| Nullifiers | `IndexedMerkleTree` | `ImtState` |

`ImtState` is 40 bytes — a root and a leaf count — and that is the whole
shielded-side state a validating node needs per pool. The leaf count is not
redundant: without it a valid insertion proof could append at *any* unoccupied
index, producing a tree that verifies but diverges from canonical replay.

Note that `UtxoForest` is **not `Send`** — `rustreexo` builds its forest from
`Rc`. A threaded bridge node must own the forest on one thread and pass proofs
across, not share the structure. Phase 4 has to design around that.

---

## D12 — Overflow checks on in release builds

`arithmetic_side_effects` is deliberately *not* denied workspace-wide: it fires
on every `i + 1` and buries the checks that matter in noise. Instead,
`overflow-checks = true` is set for release and bench profiles, and explicit
`checked_*` guards the boundaries that can genuinely overflow — leaf counts,
tree indices, decoded lengths. Zebra takes the same position: an integer
overflow in consensus code is a bug, not a wrapping convenience.

---

## D14 — The oracles' independence is enforced by a test, not by structure

**Stage 2b.**

CLAUDE.md Phase 2 requires the naive model to share **zero code** with the
implementation, so the two cannot be wrong in the same way. Nothing in Rust
enforces that. `zutreexo-testkit` must depend on `zutreexo-chain` — `harness`
drives the replay and has to reach the code under test — so the dependency graph
permits an import from `naive.rs` or `state.rs` that would quietly destroy the
oracle's value, and the suite would stay green.

`tests/independence.rs` therefore reads those two files **as text** and fails if
either mentions `zutreexo_accumulator` or `zutreexo_chain` in code. Comments are
stripped first, so the module docs can explain the rule without violating it.

This is crude, and it is the right instrument: the property is textual, so it
should be checked textually rather than trusted to review. The alternative —
a separate crate that cannot express the dependency — was rejected because the
oracle and the harness that drives it belong together for readability, and a
crate boundary would be one more thing to get around.

---

## D15 — No independent naive Utreexo; the transparent oracle is weaker, and says so

**Stage 2b.**

The shielded side has a genuine second implementation. The transparent side does
not, and the asymmetry is deliberate.

A Utreexo root depends on the entire history of insertions and deletions rather
than on current membership, so "recompute cold from the current set" is not even
well-defined — a from-scratch oracle would mean reimplementing the forest,
including whichever deletion variant (original or swapless) upstream chose.
Getting that wrong produces *false* divergences, and an oracle that cries wolf
is worse than no oracle: it trains people to dismiss the thing that is supposed
to be the primary correctness signal.

So `NaiveState` tracks which outpoints are unspent, which is enough for the
count tier, and claims nothing more. Combined with the transparent side being
blocked upstream anyway (D10), the effort is better spent elsewhere.

What partially covers the gap instead: tier 3 now cross-checks
`transparent_spends` and `transparent_creates` against zebrad's own JSON across
all four fixture slices, which the transparent side previously had no check of
at all.

Revisit if D10 is resolved and the transparent forest becomes load-bearing.

---

## D22 — A snapshot stores only the nullifier values

**Phase 3.**

A nullifier tree is persisted as its values in insertion order, and nothing
else. Leaves, successor links and the internal node map are rederived on load by
`IndexedMerkleTree::from_values_bulk`.

Two reasons, and the second matters more:

* **Size.** 32 bytes per nullifier against roughly 600 in memory, so the 54.1M
  at tip occupy about 1.7 GB rather than 32 GiB.
* **There is no redundant state on disk to disagree with itself.** A file that
  decodes at all yields exactly one tree, so the format cannot encode a subtly
  inconsistent accumulator — no stale successor pointer, no orphaned node, no
  leaf count that disagrees with the leaves. Whole classes of corruption become
  unrepresentable rather than merely detectable.

This is affordable only because the bulk builder folds the tree a level at a
time. Replaying insertions through `from_values` costs `2 * depth` hashes per
value — 80 at depth 40 — so reloading a tip snapshot that way would take longer
than fetching the chain again.

The bulk build must produce a tree **identical** to a replayed one, not merely
equal-rooted: a reloaded snapshot has to support further blocks, undo, and
rollback, all of which compare exact state. `bulk_matches_sequential` asserts
that across depths and shapes.

The transparent forest cannot work this way. A Utreexo root depends on the whole
history of insertions and deletions rather than on current membership, so there
is no value list to replay from; it is written through `rustreexo`'s own
serialization, whose variant-losing bug D19 had to fix first.

**On NU7.** CLAUDE.md §7 asks for the vote to be checked before this format
freezes. It has not concluded, and the conclusion is that the format does not
depend on it: a 3× block time changes the *rate* at which nullifier sets grow,
not the layout, and tree depth is a header field rather than a constant. What
NU7 affects is capacity planning, which D3 already derives from transaction
throughput rather than block count.

---

## D23 — Snapshots are written atomically, and the harness proves it can fail

**Phase 3.**

Writes go to a temporary file beside the target, are `fsync`ed, `rename`d over
the target, and then the containing directory is `fsync`ed. `rename` is atomic
on POSIX, so an interrupted save leaves either the previous snapshot or the new
one. The temp file is deliberately adjacent rather than in `/tmp`, since
`rename` is only atomic within a filesystem.

CLAUDE.md's Phase 3 DoD asks for `kill -9` at any point to leave the store
recoverable. `tests/crash.rs` spawns a writer and sends it a real `SIGKILL`
mid-write — not an injected fault, because the claim is about what the operating
system does with partially written data, and an in-process fault still runs
destructors and flushes buffers.

**The control is the part that makes it evidence.** Twenty-five clean kills look
identical whether the writer is atomic or the kills simply never landed on a
write — and the first version of this harness was exactly that: its delays
started at 150 microseconds while the child needed twenty milliseconds to build
state, so every kill landed during startup and the test passed having done
nothing. So the same harness is pointed at a writer that copies straight onto
the target with no temp file and no rename. That one produces a damaged snapshot
in roughly 20 of 25 rounds. Same harness, same delays, same child; only the
write strategy differs.

Two guards came out of that: the test asserts a minimum number of rounds
actually ran, and it declines to run unoptimised at all — in a debug build the
writer cannot finish building state before the readiness timeout, so every round
would skip. It says so rather than passing. CI runs it in the nightly release
sweep.

---

## D25 — The `rustreexo` D10 blocker is fixed, and the fix is pinned to a fork

**Phase 4a.** Resolves the blocker recorded in D10, which had stood since
Phase 1 and blocked the transparent half of the entire design.

Upstream PR mit-dci/rustreexo#152 proposes a one-line change to
`Proof::calculate_hashes`. `proof_positions` is derived from `translated` —
targets mapped from `MAX_FOREST_ROWS` space into the forest's own rows — but the
node list those proof hashes are paired with is built from the *untranslated*
`self.targets`. `translate` is the identity at row 0, so the two spaces agree
for as long as every target is a leaf at the bottom of the forest, and the
mismatch is invisible. A deletion promotes a leaf, the spaces diverge, and
`get_next` hands `calculate_hashes` the wrong sibling.

**It was verified rather than trusted.** Applied to v0.6.0 (`8bb8b26`) — not
`main`, which carries a breaking `Stump::modify` change — and run against a
harness that builds 400 randomised forests, deletes a random subset from each,
then proves and verifies *every* surviving leaf:

| | proofs checked | failures | root mismatches |
|---|---|---|---|
| stock v0.6.0 | 4,671 | **1,848** | 0 |
| patched | 4,671 | **0** | 0 |

Same seeds, same leaves. 40% of survivors were unprovable before and all are
provable after.

**`Pollard` is a different story, and D10's conclusion survives.** The obvious
reading — "D10 is fixed, so both full-forest types work now" — is wrong:

| after deleting leaf 0 | stock 0.6.0 | patched |
|---|---|---|
| promoted sibling | broken | works |
| unaffected leaves | broken | **still broken** |

The promoted sibling was the `calculate_hashes` fault. The unaffected-leaf
failure is a separate defect in `Pollard`'s node-upgrade path, occurs at proof
*generation*, and nothing in PR #152 touches it. So the bridge must hold a
`MemForest`, and D10's "switching structures is not the fix" holds — which is
worth stating because the first pass at this concluded the opposite from an
alarm that happened to fire. The alarm asserted `sibling_is_broken &&
unaffected_is_broken`, so it fired when only one of the two improved.

**Consequences.**

* `Cargo.toml` pins `rustreexo` to a fork of v0.6.0 carrying the one line.
  Reverting to stock silently reintroduces invalid proofs, so
  `tests/upstream_rustreexo.rs` now asserts the *fixed* behaviour: those tests
  are the guard on the pin. Drop the pin when upstream merges.
* The transparent property coverage narrowed in Phase 1 is restored.
  `utxo_forest_and_roots_stay_in_step` no longer skips rounds whose proofs will
  not verify; it asserts they do. Confirmed to fail against stock 0.6.0 and pass
  against the fork, because a restored assertion that cannot fire is worth
  nothing (D24).
* mit-dci/rustreexo#151 (`MemForest::clone` aliases rather than snapshots) is
  untouched and remains an alarm. `rollback.rs` still needs the
  serialize/deserialize round-trip.

---

## D26 — What goes in a proof bundle, and what the block already says

**Phase 4a.** The bundle is the interface between a bridge and a compact node,
and every byte in it is paid on every block by every client, so the question is
not "what might a verifier want" but "what can a verifier not derive".

**In:** the spent outputs' full contents, one batched Utreexo inclusion proof,
and one insertion proof per nullifier.

**Out, and why:**

* **Created outputs.** They are in the block. A verifier with the block computes
  their leaf hashes itself. Shipping them would double the second-largest term.
* **Nullifier values.** Likewise in the block.
* **Non-membership proofs.** An `InsertionProof` carries the low leaf and its
  path, and `verify_insertion` checks both that the low leaf is in the tree at
  the current root and that it brackets the value — which *is* a non-membership
  proof. A separate one would add bytes and a second thing to keep consistent
  for no additional assurance. `NullifierProofBundle` does carry both, and that
  is not a contradiction: it answers a wallet's standalone "has this nullifier
  been spent?" query, where there is no insertion to piggyback on.

**The spent contents are unavoidable.** A transaction that spends an output
carries only an outpoint, while the leaf being deleted commits to value, script,
height and coinbase flag (D9). Nothing in the block supplies that, so either the
bundle carries it or the verifier keeps a UTXO set — and keeping one is the
thing the project exists to avoid.

**Cancellation is claimed by the bridge and checked by the node.** An output
created and spent in the same block never enters the accumulator (D21), so it
has no proof. Rather than have the compact node re-derive which spends were
cancelled — it cannot, exactly: `apply_block` consults the outpoint index first
and the compact node has no index — the bundle simply omits them, and the node
verifies that every omitted spend is an output the block does create. The
bridge asserts, the node checks against the block. A bridge that omitted a
*real* spend would otherwise get a deletion skipped, and the divergence would
surface blocks later with nothing pointing at the cause.

Three tampering cases are tested and rejected: a substituted leaf (a different
output that is genuinely in the accumulator), an omitted spend, and a smuggled
extra leaf. A hostile bridge can withhold service and can observe which blocks a
node asks for — the Phase 6 privacy question — but it cannot make a compact node
accept a wrong transition.

---

## D24 — A checksum in front of a parser hides every check behind it

**Phase 3.** Found while merging `main` into the Phase 3 branch, by the coverage
gate rather than by any test.

`load` verifies the magic bytes and the payload checksum before handing the
payload to `decode`. That ordering is right — a wrong-format file should say so
rather than fail a checksum, and corruption should be named as corruption. The
consequence is easy to miss: **every structural check inside `decode` becomes
unreachable by any edit that disturbs the payload.** The checksum fires first,
every time.

Three of the twelve round-trip tests were written without noticing this, and all
three passed:

| test | intended check | check that actually fired |
|---|---|---|
| `an_unknown_version_is_refused_not_guessed` | `UnsupportedVersion` | `ChecksumMismatch` |
| `trailing_bytes_are_rejected` | trailing-byte arm in `decode` | `ChecksumMismatch` |
| `truncation_at_any_length_is_an_error_not_a_panic` | `Truncated` arms in `decode` | `ChecksumMismatch` |

Two of them asserted only `is_err()`, which is what let it through. Worse, the
version test carried a comment claiming it checked the valid-checksum path "directly
too" — it did not, and the comment is the reason nobody looked again. The
trailing-byte test's comment asserted "the payload still verifies", which is
false: splicing bytes in ahead of the recorded checksum puts them *inside* the
checksummed region.

Nothing was wrong with `store.rs`. The arms all work. What was wrong is that
they were **never executed**, so nothing would have noticed if they stopped
working — and `decode` is the crate's only untrusted-input surface, which is
precisely where an unexercised arm means a parser accepting what it should
refuse.

**Reaching those arms requires forging a well-formed file:** edit the payload,
then reseal it with a checksum that matches. That is also the realistic
adversary — anyone who can hand a node a snapshot can compute a checksum — so
these are the cases that matter, and the bit-flip cases the original tests
constructed are the ones that do not. The three tests were renamed to what they
actually verify (they are still worth keeping; checksum-first ordering is a real
property) and three new tests were added behind `reseal`.

Both new tests were then **mutation-checked**: disabling the version comparison
and disabling the trailing-byte comparison each turn exactly one new test red
while every original test stays green. That last part is the finding restated as
evidence — the old tests cannot see either bug.

Two things generalise:

* **`assert!(x.is_err())` is not a test of which error.** It is a test that
  something went wrong somewhere. Where a function has several rejection paths,
  the assertion has to name the variant, or it silently accepts the wrong one.
* **A validation ordered behind a cheaper, broader check needs tests that
  deliberately satisfy the cheaper check.** Otherwise the broader check masks
  the narrower one and the narrower one rots untested. This is a general shape,
  not a snapshot-format quirk; Phase 6's deserialisation fuzzing will hit the
  same wall and must reseal too, or it will spend its whole budget bouncing off
  the checksum.

The mechanism that caught it was the per-file coverage floor — green tests with
zero coverage, sitting directly above each other. It is the third time on this
project that a test has passed for a reason other than its name (see D17 and
D21), and the first time a non-test tool found one.

---

## D21 — An output created and spent in one block is cancelled, not accumulated

**Stage 2d. Corrects a wrong claim made in 2a.**

A transaction may spend an output created by an **earlier transaction in the
same block**. Both Bitcoin and Zcash permit it; mainnet block 572 does it, with
`tx[10]` spending an output of `tx[8]`. Only spending an output created *later*
in the block is forbidden.

`block_apply.rs` originally ordered every deletion before every insertion and
documented that ordering as *preventing* intra-block spends, "which Zcash
consensus forbids". The claim was false — a Bitcoin analogy applied backwards,
which is the specific error CLAUDE.md §5 rule 7 exists to prevent.

**Why three stages missed it.** Every fixture replay in 2a, 2b and 2c ran with
`allow_unknown_spends`, because those windows do not start at genesis and
spends of pre-window outputs are expected there. That option counted every
intra-block spend as a pre-window spend and moved on. The genesis-forward
replay in 2d cannot use it, and hit the problem after 572 blocks.

The general lesson is worth more than the fix: **a tolerance added for one
legitimate reason silently absorbed a different, illegitimate case.** Anything
of the form "ignore what we cannot resolve" should be viewed the same way.

**The choice: cancellation.** Such an output never enters the accumulator or the
index at all. The alternative — insert it, then delete it — is equally well
defined but makes the resulting forest depend on how insertions and deletions
interleave, so it would need an ordering rule. Cancellation needs none, which is
why it is a *specification* choice rather than an optimisation (CLAUDE.md §5
rule 6 would otherwise require a benchmark to justify it). Bitcoin's Utreexo
made the same choice.

Consequences:

* `StateDelta` records neither the create nor the delete, because neither
  happened — so rollback needs no special case.
* A compact state node needs no inclusion proof for such a spend, which is a
  small bandwidth saving that Phase 5 should measure rather than assume.
* The naive oracle implements the same *rule*, derived from it independently
  rather than copied. The harness caught the two disagreeing the moment the
  implementation changed, which is what it is for.

Not enforced: that the creating transaction precedes the spending one. Doing so
needs per-transaction indices in `BlockSummary`, and this project is
consensus-neutral — Zebra has already validated every block it is fed, so the
ordering violation cannot arrive. **A Phase 7 consensus-enforcing
implementation must add that check.**

---

## D18 — Rollback is delta-based for nullifiers and snapshot-based for the forest

**Stage 2c.**

CLAUDE.md Phase 2 says to persist "the deleted leaves *and their positions*" in
a `StateDelta` and undo from that. **That plan assumes an API `rustreexo` does
not have.** It exposes only `modify(add, del)`, which appends; there is no way
to reinsert a leaf at the position it occupied. A Utreexo deletion therefore
cannot be inverted from a delta at any price, and `StateDelta::spent` — built in
2a for exactly this — cannot serve it.

The two halves get different mechanisms:

* **Nullifiers — delta undo, exact.** An IMT insertion rewrites one leaf and
  appends another, and `InsertionProof` already carries the low leaf as it stood
  beforehand. `undo_insert` inverts it precisely, and is strictly LIFO because
  undoing out of order leaves the linked list pointing at an index that no
  longer holds what the pointer claims — a tree that hashes to a plausible root
  while encoding a set nobody can reason about.
* **Transparent — snapshot and replay.** Restore a serialised forest from at or
  below the target, then replay the intervening deltas forward.

Snapshots go through `serialize`/`deserialize` and **not** `clone()`.
`MemForest` derives `Clone`, but holds `Rc<Node>` where `Node` keeps its hash in
a `Cell`, so the clone shares nodes and mutating either handle changes both. It
compiles and reads like a snapshot. Pinned in
`tests/upstream_rustreexo.rs`, reported upstream.

Two corrections fell out of building it, both in code written earlier:

* **`StateDelta::created` kept almost enough.** It stored `(OutPoint, Hash)`.
  The forest needs only the hash, so it looked sufficient — but replay must also
  rebuild the *outpoint index*, which needs the output's value, script, height
  and coinbase flag. The forest would have come back correct while the index
  came back short, surfacing much later as an `UnknownOutpoint` on an unrelated
  block. CLAUDE.md warns that this is exactly where reorg work goes wrong.
* **Retention is a depth, not a count.** Keeping "two snapshots" gives 200
  blocks of reach at an interval of 100 and *one block* at an interval of 1.
  `max_depth` is now its own knob, so a small interval costs memory and never
  costs reach.

Sizing snapshots for mainnet needs the transparent UTXO count, still a Phase 0
gap — Zebra does not implement `gettxoutsetinfo`.

---

## D19 — `ZcashNodeHash` serialisation must be tagged

**Stage 2c. A latent Phase 1 defect, found by the reorg fuzzer.**

`write` emitted a bare 32 bytes and `read` returned `Some(bytes)`
unconditionally. Byte-symmetric, and wrong: the *variant* was lost, so `Empty`
came back as `Some([0; 32])`.

`MemForest`'s reader only descends into a branch's children when
`!data.is_empty()`, so an empty node writes none. A reader that resurrects it as
`Some` goes looking for two children that were never written and fails with
"failed to fill whole buffer".

The encoding is now tagged — `[0]` empty, `[1]` placeholder, `[2]` plus the
digest — matching upstream `BitcoinNodeHash` byte for byte. Unknown tags are
rejected rather than assumed, since snapshots are bytes from disk.

This was invisible from Phase 1 until stage 2c because **nothing serialised a
forest until rollback needed a snapshot**. It would have corrupted any snapshot
containing an empty branch node — which is to say, any forest that had ever seen
a deletion.

One knock-on: `rustreexo` writes proof hashes through the same
`AccumulatorHash::write`, so a proof hash is 33 bytes on the wire, not 32. The
header validator's exact-fit check rejected every valid proof until corrected.
It is now an upper bound, because tagged entries are variable width — `Empty`
and `Placeholder` cost one byte — and an equality check is simply wrong against
a variable-width encoding. It still refuses a header claiming a billion hashes
in forty bytes, which is what it exists for.

---

## D20 — The reorg fuzzer pins the chain height

**Stage 2c.**

The first version chose a rollback depth and an extension length independently.
Both averaged about four blocks, so the tip random-walked upward — reaching
height 15,722 by iteration 24,523, where the depth-12 tree hit its 4,096-leaf
ceiling and the run died on a capacity error that read like a rollback bug.

It also dominated the cost. A cold replay is linear in chain length, so the
validating step grew steadily more expensive; most of the 340 seconds that
100,000 iterations took was replaying a chain thousands of blocks long rather
than exercising reorgs. Pinning the height took the same run to **7.4 seconds**,
and made the 10⁶ definition of done a **75-second** job rather than a
ninety-minute one.

Nothing is lost: the state machine does not care about absolute height, and
every block's content still varies. `ReorgReport::highest_tip` is asserted
against `chain_len` so the regression is visible immediately rather than tens of
thousands of iterations later.

---

## D17 — Every tier is proven to fire, and proven to be the only one that does

**Stage 2b.**

A harness that has never caught anything is unproven, and a *tier* that has
never caught anything is dead weight that looks like coverage. So each tier has
a fault injected into the implementation's input — the oracle still sees the
truth, making the fault indistinguishable from a real bug — plus a paired test
showing the other tiers cannot see it. Without the pairing, a test proves only
that *something* fired, not that the expensive tier was needed.

| Fault | Caught by | Blind |
|---|---|---|
| drop a nullifier | tier 1 | — |
| drop an output | tier 1 | — |
| reorder nullifiers within a pool | **tier 2** | tier 1 (counts unchanged) |
| undercount a note commitment | **tier 3** | tiers 1 and 2 |

The last row was added after coverage measurement showed
`compare_checkpoint`'s mismatch branch had never executed — tier 3 was asserted
to work and never demonstrated. Commitments are counted but never accumulated,
so they reach no root and no compared count, and both local oracles are fed from
the same parse. Only the node's independently-derived answer disagrees, which is
exactly the bug class tier 3 exists for.

One consequence for the implementation: `Report::totals` accumulates from what
the implementation *saw*, not from the pristine parse. Reading the untouched
summary there would have made tier 3 structurally incapable of detecting a
parsing bug — the only thing it is for.

---

## D16 — Tier 2's cost is tuned down by default, not left at its strictest

**Stage 2b.**

A cold root rebuild costs about `2^(depth+1)` hashes per pool per check. At
depth 14 checking after every block, the four fixture slices come to roughly
10⁸ hashes — 18 seconds in release, but `cargo test` builds unoptimised, and it
turned the per-push job into a twenty-minute one.

The default is therefore depth 12 with a rebuild every 10 blocks, and the
nightly sweep runs depth 14 with a rebuild after every block. Both are
controlled by `ZUTREEXO_HARNESS_DEPTH` and `ZUTREEXO_ROOT_CHECK_EVERY`.

The reasoning is that a check slow enough to be skipped protects nothing. The
strict setting still runs every night and on demand, and the test asserts the
*exact* number of rebuilds performed, so a tier that silently stopped running
fails rather than passing quietly.

---

## Open questions not yet answered

These are CLAUDE.md §7 items that Phase 1 could not resolve, carried forward.

* **Does Tachyon's PIR work subsume this?** Unresolved, and it remains the
  single question most likely to make the effort redundant. If private
  information retrieval gives wallets private nullifier queries with a better
  privacy story than bridge-served non-membership proofs, the main use case
  evaporates. Requires talking to people, not writing code.
* **Phase 0 measurements.** ~~Not taken.~~ **Taken 2026-08-12** against
  zebrad 6.3.0 at mainnet tip; see `docs/benchmarks.md`. They disproved the
  headroom claim in D3, which is corrected above and now carries an open
  decision on tree depth. Two gaps remain: the transparent UTXO set count
  (Zebra does not implement `gettxoutsetinfo`) and per-pool commitment counts,
  both needing a full-history scan or direct RocksDB access.
* **NU7 vote outcome.** Opens late August 2026. D3 is constructed to survive a
  3× block-time change, but the vote result should be checked before Phase 3.
* **Privacy of the query pattern.** A wallet asking a bridge for a *specific*
  nullifier's non-membership proof is a metadata leak. Phase 6 gates on this.
  Nothing in Phase 1 forecloses any mitigation — batching with decoys, oblivious
  retrieval, or restricting queries to nullifiers about to be published anyway —
  but the bridge's query API in Phase 4 must be designed with the answer in
  hand, not retrofitted.

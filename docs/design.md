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

## D27 — The bridge speaks binary over HTTP, not gRPC

**Phase 4b.** A deliberate departure from CLAUDE.md §4, which says to expose
these methods through Zaino "otherwise as a standalone sidecar with the same
transport" — Zaino speaks gRPC, so that reads as protobuf.

Everything the bridge serves already has a canonical binary encoding, built in
Phase 4a and made sparse in D28. Wrapping those bytes in protobuf puts one
length-delimited framing inside another and buys nothing, while adding
`tonic`/`prost` and their transitive tree to a dependency policy that has stayed
deliberately narrow. So the transport is HTTP/1.1 with
`application/octet-stream` bodies: a one-byte method tag in, a one-byte status
plus payload out.

Not base64 or hex, which would have been the easy way to reuse the existing
JSON-RPC client shape. Hex doubles the payload and base64 adds a third, and the
whole point of Phase 4a's measurements is what these bundles cost on the wire.
An encoding that inflates them by a third would corrupt the numbers this project
exists to produce.

The codec is kept in `wire.rs`, separate from the socket handling, precisely so
a Zaino adapter is a shim over the same bytes rather than a reimplementation. If
the maintainers are receptive, that shim is the integration.

**`GetUtxoInclusionProofs(outpoints)` is not implemented**, though CLAUDE.md
lists it. Every caller identified so far wants the inclusion proofs *for a
block*, which the bundle already batches — and Phase 4a measured batching at an
85.4% saving over proving inputs individually. A per-outpoint method invites
exactly the access pattern that measurement says to avoid, and it is a
denial-of-service lever for Phase 6 besides. It can be added when something
needs it.

### The bridge cannot be multi-threaded as it stands

Found while writing the definition-of-done test: **`ChainAccumulators` is not
`Send`.** `rustreexo`'s `MemForest` is a `Vec<Rc<Node>>` plus a
`HashMap<_, Weak<Node>>`, with each node's hash in a `Cell` — the same structure
behind the clone-aliasing defect in D11 (mit-dci/rustreexo#151).

So the state cannot be moved to a worker thread, and the server runs on the
thread that owns it. That is fine for a loopback sidecar and it is what the test
does, but it constrains any real deployment: concurrency has to come from
owning the state on one thread and passing requests to it over a channel, not
from sharing it behind a lock. Worth knowing before anyone designs the
production topology.

The server also has no TLS, no authentication, no rate limiting, and no
proof-size caps. **Bind it to loopback.** A peer requesting proofs for every
UTXO is the explicit Phase 6 denial-of-service concern and none of that analysis
has been done.

### Retention is the real limit on the Phase 4 definition of done

A bundle's inclusion proof is only valid against the accumulator as it stood
before its block, and Utreexo deletion is not invertible (D18), so a proof
cannot be regenerated once later blocks land. A bridge that will be asked for
height `H` has to have kept `H`'s bundle.

`Bridge::keep` bounds that, because keeping every bundle is keeping the chain a
second time. The definition of done — "a CSN can complete IBD to tip using only
headers + blocks + bridge-served proofs" — therefore holds *only for a bridge
retaining every bundle a client will request*, which for a genesis-forward sync
means all of them. A client asking for an evicted height is told
`NO_SUCH_HEIGHT` and has to sync from a snapshot or a bridge with a longer
window. That is a real operational cost of the design and it is not hidden
behind a hang or a corrupt answer.

---

## D28 — Sparse proof paths: omit the siblings both sides can derive

**Phase 4b.** Wire format change, `PROOF_FORMAT_VERSION` 1 to 2. Taken now
rather than later because Phase 4b gives the format its first clients, and
after that it is frozen.

A depth-40 indexed Merkle tree holding a few million nullifiers is
overwhelmingly empty: above roughly `log2(leaf_count)` every sibling on a path
is the canonical hash of an empty subtree at that level, which both encoder and
decoder can derive from the pool's domain separator. Phase 4a measured 71.4% of
sibling hashes to be exactly that.

The encoding replaces the dense path with a length byte, a presence bitmap of
one bit per level, and only the siblings whose bit is set. `empty_subtree_hashes`
is public so both sides build the identical ladder.

Measured, not projected:

| | dense | sparse | saved |
|---|---|---|---|
| wallet non-membership proof, depth 40 | 1,362 B | 637 B | **53.2%** |
| nullifier proofs in a block bundle (heights 0–20,000) | 186,943,218 B | 58,698,488 B | **68.6%** |
| compact-node proof overhead (heights 0–20,000) | 101.3% | 73.1% | — |

**A lying bitmap cannot forge acceptance.** A hostile bridge can clear a bit for
a sibling that is not empty; the decoder then substitutes the empty hash, the
verifier folds the path, and the computed root does not match the trusted one,
so the proof is rejected. The bitmap is not a trusted channel — it can only
produce a proof that fails, which is the same guarantee the dense encoding
gives against a corrupted sibling. Tested directly rather than argued.

The pool is now carried explicitly, in `NonMembershipResponse` and in the block
bundle. It has to be: the omitted hashes are domain-separated per pool, so a
decoder cannot rebuild them without knowing the tree. That also makes a proof
moved between pools a decode-time error naming the mistake, rather than a root
mismatch several layers down — the reasoning already applied to
`NullifierProofBundle`.

The depth is carried for the same reason, once per bundle rather than per proof.
A verifier whose depth disagrees fails on the first proof instead of computing a
wrong root.

---

## D29 — A length guard that only checked one direction

**Phase 4b.** A denial-of-service hole in our own decoder, found by a bit-flip
sweep written for coverage rather than for security.

`decode_utxo_proof` wraps `rustreexo`'s proof parser, which allocates from a
length prefix before checking it against the input (D13, reported upstream,
still open). `validate_utxo_proof_header` exists to guard that. It checked:

```rust
if hashes_bytes < reader.remaining() { return Err(...); }
```

which rejects a header declaring *fewer* hashes than the bytes present. It never
checked the other direction. A header declaring **more** hashes than could
possibly be there passed straight through into `Proof::deserialize` and its
`with_capacity`.

`bundle_codec.rs`'s bit-flip test found it immediately: one flipped bit set the
count to 2^32+1, and 2^32+1 × 33 bytes is 141,733,920,801 — the test process
aborted on the allocation.

**The comment above the check asserted the opposite of what the code did.** It
read: *"a header claiming a billion hashes in forty bytes is rejected before
anything is allocated."* That is precisely the case that was accepted. This is
the fourth time on this project that prose has described a check the code did
not perform (D17, D21, D24), and the second time the false statement was written
by the same hand as the code it described.

The fix is a lower bound before the upper one. Every hash entry costs at least
one byte under the tagged encoding — a bare tag for `Empty` or `Placeholder` —
so a declared count exceeding the remaining bytes is unsatisfiable whatever
those bytes contain:

```rust
if hashes_len > reader.remaining() { return Err(DeclaredLengthExceedsInput { .. }); }
```

Two things worth carrying forward.

**A bounded outer length does not bound an inner decoder.** The bundle decoder
already read the proof as a length-prefixed byte string, correctly bounded
against the bytes remaining. That guarantees the *slice* is small; it says
nothing about what a nested parser will do with a length prefix *inside* the
slice. Every layer that hands bytes to another parser needs its own bound.

**This is Phase 6 arriving early and unannounced.** CLAUDE.md schedules
deserialisation fuzzing for Phase 6, and the reasoning had been that D13 is an
upstream problem to be waited out. It is not only upstream: the wrapper written
to contain it did not. A three-line bit-flip loop in a test written to raise a
coverage number found in seconds what the schedule had deferred by two phases.
`tests/utxo_proof_header.rs` pins the vector as a named seed, because the sweep
that found it is randomised over bit positions and a future refactor could
reopen the hole on a byte the sweep does not happen to hit.

---

## D30 — The shadow node is external to Zebra, not a flag inside it

**Phase 5b.** A deliberate departure from the wording of CLAUDE.md Phase 5, and
one that narrows what the phase can claim.

Phase 5 asks to run the compact path *"behind a shadow-mode feature flag against
a normal Zebra node: both validate every block, results compared, any
disagreement is a hard failure and a loud log line. Never let the accumulator
path gate consensus during this phase."*

A feature flag *inside* Zebra means a patched `zebrad`, which means maintaining
a fork of a consensus node for the duration of the project. That is a larger
undertaking than the rest of Phase 5 combined, and it buys less than it appears
to, because the thing being compared — accumulator roots — is something Zebra
does not compute at all. Being inside the process would not create an oracle
that does not exist; it would only remove an RPC hop.

So `crates/zutreexo-testkit/src/bin/shadow.rs` observes an unmodified `zebrad`
over its JSON-RPC. The never-gate-consensus requirement is met trivially and
uninterestingly: the process cannot influence what Zebra accepts, because Zebra
does not know it is there.

**What is honestly gained over the historical replays**, and it is not nothing:

* **Real reorgs.** `tests/reorg_fuzz.rs` ran 10⁶ reorgs, every one of our own
  construction on chains we generated. Until now the rollback path had never met
  one it did not design.
* **Blocks nobody chose.** The fixture slices were selected for being
  interesting. Tip blocks are whatever miners produce.
* **The parse oracle continuously.** The committed checkpoints cover four
  200-block slices; the shadow run compares `getblock` verbosity 2 counts
  against our extractor on *every* block, field for field with
  `scripts/capture_checkpoints.py`.

**What is not claimed:** that a compact node reaches the same accept/reject
decision as Zebra on a block. It does not and cannot — it validates strictly
less (no signatures, no consensus rules, no shielded proof verification). What
is compared is the accumulator state transition, between our own full and
compact implementations, with Zebra oracling the parse underneath both.

---

## D31 — Reorg recovery is a queue for a compact node and a reload for a full one

**Phase 5b.** Discovered while building the shadow runner, and it is an argument
in the design's favour that had not previously been made.

The obvious way to unwind the bridge at tip was `RollbackJournal`, built in
stage 2c. Measured, it is the wrong tool there: `record` snapshots the forest
*and* clones the whole outpoint index, and a smoke run at height 2,000 grew
**14 MiB per block** doing it. At tip that index holds 27.5M entries at roughly
550 bytes each, so one retained snapshot is on the order of 15 GiB on top of the
33 GiB the state already occupies — more than the measurement machine has, for a
path that may never fire.

The shadow runner therefore unwinds the bridge by reloading its on-disk snapshot
and replaying the common prefix. Heights at or below a fork point are unchanged
by definition, so refetching them is safe. Cost: a ~21 s load plus replay at
~1,500 blk/s, paid only when a reorg happens.

**The compact node's equivalent is taking an older state off a queue.** Its
entire state is a few hundred bytes, so retaining hundreds of historical states
costs a few hundred kilobytes. Utreexo deletion is not invertible
([D18](#d18--rollback-is-delta-based-for-nullifiers-and-snapshot-based-for-the-forest))
and that is precisely why a full node needs undo data — but a node that holds
only roots does not need to invert anything, because it can afford to keep every
root it has ever had.

So the asymmetry is not a detail of this harness. A full node's reorg cost
scales with the state; a compact node's scales with the reorg depth, at a few
hundred bytes per block, and Zcash's reorg limit is 100 blocks. This belongs
alongside the storage figures when the narrow-or-keep decision is taken, and it
applies to the *nullifier* side as much as the transparent one.

---

## D32 — Keep the transparent forest; the case against it was one era's arithmetic

**Phase 5b.** Reverses a direction three earlier measurements appeared to
establish, and the reversal matters more as a lesson than as a decision.

CLAUDE.md Phase 5 anticipates narrowing: *"If the measurements say that, narrow
the project to the nullifier accumulator and drop the transparent forest rather
than shipping both out of sunk cost."* Phase 4a and 4b appeared to say it —
73.0% of proof bandwidth in Utreexo inclusion proofs, overhead climbing from
100.9% at height 25,000 to 170.5% at 150,000 — and `PLAN.md` recorded the
evidence as "three-deep".

Every one of those numbers came from heights 0–150,000, because that is the only
range a compact-node replay could reach before Phase 5b made it possible to
resume from a snapshot. Measured elsewhere:

| measured over | proof overhead | Utreexo share | nullifier share |
|---|---|---|---|
| heights 0–150,000 | 152.6% | **73.0%** | ~27% |
| heights 1.70M–1.76M | 8.3% | **9.5%** | **87.1%** |
| live tip | 38.4% | — | — |

2011 blocks are tiny and almost purely transparent, so proofs dominate them. A
sandblasted block averages 471 KB and the whole bundle is 8.3% of it. On the
modern chain, Utreexo proofs are under a tenth of a bundle and nullifier proofs
are seven eighths.

Of the three signals: 27.5M transparent outputs at tip stands; 73.0% of
bandwidth is withdrawn; and "overhead rises with height" is contradicted
outright, since tip overhead is 38.4% against 152.6% early.

**Decision: keep both accumulators.** Narrowing would have dropped the cheap
half and kept the expensive one.

### The lesson, which is the durable part

**A figure measured over one slice of chain history is not a property of the
design.** The 73.0% was never wrong — it was a property of 2011 presented as a
property of Utreexo, and it came within one phase of deciding what this project
ships. Zcash's history is not homogeneous: it has a transparent-only era, a
Sapling era, a sandblasting era, and a post-Ironwood era, and they differ by
more than an order of magnitude in block size and composition.

So every bandwidth or composition figure in `docs/benchmarks.md` names its
height range, and any that cannot be reproduced in at least two eras is
provisional.

**Phase 5a's headline was re-checked on 2026-08-22 across three eras and
survives** — unlike the figure that prompted this entry. On one basis (the
sparse 637-byte proof), a one-note wallet at a 400,000-block gap sees 13,201× in
the Sapling era, 69,040× at tip, and 107,371× across sandblasting. A spread of
eight, tracking shielded activity, and never a change of sign.

Re-measuring also caught a second-order version of this entry's own mistake:
the first write-up compared the new pre-NU5 figure against Phase 5a's published
31,705×, which predates the sparse encoding and is on the dense 1,362-byte
basis. Not the wrong era that time — the wrong units.

That is the distinction worth keeping. D32's 73.0% *inverted* between eras; this
one only changes scale. A result that moves by a factor is era-dependent and
must name its range; a result that changes sign was never a result.

---

## D33 — `MemForest::deserialize` is not total on malformed input

**Phase 6.** Found by the fuzzer in under 3,000 executions, twenty-five bytes
long, and reachable from a file on disk.

`MemForest::deserialize` reads an eight-byte node-type field and does
`_ => panic!("Invalid node type")` (`mem_forest/mod.rs:144`) rather than
returning the `io::Result` its signature promises. Identical in crates.io 0.6.0
and in our pinned fork.

The reproducer is `0a00007e7e000000000a000000000000000a00000000000000`.

**Why it matters more than a library nit.** `UtxoForest::from_bytes` is called
by `store::decode`, so a corrupt or hostile *snapshot file* takes the process
down. The `snapshot_decode` fuzz target reaches the identical panic through
`load_bytes`. CLAUDE.md §5 rule 3 forbids exactly this — "a panic in block
application is a remote crash vector" — and the rule binds our wrapper whether
or not the panicking line is ours.

### Contained at our boundary

`UtxoForest::from_bytes` wraps the call in `catch_unwind` and returns
`UtreexoError::Snapshot`, the same error a clean parse failure gives, because to
a caller they are the same event: these bytes are not a forest.

**Two honest costs of doing it this way.**

First, it is containment and not a repair. The real fix belongs in the fork
([D25](#d25--the-rustreexo-d10-blocker-is-fixed-and-the-fix-is-pinned-to-a-fork))
and upstream after that — three lines, turning the `panic!` into an
`io::Error::new(InvalidData, ...)`, exactly as our own `ZcashNodeHash::read`
already does for an unknown tag ([D19](#d19--zcashnodehash-serialisation-must-be-tagged)).

Second, and worse: **`catch_unwind` blinds the fuzzer to every other panic in
that deserialiser**, because they all become `Err` now. That is a real loss of
signal, and it is the strongest argument for fixing upstream rather than
leaving the wrapper in place indefinitely.

### Consequence for the 72-hour run

`libfuzzer-sys` installs a panic hook that aborts the process *before*
unwinding, so the containment is invisible under the fuzzer and both
forest-reaching targets still die within seconds. They are excluded from the
72-hour run — including them would spend three days re-finding one known bug —
and go back in when the pinned revision returns an error.

The regression test is written against the public behaviour ("this returns an
error"), not against the panic, so it keeps passing unchanged once the fork is
fixed and the `catch_unwind` comes out. A test asserting a panic would have to
be rewritten by whoever fixed it, which is how a seed gets quietly deleted.

### Correction (2026-08-23): the containment above is incomplete

Writing the fork fix turned up a **second** bug in the same function, and it is
the more serious of the two — because the paragraphs above claim a containment
that does not hold against it.

`Node::read_one` recurses once per branch node, and nothing bounds the depth,
so the *input* chooses how deep the recursion goes. A left spine of nested
branch nodes overflows the stack: **~1.2 MB of input in a debug build, ~4 MB in
release**, measured. A snapshot file is an ordinary place to find four
megabytes.

**A stack overflow aborts the process. It does not unwind.** So
`catch_unwind` in `UtxoForest::from_bytes` does nothing for this input class,
and the section above — written when the node-type `panic!` looked like the
whole problem — was wrong to describe our boundary as contained. It was
contained against the panic and open against the overflow. The distinction was
not visible until the panic was fixed and the fuzzer's next crash was a SIGABRT
with no unwind to catch.

This is the same shape of error as [D29](#d29--a-length-guard-that-only-checked-one-direction): a guard that is real, tested,
and narrower than the claim written next to it.

### The fix, written and verified

Two commits on `d33-deserialize-no-panic` in the fork clone, **not yet pushed**
— that is the user's to do:

1. The node-type tag returns `io::Error::new(InvalidData, ...)` instead of
   panicking, matching what `node_hash/mod.rs:316` already does for an unknown
   hash tag.
2. The recursion is bounded at `MAX_FOREST_ROWS`. This is not an arbitrary
   cap: a root is a perfect tree of at most that many rows, so its leaves sit
   at most that many levels below it, and anything deeper is not a forest the
   crate could have written. A spine exactly `MAX_FOREST_ROWS` deep still
   round-trips; 64 is rejected.

A third commit fixes an unrelated `unwrap()` on the *write* side —
`serialize` `?`s its two length prefixes and then unwrapped the result of
writing each root, so a full disk or closed pipe panicked out of a function
returning `io::Result`.

Verified: all five crash artifacts under `fuzz/artifacts/{forest,snapshot}_decode/`
now return errors, and they return the *fork's* error
("unexpected node type for MemForest node"), not the `catch_unwind` fallback —
which is the evidence the repair is doing the work rather than the containment.
The full workspace suite passes against the patched fork, `upstream_rustreexo.rs`
included. Each fork-side regression test was confirmed to fail with only its own
fix reverted.

**The `catch_unwind` stays** until the pin moves to the pushed revision. It
costs the fuzzer signal (above), but removing it before the pin moves would
reopen the panic it was written for.

---

## D34 — The DoS scenario CLAUDE.md names is the mild one

**Phase 6.** Measured against real tip state (`crates/zutreexo-testkit/src/bin/dos_cost.rs`),
27,522,884 unspent outputs.

CLAUDE.md Phase 6 asks for "cost to a bridge node of a peer requesting proofs
for every UTXO". Measured, that scenario is **not** the one to worry about, and
two others are.

### The named scenario: 193 seconds

| | p50 | p99 | mean | size |
|---|---|---|---|---|
| transparent inclusion proof | 0.008 ms | 0.011 ms | 0.007 ms | 809 B |
| nullifier non-membership proof | 0.009 ms | 0.021 ms | 0.010 ms | 775 B |

Proving **every** UTXO in the set is 193 s of CPU and 22.28 GB served. Three
minutes. Nullifier proofs are flat in set size — `O(depth)`, not `O(log n)` —
so 54.1M nullifiers cost no more each than 70,000 did.

CPU is not the constraint. Rate limiting bounds it anyway: at the default 600
requests per minute, walking the whole set takes an attacker **765 hours of
requests the bridge was willing to answer**.

### The first real one: slowloris, and it is total

The bridge is single-threaded by construction —
[D27](#d27--the-bridge-speaks-binary-over-http-not-grpc) — so serving is one
queue. A client that connects and sends one byte of an HTTP header, then
nothing, parked the only serving thread in `read()` **indefinitely**, for every
other client, from one socket carrying no traffic and costing no CPU.

Against a threaded server slowloris degrades throughput. Against this one it was
complete denial from a single connection, and it cost the attacker nothing.

Fixed: socket read/write timeouts, plus a **total request deadline**, because a
per-read timeout alone is insufficient — a client can send one byte just inside
every deadline forever. `crates/zutreexo-bridge/tests/dos.rs` proves both, and
carries the control showing a complete request is still served, since a server
that refuses everything would pass a timeout test too. Removing the timeout
makes the test hang rather than fail, which was verified.

### The second: amplification

Request and response are wildly asymmetric.

| request | bytes in | bytes out | ratio |
|---|---|---|---|
| non-membership proof | 35 | 775 | **22×** |
| block proof bundle (mean at tip) | 6 | 18,889 | **3,148×** |
| block proof bundle (largest seen) | 6 | 87,577 | **14,596×** |

A six-byte request returning 87 KB is a reflector. Even *within* the rate limit,
600 bundle requests a minute is 0.7 GB/h of egress driven by 0.22 MB/h of
ingress.

**A proof-size cap does not help**, which is worth stating because CLAUDE.md
proposes one: every individual proof is small and legitimate; the asymmetry is
inherent to the service. The defences that do apply are rate limiting by
*bytes served* rather than by request count, and not exposing the bridge
publicly — which remains the standing advice.

### What is still not addressed

No TLS, no authentication, no per-connection byte accounting. These limits make
a bridge survivable on a trusted network; they do not make it safe on a hostile
one. Bind it to loopback.

---

## D35 — Privacy: the headline capability cannot be delivered privately as designed

**Phase 6.** CLAUDE.md requires this analysis be written "regardless of
outcome". The outcome is negative, and it lands on Phase 5a's headline result.

### Two users, and only one of them has a problem

The design serves two very different callers, and they leak differently.

**A compact validating node** requests `BlockProofBundle`s **by height**. Doing
initial block download it wants every height; following the tip it wants the
latest. The request pattern carries no information the node is not already
broadcasting by being a node. **This use case is clean**, and it is what Phases
4 and 5b measured.

**A light wallet** requests non-membership proofs **by nullifier value**. This
one is the problem, and it is the use case behind Phase 5a's headline.

### What a nullifier query actually discloses

A nullifier is derived from the note and the spending key's nullifier key. Until
the note is spent, **nobody but the holder can compute it** — that unlinkability
is the shielded design. So asking a bridge "is nullifier X spent?" hands over a
value that was, up to that moment, a secret.

Three consequences, worsening:

1. **The value itself.** The bridge learns a nullifier exists and is unspent.
2. **Network identity bound to a future on-chain event.** When X is later
   spent it appears in a block. The bridge — which also reads the chain — can
   tie that transaction to whoever asked about X, and to when.
3. **Linkage across a wallet's notes, which is the severe one.** A wallet
   asking about X₁…Xₙ reveals that those n notes share an owner. On-chain those
   spends may fall in different transactions, at different times, and would
   otherwise be unlinkable. **A single batched query undoes that.**

Compared to the status quo this is a strict regression. A scanning wallet
downloads public data and compares locally; the server learns which blocks were
fetched and nothing about which notes matched.

### Decoy batching does not work, and the reason is specific to nullifiers

The obvious mitigation is k-anonymity: ask about the real nullifier alongside
k−1 fabricated ones. Decoys are cheap to generate, since nullifiers are
pseudorandom 32-byte values and a random one is indistinguishable on its face.
Responses do not betray them either — an absent decoy returns the same
non-membership proof a genuine unspent nullifier does.

**It fails retrospectively.** The wallet queried S = {X} ∪ decoys, all reported
unspent. Later the wallet spends the note, and X appears in a block. The bridge
reads the chain, observes that exactly one member of S ever showed up, and knows
it was the real one. The anonymity set collapses from k to 1 **at the moment the
note is spent** — which is the moment it mattered.

Decoys therefore protect only notes that are never spent, and the linkage in
point 3 above is untouched: the subset of previously-queried values that later
appear on-chain is precisely the wallet's own set.

The wallet cannot escape by drawing decoys from real unspent nullifiers,
because it cannot compute anyone else's. Drawing them from already-spent ones
fails immediately, since those answer `ALREADY_SPENT`.

Even granting that decoys worked, the price is steep. Against Phase 5a's
measured figures, with a sparse proof at 631 bytes:

| gap | notes | k=1 | k=10 | k=100 |
|---|---|---|---|---|
| 1,000 | 10 | 46.1× | 4.6× | **0.5×** |
| 10,000 | 10 | 347× | 34.7× | 3.5× |
| 400,000 | 10 | 6,844× | 684× | 68.4× |
| 400,000 | 100 | 684× | 68.4× | 6.8× |

and the crossover for a 10-note wallet moves from 58 blocks to 5,846 — from
about an hour offline to about five days.

### The other three options

**Ask only about nullifiers you are about to publish.** Sound: the value goes
public within seconds anyway. It also **eliminates Framing A entirely**, which
is the watch-only spend-status query — the one Phase 5a measured at 317× to
31,705×, and the one CLAUDE.md calls the headline. A wallet checking whether its
note has *already* been spent is by definition not about to publish that
nullifier.

**Private information retrieval.** Genuinely solves it, and destroys the
efficiency argument that motivates the design: single-server PIR costs the
server work linear in the database per query. D34 measured a non-membership
proof at 0.010 ms; a PIR query over 54.1M nullifiers is many orders above that.
CLAUDE.md §7 already flags Tachyon's PIR work as possibly subsuming this
project, and on this axis it does.

**Run your own bridge.** No leak, no saving — the wallet holds the full IMT. Fine
for an operator who wants compact *validation*, which is the clean use case
above, and no answer at all for a light client.

### A direction that might survive, offered as a sketch

Random decoys fail because the wallet chooses them. **Ambiguity drawn from the
value space does not**, because the candidate set is other people's real
nullifiers, which do appear on-chain and so cannot be filtered out
retrospectively.

Concretely: reveal a b-bit prefix of the nullifier and receive enough of the
tree to settle membership locally. The bridge learns X lies among roughly
2⁻ᵇ·|set| real values — at b = 16 over 54.1M nullifiers, about 760 candidates —
and that ambiguity persists after the spend, because the other candidates are
genuine notes belonging to other people.

**The obstacle is our own layout.** An indexed Merkle tree stores leaves in
*insertion* order and maintains sortedness through the `next_index` linked list
(§2.1), so a contiguous value range is not a contiguous subtree and cannot be
served as one. A wallet would have to fetch scattered low-leaf candidates and
their paths — roughly 760 × 631 B ≈ 480 KB, still about 90× better than a
year-long scan, but nothing like 31,705×, and it needs an index the bridge does
not currently maintain.

This is a research direction, not a design. It is recorded because it is the
only mitigation examined here that is not defeated on inspection.

### Conclusion

**Phase 5a's headline capability — cheap watch-only spend-status checking —
cannot be delivered privately by bridge-served non-membership proofs.** Every
mitigation either destroys the capability (publish-only), destroys the
efficiency (PIR), destroys the point (run your own bridge), or does not work
(decoys).

This does not sink the project. The compact-node use case is unaffected and is
where Phases 4 and 5b's results live. But `docs/benchmarks.md` Phase 5a should
be read with this attached: **the 31,705× is a bandwidth measurement of a query
a privacy-conscious Zcash wallet should not make**, and it sits alongside the
trust caveat already recorded there. Two independent reasons the headline is
weaker than its number.

Phase 7 does not change this. Committing accumulator roots on-chain fixes the
*trust* caveat — the wallet would no longer need a bridge's word for the root —
and does nothing about the leak, because the wallet must still ask someone for
a proof.

---

## D38 — 12,288-member anonymity for 384.9 KB, from a sorted snapshot the IMT never sees

**Phase 6b, step 2.** Measured at Orchard's real 50,392,547 nullifiers
(`crates/zutreexo-testkit/src/bin/cohort_cost.rs`). **Target chosen: k = 12,298**
— [D37](#d37--a-private-spend-status-query-costs-4497-kb-and-the-published-proof-size-was-measured-on-the-wrong-tree)
priced that at **5.35 MB** per query, which was judged too much.

| prefix | members | siblings | **sorted** | IMT cohort | saving | B/member |
|---|---|---|---|---|---|---|
| 8 bits | 196,689 | 24.9 | 6.00 MB | 59.48 MB | 9.9× | 32 B |
| **12 bits** | **12,288** | **25.2** | **384.9 KB** | 5.35 MB | **14.2×** | **32 B** |
| 16 bits | 777 | 26.6 | 25.2 KB | 453.6 KB | 18.0× | 33 B |
| 20 bits | 51 | 26.4 | 2.6 KB | 36.4 KB | 14.2× | 51 B |
| 24 bits | 4.5 | 26.0 | 1.1 KB | 3.1 KB | 2.8× | 250 B |

**The target costs 384.9 KB** — less than a 768-member cohort cost before. The
projection going in was ~395 KB; measured 384.9 KB, within 3%.

The `siblings` column is the whole argument. It sits at ~25 whatever the cohort
size, because a value range in a sorted tree is one **contiguous run** and its
proof is the fringe of the covering subtrees: at most two per level, `O(log n)`.
Cost per member collapses to the value itself, 32 bytes, against ~585 B in the
IMT layout after deduplication.

### Why this is not "reorder the IMT"

Insertion order is not an accident. Appending to an indexed Merkle tree is
`O(1)` and touches one path; inserting into the middle of a value-ordered tree
of 50.4M leaves shifts about 25M of them, each a path update. That trade is what
IMTs exist to make, and taking it back per block would be ruinous. An earlier
note here described step 2 as "the value-ordered layout" without saying so,
which understated the problem.

What makes a sorted tree affordable is that **nullifier sets are append-only**.
Nothing is ever removed, so a sorted snapshot stays correct for everything it
contains, permanently — it can only become *incomplete*, never wrong. So it is
rebuilt in bulk once an epoch. Measured: **16.8 s** to sort and hash 50.4M
values into a depth-26 tree, against an epoch measured in hours.

**The consequence for the frozen format is that there isn't one.** The IMT is
untouched, its on-disk layout is untouched, no version bump, no migration. The
sorted tree is derived, additive, bridge-side state, and consensus-neutral like
everything before Phase 7. An earlier note said step 2 "touches a Phase 3-frozen
structure"; under this design it does not, and the risk is much lower than that
implied.

### The gap between epochs is public data

A snapshot at height H cannot know about nullifiers revealed after H. Those are
**published on-chain**, so a wallet following the chain already holds them and
needs no accumulator proof for them — the private query covers the 50.4M-member
history, and the recent tail is public either way. This is tested:
`sorted_differential.rs` asserts that a value revealed after the snapshot reads
as unspent against it while the live IMT knows better, which is correct for that
height and is exactly why the delta must be consulted.

### The omission attack disappears

[D37](#d37--a-private-spend-status-query-costs-4497-kb-and-the-published-proof-size-was-measured-on-the-wrong-tree)
records that a bridge can drop an in-range leaf from an IMT cohort, recompute
the deduplication, and produce a valid Merkle proof of a smaller set —
detectable only by consulting the linked list in `resolve`.

Here it is **structural**. Members occupy consecutive positions and the proof
commits to those positions, so a hole cannot be papered over. Completeness is
checked directly: the run must begin below `range.lo` and continue to at or
above `range.hi`, or to the last occupied leaf.

That second half needed a fix the tests caught. The prover originally ended the
run at the last in-range value, and a verifier shown a run ending at some
`v < hi` cannot tell whether `v` is genuinely the largest in the range or
whether the bridge stopped early. The run now includes the first value **at or
above** `hi` as an upper witness — 32 bytes, and it turns completeness from an
argument into a check.

### Correctness

`sorted_differential.rs` settles every probe three ways — the IMT directly, an
IMT cohort, and a sorted cohort **through the wire** — and requires all three to
agree. Two structures over one set is exactly where a silent disagreement lives:
both self-consistent, both verifying, one wrong. The test also asserts it saw
both verdicts, since a differential run that only ever saw "unspent" has proven
nothing about "spent". Confirmed to fail on an injected off-by-one in the
bracket.

Domain separation is a distinct family, `ZSortNul‖pool‖role`, not a new role
under `ZNullIMT`. The two trees hold the same values for the same pool, so
sharing a separator would let a leaf digest from one be presented as a node
digest from the other — CLAUDE.md §5 rule 4 for precisely this case.

The decoder got its bit-flip and truncation sweep at the time it was written.
It has the largest allocation lever of any decoder in the project: at the target
width a legitimate cohort is 12,288 values, and a declared `u32::MAX` asks for
**137 GB**. Confirmed by removing the guard — `memory allocation of
137438953440 bytes failed`, SIGABRT.

### What is decided and what is not

**Decided:** the target is affordable. 12,288-member anonymity costs 384.9 KB,
14.2× better than the IMT cohort, with no change to any frozen format.

**Not decided:** how the bridge serves and retains snapshots (epoch length,
how many to keep, what a wallet does across an epoch boundary), and the per-pool
split — [D37](#d37--a-private-spend-status-query-costs-4497-kb-and-the-published-proof-size-was-measured-on-the-wrong-tree)
shows Ironwood's 70,380 nullifiers give a 1.07-member cohort at 16 bits, and its
whole set is 2.25 MB, so small pools likely want whole-set download instead.

---

## D37 — A private spend-status query costs 449.7 KB, and the published proof size was measured on the wrong tree

**Phase 6b.** Measured against a depth-40 IMT holding Orchard's real nullifier
count, 50,392,547 (`crates/zutreexo-testkit/src/bin/cohort_cost.rs`). 21 GB,
three minutes to build.

[D35](#d35--privacy-the-headline-capability-cannot-be-delivered-privately-as-designed)
killed every privacy mitigation but one: reveal a `b`-bit **prefix** of the
nullifier and receive enough of the tree to settle membership locally. It
survives retrospective correlation, which is what defeats decoys, because the
other cohort members are genuine nullifiers belonging to other people — they
appear on-chain too, so the ambiguity is permanent rather than unmasked at
spend time.

D35 estimated that at "roughly 760 × 631 B ≈ 480 KB" and stopped, calling it a
research direction. It is now built (`crates/zutreexo-accumulator/src/cohort.rs`)
and measured.

### What a cohort costs

| prefix | cohort *k* | nodes | encoded | naive *k*×proof | dedup saves | vs one proof |
|---|---|---|---|---|---|---|
| 8 bits | 196,885 | 1,403,137 | 59.53 MB | 173.68 MB | 65.7% | 67,484× |
| 12 bits | 12,298 | 136,678 | 5.35 MB | 10.85 MB | 50.6% | 6,070× |
| **16 bits** | **768** | **11,614** | **449.7 KB** | 693.9 KB | **35.2%** | **498×** |
| 20 bits | 49 | 939 | 35.7 KB | 44.4 KB | 19.6% | 40× |
| 24 bits | 3.8 | 88 | 3.4 KB | 3.5 KB | 2.9% | 4× |

`k` counts the predecessor leaf, which is a witness rather than a candidate, so
the anonymity set is `k − 1`.

**D35's estimate was accurate and its reasoning was not.** It predicted
`k ≈ 760` (measured 768) and 480 KB (measured 449.7 KB), but reached that
figure by multiplying a proof size that was 31% too small by a cohort size it
then did not deduplicate — two errors that happened to cancel. Path
deduplication is worth **35.2%** at this scale, not the ~20% predicted before
measuring.

Dedup is strongly `k`-dependent, and in a way that flatters small test trees: at
`k ≈ 973` in a 250,000-leaf tree it saves 52.6%, because a cohort that is a
large fraction of a small pool has heavily converging paths. Any measurement of
this taken at toy scale overstates the saving. Which is the second finding.

### The published sparse proof size was measured on a tree 768× too small

`gap_cost` built its sample tree at 2^16 = 65,536 leaves, justified by a comment
reading *"2^16 keeps the build fast while putting the occupied levels well below
the depth, which is the regime the whole chain is in: 54.1M nullifiers is 2^25.7
against 2^40."*

**That reasoning is wrong.** The sparse encoding omits siblings equal to the
canonical empty-subtree hash ([D28](#d28--sparse-proof-paths-omit-the-siblings-both-sides-can-derive)).
The count of *non-empty* siblings on a path is `log2(occupied leaves)`; it does
not depend on how far occupancy sits below `depth`. So the proof grows a flat 32
bytes per doubling of the set:

| occupied | sparse proof |
|---|---|
| 65,536 (2^16) | **637 B** ← the published figure |
| 1,000,000 | 733 B |
| 8,000,000 | 829 B |
| 50,392,547 (2^25.6) | **925 B** |

`cohort_cost` reproduces 637 B exactly at 2^16, so the two tools agree and the
only difference is set size.

**Every Phase 5a ratio for an Orchard-pool note was overstated by
925 / 637 = 1.452×.** Re-measured over the same tip window (3,057,000–3,457,000)
with the corrected tree, the headline goes from **69,040× to 47,545×** and the
one-note crossover from 6 blocks to **8**. The direction is untouched and the
conclusion is untouched; the numbers were wrong.

This is the third instance of the same failure in this project — a denominator
measured under conditions the claim does not hold. [D32](#d32) compared eras;
the era comparison itself mixed sparse and dense bases; this one compared pool
sizes. The pattern is worth naming: **a ratio is only as good as the conditions
its denominator was measured under, and those conditions are never in the
number.**

One thing partly rescues it: **637 B is correct for Ironwood**, which holds
70,380 nullifiers and genuinely is a 2^16-scale tree. Proof size is per pool, so
`gap_cost` now takes the leaf count as a parameter defaulting to Orchard's real
size rather than hardcoding either figure.

### Per-pool anonymity is the binding constraint, not bandwidth

Prefix width has to be chosen per pool, and the pools differ by three orders of
magnitude:

| pool | nullifiers | cohort at *b* = 16 |
|---|---|---|
| Orchard | 50,392,547 | 769 |
| Sapling | 2,129,852 | 32 |
| Sprout | 1,547,198 | 24 |
| **Ironwood** | **70,380** | **1.07** |

At 16 bits an Ironwood query names a single note. Reaching `k ≈ 760` there means
a prefix so wide it pulls 1.1% of the pool — and the entire Ironwood nullifier
set is only 2.25 MB, so shipping the whole thing is competitive with any cohort
large enough to hide in. The likely shape of a real answer is therefore
**split by pool size**: whole-set download for small pools, prefix cohorts for
large ones, with a crossover that falls out of these numbers.

Ironwood is the newest pool and the one CLAUDE.md §7 says will remain live
indefinitely alongside Orchard, so this is not a transitional detail.

### What is decided and what is not

**Decided:** the mitigation works, it is buildable, and at Orchard scale a
768-member anonymity set costs 449.7 KB — 498× a single proof, and still 98×
cheaper than the 43.98 MB a 400,000-block scan costs. The capability D35
declared undeliverable is deliverable; the question was only ever the price.

**Not decided:** whether 768 is enough anonymity, which is policy rather than
measurement, and whether the value-ordered layout is worth its cost. A cohort in
a value-ordered tree is a contiguous subtree — one path plus the range,
projected near 25 KB against the measured 449.7 KB — but value-ordered insertion
breaks the IMT's append-only property, which is the reason indexed Merkle trees
use insertion order in the first place. That is step 2.

### Security of the construction

Two attacks, handled in different places, and the split is not obvious:

* **Tampering** — a forged leaf or node fails the fold against the trusted root.
  Ordinary Merkle security.
* **Omission** — a bridge drops an in-range leaf. This does **not** fail the
  fold. Deleting a leaf while leaving the node set alone does, which is
  misleading, and an early version of the test was fooled by exactly that; a
  bridge that recomputes the deduplication for the shorter cohort produces a
  perfectly valid Merkle proof of a smaller set. It is caught in `resolve`
  instead, where the bracketing leaf's own `next_value` must not point into the
  range at a value the cohort failed to deliver. **Omission must not read as
  absence**, and that is a linked-list check, not a hash check.

The decoder was given its bit-flip and truncation sweep at the time it was
written, per PLAN.md's standing rule. It needed it: removing the leaf-count
guard and feeding a declared `u32::MAX` gives `memory allocation of
343597383600 bytes failed` and SIGABRT — [D29](#d29--a-length-guard-that-only-checked-one-direction)
reproduced exactly in a decoder written two phases after D29 was fixed.

---

## D36 — Fuzz budget: four of five targets saturated in under two hours

**Phase 6.** The 72-hour run launched 2026-08-22 finished 2026-08-25 05:44:01
with **zero crashes, zero hangs, zero OOMs across all five targets** and
**206,659,449,674 executions**. Phase 6's DoD ("fuzzers run 72 h clean") is met
for the five included targets; `forest_decode` and `snapshot_decode` remain
excluded on [D33](#d33--memforestdeserialize-is-not-total-on-malformed-input)
and owe their own run once the fork fix is pushed.

What follows is about how that budget was *spent*, which is where the run has
something to teach.

The run was configured the obvious way: five targets, one core each, the same
`-max_total_time=259200` for all of them. That allocation turns out to be
badly wrong, and the run's own logs say so.

### What the 38 hours actually bought

`cov` at `INITED` is what the *seed corpus* already reached. The difference
between that and the current figure is what 38 hours of fuzzing added.

| target | edges at INITED | final | gained | executions | last new edge | share of run after it |
|---|---|---|---|---|---|---|
| `bundle_decode` | 781 | 812 | **+31** | 4.7e9 | **71.5 h** | 0.6% |
| `utxo_proof_decode` | 181 | 184 | +3 | 42.1e9 | `#101` | ~100% |
| `compact_state_decode` | 301 | 301 | **0** | 35.4e9 | never | 100% |
| `nonmembership_decode` | 323 | 323 | **0** | 5.0e9 | never | 100% |
| `wire_request_decode` | 111 | 111 | **0** | 119.5e9 | never | 100% |

**Five targets, 206 billion executions, 72 hours, 34 new edges** — and 31 of
them belong to one target. Three targets never reached a single edge their seed
corpus had not already reached; `nonmembership_decode` reports the identical
`cov: 323` on every stat line it has ever printed. `utxo_proof_decode` found
its three at execution **101** and nothing in the 42 billion since.

### `bundle_decode` was not saturated — the clock cut it off

Its full discovery trace, by execution count:

| edge | at | ≈ elapsed |
|---|---|---|
| 809 | 566M | 8.7 h |
| 810 | 1.29e9 | 19.7 h |
| 811 | 4.32e9 | 66.3 h |
| **812** | **4.66e9** | **71.5 h** |

The last edge landed with about twenty-five minutes left on a 72-hour clock.
So the budget was simultaneously three days too long for four targets and *too
short* for the fifth.

**This refutes an intermediate call recorded here.** Mid-run, `bundle_decode`
had been quiet for 33 hours and I judged the 10×-past-last-discovery rule to be
over-extrapolating, and advised planning ~2 days for it and spending the
surplus on seeds. Two edges then arrived at 66.3 h and 71.5 h. Cutting at two
days would have missed both.

The error was reading a quiet stretch as exhaustion. Discovery here is
**bursty, not smoothly decaying**: the gap from 810 to 811 was 3.0 billion
executions, and the gap from 811 to 812 only 0.34 billion. On a target with
this much surface — 3,451 instrumented edges against a 289-file corpus — a day
of silence carries much less information than it feels like it does. The
mechanical rule was right and the judgement call over it was wrong, which is
the reason the rule is written down.

**A `NEW` line does not mean a new edge**, and conflating the two is how a
saturated target looks busy. libFuzzer emits `NEW` for a new *feature* — an
edge-count bucket — so `compact_state_decode` (4 `NEW` lines) and
`nonmembership_decode` (6) appear to be finding things hours in while their
coverage has not moved once. An earlier draft of this table read the last `NEW`
timestamp and reported saturation at "~7 min" and "~2.1 h" for those two; both
are actually *never*. `scripts/fuzz_saturation.py` tracks the high-water mark of
`cov` instead, which is why the numbers above come from the tool rather than
from reading the logs by eye.

### The correction this implies

**More hours is the wrong lever for a saturated target.** A target stuck at the
same edge count for 34 billion executions is not short of time; mutation cannot
reach further from the seeds it has. The fix is a better seed corpus or a
structured `Arbitrary`-based generator that constructs well-formed-ish inputs,
so the fuzzer spends its budget past the length and magic checks instead of in
front of them. This is the same lesson as
[D24](#d24--a-checksum-in-front-of-a-parser-hides-every-check-behind-it),
one level out: there, a checksum hid the parser from the fuzzer; here, the
input distribution does.

**So budget the next run per target, not per clock:**

1. **Stop a target on saturation, not on the wall clock.** A workable rule:
   end it once it has run 10× longer since its last new edge than it took to
   find that edge. On the final numbers four of the five end within minutes and
   `bundle_decode` wants **~30 days** — the rule's output grows each time a late
   edge lands, which is the behaviour you want from a stopping rule and not a
   literal schedule. `scripts/fuzz_72h.sh` now encodes 7 days for
   `bundle_decode` and 24 h for the rest;
   `scripts/fuzz_saturation.py` recomputes it after any run.
2. **Spend the freed cores on the target still finding things**, with
   `-fork=N` — *not* `-jobs=N -workers=N`. Measured, `-jobs` writes each
   worker's output to `fuzz-<n>.log` in the current directory and leaves the
   main log carrying one worker's numbers, so the run's own analysis silently
   under-reports; fork mode keeps a single stream and merges the workers'
   corpora. Two forks took `bundle_decode` from ~18k to ~40k exec/s.

   Fork mode prints no `INITED`, no `Done ... runs` and no `stat::` block, and
   its stat lines have a different shape, so it needed explicit parser support
   — without it a parallel run's log yields an empty report that looks exactly
   like a target that never ran. Both dialects are covered by self-checks that
   run on every invocation.
3. **Re-seed rather than re-run.** For any target that gains zero edges,
   the next iteration's work item is corpus and harness, not schedule.
4. **Estimating a future run:** the useful unit is *time to last discovery per
   target*, and on this codebase it spans from execution 101 to 71.5 hours. A
   single figure covering all targets is necessarily wrong in both directions
   at once. Budget `bundle_decode`-class targets in **weeks** and treat the rest
   as a seeding problem. Run `scripts/fuzz_saturation.py` against the previous
   run's logs rather than guessing — it needs no arguments once a run has
   finished, and mid-run with `--elapsed-hours H` it answers "is this worth
   letting finish?". Note the answer it would have given at 38 h here, and that
   the honest reading of it was still to let the run finish.

### What this does not say

It does not say the run was worthless. Its product is the *absence* of a crash
across 73 billion executions, and a saturated target still contributes to that
— it is a negative result about robustness, not about coverage. Phase 6's DoD
is "fuzzers run 72 h clean," and that is being met.

Nor do the raw coverage percentages mean the parsers are 15–23% tested. The
instrumented edge count includes dependency code linked into the binary that no
decode entry point can reach, so the denominator is inflated by an unknown
amount. The load-bearing number here is the *marginal* one — edges gained
during the run — which needs no denominator.

`scripts/fuzz_72h.sh` now carries the per-target budgeting above, applied once
the run ended — a script that is executing is not a file to edit, since bash
reads it by byte offset. The same pass fixed a reporting bug in it:
`ls | grep -c .` exits 1 on an empty directory, so the `|| echo 0` fallback
appended a *second* line and every completion line in `driver.log` read
`artifacts=0` followed by a stray `0`. The counts were right; the log was
malformed. `wc -l` replaces it.

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

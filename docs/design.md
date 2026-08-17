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

# Regression corpus

Every divergence the harness ever finds becomes a permanent seed here.

CLAUDE.md Phase 2 states the rule, and the ordering in it is the part that
matters:

> Every divergence becomes a permanent seed in the fuzzer's regression corpus,
> **added and confirmed failing before the fix**.

## The workflow

1. The harness finds a divergence and writes a repro to its `repro_dir`.
2. Copy that file into this directory. Name it for what went wrong, not for the
   date: `orchard-root-drift-after-reorg.json`, not `repro-3.json`.
3. **Run `cargo test -p zutreexo-testkit --test corpus` and watch it fail.**
   This is not a formality. A seed that passes before the fix is not reproducing
   the bug, and committing it would leave a permanent green test guarding
   nothing.
4. Fix the bug.
5. Run the corpus test again. It must now pass.
6. Commit the seed and the fix together.

Step 3 is the one people skip. Do not skip it.

## What a seed is

A repro is self-contained: the offending block as raw hex, plus the
configuration that caught it. Replaying needs no node, no fixture directory, and
no network. That is deliberate — a divergence you cannot replay offline is one
you will not fix.

Seeds are replayed against a **fresh, empty state**, one block, with contiguity
checks relaxed. That covers any divergence the block causes on its own.

## The known limitation

A divergence that depends on accumulated state — one that only appears at height
N because of what happened at heights 1..N-1 — is **not** fully captured by a
single-block seed. The seed records the block and the configuration, and the
`slice` and `height` fields say where to look, but reproducing it needs the
fixtures.

When that happens, add the seed anyway *and* add a dedicated test alongside it
that replays the necessary window. The seed is still worth having: it pins the
block bytes, which is the part that gets lost.

## Current contents

Empty. The harness has found no divergences yet: all four fixture slices replay
with tier 1 on every block, tier 2 recomputing roots cold after every block, and
tier 3 agreeing with `zebrad` on every counted field.

An empty corpus is not evidence the harness works — that is what the
fault-injection tests in `tests/harness_replay.rs` are for. They inject known
corruptions and assert the expected tier fires, including one reordering that
tier 1 is provably blind to and only tier 2 catches.

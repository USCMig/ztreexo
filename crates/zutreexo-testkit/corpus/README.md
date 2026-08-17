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

There are two kinds, distinguished by a `"kind"` field.

### Block seeds — what the differential harness writes

Self-contained: the offending block as raw hex, plus the configuration that
caught it. Replaying needs no node, no fixture directory, and no network. That
is deliberate — a divergence you cannot replay offline is one you will not fix.

Replayed against a **fresh, empty state**, one block, with contiguity checks
relaxed. That covers any divergence the block causes on its own.

### Reorg seeds — what the reorg fuzzer writes

```json
{
  "kind": "reorg",
  "divergence": "what went wrong, as reported",
  "seed": 1,
  "iterations": 25000,
  "depth": 12,
  "chain_len": 30,
  "max_reorg_depth": 8,
  "snapshot_interval": 4
}
```

A reorg divergence is not a block. It emerges from a *sequence* of rollbacks and
re-applications, and the only compact way to record that sequence is the number
it all derives from. The fuzzer's RNG is a xorshift64\* written out in
`src/reorg.rs` rather than pulled from a crate, precisely so this stays
reproducible — if the seed-to-sequence mapping ever changes, every committed
reorg seed silently stops reproducing what it was recorded for.

Reorg seeds always replay with `cold_check_every = 1`. A seed exists because
something diverged, and the sampling cadence used in normal runs could step
straight past the iteration that mattered.

Seeds never carry an injected fault. A committed seed describes real inputs; a
fault describes deliberate damage, and a "regression" that only reproduces under
injected damage is not guarding anything.

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

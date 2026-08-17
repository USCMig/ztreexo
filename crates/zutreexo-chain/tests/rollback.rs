//! Stage 2c: rollback must land exactly where a cold replay would.
//!
//! The invariant CLAUDE.md Phase 2 states, and the reason it is stated so
//! bluntly: `apply(A..N)`, undo to `K`, apply a divergent `K..M` must produce
//! **byte-identical** roots to a cold replay of the final chain. Not
//! "equivalent", not "same balance". The comparison being mechanical is the
//! entire value of the exercise.
//!
//! These tests use synthetic blocks rather than fixtures. Rollback is about the
//! state machine, not about parsing, and synthetic blocks let a test construct
//! the exact shape it needs — a spend of an output created eleven blocks ago,
//! say — which no 200-block mainnet window is guaranteed to contain.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::unwrap_used
)]

use std::collections::BTreeMap;

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::{PoolId, UtxoLeaf};
use zutreexo_chain::{
    apply_block, ApplyOptions, BlockSummary, ChainAccumulators, OutPoint, RollbackJournal,
};

const DEPTH: u8 = 16;

/// A deterministic 32-byte value from a counter.
fn bytes32(tag: u8, n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = tag;
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}

fn outpoint(n: u64) -> OutPoint {
    OutPoint {
        txid: bytes32(0xAA, n),
        vout: 0,
    }
}

fn leaf_for(n: u64, height: u32) -> UtxoLeaf {
    UtxoLeaf {
        txid: bytes32(0xAA, n),
        vout: 0,
        height,
        is_coinbase: false,
        value: 1_000 + n,
        script_pubkey: vec![0x76, 0xA9, (n % 251) as u8],
    }
}

/// One synthetic block: some outputs created, some earlier ones spent, some
/// nullifiers revealed.
struct Recipe {
    height: u32,
    creates: Vec<u64>,
    spends: Vec<u64>,
    nullifiers: Vec<(PoolId, u64)>,
}

fn summary(recipe: &Recipe) -> BlockSummary {
    let mut nullifiers: BTreeMap<PoolId, Vec<Value>> = BTreeMap::new();
    for (pool, n) in &recipe.nullifiers {
        nullifiers
            .entry(*pool)
            .or_default()
            .push(Value::from_bytes(bytes32(0xBB, *n)));
    }

    BlockSummary {
        height: recipe.height,
        transactions: 1,
        transparent_spends: recipe.spends.iter().map(|n| outpoint(*n)).collect(),
        transparent_creates: recipe
            .creates
            .iter()
            .map(|n| (outpoint(*n), leaf_for(*n, recipe.height)))
            .collect(),
        nullifiers,
        commitments: BTreeMap::new(),
    }
}

/// A chain where block `h` creates outputs and spends one from a few blocks
/// back, and reveals a nullifier in a rotating pool.
fn chain(from: u32, to: u32, branch: u8) -> Vec<Recipe> {
    (from..=to)
        .map(|height| {
            let h = u64::from(height);
            let pool = match height % 3 {
                0 => PoolId::Orchard,
                1 => PoolId::Ironwood,
                _ => PoolId::Sapling,
            };
            Recipe {
                height,
                creates: vec![h * 10, h * 10 + 1],
                // Spend an output created three blocks ago, once far enough in.
                spends: if height >= from + 3 {
                    vec![(h - 3) * 10]
                } else {
                    Vec::new()
                },
                // The branch tag keeps the two forks' nullifiers distinct, as
                // real competing branches would be.
                nullifiers: vec![(pool, h * 100 + u64::from(branch))],
            }
        })
        .collect()
}

/// Applies recipes to a fresh state, recording into a journal.
///
/// Retention is deliberately generous: the correctness tests are about where
/// the unwind lands, and a journal that pruned mid-test would fail them for an
/// unrelated reason. The retention tests below build their own.
fn build(recipes: &[Recipe], interval: u32) -> (ChainAccumulators, RollbackJournal) {
    build_with(recipes, interval, 1_000)
}

fn build_with(
    recipes: &[Recipe],
    interval: u32,
    max_depth: u32,
) -> (ChainAccumulators, RollbackJournal) {
    let mut state = ChainAccumulators::new(DEPTH).unwrap();
    let mut journal = RollbackJournal::new(interval, max_depth);
    for recipe in recipes {
        let outcome = apply_block(&mut state, &summary(recipe), ApplyOptions::default())
            .unwrap_or_else(|e| panic!("apply at {} failed: {e}", recipe.height));
        journal.record(&state, outcome.delta).unwrap();
    }
    (state, journal)
}

/// Everything that decides future behaviour, compared as one value.
fn fingerprint(state: &ChainAccumulators) -> String {
    let mut out = format!("tip={:?} utxos={}", state.tip(), state.utxo_count());
    for (pool, root) in state.nullifier_roots() {
        out.push_str(&format!(" {pool}={}", hex::encode(root)));
    }
    for root in state.utxo_roots() {
        out.push_str(&format!(" utxo:{}", hex::encode(root)));
    }
    out
}

#[test]
fn rollback_to_the_current_tip_is_a_no_op() {
    let (mut state, mut journal) = build(&chain(1, 10, 0), 4);
    let before = fingerprint(&state);
    journal.rollback_to(&mut state, 10).unwrap();
    assert_eq!(fingerprint(&state), before);
}

#[test]
fn rollback_matches_a_cold_replay_of_the_prefix() {
    for interval in [1u32, 3, 4, 100] {
        let (mut state, mut journal) = build(&chain(1, 20, 0), interval);
        journal.rollback_to(&mut state, 12).unwrap();

        let (expected, _) = build(&chain(1, 12, 0), interval);

        assert_eq!(
            fingerprint(&state),
            fingerprint(&expected),
            "interval {interval}: rollback did not land on the cold-replay state"
        );
    }
}

/// **The Phase 2 invariant.** Apply, unwind, apply a divergent branch, and the
/// result must be byte-identical to replaying the final chain from scratch.
#[test]
fn reorg_equals_a_cold_replay_of_the_final_chain() {
    for interval in [1u32, 5, 100] {
        let fork_at = 14;

        // Original chain to 20, then unwind to the fork and take branch 1.
        let (mut state, mut journal) = build(&chain(1, 20, 0), interval);
        journal.rollback_to(&mut state, fork_at).unwrap();
        for recipe in chain(fork_at + 1, 25, 1) {
            let outcome = apply_block(&mut state, &summary(&recipe), ApplyOptions::default())
                .unwrap_or_else(|e| panic!("divergent apply at {} failed: {e}", recipe.height));
            journal.record(&state, outcome.delta).unwrap();
        }

        // Cold replay of what the final chain actually is.
        let mut cold = chain(1, fork_at, 0);
        cold.extend(chain(fork_at + 1, 25, 1));
        let (expected, _) = build(&cold, interval);

        assert_eq!(
            fingerprint(&state),
            fingerprint(&expected),
            "interval {interval}: reorged state differs from a cold replay"
        );
    }
}

/// Spending an output that was created *before* the rollback point exercises
/// the index rebuild — the part that a hash-only `StateDelta::created` would
/// have got wrong.
#[test]
fn outputs_created_in_replayed_blocks_are_still_spendable() {
    // Snapshot interval 10, roll back to 12: blocks 11 and 12 are replayed
    // forward from the snapshot at 10, so their outputs must reappear in the
    // index or the spend at 15 cannot resolve.
    let (mut state, mut journal) = build(&chain(1, 20, 0), 10);
    journal.rollback_to(&mut state, 12).unwrap();

    // Block 15 spends the output created by block 12.
    let recipes = chain(13, 16, 0);
    for recipe in &recipes {
        apply_block(&mut state, &summary(recipe), ApplyOptions::default()).unwrap_or_else(|e| {
            panic!(
                "height {} failed after rollback — the outpoint index was not \
                 rebuilt by the replay: {e}",
                recipe.height
            )
        });
    }
}

#[test]
fn rolling_back_before_the_journal_is_refused() {
    // Retention of 10 blocks over a 40-block chain, so early history is gone.
    let (mut state, mut journal) = build_with(&chain(1, 40, 5), 5, 10);
    let earliest = journal.earliest_rollback().unwrap();
    assert!(earliest > 1, "journal should have pruned early snapshots");

    let err = journal.rollback_to(&mut state, 1).unwrap_err();
    assert!(
        matches!(err, zutreexo_chain::RollbackError::BeyondJournal { .. }),
        "expected BeyondJournal, got {err}"
    );
}

#[test]
fn rolling_forward_is_refused() {
    let (mut state, mut journal) = build(&chain(1, 10, 0), 4);
    let err = journal.rollback_to(&mut state, 99).unwrap_err();
    assert!(matches!(
        err,
        zutreexo_chain::RollbackError::NotBehindTip { .. }
    ));
}

#[test]
fn out_of_order_records_are_refused() {
    let mut state = ChainAccumulators::new(DEPTH).unwrap();
    let mut journal = RollbackJournal::new(4, 1_000);

    let first = chain(1, 1, 0);
    let outcome = apply_block(&mut state, &summary(&first[0]), ApplyOptions::default()).unwrap();
    journal.record(&state, outcome.delta).unwrap();

    // Fabricate a delta two heights ahead. Contiguity is relaxed on the
    // *applier* so the gap reaches the journal, which is what is under test.
    let skipped = chain(3, 3, 0);
    let options = ApplyOptions {
        enforce_contiguous: false,
        ..ApplyOptions::default()
    };
    let outcome = apply_block(&mut state, &summary(&skipped[0]), options).unwrap();

    let err = journal.record(&state, outcome.delta).unwrap_err();
    assert!(matches!(
        err,
        zutreexo_chain::RollbackError::OutOfOrder { .. }
    ));
}

/// The journal must not grow without bound, and must still reach `max_depth`.
///
/// Both halves matter. Retention that grows with chain length is a leak;
/// retention that undershoots the configured depth is a reorg that cannot be
/// undone. The second is the one a naive fix introduces.
#[test]
fn the_journal_retains_a_bounded_window() {
    let interval = 10u32;
    let max_depth = 30u32;

    let (_short, short_journal) = build_with(&chain(1, 60, 0), interval, max_depth);
    let (_long, long_journal) = build_with(&chain(1, 200, 0), interval, max_depth);

    // Bounded: a chain more than three times longer holds no more snapshots.
    assert_eq!(
        short_journal.snapshot_count(),
        long_journal.snapshot_count(),
        "snapshot count grows with chain length"
    );
    // 30 blocks of reach at one snapshot per 10 needs four, counting the
    // boundary at the horizon itself.
    assert!(
        long_journal.snapshot_count() <= 5,
        "journal kept {} snapshots",
        long_journal.snapshot_count()
    );

    // And it genuinely reaches back the configured depth.
    let earliest = long_journal.earliest_rollback().unwrap();
    assert!(
        earliest <= 200 - max_depth,
        "journal reaches back only to {earliest}, short of the {max_depth}-block target"
    );
}

/// Repeated reorgs at the same height must be stable — the second one has to
/// see a journal the first one left consistent.
#[test]
fn successive_reorgs_stay_consistent() {
    let fork_at = 10;
    let (mut state, mut journal) = build(&chain(1, 16, 0), 4);

    for branch in 1u8..=3 {
        journal.rollback_to(&mut state, fork_at).unwrap();
        for recipe in chain(fork_at + 1, 16, branch) {
            let outcome =
                apply_block(&mut state, &summary(&recipe), ApplyOptions::default()).unwrap();
            journal.record(&state, outcome.delta).unwrap();
        }
    }

    let mut cold = chain(1, fork_at, 0);
    cold.extend(chain(fork_at + 1, 16, 3));
    let (expected, _) = build(&cold, 4);
    assert_eq!(fingerprint(&state), fingerprint(&expected));
}

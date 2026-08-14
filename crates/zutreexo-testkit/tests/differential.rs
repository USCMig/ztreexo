//! Differential tests: the real accumulator against the naive oracle.
//!
//! CLAUDE.md §5 rule 2 makes differential testing the primary correctness
//! signal — a green unit-test suite with a divergent root is a failure. This
//! file is the Phase 1 half of that: `zutreexo-accumulator`'s incremental
//! indexed Merkle tree against `zutreexo-testkit`'s from-scratch model, which
//! shares no code with it.
//!
//! The load-bearing comparison is the one Phase 2 calls the "recompute cold"
//! tier: the incremental path must agree with a computation that rebuilds every
//! successor pointer and every internal node from nothing. That is the failure
//! mode that accumulates silently over a long replay and surfaces only when
//! someone cannot spend.

#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use zutreexo_accumulator::imt::{ImtError, ImtState, IndexedMerkleTree, Value};
use zutreexo_accumulator::PoolId;
use zutreexo_testkit::naive::{NaiveImt, NaivePool};

/// The oracle materialises `2^depth` leaves per root, so keep it small.
const DEPTH: u8 = 10;

fn pools() -> [(PoolId, NaivePool); 4] {
    [
        (PoolId::Sprout, NaivePool::Sprout),
        (PoolId::Sapling, NaivePool::Sapling),
        (PoolId::Orchard, NaivePool::Orchard),
        (PoolId::Ironwood, NaivePool::Ironwood),
    ]
}

/// Deterministic pseudo-random values. No system time, no RNG crate: a
/// divergence has to be replayable offline from the seed alone.
fn spread(seed: u64, n: usize) -> Vec<[u8; 32]> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            // xorshift64*, inlined so this file depends on nothing.
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let word = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out.push(bytes);
    }
    out
}

#[test]
fn empty_roots_agree_for_every_pool() {
    for (pool, naive_pool) in pools() {
        let real = IndexedMerkleTree::with_depth(pool, DEPTH).unwrap();
        let model = NaiveImt::new(naive_pool, DEPTH).unwrap();
        assert_eq!(
            real.root(),
            model.root(),
            "empty root diverged for pool {pool}"
        );
    }
}

#[test]
fn roots_agree_after_every_insertion() {
    for (pool, naive_pool) in pools() {
        let mut real = IndexedMerkleTree::with_depth(pool, DEPTH).unwrap();
        let mut model = NaiveImt::new(naive_pool, DEPTH).unwrap();

        for (step, value) in spread(0xC0FF_EE00, 64).into_iter().enumerate() {
            real.insert(Value::from_bytes(value)).unwrap();
            model.insert(value).unwrap();

            assert_eq!(
                real.leaf_count(),
                model.leaf_count(),
                "leaf count diverged at step {step} for pool {pool}"
            );
            assert_eq!(
                real.root(),
                model.root(),
                "root diverged at step {step} for pool {pool}, value {}",
                hex::encode(value)
            );
        }
    }
}

/// Sorted, reverse-sorted, and clustered inputs exercise different parts of the
/// linked-list splice than random ones do.
#[test]
fn roots_agree_for_pathological_orderings() {
    let cases: Vec<(&str, Vec<[u8; 32]>)> = vec![
        ("ascending", (1..=40u64).map(small).collect()),
        ("descending", (1..=40u64).rev().map(small).collect()),
        (
            "alternating extremes",
            (0..20u64)
                .flat_map(|n| [small(n + 1), high(n + 1)])
                .collect(),
        ),
        (
            "dense cluster",
            (0..40u64).map(|n| small(1_000_000 + n)).collect(),
        ),
        ("maximum first", {
            let mut v = vec![[0xffu8; 32]];
            v.extend((1..=20u64).map(small));
            v
        }),
        ("maximum last", {
            let mut v: Vec<[u8; 32]> = (1..=20u64).map(small).collect();
            v.push([0xffu8; 32]);
            v
        }),
    ];

    for (name, values) in cases {
        let mut real = IndexedMerkleTree::with_depth(PoolId::Orchard, DEPTH).unwrap();
        let mut model = NaiveImt::new(NaivePool::Orchard, DEPTH).unwrap();
        for value in &values {
            real.insert(Value::from_bytes(*value)).unwrap();
            model.insert(*value).unwrap();
        }
        assert_eq!(real.root(), model.root(), "root diverged for case: {name}");
    }
}

/// A `u64` in the low bytes, so ordering is easy to reason about.
fn small(n: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    bytes
}

/// A `u64` in the *high* bytes, so these all sort above every `small`.
fn high(n: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    bytes
}

/// The two models must reject the same inputs, not merely agree when both
/// succeed.
#[test]
fn rejections_agree() {
    let mut real = IndexedMerkleTree::with_depth(PoolId::Sapling, DEPTH).unwrap();
    let mut model = NaiveImt::new(NaivePool::Sapling, DEPTH).unwrap();

    let value = small(7);
    real.insert(Value::from_bytes(value)).unwrap();
    model.insert(value).unwrap();

    assert!(real.insert(Value::from_bytes(value)).is_err());
    assert!(model.insert(value).is_err());

    assert!(real.insert(Value::ZERO).is_err());
    assert!(model.insert([0u8; 32]).is_err());

    assert_eq!(real.root(), model.root(), "a rejected insert mutated state");
}

/// Membership answers must match, including for the sentinel.
#[test]
fn membership_answers_agree() {
    let mut real = IndexedMerkleTree::with_depth(PoolId::Ironwood, DEPTH).unwrap();
    let mut model = NaiveImt::new(NaivePool::Ironwood, DEPTH).unwrap();

    let inserted = spread(0x1234_5678, 32);
    for value in &inserted {
        real.insert(Value::from_bytes(*value)).unwrap();
        model.insert(*value).unwrap();
    }

    for value in &inserted {
        assert!(real.contains(&Value::from_bytes(*value)));
        assert!(model.contains(value));
    }
    for value in spread(0x8765_4321, 32) {
        assert_eq!(
            real.contains(&Value::from_bytes(value)),
            model.contains(&value),
            "membership diverged for {}",
            hex::encode(value)
        );
    }
    assert!(real.contains(&Value::ZERO) && model.contains(&[0u8; 32]));
}

/// Every proof the tree issues must verify against a root-only state, and that
/// state must track the tree exactly. This is the compact-state-node path in
/// miniature.
#[test]
fn root_only_state_tracks_the_full_tree() {
    let pool = PoolId::Orchard;
    let mut real = IndexedMerkleTree::with_depth(pool, DEPTH).unwrap();
    let mut model = NaiveImt::new(NaivePool::Orchard, DEPTH).unwrap();
    let mut state = ImtState::new(pool, DEPTH).unwrap();

    for (step, value) in spread(0xDEAD_BEEF, 48).into_iter().enumerate() {
        let value = Value::from_bytes(value);

        // Before inserting, the value is absent and provably so.
        let absence = real.prove_non_membership(value).unwrap();
        state
            .verify_non_membership(pool, DEPTH, value, &absence)
            .unwrap();

        let insertion = real.insert(value).unwrap();
        model.insert(value.to_bytes()).unwrap();
        state
            .apply_insertion(pool, DEPTH, value, &insertion)
            .unwrap();

        assert_eq!(
            state,
            real.state(),
            "state diverged from tree at step {step}"
        );
        assert_eq!(
            state.root,
            model.root(),
            "state diverged from oracle at {step}"
        );

        // And now it is present, so absence is no longer provable.
        assert_eq!(
            real.prove_non_membership(value).err(),
            Some(ImtError::ValueIsMember)
        );
    }
}

/// Batch and one-at-a-time application must produce the same root. An
/// optimised batch path is exactly where this stops being true.
#[test]
fn batch_matches_sequential_matches_oracle() {
    let values: Vec<[u8; 32]> = spread(0x0BAD_F00D, 50);
    let as_values: Vec<Value> = values.iter().copied().map(Value::from_bytes).collect();

    let mut batched = IndexedMerkleTree::with_depth(PoolId::Sprout, DEPTH).unwrap();
    batched.insert_batch(&as_values).unwrap();

    let mut sequential = IndexedMerkleTree::with_depth(PoolId::Sprout, DEPTH).unwrap();
    for value in &as_values {
        sequential.insert(*value).unwrap();
    }

    let mut model = NaiveImt::new(NaivePool::Sprout, DEPTH).unwrap();
    for value in &values {
        model.insert(*value).unwrap();
    }

    assert_eq!(batched.root(), sequential.root());
    assert_eq!(batched.root(), model.root());
}

/// A cold rebuild from the same value sequence must land on the same root as
/// the tree that was built incrementally.
#[test]
fn cold_rebuild_matches_incremental() {
    let values: Vec<Value> = spread(0xFEED_FACE, 60)
        .into_iter()
        .map(Value::from_bytes)
        .collect();

    let mut incremental = IndexedMerkleTree::with_depth(PoolId::Orchard, DEPTH).unwrap();
    for value in &values {
        incremental.insert(*value).unwrap();
    }

    let cold = IndexedMerkleTree::from_values(PoolId::Orchard, DEPTH, &values).unwrap();
    assert_eq!(incremental.root(), cold.root());
}

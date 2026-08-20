//! Property tests for the Phase 1 invariants listed in CLAUDE.md.
//!
//! Run the definition-of-done sweep with:
//!
//! ```text
//! PROPTEST_CASES=10000 cargo test --release -p zutreexo-accumulator --test properties
//! ```
//!
//! `proptest` reads `PROPTEST_CASES` from the environment and it overrides the
//! configured default below, which is kept small so the ordinary `cargo test`
//! stays fast.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::expect_used
)]

use proptest::collection::vec as prop_vec;
use proptest::prelude::*;

use zutreexo_accumulator::hash::Hash;
use zutreexo_accumulator::imt::{verify_insertion, ImtError, ImtState, IndexedMerkleTree, Value};
use zutreexo_accumulator::proof::CanonicalSerialize;
use zutreexo_accumulator::{
    InsertionProof, NonMembershipProof, NullifierProofBundle, PoolId, UtxoForest, UtxoLeaf,
    UtxoRoots,
};

/// Deep enough to be realistic, shallow enough that a failing case is legible.
const DEPTH: u8 = 20;

fn any_pool() -> impl Strategy<Value = PoolId> {
    prop_oneof![
        Just(PoolId::Sprout),
        Just(PoolId::Sapling),
        Just(PoolId::Orchard),
        Just(PoolId::Ironwood),
    ]
}

/// Nullifier values, biased toward the cases that stress the linked list.
///
/// Uniformly random 256-bit values are almost never adjacent, so a purely
/// random generator would rarely exercise the splice between two neighbouring
/// leaves. Mixing in a dense low range fixes that.
fn any_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        // Dense: collisions and adjacency are likely.
        3 => (1u64..64).prop_map(low_value),
        // Sparse but ordered.
        2 => (1u64..u64::MAX).prop_map(low_value),
        // Full-width, including values near the maximum.
        3 => any::<[u8; 32]>().prop_filter("zero is reserved", |b| *b != [0u8; 32])
                              .prop_map(Value::from_bytes),
    ]
}

fn low_value(n: u64) -> Value {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    Value::from_bytes(bytes)
}

/// A set of distinct values, in a random insertion order.
fn distinct_values(max: usize) -> impl Strategy<Value = Vec<Value>> {
    prop_vec(any_value(), 0..max).prop_map(|values| {
        let mut seen = std::collections::BTreeSet::new();
        values.into_iter().filter(|v| seen.insert(*v)).collect()
    })
}

fn tree_with(pool: PoolId, values: &[Value]) -> IndexedMerkleTree {
    IndexedMerkleTree::from_values(pool, DEPTH, values)
        .expect("distinct non-zero values below capacity always insert")
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        max_shrink_iters: 4096,
        ..ProptestConfig::default()
    })]

    /// Every value in the set is a member; nothing else claims to be.
    #[test]
    fn inserted_values_are_members(pool in any_pool(), values in distinct_values(48)) {
        let tree = tree_with(pool, &values);
        for value in &values {
            prop_assert!(tree.contains(value));
        }
        prop_assert_eq!(tree.value_count(), values.len() as u64);
    }

    /// Non-membership succeeds for absent values and fails for present ones.
    /// This is the core claim of the whole structure.
    #[test]
    fn non_membership_is_exactly_absence(
        pool in any_pool(),
        values in distinct_values(48),
        probes in prop_vec(any_value(), 1..24),
    ) {
        let tree = tree_with(pool, &values);
        let state = tree.state();

        for probe in probes {
            match tree.prove_non_membership(probe) {
                Ok(proof) => {
                    prop_assert!(!values.contains(&probe), "proved absence of a member");
                    prop_assert!(
                        state.verify_non_membership(pool, DEPTH, probe, &proof).is_ok()
                    );
                }
                Err(ImtError::ValueIsMember) => {
                    prop_assert!(values.contains(&probe), "refused to prove absence of a non-member");
                }
                Err(other) => prop_assert!(false, "unexpected error: {other}"),
            }
        }
    }

    /// A proof issued for one value must not verify for another.
    #[test]
    fn non_membership_proofs_do_not_transfer(
        pool in any_pool(),
        values in distinct_values(32),
        a in any_value(),
        b in any_value(),
    ) {
        prop_assume!(a != b);
        let tree = tree_with(pool, &values);
        prop_assume!(!values.contains(&a) && !values.contains(&b));

        let proof = tree.prove_non_membership(a).expect("a is absent");
        // Verifying `b` against `a`'s proof may legitimately succeed when the
        // same low leaf brackets both. It must never succeed otherwise.
        if tree.state().verify_non_membership(pool, DEPTH, b, &proof).is_ok() {
            prop_assert!(proof.low_leaf.covers(&b));
        }
    }

    /// Inserting a duplicate is rejected and leaves the tree untouched.
    #[test]
    fn duplicates_are_rejected_without_side_effects(
        pool in any_pool(),
        values in distinct_values(32),
    ) {
        prop_assume!(!values.is_empty());
        let mut tree = tree_with(pool, &values);
        let root_before = tree.root();
        let count_before = tree.leaf_count();

        for value in &values {
            prop_assert_eq!(tree.insert(*value).err(), Some(ImtError::DuplicateValue));
        }
        prop_assert_eq!(tree.root(), root_before);
        prop_assert_eq!(tree.leaf_count(), count_before);
    }

    /// The reserved sentinel is never insertable and never provably absent.
    #[test]
    fn zero_stays_reserved(pool in any_pool(), values in distinct_values(16)) {
        let mut tree = tree_with(pool, &values);
        prop_assert_eq!(tree.insert(Value::ZERO).err(), Some(ImtError::ReservedValue));
        prop_assert_eq!(
            tree.prove_non_membership(Value::ZERO).err(),
            Some(ImtError::ReservedValue)
        );
    }

    /// Batch application and one-at-a-time application agree.
    #[test]
    fn batch_equals_sequential(pool in any_pool(), values in distinct_values(48)) {
        let mut batched = IndexedMerkleTree::with_depth(pool, DEPTH).unwrap();
        batched.insert_batch(&values).unwrap();

        let mut sequential = IndexedMerkleTree::with_depth(pool, DEPTH).unwrap();
        for value in &values {
            sequential.insert(*value).unwrap();
        }

        prop_assert_eq!(batched.root(), sequential.root());
        prop_assert_eq!(batched.leaf_count(), sequential.leaf_count());
    }

    /// A root-only state driven by insertion proofs stays identical to the
    /// full tree. This is the compact state node's entire correctness claim.
    #[test]
    fn insertion_proofs_drive_the_compact_state(
        pool in any_pool(),
        values in distinct_values(40),
    ) {
        let mut tree = IndexedMerkleTree::with_depth(pool, DEPTH).unwrap();
        let mut state = ImtState::new(pool, DEPTH).unwrap();

        for value in &values {
            let proof = tree.insert(*value).unwrap();
            prop_assert!(state.apply_insertion(pool, DEPTH, *value, &proof).is_ok());
            prop_assert_eq!(state, tree.state());
        }
    }

    /// An insertion proof is bound to the state it was generated against.
    /// Replaying it once applied must fail.
    #[test]
    fn insertion_proofs_do_not_replay(pool in any_pool(), values in distinct_values(24)) {
        prop_assume!(values.len() >= 2);
        let mut tree = IndexedMerkleTree::with_depth(pool, DEPTH).unwrap();
        let mut state = ImtState::new(pool, DEPTH).unwrap();

        let mut used: Vec<(Value, InsertionProof, ImtState)> = Vec::new();
        for value in &values {
            let before = state;
            let proof = tree.insert(*value).unwrap();
            state.apply_insertion(pool, DEPTH, *value, &proof).unwrap();
            used.push((*value, proof, before));
        }

        // Every past proof must fail against the *current* state.
        for (value, proof, _) in &used {
            prop_assert!(verify_insertion(pool, DEPTH, &state, *value, proof).is_err());
        }
    }

    /// A proof from one pool must not verify against another. Domain
    /// separation is what makes this true.
    #[test]
    fn proofs_do_not_cross_pools(values in distinct_values(24), probe in any_value()) {
        prop_assume!(!values.contains(&probe));
        let orchard = tree_with(PoolId::Orchard, &values);
        let ironwood = tree_with(PoolId::Ironwood, &values);
        prop_assert_ne!(orchard.root(), ironwood.root());

        let proof = orchard.prove_non_membership(probe).unwrap();
        prop_assert!(
            ironwood.state()
                .verify_non_membership(PoolId::Ironwood, DEPTH, probe, &proof)
                .is_err()
        );
    }

    /// The linked list threaded through the leaves enumerates the set in
    /// ascending order, with no gaps and no cycles.
    #[test]
    fn linked_list_is_a_sorted_traversal(pool in any_pool(), values in distinct_values(48)) {
        let tree = tree_with(pool, &values);

        let mut walked = Vec::new();
        let mut leaf = tree.leaf(0).expect("sentinel");
        let mut steps = 0u64;
        loop {
            walked.push(leaf.value);
            if leaf.next_value.is_zero() {
                break;
            }
            steps += 1;
            prop_assert!(steps <= tree.leaf_count(), "linked list contains a cycle");

            let next = tree.leaf(leaf.next_index).expect("next_index must resolve");
            prop_assert_eq!(next.value, leaf.next_value);
            prop_assert!(next.value > leaf.value, "list is not ascending");
            leaf = next;
        }

        let mut expected = values.clone();
        expected.push(Value::ZERO);
        expected.sort_unstable();
        prop_assert_eq!(walked, expected);
    }

    // --- serialization ---------------------------------------------------

    /// Encode, decode, encode is the identity, and the decoded proof still
    /// verifies.
    #[test]
    fn proofs_round_trip(pool in any_pool(), values in distinct_values(24), probe in any_value()) {
        let tree = tree_with(pool, &values);
        prop_assume!(!values.contains(&probe));

        let proof = tree.prove_non_membership(probe).unwrap();
        let bytes = proof.to_bytes();
        let decoded = NonMembershipProof::from_bytes(&bytes).unwrap();
        prop_assert_eq!(&decoded, &proof);
        prop_assert_eq!(decoded.to_bytes(), bytes);
        prop_assert!(
            tree.state().verify_non_membership(pool, DEPTH, probe, &decoded).is_ok()
        );
    }

    /// A whole bundle round-trips.
    #[test]
    fn bundles_round_trip(pool in any_pool(), values in distinct_values(16)) {
        let mut tree = IndexedMerkleTree::with_depth(pool, DEPTH).unwrap();
        let mut non_membership = Vec::new();
        let mut insertions = Vec::new();
        for value in &values {
            non_membership.push(tree.prove_non_membership(*value).unwrap());
            insertions.push(tree.insert(*value).unwrap());
        }
        let bundle = NullifierProofBundle {
            pool,
            nullifiers: values,
            non_membership,
            insertions,
        };
        prop_assert!(bundle.is_well_formed());

        let bytes = bundle.to_bytes();
        let decoded = NullifierProofBundle::from_bytes(&bytes).unwrap();
        prop_assert_eq!(&decoded, &bundle);
        prop_assert_eq!(decoded.to_bytes(), bytes);
    }

    /// Arbitrary bytes must never panic a decoder. Phase 6 fuzzes this
    /// properly; this is the cheap always-on version.
    #[test]
    fn decoders_never_panic(bytes in prop_vec(any::<u8>(), 0..512)) {
        let _ = NonMembershipProof::from_bytes(&bytes);
        let _ = InsertionProof::from_bytes(&bytes);
        let _ = NullifierProofBundle::from_bytes(&bytes);
        let _ = zutreexo_accumulator::proof::decode_utxo_proof(&bytes);
    }

    /// Truncating a valid encoding anywhere must error, never panic.
    #[test]
    fn truncation_never_panics(pool in any_pool(), values in distinct_values(8), cut in 0usize..4096) {
        let mut tree = IndexedMerkleTree::with_depth(pool, DEPTH).unwrap();
        let mut insertions = Vec::new();
        for value in &values {
            insertions.push(tree.insert(*value).unwrap());
        }
        let bundle = NullifierProofBundle {
            pool,
            nullifiers: values,
            non_membership: Vec::new(),
            insertions,
        };
        let bytes = bundle.to_bytes();
        let cut = cut.min(bytes.len());
        let _ = NullifierProofBundle::from_bytes(&bytes[..cut]);
    }

    // --- transparent accumulator -----------------------------------------

    /// Insert then prove always verifies against a roots-only view.
    #[test]
    fn utxo_insert_then_prove_verifies(count in 1usize..40, pick in 0usize..40) {
        let leaves = utxo_leaves(count);
        let mut forest = UtxoForest::new();
        let mut roots = UtxoRoots::new();
        forest.insert(&leaves).unwrap();
        roots.insert(&leaves).unwrap();

        prop_assert_eq!(forest.roots(), roots.roots());
        prop_assert_eq!(roots.leaves(), count as u64);

        let target = vec![leaves[pick % count]];
        let proof = forest.prove(&target).unwrap();
        prop_assert!(roots.verify(&proof, &target).unwrap_or(false));
    }

    /// Delete then prove fails — the CLAUDE.md Phase 1 invariant for the
    /// transparent side.
    #[test]
    fn utxo_delete_then_prove_fails(count in 2usize..32, pick in 0usize..32) {
        let leaves = utxo_leaves(count);
        let mut forest = UtxoForest::new();
        let mut roots = UtxoRoots::new();
        forest.insert(&leaves).unwrap();
        roots.insert(&leaves).unwrap();

        let target = vec![leaves[pick % count]];
        let proof = forest.prove(&target).unwrap();

        roots.delete(&target, &proof).unwrap();
        forest.delete(&target).unwrap();

        prop_assert_eq!(forest.roots(), roots.roots());
        prop_assert!(!roots.verify(&proof, &target).unwrap_or(false));
        prop_assert!(forest.prove(&target).is_err() || !forest.verify(&proof, &target).unwrap_or(false));
    }

    /// Forest and roots-only view agree across repeated delete-and-add rounds,
    /// and **every proof the forest issues verifies against the roots-only
    /// view** — including proofs for leaves that earlier deletions promoted.
    ///
    /// That second half is the property a bridge node lives on: it applies a
    /// block, then serves proofs for the next block's inputs against leaves
    /// whose neighbours have just been spent. It was false under stock
    /// `rustreexo` 0.6.0 (`docs/design.md` D10) and this test was narrowed to
    /// skip the rounds it could not satisfy. The pinned fork restores it, so
    /// the skip is gone; `tests/upstream_rustreexo.rs` guards the pin.
    #[test]
    fn utxo_forest_and_roots_stay_in_step(
        created in prop_vec(1usize..6, 1..8),
        spend_every in 1usize..4,
    ) {
        let mut forest = UtxoForest::new();
        let mut roots = UtxoRoots::new();
        let mut live: Vec<Hash> = Vec::new();
        let mut next = 0u32;

        for batch in created {
            let additions: Vec<Hash> = (0..batch)
                .map(|_| { next += 1; utxo_leaf(next) })
                .collect();

            let deletions: Vec<Hash> = live
                .iter()
                .step_by(spend_every)
                .copied()
                .collect();

            let proof = forest.prove(&deletions).unwrap();

            // No longer a skip: a proof the forest issued must verify against a
            // view holding nothing but roots. Rounds after the first are the
            // ones that matter, since those are the deletions acting on a
            // forest that earlier deletions already reshaped.
            prop_assert!(
                roots.verify(&proof, &deletions).unwrap_or(false),
                "a forest-issued proof failed against the roots-only view"
            );

            roots.apply(&additions, &deletions, &proof).unwrap();
            forest.apply(&additions, &deletions).unwrap();
            prop_assert_eq!(forest.roots(), roots.roots());

            live.retain(|leaf| !deletions.contains(leaf));
            live.extend(additions);
        }
    }

    /// **The reorg invariant, at the accumulator level.**
    ///
    /// Insert a sequence, undo an arbitrary suffix of it in reverse, and the
    /// result must equal a tree built from the surviving prefix alone. Stage 2c
    /// rests on this: a reorg is exactly "undo a suffix, apply a different
    /// one", and if undo does not land precisely on the prefix state then every
    /// root after the reorg is wrong.
    ///
    /// Compared by root *and* by non-membership answers, because a tree can
    /// carry a stale successor pointer while still hashing correctly, and it is
    /// the pointer that decides future proofs.
    #[test]
    fn undoing_a_suffix_equals_never_inserting_it(
        pool in any_pool(),
        values in distinct_values(32),
        keep in 0usize..32,
    ) {
        let keep = keep.min(values.len());
        let (prefix, suffix) = values.split_at(keep);

        let mut tree = IndexedMerkleTree::with_depth(pool, DEPTH).unwrap();
        let mut undo_stack = Vec::new();
        for value in &values {
            let proof = tree.insert(*value).unwrap();
            undo_stack.push((*value, proof));
        }

        // Unwind the suffix, newest first.
        for (value, proof) in undo_stack.into_iter().rev().take(suffix.len()) {
            tree.undo_insert(value, &proof).unwrap();
        }

        let expected = tree_with(pool, prefix);

        prop_assert_eq!(tree.root(), expected.root(), "root diverged after undo");
        prop_assert_eq!(tree.leaf_count(), expected.leaf_count());
        prop_assert_eq!(tree.value_count(), expected.value_count());

        // Membership must agree for everything, kept or undone.
        for value in &values {
            prop_assert_eq!(
                tree.contains(value),
                expected.contains(value),
                "membership disagreed after undo"
            );
        }

        // And so must the proofs, which is the stricter claim: a stale pointer
        // shows up here even when the root happens to match.
        for value in suffix {
            let a = tree.prove_non_membership(*value);
            let b = expected.prove_non_membership(*value);
            prop_assert_eq!(a.is_ok(), b.is_ok());
            if let (Ok(a), Ok(b)) = (a, b) {
                prop_assert_eq!(a.low_leaf, b.low_leaf, "low leaf diverged after undo");
            }
        }
    }

    /// Undo must refuse anything that is not the newest insertion, and leave
    /// the tree untouched when it does.
    #[test]
    fn out_of_order_undo_is_always_refused(
        pool in any_pool(),
        values in distinct_values(16),
    ) {
        // No `prop_assume!` on the length. The loop below is already empty for
        // fewer than two values, so short inputs are vacuous rather than wrong
        // — and assuming them away burned proptest's global reject budget at
        // 10,000 cases, because `distinct_values` dedups below two often
        // enough to trip it. A rejected case tests nothing either way; this
        // way the run does not abort.
        let mut tree = IndexedMerkleTree::with_depth(pool, DEPTH).unwrap();
        let mut proofs = Vec::new();
        for value in &values {
            proofs.push((*value, tree.insert(*value).unwrap()));
        }

        let root_before = tree.root();
        let count_before = tree.leaf_count();

        // Everything except the last insertion must be refused.
        for (value, proof) in proofs.iter().take(values.len().saturating_sub(1)) {
            prop_assert!(
                tree.undo_insert(*value, proof).is_err(),
                "an out-of-order undo was accepted"
            );
        }
        prop_assert_eq!(tree.root(), root_before, "a refused undo mutated the tree");
        prop_assert_eq!(tree.leaf_count(), count_before);
    }
}

fn utxo_leaf(n: u32) -> Hash {
    UtxoLeaf {
        txid: [(n % 251) as u8; 32],
        vout: n,
        height: 3_428_143,
        is_coinbase: n % 7 == 0,
        value: u64::from(n) * 1_000,
        script_pubkey: vec![0x76, 0xa9, (n % 256) as u8],
    }
    .hash()
}

fn utxo_leaves(count: usize) -> Vec<Hash> {
    (0..count).map(|n| utxo_leaf(n as u32 + 1)).collect()
}

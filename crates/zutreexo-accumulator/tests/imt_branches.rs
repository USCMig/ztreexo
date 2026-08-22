//! Every rejection path in `imt.rs`, driven deterministically.
//!
//! # Why this file exists, and why it is not proptest
//!
//! CLAUDE.md's Phase 1 definition of done requires **100% branch coverage on
//! `imt.rs`**. That has been unmet since Phase 1, and `PLAN.md` records why the
//! gap could not simply be closed by writing more property tests:
//!
//! > Branch coverage is not reproducible between runs. The property suites
//! > drive `proof.rs` and `imt.rs` through proptest, which seeds a fresh RNG
//! > each run, so which bounds-check branches get exercised varies: measured
//! > back to back on identical source, `proof.rs` reported 17/20 and then
//! > 16/20 while its region and line coverage were byte-identical both times.
//!
//! A gate on a number that moves on its own gets switched off, and takes the
//! stable ratchets with it. `PLAN.md` names the fix — "a fixed proptest seed,
//! or a separate non-randomised suite for `imt.rs`" — and this is the second,
//! chosen because it does two jobs at once: it removes the variance *and* it is
//! the thing that closes the branches.
//!
//! Every case below is a fixed input with a named expected error. Nothing here
//! is random, nothing is generated, and running it twice measures identically.
//!
//! # What is deliberately not here
//!
//! The happy paths. Those are covered by `properties.rs`, which should stay
//! randomised — searching for counterexamples is what proptest is for. This
//! file covers only the paths a caller reaches by getting something *wrong*,
//! which is precisely the set proptest is bad at hitting reliably.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use zutreexo_accumulator::imt::{
    check_depth, verify_insertion, verify_non_membership, ImtError, ImtState, IndexedMerkleTree,
    Value, MAX_DEPTH, MIN_DEPTH,
};
use zutreexo_accumulator::PoolId;

const POOL: PoolId = PoolId::Orchard;
const DEPTH: u8 = 8;

fn value(n: u64) -> Value {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    Value::from_bytes(bytes)
}

/// A tree holding 1, 3 and 5, so there are gaps to prove absence in.
fn tree() -> IndexedMerkleTree {
    IndexedMerkleTree::from_values_bulk(POOL, DEPTH, &[value(1), value(3), value(5)]).unwrap()
}

// ---------------------------------------------------------------------------
// check_depth / check_path
// ---------------------------------------------------------------------------

#[test]
fn a_depth_outside_the_legal_range_is_refused_at_both_ends() {
    assert!(matches!(
        check_depth(MIN_DEPTH.saturating_sub(1)),
        Err(ImtError::InvalidDepth { .. })
    ));
    assert!(matches!(
        check_depth(MAX_DEPTH.saturating_add(1)),
        Err(ImtError::InvalidDepth { .. })
    ));
    assert!(check_depth(MIN_DEPTH).is_ok());
    assert!(check_depth(MAX_DEPTH).is_ok());
}

#[test]
fn a_path_of_the_wrong_length_is_refused() {
    // The sibling count is fixed by the depth. A short path would fold to a
    // root over the wrong number of levels and could otherwise be made to
    // match by choosing the siblings.
    let tree = tree();
    let mut proof = tree.prove_non_membership(value(2)).unwrap();
    proof.siblings.pop();

    match verify_non_membership(POOL, DEPTH, &tree.root(), value(2), &proof) {
        Err(ImtError::WrongPathLength { expected, found }) => {
            assert_eq!(expected, usize::from(DEPTH));
            assert_eq!(found, usize::from(DEPTH) - 1);
        }
        other => panic!("expected WrongPathLength, got {other:?}"),
    }

    // And too long, which is the other side of the same branch.
    let mut proof = tree.prove_non_membership(value(2)).unwrap();
    proof.siblings.push([0u8; 32]);
    assert!(matches!(
        verify_non_membership(POOL, DEPTH, &tree.root(), value(2), &proof),
        Err(ImtError::WrongPathLength { .. })
    ));
}

#[test]
fn a_leaf_index_beyond_capacity_is_refused() {
    let tree = tree();
    let mut proof = tree.prove_non_membership(value(2)).unwrap();
    proof.low_leaf_index = 1u64 << DEPTH; // exactly capacity: the first illegal index

    match verify_non_membership(POOL, DEPTH, &tree.root(), value(2), &proof) {
        Err(ImtError::IndexOutOfRange { index, capacity }) => {
            assert_eq!(index, 1u64 << DEPTH);
            assert_eq!(capacity, 1u64 << DEPTH);
        }
        other => panic!("expected IndexOutOfRange, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// verify_non_membership
// ---------------------------------------------------------------------------

#[test]
fn proving_the_sentinel_absent_is_refused() {
    // Value zero is the sentinel and is always present, so a non-membership
    // proof for it is a category error rather than a false statement.
    let tree = tree();
    let proof = tree.prove_non_membership(value(2)).unwrap();
    assert!(matches!(
        verify_non_membership(POOL, DEPTH, &tree.root(), Value::ZERO, &proof),
        Err(ImtError::ReservedValue)
    ));
}

#[test]
fn a_low_leaf_that_does_not_bracket_the_value_is_refused() {
    // The proof is for 2, presented for 9. The low leaf covering 2 is (1 -> 3),
    // which says nothing about 9 — and 9 might well be present.
    let tree = tree();
    let proof = tree.prove_non_membership(value(2)).unwrap();
    assert!(matches!(
        verify_non_membership(POOL, DEPTH, &tree.root(), value(9), &proof),
        Err(ImtError::LowLeafDoesNotCover)
    ));
}

// ---------------------------------------------------------------------------
// verify_insertion
// ---------------------------------------------------------------------------

/// A state and a valid insertion proof for `value(2)` against it.
fn insertion_fixture() -> (ImtState, Value, zutreexo_accumulator::InsertionProof) {
    let mut tree = tree();
    let state = tree.state();
    let proof = tree.insert(value(2)).unwrap();
    (state, value(2), proof)
}

#[test]
fn inserting_the_reserved_value_is_refused() {
    let (state, _, proof) = insertion_fixture();
    assert!(matches!(
        verify_insertion(POOL, DEPTH, &state, Value::ZERO, &proof),
        Err(ImtError::ReservedValue)
    ));
}

#[test]
fn an_insertion_at_the_wrong_append_index_is_refused() {
    let (state, value, mut proof) = insertion_fixture();
    proof.new_leaf_index = proof.new_leaf_index.saturating_add(1);
    match verify_insertion(POOL, DEPTH, &state, value, &proof) {
        Err(ImtError::UnexpectedLeafIndex { expected, found }) => {
            assert_eq!(expected, state.leaf_count);
            assert_eq!(found, state.leaf_count + 1);
        }
        other => panic!("expected UnexpectedLeafIndex, got {other:?}"),
    }
}

#[test]
fn an_insertion_aliasing_the_low_leaf_onto_the_new_leaf_is_refused() {
    // Both indices equal would let a single path stand for two different
    // leaves, and the two root computations would collapse into one.
    let (state, value, mut proof) = insertion_fixture();
    proof.low_leaf_index = proof.new_leaf_index;
    match verify_insertion(POOL, DEPTH, &state, value, &proof) {
        Err(ImtError::AliasedLeafIndex { index }) => {
            assert_eq!(index, proof.new_leaf_index);
        }
        other => panic!("expected AliasedLeafIndex, got {other:?}"),
    }
}

#[test]
fn an_insertion_whose_low_leaf_does_not_bracket_the_value_is_refused() {
    let (state, _, proof) = insertion_fixture();
    // The proof's low leaf brackets 2; 9 sits outside it.
    assert!(matches!(
        verify_insertion(POOL, DEPTH, &state, value(9), &proof),
        Err(ImtError::LowLeafDoesNotCover)
    ));
}

#[test]
fn an_insertion_against_the_wrong_root_is_refused() {
    let (mut state, value, proof) = insertion_fixture();
    state.root[0] ^= 0x01;
    assert!(matches!(
        verify_insertion(POOL, DEPTH, &state, value, &proof),
        Err(ImtError::RootMismatch { .. })
    ));
}

#[test]
fn an_insertion_whose_append_slot_was_not_empty_is_refused() {
    // The second root check: the new-leaf path must fold the *empty* leaf hash
    // to the tree that exists after the low leaf is rewritten. Corrupting the
    // new-leaf path passes the first check and fails this one, which is what
    // makes the two checks distinct rather than redundant.
    let (state, value, mut proof) = insertion_fixture();
    proof.new_leaf_siblings[0][0] ^= 0x01;
    assert!(matches!(
        verify_insertion(POOL, DEPTH, &state, value, &proof),
        Err(ImtError::RootMismatch { .. })
    ));
}

#[test]
fn an_insertion_past_capacity_is_refused() {
    // A depth-1 tree holds two leaves: the sentinel and one value. The second
    // insertion has nowhere to go.
    let mut tree = IndexedMerkleTree::with_depth(POOL, MIN_DEPTH).unwrap();
    let mut state = tree.state();
    let first = tree.insert(value(1)).unwrap();
    state = verify_insertion(POOL, MIN_DEPTH, &state, value(1), &first).unwrap();

    match tree.insert(value(2)) {
        Err(ImtError::CapacityExhausted { depth, .. }) => assert_eq!(depth, MIN_DEPTH),
        other => panic!("expected CapacityExhausted from insert, got {other:?}"),
    }

    // The stateless verifier refuses it too, and it is worth pinning *which*
    // check fires. `verify_insertion` has its own `leaf_count > capacity`
    // guard, but nothing can reach it: the append index equals `leaf_count`,
    // so a count at or past capacity is an index at or past capacity, and
    // `check_path` rejects that first. Measured at depths 1, 2 and 3 — always
    // `UnexpectedLeafIndex`, never `CapacityExhausted`.
    //
    // Asserting the precise variant rather than "one of these two" is the
    // point: the loose version passed while telling us nothing about which
    // defence was doing the work.
    let mut overfull = state;
    overfull.leaf_count = 1u64 << MIN_DEPTH;
    assert!(matches!(
        verify_insertion(POOL, MIN_DEPTH, &overfull, value(2), &first),
        Err(ImtError::UnexpectedLeafIndex { .. })
    ));
}

// ---------------------------------------------------------------------------
// from_values_bulk
// ---------------------------------------------------------------------------

#[test]
fn bulk_building_past_capacity_is_refused() {
    let values: Vec<Value> = (1..=4u64).map(value).collect();
    // Depth 2 holds four leaves; four values plus the sentinel is five.
    match IndexedMerkleTree::from_values_bulk(POOL, 2, &values) {
        Err(ImtError::CapacityExhausted { depth, capacity }) => {
            assert_eq!(depth, 2);
            assert_eq!(capacity, 4);
        }
        other => panic!("expected CapacityExhausted, got {other:?}"),
    }
}

#[test]
fn bulk_building_with_the_reserved_value_is_refused() {
    assert!(matches!(
        IndexedMerkleTree::from_values_bulk(POOL, DEPTH, &[value(1), Value::ZERO]),
        Err(ImtError::ReservedValue)
    ));
}

#[test]
fn bulk_building_with_a_duplicate_is_refused() {
    // Rejected before anything is built, and it must be, because the linked
    // list has no representation for two leaves of equal value.
    assert!(matches!(
        IndexedMerkleTree::from_values_bulk(POOL, DEPTH, &[value(1), value(3), value(1)]),
        Err(ImtError::DuplicateValue)
    ));
}

#[test]
fn bulk_building_nothing_gives_a_sentinel_only_tree() {
    let tree = IndexedMerkleTree::from_values_bulk(POOL, DEPTH, &[]).unwrap();
    assert_eq!(tree.leaf_count(), 1);
    assert_eq!(tree.value_count(), 0);
    assert_eq!(
        tree.root(),
        IndexedMerkleTree::with_depth(POOL, DEPTH).unwrap().root()
    );
}

// ---------------------------------------------------------------------------
// rebuild_root
// ---------------------------------------------------------------------------

#[test]
fn a_cold_rebuild_of_a_sentinel_only_tree_matches() {
    // The `level.len() == 1` collapse: with one leaf, every level above is an
    // empty subtree and the loop must short-circuit rather than pair a lone
    // node with itself. Neither side of that branch was reachable from any
    // existing test, because they all build trees with several values.
    let tree = IndexedMerkleTree::with_depth(POOL, DEPTH).unwrap();
    assert_eq!(tree.rebuild_root().unwrap(), tree.root());
}

#[test]
fn a_cold_rebuild_matches_at_each_size_through_the_collapse() {
    // Sizes either side of a power of two, where the dense prefix stops
    // collapsing at a different height each time.
    for count in 0..=8u64 {
        let values: Vec<Value> = (1..=count).map(value).collect();
        let tree = IndexedMerkleTree::from_values_bulk(POOL, DEPTH, &values).unwrap();
        assert_eq!(
            tree.rebuild_root().unwrap(),
            tree.root(),
            "cold rebuild diverged at {count} values"
        );
    }
}

// ---------------------------------------------------------------------------
// undo_insert
// ---------------------------------------------------------------------------

#[test]
fn undoing_the_reserved_value_is_refused() {
    let mut tree = tree();
    let proof = tree.insert(value(2)).unwrap();
    assert!(matches!(
        tree.undo_insert(Value::ZERO, &proof),
        Err(ImtError::ReservedValue)
    ));
}

#[test]
fn undo_is_lifo_and_says_so() {
    let mut tree = tree();
    let first = tree.insert(value(2)).unwrap();
    let _second = tree.insert(value(4)).unwrap();

    // `first` is no longer the newest leaf.
    match tree.undo_insert(value(2), &first) {
        Err(ImtError::NotMostRecent { asked, newest }) => {
            assert_eq!(asked, first.new_leaf_index);
            assert!(newest > asked);
        }
        other => panic!("expected NotMostRecent, got {other:?}"),
    }
}

#[test]
fn undoing_the_sentinel_is_refused() {
    // `last_index == 0` — a tree holding only the sentinel has nothing to undo,
    // and the sentinel itself is not an insertion.
    let mut tree = IndexedMerkleTree::with_depth(POOL, DEPTH).unwrap();
    let mut donor = IndexedMerkleTree::with_depth(POOL, DEPTH).unwrap();
    let mut proof = donor.insert(value(1)).unwrap();
    proof.new_leaf_index = 0;
    assert!(matches!(
        tree.undo_insert(value(1), &proof),
        Err(ImtError::NotMostRecent { newest: 0, .. })
    ));
}

#[test]
fn undoing_a_value_other_than_the_one_appended_is_refused() {
    let mut tree = tree();
    let proof = tree.insert(value(2)).unwrap();
    // The proof is well-formed but names a different value than the leaf holds.
    assert!(matches!(
        tree.undo_insert(value(4), &proof),
        Err(ImtError::ProofMismatch)
    ));
}

#[test]
fn undoing_with_a_low_leaf_that_no_longer_points_at_the_value_is_refused() {
    let mut tree = tree();
    let mut proof = tree.insert(value(2)).unwrap();
    // Point the proof at a low leaf that does not link to the appended value.
    proof.low_leaf_index = 0;
    assert!(matches!(
        tree.undo_insert(value(2), &proof),
        Err(ImtError::ProofMismatch)
    ));
}

#[test]
fn undoing_with_the_wrong_successor_link_is_refused() {
    // The final check: restoring the low leaf must re-link it to whatever the
    // appended leaf points at, or the list develops a gap that still hashes to
    // a well-formed root.
    let mut tree = tree();
    let mut proof = tree.insert(value(2)).unwrap();
    proof.low_leaf.next_value = value(99);
    assert!(matches!(
        tree.undo_insert(value(2), &proof),
        Err(ImtError::ProofMismatch)
    ));
}

#[test]
fn undoing_with_the_wrong_successor_index_is_refused() {
    // The *other* half of the successor check. The test above corrupts
    // `next_value`, which trips the left side of the `||`; this corrupts
    // `next_index` alone, which can only be caught by the right side.
    //
    // Worth separating because short-circuit evaluation means a single test
    // covering the left disjunct leaves the right one unexecuted, and a
    // proof that re-linked the low leaf to the correct value at the wrong
    // index would build a list that still hashes to a well-formed root.
    let mut tree = tree();
    let mut proof = tree.insert(value(2)).unwrap();
    assert_eq!(
        proof.low_leaf.next_value,
        tree.leaf(proof.new_leaf_index).unwrap().next_value,
        "fixture assumption: the proof's low leaf agrees on next_value"
    );
    proof.low_leaf.next_index = proof.low_leaf.next_index.wrapping_add(7);
    assert!(matches!(
        tree.undo_insert(value(2), &proof),
        Err(ImtError::ProofMismatch)
    ));
}

#[test]
fn undoing_with_a_low_leaf_of_the_wrong_value_is_refused() {
    let mut tree = tree();
    let mut proof = tree.insert(value(2)).unwrap();
    proof.low_leaf.value = value(99);
    assert!(matches!(
        tree.undo_insert(value(2), &proof),
        Err(ImtError::ProofMismatch)
    ));
}

#[test]
fn a_valid_undo_still_works_after_all_of_that() {
    // The control. Every test above asserts a refusal; without this one they
    // would all pass on an `undo_insert` that refused everything.
    let mut tree = tree();
    let before = tree.root();
    let proof = tree.insert(value(2)).unwrap();
    assert_ne!(tree.root(), before);
    tree.undo_insert(value(2), &proof).unwrap();
    assert_eq!(tree.root(), before, "undo did not restore the root");
    assert!(!tree.contains(&value(2)));
}

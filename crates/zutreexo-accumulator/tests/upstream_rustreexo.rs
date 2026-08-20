//! Characterization tests for `rustreexo` 0.6.0 defects we depend on.
//!
//! # Why this file exists
//!
//! CLAUDE.md §3 says to use `rustreexo` for the transparent accumulator rather
//! than reimplementing it. Phase 1's differential testing found that
//! `rustreexo` 0.6.0 **generates invalid inclusion proofs after any deletion**:
//! a leaf whose sibling has been deleted can no longer be proven, by either of
//! the two full-forest types it offers.
//!
//! That is not an exotic corner. Spending one of two adjacent outputs is
//! routine, so on mainnet this would fire constantly — it blocks the
//! transparent half of the design as things stand (see `docs/design.md`,
//! "Upstream blocker").
//!
//! These tests **assert the buggy behaviour on purpose.** They are alarms, not
//! endorsements: when upstream fixes this, they start failing, which is the
//! signal to delete this file and re-enable the full property coverage in
//! `properties.rs`. A test that merely skipped the broken cases would let the
//! problem rot silently.
//!
//! Everything here uses stock `rustreexo` types — `BitcoinNodeHash`, not our
//! [`ZcashNodeHash`](zutreexo_accumulator::ZcashNodeHash) — so there is no
//! question of our domain separation being the cause.
//!
//! Reproduced against `rustreexo = "0.6.0"`.

#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use rustreexo::mem_forest::MemForest;
use rustreexo::node_hash::BitcoinNodeHash;
use rustreexo::pollard::{Pollard, PollardAddition};
use rustreexo::proof::Proof;
use rustreexo::stump::Stump;

fn leaf(n: u32) -> BitcoinNodeHash {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    BitcoinNodeHash::new(bytes)
}

fn eight_leaves() -> Vec<BitcoinNodeHash> {
    (1..=8u32).map(leaf).collect()
}

/// Baseline: with no deletions, everything works. If *this* ever fails, the
/// dependency is unusable outright rather than partially.
#[test]
fn proofs_are_sound_before_any_deletion() {
    let leaves = eight_leaves();
    let mut forest: MemForest<BitcoinNodeHash> = MemForest::new();
    let stump: Stump<BitcoinNodeHash> = Stump::new();

    forest.modify(&leaves, &[]).unwrap();
    let (stump, _) = stump.modify(&leaves, &[], &Proof::default()).unwrap();

    for target in &leaves {
        let proof = forest.prove(&[*target]).unwrap();
        assert_eq!(
            stump.verify(&proof, &[*target]),
            Ok(true),
            "a pre-deletion proof failed to verify"
        );
    }
}

/// The defect, minimised: delete one leaf, then try to prove its sibling.
///
/// In canonical Utreexo the surviving sibling is promoted a row when its
/// partner is deleted, and its proof becomes one node shorter.
/// `MemForest::prove` appears to keep reporting the leaf's original position,
/// so verification then asks for a sibling that is no longer part of the path.
#[test]
fn memforest_cannot_prove_the_sibling_of_a_deleted_leaf() {
    let leaves = eight_leaves();
    let mut forest: MemForest<BitcoinNodeHash> = MemForest::new();
    let stump: Stump<BitcoinNodeHash> = Stump::new();

    forest.modify(&leaves, &[]).unwrap();
    let (stump, _) = stump.modify(&leaves, &[], &Proof::default()).unwrap();

    // Delete leaf 0. Leaf 1 is its sibling.
    let deletion_proof = forest.prove(&[leaves[0]]).unwrap();
    assert_eq!(stump.verify(&deletion_proof, &[leaves[0]]), Ok(true));
    forest.modify(&[], &[leaves[0]]).unwrap();
    let (stump, _) = stump.modify(&[], &[leaves[0]], &deletion_proof).unwrap();

    // Roots still agree, so the *state* is fine. It is proof generation that
    // is broken.
    let forest_roots: Vec<_> = forest.get_roots().iter().map(|n| n.get_data()).collect();
    assert_eq!(forest_roots, stump.roots, "forest and stump state diverged");

    // A leaf whose sibling is untouched still proves correctly.
    let ok = forest.prove(&[leaves[3]]).unwrap();
    assert_eq!(
        stump.verify(&ok, &[leaves[3]]),
        Ok(true),
        "unaffected leaves should still be provable"
    );

    // The sibling of the deleted leaf does not.
    let broken = forest
        .prove(&[leaves[1]])
        .expect("prove() returns Ok — it is the resulting proof that is wrong");
    assert!(
        stump.verify(&broken, &[leaves[1]]).is_err(),
        "UPSTREAM FIXED: rustreexo can now prove the sibling of a deleted \
         leaf. Delete tests/upstream_rustreexo.rs and restore the full \
         transparent property coverage in tests/properties.rs."
    );
}

/// The same defect through `Pollard`, the other full-forest type, which is
/// worse: after a deletion it cannot generate a proof for an *unaffected* leaf
/// either, and reports `"Could not upgrade node, this is probably a bug"`.
///
/// Recorded so nobody spends a day concluding that switching structures is the
/// fix. It is not.
#[test]
fn pollard_proof_generation_also_breaks_after_a_deletion() {
    let leaves = eight_leaves();
    let mut pollard: Pollard<BitcoinNodeHash> = Pollard::new();
    let stump: Stump<BitcoinNodeHash> = Stump::new();

    let additions: Vec<_> = leaves
        .iter()
        .map(|hash| PollardAddition {
            hash: *hash,
            remember: true,
        })
        .collect();
    pollard.modify(&additions, &[], Proof::default()).unwrap();
    let (stump, _) = stump.modify(&leaves, &[], &Proof::default()).unwrap();
    assert_eq!(pollard.roots(), stump.roots);

    let deletion_proof = pollard.batch_proof(&[leaves[0]]).unwrap();
    pollard
        .modify(&[], &[leaves[0]], deletion_proof.clone())
        .unwrap();
    let (stump, _) = stump.modify(&[], &[leaves[0]], &deletion_proof).unwrap();
    assert_eq!(pollard.roots(), stump.roots, "pollard state diverged");

    let sibling_is_broken = match pollard.batch_proof(&[leaves[1]]) {
        Ok(proof) => stump.verify(&proof, &[leaves[1]]).is_err(),
        Err(_) => true,
    };
    let unaffected_is_broken = match pollard.batch_proof(&[leaves[3]]) {
        Ok(proof) => stump.verify(&proof, &[leaves[3]]).is_err(),
        Err(_) => true,
    };

    assert!(
        sibling_is_broken && unaffected_is_broken,
        "UPSTREAM FIXED: Pollard proof generation survives deletions now. \
         Re-evaluate which structure the bridge node should use."
    );
}

/// `MemForest::clone()` does not produce an independent snapshot.
///
/// # Why this is pinned
///
/// `MemForest` derives `Clone`, and its fields are `Vec<Rc<Node>>` plus a
/// `HashMap<_, Weak<Node>>`. `Node` holds its hash in a `Cell`. So the derived
/// clone copies the `Rc` handles, not the nodes, and mutating either handle is
/// visible through the other.
///
/// That matters directly for reorg handling (stage 2c). Utreexo deletion is not
/// invertible from a delta — there is no API to reinsert a leaf at its original
/// position, only `modify(add, del)`, which appends. So undo needs a snapshot,
/// and `clone()` is the obvious way to take one. It compiles, it reads
/// correctly, and it silently aliases.
///
/// `serialize`/`deserialize` round-trips to a genuinely independent forest and
/// is the only safe snapshot available. It costs about 79 bytes per leaf.
///
/// If this test starts failing, upstream has made `Clone` deep — at which point
/// `rollback.rs` can use it and drop the serialization round-trip.
#[test]
fn memforest_clone_aliases_rather_than_snapshots() {
    let leaves = eight_leaves();
    let mut forest: MemForest<BitcoinNodeHash> = MemForest::new();
    forest.modify(&leaves, &[]).unwrap();

    let snapshot = forest.clone();
    let before: Vec<_> = snapshot.get_roots().iter().map(|n| n.get_data()).collect();

    forest.modify(&[], &[leaves[0]]).unwrap();
    let after: Vec<_> = snapshot.get_roots().iter().map(|n| n.get_data()).collect();

    assert_ne!(
        before, after,
        "UPSTREAM FIXED: MemForest::clone() is now a real snapshot. \
         rollback.rs can use it instead of a serialize/deserialize round-trip."
    );

    // The alternative that does work, pinned alongside so the replacement is
    // never in doubt.
    let mut fresh: MemForest<BitcoinNodeHash> = MemForest::new();
    fresh.modify(&leaves, &[]).unwrap();
    let mut bytes = Vec::new();
    fresh.serialize(&mut bytes).unwrap();
    let restored: MemForest<BitcoinNodeHash> = MemForest::deserialize(&bytes[..]).unwrap();

    let restored_before: Vec<_> = restored.get_roots().iter().map(|n| n.get_data()).collect();
    fresh.modify(&[], &[leaves[0]]).unwrap();
    let restored_after: Vec<_> = restored.get_roots().iter().map(|n| n.get_data()).collect();

    assert_eq!(
        restored_before, restored_after,
        "serialize/deserialize must give an independent forest; if this fails \
         there is no safe snapshot mechanism left and 2c needs redesigning"
    );
}

/// The consequence for us, stated in our own types: a delete-then-prove cycle
/// cannot currently be sustained across blocks.
///
/// This is the shape a bridge node would need in Phase 4 — apply a block's
/// spends and creations, then serve proofs for the next block's inputs — so it
/// is the test that says whether the transparent side is viable today.
#[test]
fn our_wrapper_inherits_the_defect() {
    use zutreexo_accumulator::{UtxoForest, UtxoRoots};

    let mut forest = UtxoForest::new();
    let mut roots = UtxoRoots::new();

    let leaves: Vec<[u8; 32]> = (1..=8u32)
        .map(|n| {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&n.to_le_bytes());
            h
        })
        .collect();
    forest.insert(&leaves).unwrap();
    roots.insert(&leaves).unwrap();

    let spend = vec![leaves[0]];
    let proof = forest.prove(&spend).unwrap();
    roots.delete(&spend, &proof).unwrap();
    forest.delete(&spend).unwrap();
    assert_eq!(forest.roots(), roots.roots());

    // Now spend the sibling in the next block.
    let next_spend = vec![leaves[1]];
    let next_proof = forest.prove(&next_spend).unwrap();
    assert!(
        !roots.verify(&next_proof, &next_spend).unwrap_or(false),
        "UPSTREAM FIXED: a bridge node can now serve proofs across blocks. \
         See tests/upstream_rustreexo.rs and docs/design.md."
    );
}

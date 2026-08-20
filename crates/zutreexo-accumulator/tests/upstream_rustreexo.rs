//! Upstream `rustreexo` behaviours this project depends on, pinned in both
//! directions.
//!
//! # Two kinds of test live here
//!
//! **Regression tests for a fix we carry.** `rustreexo` 0.6.0 as published
//! generates *invalid inclusion proofs* for any leaf whose sibling has been
//! deleted, which blocked the transparent half of the design outright
//! (`docs/design.md` D10). The workspace pins a fork of v0.6.0 carrying the
//! one-line fix from upstream PR #152. The tests below assert the *fixed*
//! behaviour, so they fail if the pin is ever lost — reverting to stock 0.6.0
//! would otherwise reintroduce the defect silently, and the symptom is a bridge
//! node serving proofs that do not verify.
//!
//! **Alarms for defects still present.** These assert the broken behaviour on
//! purpose and fail when upstream fixes it, which is the signal to simplify
//! whatever works around them. One remains: `MemForest::clone` aliases
//! (mit-dci/rustreexo#151).
//!
//! Everything here uses stock `rustreexo` types — `BitcoinNodeHash`, not our
//! [`ZcashNodeHash`](zutreexo_accumulator::ZcashNodeHash) — so nothing depends
//! on our domain separation being right.

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

/// D10, minimised, now asserting the fixed behaviour.
///
/// Deleting a leaf promotes its surviving sibling one row, and the sibling's
/// proof becomes one node shorter. Stock 0.6.0 kept reporting the leaf's
/// original position, so verification asked for a sibling no longer on the
/// path and returned `InvalidProof(MissingSibling(9))`.
#[test]
fn memforest_proves_the_sibling_of_a_deleted_leaf() {
    let leaves = eight_leaves();
    let mut forest: MemForest<BitcoinNodeHash> = MemForest::new();
    let stump: Stump<BitcoinNodeHash> = Stump::new();

    forest.modify(&leaves, &[]).unwrap();
    let (stump, _) = stump.modify(&leaves, &[], &Proof::default()).unwrap();

    // Delete leaf 0. Leaf 1 is its sibling, and is promoted by the deletion.
    let deletion_proof = forest.prove(&[leaves[0]]).unwrap();
    assert_eq!(stump.verify(&deletion_proof, &[leaves[0]]), Ok(true));
    forest.modify(&[], &[leaves[0]]).unwrap();
    let (stump, _) = stump.modify(&[], &[leaves[0]], &deletion_proof).unwrap();

    let forest_roots: Vec<_> = forest.get_roots().iter().map(|n| n.get_data()).collect();
    assert_eq!(forest_roots, stump.roots, "forest and stump state diverged");

    // A leaf whose sibling is untouched. This worked even before the fix, so
    // it is the control: it distinguishes "the fix works" from "the test
    // stopped exercising promotion".
    let unaffected = forest.prove(&[leaves[3]]).unwrap();
    assert_eq!(stump.verify(&unaffected, &[leaves[3]]), Ok(true));

    // The promoted sibling: the case that was broken.
    let promoted = forest.prove(&[leaves[1]]).unwrap();
    assert_eq!(
        stump.verify(&promoted, &[leaves[1]]),
        Ok(true),
        "REGRESSION: the D10 fix is missing — is the rustreexo pin still the \
         patched fork? See docs/design.md D10 and D25."
    );
}

/// The same case through `Pollard`, the other full-forest type — **still
/// unusable, for a different reason than D10 recorded.**
///
/// D10 said `Pollard` was worse than `MemForest`: after a deletion it could not
/// prove an *unaffected* leaf either, failing with "Could not upgrade node,
/// this is probably a bug". The one-line `calculate_hashes` fix changes the
/// picture but does not resolve it, and it is worth stating which half moved,
/// because the obvious reading of "D10 is fixed" is wrong here:
///
/// | after deleting leaf 0 | stock 0.6.0 | patched |
/// |---|---|---|
/// | promoted sibling (leaf 1) | broken | works |
/// | unaffected leaves (2..7) | broken | **still broken** |
///
/// The promoted sibling was a `calculate_hashes` fault and is gone. The
/// unaffected-leaf failure is a separate defect in `Pollard`'s node-upgrade
/// path, it happens at proof *generation*, and nothing in PR #152 touches it.
///
/// So CLAUDE.md's bridge node must use `MemForest`, and D10's conclusion —
/// switching structures is not the fix — survives the fix that prompted
/// re-checking it. This test is half regression test, half alarm: if the
/// second assertion starts failing, `Pollard` has become viable and is worth
/// re-evaluating, since it is the structure designed for exactly the
/// partial-forest role a bridge serving proofs would want.
#[test]
fn pollard_still_cannot_prove_unaffected_leaves_after_a_deletion() {
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

    // Regression half: the promoted sibling, which the fix repaired.
    let promoted = pollard
        .batch_proof(&[leaves[1]])
        .expect("REGRESSION: the D10 fix is missing — check the rustreexo pin");
    assert_eq!(
        stump.verify(&promoted, &[leaves[1]]),
        Ok(true),
        "REGRESSION: the D10 fix is missing — check the rustreexo pin"
    );

    // Alarm half: every leaf the deletion did not touch is still unprovable.
    for (index, target) in leaves.iter().enumerate().skip(2) {
        assert!(
            pollard.batch_proof(&[*target]).is_err(),
            "UPSTREAM FIXED: Pollard can prove unaffected leaf {index} after a              deletion. Re-evaluate whether the bridge should hold a Pollard              rather than a MemForest — see docs/design.md D10."
        );
    }
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
/// Reported as mit-dci/rustreexo#151.
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

/// The consequence for us, in our own types: **a bridge node can serve proofs
/// across blocks.**
///
/// This is the shape Phase 4 needs — apply a block's spends and creations, then
/// serve proofs for the next block's inputs — so it is the test that says
/// whether the transparent side is viable. Under stock 0.6.0 it is not.
#[test]
fn our_wrapper_serves_proofs_across_blocks() {
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

    // Now spend the sibling in the next block — the promoted leaf.
    let next_spend = vec![leaves[1]];
    let next_proof = forest.prove(&next_spend).unwrap();
    assert!(
        roots.verify(&next_proof, &next_spend).unwrap_or(false),
        "REGRESSION: a bridge node cannot serve proofs across blocks. \
         Check the rustreexo pin; see docs/design.md D10 and D25."
    );

    // And the spend must actually apply, not merely verify.
    roots.delete(&next_spend, &next_proof).unwrap();
    forest.delete(&next_spend).unwrap();
    assert_eq!(forest.roots(), roots.roots());
}

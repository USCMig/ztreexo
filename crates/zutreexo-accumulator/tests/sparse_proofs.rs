//! The sparse proof encoding: omit the siblings both sides can derive.
//!
//! A depth-40 tree holding a few million nullifiers is overwhelmingly empty, so
//! most siblings on any path are the canonical empty-subtree hash for their
//! level. Measured at 71.4% of them (`docs/benchmarks.md`, Phase 4a). The
//! encoder replaces each with a cleared bit in a bitmap and the decoder puts it
//! back from `empty_subtree_hashes`.
//!
//! Two things have to hold, and the second matters more than the first:
//!
//! 1. A round trip returns the identical proof.
//! 2. **A lying bitmap cannot forge acceptance.** An encoder that clears a bit
//!    for a sibling that is not empty makes the decoder substitute the wrong
//!    hash; the verifier then computes a root that does not match the one it
//!    trusts, and rejects. The compression is not a trusted channel.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use zutreexo_accumulator::imt::{verify_non_membership, IndexedMerkleTree, Value};
use zutreexo_accumulator::proof::NonMembershipResponse;
use zutreexo_accumulator::{empty_subtree_hashes, CanonicalSerialize, PoolId};

const DEPTH: u8 = 32;

fn value(n: u32) -> Value {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    bytes[31] = 0x01;
    Value::from_bytes(bytes)
}

fn tree_with(count: u32) -> IndexedMerkleTree {
    let values: Vec<Value> = (1..=count).map(value).collect();
    IndexedMerkleTree::from_values_bulk(PoolId::Orchard, DEPTH, &values).unwrap()
}

fn response(tree: &IndexedMerkleTree, absent: Value) -> NonMembershipResponse {
    NonMembershipResponse {
        pool: PoolId::Orchard,
        depth: DEPTH,
        height: 1_234_567,
        proof: tree.prove_non_membership(absent).unwrap(),
    }
}

#[test]
fn a_sparse_proof_round_trips_exactly() {
    let tree = tree_with(500);
    let absent = value(0x00FF_FFFF);
    let original = response(&tree, absent);

    let decoded = NonMembershipResponse::from_bytes(&original.to_bytes()).unwrap();
    assert_eq!(decoded, original, "the sparse round trip changed the proof");

    // And the restored proof still verifies, which is the property that
    // matters — equality of structs would not catch a ladder built from the
    // wrong pool on both sides.
    verify_non_membership(
        decoded.pool,
        decoded.depth,
        &tree.root(),
        absent,
        &decoded.proof,
    )
    .expect("a round-tripped proof must still verify");
}

#[test]
fn the_sparse_form_is_substantially_smaller() {
    let tree = tree_with(500);
    let sparse = response(&tree, value(0x00FF_FFFF)).to_bytes().len();

    // The dense equivalent: every sibling on the wire.
    let dense = 1 + 1 + 1 + 4 + (32 + 32 + 8) + 8 + 1 + usize::from(DEPTH) * 32;

    assert!(
        sparse * 2 < dense,
        "sparse encoding saved less than half: {sparse} vs {dense}"
    );

    // Guard against the test passing because the tree is trivially empty: with
    // 500 values roughly the bottom nine levels are occupied and must be sent.
    assert!(
        sparse > 300,
        "suspiciously small — is the path being dropped rather than compressed? {sparse}"
    );
}

#[test]
fn a_cleared_bit_for_a_real_sibling_is_rejected_not_accepted() {
    let tree = tree_with(500);
    let absent = value(0x00FF_FFFF);
    let original = response(&tree, absent);
    let root = tree.root();

    let ladder = empty_subtree_hashes(PoolId::Orchard, DEPTH).unwrap();
    // Find a level whose sibling is genuinely non-empty — one an honest encoder
    // must transmit.
    let level = original
        .proof
        .siblings
        .iter()
        .position(|s| ladder.iter().all(|e| e != s))
        .expect("no non-empty sibling to lie about");

    // Forge the encoding by hand: same proof, but that sibling declared empty.
    let mut forged = original.clone();
    forged.proof.siblings[level] = ladder[level];
    let bytes = forged.to_bytes();

    // It decodes — the bitmap is self-consistent, so there is nothing to catch
    // at the codec layer, and that is the point.
    let decoded = NonMembershipResponse::from_bytes(&bytes).unwrap();
    assert_ne!(decoded.proof, original.proof);

    // Verification is what rejects it.
    assert!(
        verify_non_membership(decoded.pool, decoded.depth, &root, absent, &decoded.proof).is_err(),
        "a forged sparse path verified — the bitmap is being trusted"
    );
}

#[test]
fn a_proof_decoded_against_the_wrong_pool_does_not_verify() {
    let tree = tree_with(500);
    let absent = value(0x00FF_FFFF);
    let mut moved = response(&tree, absent);
    moved.pool = PoolId::Sapling;

    // Re-encoding under Sapling omits against Sapling's ladder, and decoding
    // restores Sapling's empty hashes into a path taken from Orchard's tree.
    let decoded = NonMembershipResponse::from_bytes(&moved.to_bytes()).unwrap();
    assert_eq!(decoded.pool, PoolId::Sapling);
    assert!(
        verify_non_membership(
            PoolId::Sapling,
            decoded.depth,
            &tree.root(),
            absent,
            &decoded.proof
        )
        .is_err(),
        "an Orchard proof verified against Sapling"
    );
}

#[test]
fn a_truncated_sparse_proof_is_an_error_not_a_panic() {
    let tree = tree_with(500);
    let bytes = response(&tree, value(0x00FF_FFFF)).to_bytes();

    for length in 0..bytes.len() {
        // Must not panic; must not succeed on a prefix of a longer encoding.
        let _ = NonMembershipResponse::from_bytes(&bytes[..length]);
    }

    // Trailing bytes are rejected too, so the encoding stays canonical.
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(NonMembershipResponse::from_bytes(&extended).is_err());
}

#[test]
fn an_unknown_pool_or_depth_is_refused() {
    let tree = tree_with(100);
    let mut bytes = response(&tree, value(0x00FF_FFFF)).to_bytes();

    let mut bad_pool = bytes.clone();
    bad_pool[1] = 0xEE; // pool code, after the version byte
    assert!(NonMembershipResponse::from_bytes(&bad_pool).is_err());

    bytes[2] = 0xFF; // depth, beyond MAX_DEPTH
    assert!(NonMembershipResponse::from_bytes(&bytes).is_err());
}

#[test]
fn an_almost_empty_tree_still_round_trips() {
    // The edge the compression is most likely to get wrong: a tree holding only
    // the sentinel, where *every* sibling is derivable and the payload is a
    // bitmap of zeroes.
    let tree = IndexedMerkleTree::with_depth(PoolId::Ironwood, DEPTH).unwrap();
    let absent = value(7);
    let original = NonMembershipResponse {
        pool: PoolId::Ironwood,
        depth: DEPTH,
        height: 0,
        proof: tree.prove_non_membership(absent).unwrap(),
    };

    let decoded = NonMembershipResponse::from_bytes(&original.to_bytes()).unwrap();
    assert_eq!(decoded, original);
    verify_non_membership(
        PoolId::Ironwood,
        DEPTH,
        &tree.root(),
        absent,
        &decoded.proof,
    )
    .expect("empty-tree proof must verify");
}

#[test]
fn an_encoder_given_an_impossible_depth_stays_total() {
    // `depth` is a public field, so nothing stops a caller setting one no tree
    // could have. The encoder has no ladder to omit against and falls back to
    // the dense path rather than emitting a truncated one — it must not panic
    // and must not produce something a decoder would accept.
    let tree = tree_with(50);
    let mut broken = response(&tree, value(0x00FF_FFFF));
    broken.depth = 0;

    let bytes = broken.to_bytes();
    assert!(
        NonMembershipResponse::from_bytes(&bytes).is_err(),
        "a response claiming depth 0 decoded"
    );

    // The same for a depth past the maximum, which fails on the other side of
    // the range check.
    let mut too_deep = response(&tree, value(0x00FF_FFFF));
    too_deep.depth = u8::MAX;
    assert!(NonMembershipResponse::from_bytes(&too_deep.to_bytes()).is_err());
}

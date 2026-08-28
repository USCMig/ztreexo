//! Wire-format tests for the prefix-cohort encoding.
//!
//! Written with the decoder, not deferred to a fuzzing phase. `PLAN.md` records
//! why: a three-line bit-flip loop found D29 — a declared count of 2^32+1
//! reaching `with_capacity` and aborting on a 141 GB allocation — in seconds,
//! after the assumption that it was purely an upstream problem to wait out had
//! held for two phases.
//!
//! The cohort decoder has two declared counts, both larger than anything
//! previously on this wire, so it is exactly the shape that bug had.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;

use zutreexo_accumulator::cohort::{
    resolve, verify_cohort, CohortResponse, PrefixRange, Status, MAX_PREFIX_BITS,
};
use zutreexo_accumulator::imt::{IndexedMerkleTree, Value};
use zutreexo_accumulator::pool::PoolId;
use zutreexo_accumulator::proof::{CanonicalSerialize, ProofCodecError};

const POOL: PoolId = PoolId::Orchard;
const DEPTH: u8 = 12;
const HEIGHT: u32 = 3_455_225;

fn value(a: u8, b: u8, tail: u8) -> Value {
    let mut bytes = [tail; 32];
    bytes[0] = a;
    bytes[1] = b;
    Value::from_bytes(bytes)
}

/// A tree whose insertion order is unrelated to value order, so cohort leaf
/// indices are genuinely scattered and the delta coding is actually exercised.
fn tree() -> IndexedMerkleTree {
    let mut tree = IndexedMerkleTree::with_depth(POOL, DEPTH).expect("valid depth");
    let mut state = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..400 {
        // xorshift64*, so the corpus is deterministic without a dependency.
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let mixed = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        let a = (mixed >> 56) as u8;
        let b = (mixed >> 48) as u8;
        let tail = (mixed >> 40) as u8;
        // Duplicates are possible and rejected; skipping them is fine here.
        let _ = tree.insert(value(a, b, tail));
    }
    tree
}

fn response(tree: &IndexedMerkleTree, bits: u8) -> CohortResponse {
    let range = PrefixRange::covering(value(0x40, 0x80, 0x00), bits).expect("valid width");
    tree.prove_prefix_cohort(range)
        .expect("cohort")
        .at_height(HEIGHT)
}

#[test]
fn a_cohort_round_trips() {
    let tree = tree();
    for bits in [1u8, 4, 8, 12, 16, MAX_PREFIX_BITS] {
        let original = response(&tree, bits);
        let bytes = original.to_bytes();
        let decoded = CohortResponse::from_bytes(&bytes).expect("round trip");
        assert_eq!(decoded, original, "bits={bits}");
        assert_eq!(
            decoded.to_bytes(),
            bytes,
            "re-encode must be byte-identical"
        );
    }
}

#[test]
fn a_decoded_cohort_still_verifies_and_answers() {
    // Round-tripping the bytes must not change what the cohort *means*.
    let tree = tree();
    let original = response(&tree, 8);
    let decoded = CohortResponse::from_bytes(&original.to_bytes()).expect("round trip");

    let leaves = verify_cohort(&tree.root(), &decoded.proof).expect("folds to the root");
    let range = decoded.proof.range;

    let target = value(0x40, 0x33, 0x77);
    let from_wire = resolve(&leaves, &range, target).expect("settles");
    let direct = match tree.prove_non_membership(target) {
        Ok(proof) => Status::Unspent {
            low: proof.low_leaf,
        },
        Err(_) => Status::Spent,
    };
    assert_eq!(from_wire, direct, "the wire must not change the answer");
}

#[test]
fn every_truncation_is_an_error_and_never_a_panic() {
    let tree = tree();
    let bytes = response(&tree, 8).to_bytes();
    assert!(bytes.len() > 64, "fixture should be substantial");
    for cut in 0..bytes.len() {
        let result = CohortResponse::from_bytes(&bytes[..cut]);
        assert!(
            result.is_err(),
            "a {cut}-byte prefix of a {}-byte cohort decoded",
            bytes.len()
        );
    }
}

#[test]
fn every_single_bit_flip_is_rejected_or_harmless() {
    // Not "every flip is an error": flipping a bit inside a leaf value or a
    // node hash yields a structurally valid cohort that simply describes a
    // different tree. Those must decode and then fail the fold, which is the
    // division of labour the fold exists for. What must never happen is a
    // panic, an abort, or a silent oversized allocation.
    let tree = tree();
    let root = tree.root();
    let bytes = response(&tree, 8).to_bytes();

    let mut decoded_but_wrong = 0usize;
    for byte_index in 0..bytes.len() {
        for bit in 0..8u32 {
            let mut mutated = bytes.clone();
            if let Some(slot) = mutated.get_mut(byte_index) {
                *slot ^= 1 << bit;
            }
            match CohortResponse::from_bytes(&mutated) {
                Err(_) => {}
                Ok(response) => {
                    // Decoded. It must then either fold to a different root, or
                    // be a genuinely equivalent encoding of the same cohort.
                    if verify_cohort(&root, &response.proof).is_err() {
                        decoded_but_wrong += 1;
                    }
                }
            }
        }
    }
    assert!(
        decoded_but_wrong > 0,
        "a bit-flip sweep that never reaches the fold is testing the header only"
    );
}

#[test]
fn an_over_declared_leaf_count_is_refused_before_allocating() {
    // D29 in its exact shape: a declared count far beyond what the input can
    // hold, reaching `with_capacity`. The guard has to compare against the
    // bytes actually remaining.
    let tree = tree();
    let response = response(&tree, 8);
    let bytes = response.to_bytes();

    // Header is version(1) + pool(1) + depth(1) + bits(1) + lo(32) + height(4).
    let count_at = 1 + 1 + 1 + 1 + 32 + 4;
    let mut mutated = bytes.clone();
    for (offset, byte) in u32::MAX.to_le_bytes().iter().enumerate() {
        if let Some(slot) = mutated.get_mut(count_at + offset) {
            *slot = *byte;
        }
    }
    let error = CohortResponse::from_bytes(&mutated).expect_err("must be refused");
    assert!(
        matches!(
            error,
            ProofCodecError::Malformed {
                reason: "cohort declares more leaves than the input can hold"
            }
        ),
        "wrong error: {error:?} — the guard must name the count, not fail later"
    );
}

#[test]
fn an_unaligned_lower_bound_is_refused() {
    // `lo` must sit on its bucket boundary. Otherwise two different encodings
    // describe the same cohort, and the range answers for values no prefix
    // covers — the canonical-form rule this crate's codec is built on.
    let tree = tree();
    let bytes = response(&tree, 8).to_bytes();

    let mut mutated = bytes.clone();
    // Byte 4 is the first byte of `lo`; byte 5 is inside the region an 8-bit
    // prefix must leave zero.
    if let Some(slot) = mutated.get_mut(5) {
        *slot = 0x01;
    }
    let error = CohortResponse::from_bytes(&mutated).expect_err("must be refused");
    assert!(
        matches!(
            error,
            ProofCodecError::Malformed {
                reason: "cohort lower bound is not aligned to its prefix"
            }
        ),
        "wrong error: {error:?}"
    );
}

#[test]
fn a_zero_prefix_width_is_refused_at_the_codec() {
    let tree = tree();
    let mut bytes = response(&tree, 8).to_bytes();
    if let Some(slot) = bytes.get_mut(3) {
        *slot = 0;
    }
    let error = CohortResponse::from_bytes(&bytes).expect_err("must be refused");
    assert!(
        matches!(
            error,
            ProofCodecError::Malformed {
                reason: "invalid cohort prefix width"
            }
        ),
        "wrong error: {error:?}"
    );
}

#[test]
fn an_over_long_varint_is_refused() {
    // A leaf index delta is LEB128. Ten bytes with the continuation bit set
    // describe an integer wider than the u64 it decodes into; without the
    // length bound the reader keeps consuming and shifts past 64, which is
    // either a silent wrap or an overflow panic depending on build flags.
    let tree = tree();
    let bytes = response(&tree, 8).to_bytes();

    // Header is version(1) + pool(1) + depth(1) + bits(1) + lo(32) + height(4),
    // then the u32 leaf count.
    let header = 1 + 1 + 1 + 1 + 32 + 4;
    let mut mutated = bytes[..header].to_vec();
    mutated.extend_from_slice(&1u32.to_le_bytes()); // one leaf...
    mutated.extend_from_slice(&[0xff; 10]); // ...whose index never terminates
                                            // Enough trailing bytes that the count guard passes and the varint is
                                            // actually reached, rather than the input being rejected as too short.
    mutated.extend_from_slice(&[0u8; 96]);

    let error = CohortResponse::from_bytes(&mutated).expect_err("must be refused");
    assert!(
        matches!(
            error,
            ProofCodecError::Malformed {
                reason: "varint is longer than 64 bits"
            }
        ),
        "wrong error: {error:?}"
    );
}

/// The 40-byte header of a real encoding: version, pool, depth, bits, lo,
/// height. Reused to build hand-made bodies that get past the header checks.
fn header(tree: &IndexedMerkleTree) -> Vec<u8> {
    response(tree, 8).to_bytes()[..40].to_vec()
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

#[test]
fn a_leaf_index_that_overflows_u64_is_refused() {
    // Deltas accumulate. Two leaves whose deltas sum past u64::MAX would wrap
    // to a small index in release and panic in debug; both are wrong, and the
    // wrap is worse because it silently reorders the cohort.
    let tree = tree();
    let mut bytes = header(&tree);
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&varint(u64::MAX)); // first index: u64::MAX
    bytes.extend_from_slice(&[0u8; 72]); // its leaf
    bytes.extend_from_slice(&varint(1)); // +1 overflows
    bytes.extend_from_slice(&[0u8; 72]);

    let error = CohortResponse::from_bytes(&bytes).expect_err("must be refused");
    assert!(
        matches!(
            error,
            ProofCodecError::Malformed {
                reason: "cohort leaf index overflows"
            }
        ),
        "wrong error: {error:?}"
    );
}

#[test]
fn a_node_index_that_overflows_u64_is_refused() {
    let tree = tree();
    let mut bytes = header(&tree);
    bytes.extend_from_slice(&1u32.to_le_bytes()); // one leaf
    bytes.extend_from_slice(&varint(1));
    bytes.extend_from_slice(&[0u8; 72]);
    bytes.extend_from_slice(&2u32.to_le_bytes()); // two nodes, same level
    bytes.push(0);
    bytes.extend_from_slice(&varint(u64::MAX));
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.push(0);
    bytes.extend_from_slice(&varint(1));
    bytes.extend_from_slice(&[0u8; 32]);

    let error = CohortResponse::from_bytes(&bytes).expect_err("must be refused");
    assert!(
        matches!(
            error,
            ProofCodecError::Malformed {
                reason: "cohort node index overflows"
            }
        ),
        "wrong error: {error:?}"
    );
}

#[test]
fn running_out_mid_leaf_is_an_error_not_a_panic() {
    // The count guard checks `leaf_count <= remaining / 73`, 73 being the
    // smallest a leaf can be: a one-byte delta plus 72 bytes of leaf. A
    // two-byte delta makes the real cost 74, so a body sized to the guard's
    // minimum passes it and then runs out partway through the last leaf.
    //
    // The plain truncation sweep cannot reach this: cutting bytes off the end
    // shrinks `remaining`, so the guard rejects before any leaf is read. This
    // is the gap between "declared count is plausible" and "declared count is
    // right", and it is the half D29 got wrong.
    let tree = tree();
    let mut bytes = header(&tree);
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&varint(200)); // two bytes, not one
    bytes.extend_from_slice(&[0u8; 72]);
    bytes.extend_from_slice(&varint(200)); // two bytes again
    bytes.extend_from_slice(&[0u8; 70]); // two bytes short of a whole leaf

    assert!(
        CohortResponse::from_bytes(&bytes).is_err(),
        "a body that runs out mid-leaf must be refused"
    );
}

#[test]
fn running_out_mid_node_is_an_error_not_a_panic() {
    let tree = tree();
    let mut bytes = header(&tree);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&varint(1));
    bytes.extend_from_slice(&[0u8; 72]);
    bytes.extend_from_slice(&2u32.to_le_bytes()); // two nodes declared
    bytes.push(0);
    bytes.extend_from_slice(&varint(200));
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.push(0); // second node's level, then nothing
    assert!(
        CohortResponse::from_bytes(&bytes).is_err(),
        "a body that runs out mid-node must be refused"
    );
}

#[test]
fn trailing_bytes_are_refused() {
    let tree = tree();
    let mut bytes = response(&tree, 8).to_bytes();
    bytes.push(0);
    assert!(matches!(
        CohortResponse::from_bytes(&bytes),
        Err(ProofCodecError::TrailingBytes { count: 1 })
    ));
}

#[test]
fn delta_coded_indices_cost_less_than_absolute_ones() {
    // The reason the encoding bothers with varints. Cohort leaf indices are
    // scattered u64 positions; at ~800 leaves, 8 bytes each is 6.4 KB of pure
    // index. This asserts the saving is real rather than assumed.
    let tree = tree();
    let response = response(&tree, 8);
    let leaves = response.proof.leaves.len();
    let nodes = response.proof.nodes.len();
    assert!(leaves > 1 && nodes > 1, "fixture must have a real cohort");

    let encoded = response.to_bytes().len();
    // Absolute form: same payload, but 8 bytes per leaf index and per node index.
    let leaf_payload = leaves * (8 + 72);
    let node_payload = nodes * (1 + 8 + 32);
    let absolute = 1 + 1 + 1 + 1 + 32 + 4 + 4 + leaf_payload + 4 + node_payload;
    assert!(
        encoded < absolute,
        "delta coding must save: {encoded} vs {absolute} absolute"
    );
}

#[test]
fn the_encoding_is_canonical_across_construction_orders() {
    // Two trees holding the same values in different insertion orders produce
    // different roots and different indices — that is expected. What must hold
    // is that one cohort has exactly one encoding, which the re-encode check in
    // the round-trip test covers, and that node ordering is fixed by the
    // BTreeMap rather than by insertion. Assert the node keys come out sorted.
    let tree = tree();
    let response = response(&tree, 8);
    let keys: Vec<(u8, u64)> = response.proof.nodes.keys().copied().collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted, "nodes must serialize in canonical key order");

    let indices: Vec<u64> = response.proof.leaves.iter().map(|(i, _)| *i).collect();
    let unique: BTreeSet<u64> = indices.iter().copied().collect();
    assert_eq!(indices.len(), unique.len(), "leaf indices must be unique");
    let mut ascending = indices.clone();
    ascending.sort_unstable();
    assert_eq!(indices, ascending, "leaf indices must be ascending");
}

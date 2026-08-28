//! Wire-format tests for the sorted-cohort encoding.
//!
//! Written with the decoder, per `PLAN.md`'s standing rule. This one has two
//! declared counts over a payload measured in hundreds of kilobytes at the
//! operating point, so an unchecked count is a larger lever here than in any
//! decoder before it: at the target width a legitimate cohort is ~12,288
//! values, and a declared `u32::MAX` asks for 137 GB.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use zutreexo_accumulator::cohort::PrefixRange;
use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::pool::PoolId;
use zutreexo_accumulator::proof::{CanonicalSerialize, ProofCodecError};
use zutreexo_accumulator::sorted::{self, SortedCohort, SortedTree, MAX_SORTED_DEPTH};

const POOL: PoolId = PoolId::Orchard;
const HEIGHT: u32 = 3_455_225;

struct Rng(u64);

impl Rng {
    fn next_value(&mut self) -> Value {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            let word = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        if bytes.iter().all(|b| *b == 0) {
            bytes[31] = 1;
        }
        Value::from_bytes(bytes)
    }
}

fn tree() -> SortedTree {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut values: Vec<Value> = (0..600).map(|_| rng.next_value()).collect();
    values.sort_unstable();
    values.dedup();
    SortedTree::from_sorted_values(POOL, HEIGHT, values).expect("builds")
}

fn cohort(tree: &SortedTree, bits: u8) -> SortedCohort {
    let range = PrefixRange::covering(Value::from_bytes([0x40; 32]), bits).expect("valid width");
    tree.prove_prefix_cohort(range).expect("cohort")
}

/// Offset of the `value_count` field: version, pool, depth, bits, lo(32),
/// height(4), leaf_count(8), start_index(8).
const VALUE_COUNT_AT: usize = 1 + 1 + 1 + 1 + 32 + 4 + 8 + 8;

#[test]
fn a_sorted_cohort_round_trips() {
    let tree = tree();
    for bits in [1u8, 2, 4, 8, 12, 16] {
        let original = cohort(&tree, bits);
        let bytes = original.to_bytes();
        let decoded = SortedCohort::from_bytes(&bytes).expect("round trip");
        assert_eq!(decoded, original, "bits={bits}");
        assert_eq!(
            decoded.to_bytes(),
            bytes,
            "re-encode must be byte-identical"
        );
    }
}

#[test]
fn a_decoded_cohort_still_folds_to_the_root() {
    let tree = tree();
    let original = cohort(&tree, 4);
    let decoded = SortedCohort::from_bytes(&original.to_bytes()).expect("round trip");
    let values = sorted::verify_cohort(&tree.root(), &decoded).expect("folds");
    assert_eq!(values, original.values);
}

#[test]
fn every_truncation_is_an_error_and_never_a_panic() {
    let tree = tree();
    let bytes = cohort(&tree, 4).to_bytes();
    assert!(bytes.len() > 256, "fixture should be substantial");
    for cut in 0..bytes.len() {
        assert!(
            SortedCohort::from_bytes(&bytes[..cut]).is_err(),
            "a {cut}-byte prefix of a {}-byte cohort decoded",
            bytes.len()
        );
    }
}

#[test]
fn every_single_bit_flip_either_fails_to_decode_or_fails_the_fold() {
    // A flip inside a value or a sibling hash yields a structurally valid
    // cohort describing a different tree; those must decode and then fail the
    // fold. What must never happen is a panic, an abort, or a decode that then
    // *verifies* — the last would mean a second valid encoding of a different
    // set under the same root.
    let tree = tree();
    let root = tree.root();
    let bytes = cohort(&tree, 4).to_bytes();

    let mut reached_the_fold = 0usize;
    for index in 0..bytes.len() {
        for bit in 0..8u32 {
            let mut mutated = bytes.clone();
            mutated[index] ^= 1 << bit;
            if let Ok(decoded) = SortedCohort::from_bytes(&mutated) {
                if sorted::verify_cohort(&root, &decoded).is_err() {
                    reached_the_fold += 1;
                }
            }
        }
    }
    assert!(
        reached_the_fold > 0,
        "a sweep that never reaches the fold is testing the header only"
    );
}

#[test]
fn an_over_declared_value_count_is_refused_before_allocating() {
    // D29's shape, with a bigger lever: 32 bytes a value against a declared
    // u32::MAX is a 137 GB request.
    let tree = tree();
    let mut bytes = cohort(&tree, 4).to_bytes();
    bytes[VALUE_COUNT_AT..VALUE_COUNT_AT + 4].copy_from_slice(&u32::MAX.to_le_bytes());

    let error = SortedCohort::from_bytes(&bytes).expect_err("must be refused");
    assert!(
        matches!(
            error,
            ProofCodecError::Malformed {
                reason: "sorted cohort declares more values than the input can hold"
            }
        ),
        "wrong error: {error:?} — the guard must name the count, not fail later"
    );
}

#[test]
fn an_over_declared_sibling_count_is_refused_before_allocating() {
    let tree = tree();
    let original = cohort(&tree, 4);
    let mut bytes = original.to_bytes();
    let sibling_count_at = VALUE_COUNT_AT + 4 + original.values.len() * 32;
    bytes[sibling_count_at..sibling_count_at + 2].copy_from_slice(&u16::MAX.to_le_bytes());

    let error = SortedCohort::from_bytes(&bytes).expect_err("must be refused");
    assert!(
        matches!(
            error,
            ProofCodecError::Malformed {
                reason: "sorted cohort declares more siblings than the input can hold"
            }
        ),
        "wrong error: {error:?}"
    );
}

#[test]
fn a_depth_beyond_the_maximum_is_refused() {
    // Depth drives the fold loop. Unbounded, a declared 255 costs 255 levels of
    // hashing per cohort — cheap for the attacker, not for the verifier.
    let tree = tree();
    let mut bytes = cohort(&tree, 4).to_bytes();
    bytes[2] = MAX_SORTED_DEPTH + 1;
    let error = SortedCohort::from_bytes(&bytes).expect_err("must be refused");
    assert!(
        matches!(
            error,
            ProofCodecError::Malformed {
                reason: "sorted cohort depth exceeds the maximum"
            }
        ),
        "wrong error: {error:?}"
    );
}

#[test]
fn an_unaligned_lower_bound_is_refused() {
    let tree = tree();
    let mut bytes = cohort(&tree, 8).to_bytes();
    // Byte 4 begins `lo`; byte 5 is inside the region an 8-bit prefix zeroes.
    bytes[5] = 0x01;
    let error = SortedCohort::from_bytes(&bytes).expect_err("must be refused");
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

/// A body with a valid header and hand-built value and sibling sections.
fn hand_built(tree: &SortedTree, values: usize, siblings: &[u8]) -> Vec<u8> {
    let base = cohort(tree, 4).to_bytes();
    let mut out = base[..VALUE_COUNT_AT].to_vec();
    out.extend_from_slice(&(values as u32).to_le_bytes());
    out.extend_from_slice(&vec![0u8; values * 32]);
    out.extend_from_slice(siblings);
    out
}

#[test]
fn running_out_mid_sibling_is_an_error_not_a_panic() {
    // The sibling guard checks `count <= remaining / 34`, 34 being the smallest
    // a sibling can be: level byte, one-byte varint, 32-byte hash. A two-byte
    // varint makes the real cost 35, so a section sized to the guard's minimum
    // passes it and then runs out inside the last sibling.
    //
    // Plain truncation cannot reach this: cutting bytes shrinks `remaining`, so
    // the guard rejects before any sibling is read.
    let tree = tree();
    let mut section = Vec::new();
    section.extend_from_slice(&2u16.to_le_bytes());
    for _ in 0..2 {
        section.push(0); // level
        section.extend_from_slice(&varint(200)); // two bytes, not one
        section.extend_from_slice(&[0u8; 32]);
    }
    // Trim so the declared two siblings no longer fit, while the guard still
    // sees 2 <= remaining / 34.
    section.truncate(2 + 34 * 2);

    let bytes = hand_built(&tree, 1, &section);
    assert!(
        SortedCohort::from_bytes(&bytes).is_err(),
        "a sibling section that runs out must be refused"
    );
}

#[test]
fn a_sibling_index_that_overflows_u64_is_refused() {
    let tree = tree();
    let mut section = Vec::new();
    section.extend_from_slice(&2u16.to_le_bytes());
    section.push(0);
    section.extend_from_slice(&varint(u64::MAX));
    section.extend_from_slice(&[0u8; 32]);
    section.push(0); // same level, so the delta base is not reset
    section.extend_from_slice(&varint(1));
    section.extend_from_slice(&[0u8; 32]);

    let bytes = hand_built(&tree, 1, &section);
    let error = SortedCohort::from_bytes(&bytes).expect_err("must be refused");
    assert!(
        matches!(
            error,
            ProofCodecError::Malformed {
                reason: "sorted cohort sibling index overflows"
            }
        ),
        "wrong error: {error:?}"
    );
}

#[test]
fn trailing_bytes_are_refused() {
    let tree = tree();
    let mut bytes = cohort(&tree, 4).to_bytes();
    bytes.push(0);
    assert!(matches!(
        SortedCohort::from_bytes(&bytes),
        Err(ProofCodecError::TrailingBytes { count: 1 })
    ));
}

#[test]
fn a_decoded_cohort_with_unsorted_values_is_refused_at_the_fold() {
    // The codec does not check ordering — the fold and the completeness check
    // do. Swapping two values keeps the byte count identical, so this reaches
    // `verify_cohort` and must be rejected there rather than silently
    // producing a bracket from an unordered list.
    let tree = tree();
    let mut original = cohort(&tree, 4);
    assert!(original.values.len() > 3, "need values to swap");
    original.values.swap(1, 2);

    let decoded = SortedCohort::from_bytes(&original.to_bytes()).expect("still decodes");
    assert!(
        sorted::verify_cohort(&tree.root(), &decoded).is_err(),
        "an unordered run must not verify"
    );
}

#[test]
fn the_proof_stays_bounded_while_the_payload_grows() {
    // The property the whole design rests on, asserted on the wire rather than
    // in memory: widening the prefix multiplies the values and leaves the
    // sibling count alone.
    let tree = tree();
    let narrow = cohort(&tree, 8);
    let wide = cohort(&tree, 1);

    assert!(
        wide.values.len() > narrow.values.len() * 4,
        "a much wider prefix must hold many more values"
    );
    assert!(
        wide.siblings.len() <= 2 * usize::from(tree.depth()),
        "fringe is at most two per level"
    );
    assert!(
        wide.siblings.len() < narrow.siblings.len() + 8,
        "sibling count must not scale with cohort size: {} vs {}",
        wide.siblings.len(),
        narrow.siblings.len()
    );
}

//! The block proof bundle against hostile bytes.
//!
//! A bundle is the one thing a compact state node accepts from a party it does
//! not control, so its decoder is the crate's whole untrusted-input surface.
//! `zutreexo-csn`'s tests cover bundles that are *structurally valid but
//! dishonest* — a substituted leaf, a forged proof. This file covers the layer
//! below: bytes that are not a bundle at all.
//!
//! The distinction matters because the two fail in different places. A
//! dishonest bundle is caught by verification; a malformed one has to be caught
//! by the decoder, before any of it is trusted enough to verify.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::{CanonicalSerialize, PoolId, UtxoLeaf, PROOF_FORMAT_VERSION};
use zutreexo_chain::{
    apply_and_prove, ApplyOptions, BlockProofBundle, BlockSummary, ChainAccumulators, OutPoint,
};

const DEPTH: u8 = 16;

fn outpoint(tx: u32, vout: u32) -> OutPoint {
    let mut txid = [0u8; 32];
    txid[..4].copy_from_slice(&tx.to_le_bytes());
    OutPoint { txid, vout }
}

fn leaf(tx: u32, vout: u32, height: u32) -> UtxoLeaf {
    let point = outpoint(tx, vout);
    UtxoLeaf {
        txid: point.txid,
        vout: point.vout,
        height,
        is_coinbase: false,
        value: 42_000 + u64::from(vout),
        script_pubkey: vec![0x76, 0xa9, 0x14],
    }
}

fn nullifier(n: u32) -> Value {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    bytes[31] = 0x01;
    Value::from_bytes(bytes)
}

/// A bundle with a spend, a create, and nullifiers in two pools — so the
/// encoding has something of every kind in it.
fn realistic_bundle() -> BlockProofBundle {
    let mut state = ChainAccumulators::new(DEPTH).unwrap();

    let mut first = BlockSummary {
        height: 0,
        transactions: 1,
        transparent_spends: Vec::new(),
        transparent_creates: vec![
            (outpoint(0, 0), leaf(0, 0, 0)),
            (outpoint(0, 1), leaf(0, 1, 0)),
        ],
        nullifiers: BTreeMap::new(),
        commitments: BTreeMap::new(),
    };
    first.nullifiers.insert(PoolId::Sapling, vec![nullifier(1)]);
    apply_and_prove(&mut state, &first, ApplyOptions::default()).unwrap();

    let mut second = BlockSummary {
        height: 1,
        transactions: 2,
        transparent_spends: vec![outpoint(0, 0)],
        transparent_creates: vec![(outpoint(1, 0), leaf(1, 0, 1))],
        nullifiers: BTreeMap::new(),
        commitments: BTreeMap::new(),
    };
    second
        .nullifiers
        .insert(PoolId::Sapling, vec![nullifier(2), nullifier(3)]);
    second
        .nullifiers
        .insert(PoolId::Orchard, vec![nullifier(4)]);

    let (_, bundle) = apply_and_prove(&mut state, &second, ApplyOptions::default()).unwrap();
    assert!(!bundle.spent.is_empty(), "the fixture proves nothing");
    assert_eq!(bundle.insertion_count(), 3);
    bundle
}

#[test]
fn a_bundle_round_trips() {
    let original = realistic_bundle();
    let decoded = BlockProofBundle::from_bytes(&original.to_bytes()).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.depth, DEPTH);
}

#[test]
fn an_empty_bundle_round_trips() {
    // A block with no spends and no nullifiers is common and is the shape most
    // likely to trip a decoder that assumes at least one of everything.
    let mut state = ChainAccumulators::new(DEPTH).unwrap();
    let summary = BlockSummary {
        height: 0,
        transactions: 1,
        transparent_spends: Vec::new(),
        transparent_creates: Vec::new(),
        nullifiers: BTreeMap::new(),
        commitments: BTreeMap::new(),
    };
    let (_, bundle) = apply_and_prove(&mut state, &summary, ApplyOptions::default()).unwrap();
    assert_eq!(
        BlockProofBundle::from_bytes(&bundle.to_bytes()).unwrap(),
        bundle
    );
}

#[test]
fn every_truncation_is_an_error_not_a_panic() {
    let bytes = realistic_bundle().to_bytes();
    for length in 0..bytes.len() {
        assert!(
            BlockProofBundle::from_bytes(&bytes[..length]).is_err(),
            "a {length}-byte prefix decoded as a whole bundle"
        );
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = realistic_bundle().to_bytes();
    bytes.push(0);
    assert!(
        BlockProofBundle::from_bytes(&bytes).is_err(),
        "trailing bytes accepted; the encoding is not canonical"
    );
}

#[test]
fn a_bit_flip_anywhere_is_an_error_or_a_different_bundle_but_never_a_panic() {
    let original = realistic_bundle();
    let bytes = original.to_bytes();

    // Every byte, one bit each — the decoder must be total over its input.
    for index in 0..bytes.len() {
        for bit in [0u8, 3, 7] {
            let mut corrupted = bytes.clone();
            corrupted[index] ^= 1 << bit;
            if let Ok(decoded) = BlockProofBundle::from_bytes(&corrupted) {
                // Decoding a corrupted bundle is allowed — the proofs inside
                // will not verify. What is not allowed is decoding to something
                // byte-identical to the original, which would mean the
                // encoding has slack a peer could use for malleability.
                assert_ne!(
                    decoded.to_bytes(),
                    bytes,
                    "flipping bit {bit} of byte {index} re-encoded identically"
                );
            }
        }
    }
}

#[test]
fn an_unsupported_format_version_is_refused() {
    let mut bytes = realistic_bundle().to_bytes();
    assert_eq!(bytes[0], PROOF_FORMAT_VERSION);
    bytes[0] = PROOF_FORMAT_VERSION.wrapping_add(1);
    assert!(BlockProofBundle::from_bytes(&bytes).is_err());
}

#[test]
fn an_invalid_depth_is_refused_rather_than_used() {
    // The depth drives the empty-subtree ladder the sparse paths decode
    // against (docs/design.md D28). A depth outside the legal range has no
    // ladder, and guessing one would silently produce wrong siblings.
    let bundle = realistic_bundle();
    let bytes = bundle.to_bytes();

    // Find the depth byte by re-encoding with a different depth and diffing,
    // rather than hard-coding an offset that would rot silently.
    let mut other = bundle.clone();
    other.depth = DEPTH + 1;
    let shifted = other.to_bytes();
    let at = bytes
        .iter()
        .zip(&shifted)
        .position(|(a, b)| a != b)
        .expect("changing the depth changed nothing in the encoding");

    let mut corrupted = bytes.clone();
    corrupted[at] = 0xFF; // beyond MAX_DEPTH
    assert!(
        BlockProofBundle::from_bytes(&corrupted).is_err(),
        "an out-of-range depth was accepted"
    );
}

#[test]
fn a_declared_spend_count_larger_than_the_input_is_rejected() {
    // The length-prefix attack: claim a huge count and send nothing. Must be
    // refused before `Vec::with_capacity` (docs/design.md D13).
    let bytes = realistic_bundle().to_bytes();
    let mut corrupted = bytes.clone();
    // Spent-leaf count is the u32 immediately after the version and height.
    corrupted[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(BlockProofBundle::from_bytes(&corrupted).is_err());
}

#[test]
fn a_repeated_pool_is_rejected() {
    let bundle = realistic_bundle();
    let mut bytes = bundle.to_bytes();

    // Rewrite the second pool's code to match the first. Locate both by
    // re-encoding with the pools swapped rather than by offset arithmetic.
    let codes: Vec<u8> = bundle.insertions.keys().map(|pool| pool.code()).collect();
    assert_eq!(codes.len(), 2, "fixture must span two pools");

    // The pool codes appear in the insertions section; find the later one and
    // overwrite it with the earlier.
    let second = bytes
        .iter()
        .rposition(|byte| *byte == codes[1])
        .expect("second pool code not found");
    bytes[second] = codes[0];

    // Either it is caught as a repeated pool, or the shifted parse fails some
    // other way. Both are errors; silently dropping one pool's proofs is not.
    match BlockProofBundle::from_bytes(&bytes) {
        Err(_) => {}
        Ok(decoded) => panic!(
            "a bundle repeating pool {:?} decoded, with {} pools",
            codes[0],
            decoded.insertions.len()
        ),
    }
}

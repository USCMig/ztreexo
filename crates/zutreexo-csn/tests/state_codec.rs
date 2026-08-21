//! A compact node's whole persistent state, through its encoder and back.
//!
//! # Why this file is not optional
//!
//! Two rules from this repo's own history meet here.
//!
//! `docs/design.md` D19: a `ZcashNodeHash` serialisation bug survived two
//! phases because nothing ever fed an encoder's output to its decoder. The
//! encoding was byte-symmetric and still wrong. The lesson recorded in
//! `PLAN.md` was that *a serialisation format nothing round-trips is not
//! tested, whatever the unit tests say*.
//!
//! D29: a length guard that checked only one direction let a declared count
//! reach `with_capacity` and abort the test runner on a 141 GB allocation. It
//! was found by a three-line bit-flip loop, and the conclusion was that every
//! decoder added from here gets a bit-flip and truncation sweep **when it is
//! written**, not at Phase 6.
//!
//! So: round trip, truncate, flip, and reject non-canonical orderings.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use zutreexo_accumulator::imt::{ImtState, MAX_DEPTH};
use zutreexo_accumulator::proof::ProofCodecError;
use zutreexo_accumulator::{CanonicalSerialize, PoolId, PROOF_FORMAT_VERSION};
use zutreexo_csn::CompactState;

const DEPTH: u8 = 40;

/// A state that is not the default: a tip, a non-trivial leaf counter, several
/// roots, and every pool at a different leaf count. A fixture that is all
/// zeroes cannot catch a field the encoder forgot.
fn populated() -> CompactState {
    let roots: Vec<[u8; 32]> = (1u8..=5)
        .map(|n| {
            let mut root = [0u8; 32];
            root[0] = n;
            root[31] = 0xAB;
            root
        })
        .collect();

    let mut nullifiers = std::collections::BTreeMap::new();
    for (index, pool) in PoolId::ALL.into_iter().enumerate() {
        let mut root = [0u8; 32];
        root[0] = 0xF0 | (index as u8);
        nullifiers.insert(
            pool,
            ImtState {
                root,
                leaf_count: 1 + (index as u64) * 977,
            },
        );
    }

    CompactState::from_roots(DEPTH, &roots, 1_234_567_890, &nullifiers, Some(3_428_143)).unwrap()
}

/// Field-by-field equality. `CompactState` deliberately has no `PartialEq` —
/// it holds a `UtxoRoots` wrapping an upstream type — so the comparison is
/// spelled out rather than derived, and spelling it out is also what makes a
/// forgotten field visible here.
fn assert_same(left: &CompactState, right: &CompactState) {
    assert_eq!(left.depth(), right.depth(), "depth");
    assert_eq!(left.tip(), right.tip(), "tip");
    assert_eq!(left.utxo_leaves(), right.utxo_leaves(), "utxo leaf counter");
    assert_eq!(left.utxo_roots(), right.utxo_roots(), "utxo roots");
    assert_eq!(
        left.nullifier_roots(),
        right.nullifier_roots(),
        "nullifier roots"
    );
    for pool in PoolId::ALL {
        assert_eq!(
            left.imt_state(pool).map(|s| s.leaf_count),
            right.imt_state(pool).map(|s| s.leaf_count),
            "{pool} leaf count"
        );
    }
}

#[test]
fn a_populated_state_round_trips() {
    let original = populated();
    let decoded = CompactState::from_bytes(&original.to_bytes()).unwrap();
    assert_same(&original, &decoded);

    // And the encoding is stable, which is what lets two nodes compare states
    // byte-for-byte rather than field-by-field.
    assert_eq!(decoded.to_bytes(), original.to_bytes());
}

#[test]
fn an_empty_state_round_trips() {
    // `tip: None` is a distinct state from height 0 and is the one a fresh node
    // starts in, so it gets its own case rather than being assumed.
    let original = CompactState::new(DEPTH).unwrap();
    assert_eq!(original.tip(), None);
    let decoded = CompactState::from_bytes(&original.to_bytes()).unwrap();
    assert_same(&original, &decoded);
    assert_eq!(decoded.tip(), None, "None came back as a height");
}

#[test]
fn genesis_is_distinguishable_from_nothing_applied() {
    // The bug a sentinel height would have introduced: `Some(0)` and `None`
    // encoding to the same bytes. A node that confused them would re-apply
    // genesis or skip it, and either way diverge on the very first block.
    let nothing = CompactState::new(DEPTH).unwrap();
    let genesis =
        CompactState::from_roots(DEPTH, &[], 0, &nothing.nullifier_states(), Some(0)).unwrap();

    assert_ne!(
        nothing.to_bytes(),
        genesis.to_bytes(),
        "tip None and tip Some(0) encode identically"
    );
    assert_eq!(
        CompactState::from_bytes(&genesis.to_bytes()).unwrap().tip(),
        Some(0)
    );
}

#[test]
fn the_state_is_small_enough_to_be_the_point() {
    // The whole thesis is that this replaces 32.7 GiB. If it ever stops being
    // trivially small, that is the headline result changing and it should fail
    // loudly rather than be discovered in a benchmark.
    let size = populated().to_bytes().len();
    assert!(
        size < 1024,
        "a compact node's entire state is {size} B, which is no longer 'a few hundred bytes'"
    );
    // Not suspiciously small either: five roots and four pools cannot fit in
    // less than 5*32 + 4*40 bytes, so a truncating encoder would trip here.
    assert!(size > 300, "only {size} B — is a field being dropped?");
}

#[test]
fn every_truncation_is_an_error_not_a_panic() {
    let bytes = populated().to_bytes();
    for length in 0..bytes.len() {
        assert!(
            CompactState::from_bytes(&bytes[..length]).is_err(),
            "a {length}-byte prefix decoded as a whole state"
        );
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = populated().to_bytes();
    bytes.push(0);
    assert!(CompactState::from_bytes(&bytes).is_err());
}

#[test]
fn a_bit_flip_anywhere_is_an_error_or_a_different_state_but_never_a_panic() {
    // The sweep that found D29. Every byte, every bit — the decoder must be
    // total over its input, and must never re-encode to the original, which
    // would mean the format has slack.
    let bytes = populated().to_bytes();
    for index in 0..bytes.len() {
        for bit in 0..8u8 {
            let mut corrupted = bytes.clone();
            corrupted[index] ^= 1 << bit;
            if let Ok(decoded) = CompactState::from_bytes(&corrupted) {
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
fn an_unsupported_version_is_refused() {
    let mut bytes = populated().to_bytes();
    assert_eq!(bytes[0], PROOF_FORMAT_VERSION);
    bytes[0] = PROOF_FORMAT_VERSION.wrapping_add(1);
    assert!(CompactState::from_bytes(&bytes).is_err());
}

#[test]
fn an_out_of_range_depth_is_refused() {
    // The depth selects the empty-subtree ladder every later proof decodes
    // against (D28), so a state loaded at a bogus depth would verify nothing
    // correctly. Byte 1 is the depth, immediately after the version.
    for bad in [0u8, MAX_DEPTH.saturating_add(1), 0xFF] {
        let mut bytes = populated().to_bytes();
        bytes[1] = bad;
        assert!(
            CompactState::from_bytes(&bytes).is_err(),
            "depth {bad} was accepted"
        );
    }
}

#[test]
fn an_over_declared_root_count_is_named_not_merely_rejected() {
    // D29's shape aimed at this decoder: claim many roots, send few.
    //
    // **This decoder is not exposed to D29's allocation abort**, because the
    // count is a single byte and `with_capacity` therefore tops out at 8 KiB.
    // An earlier version of this test asserted only `is_err()` and stayed green
    // with the bound removed — `reader.hash()` runs out of input a moment later
    // regardless — which made it worthless as a regression test and is exactly
    // the D24 failure mode.
    //
    // So it pins the *error variant*. That keeps the check load-bearing, and it
    // is the check that would become the real D29 guard if the count field were
    // ever widened past a byte.
    //
    // Layout is version, depth, tip flag, tip, leaf counter, then the count.
    let mut bytes = populated().to_bytes();
    let count_at = 1 + 1 + 1 + 4 + 8;
    bytes[count_at] = 0xFF;

    match CompactState::from_bytes(&bytes) {
        Err(ProofCodecError::DeclaredLengthExceedsInput {
            field, declared, ..
        }) => {
            assert_eq!(field, "compact state utxo roots");
            assert_eq!(declared, 255);
        }
        Err(other) => panic!("rejected, but not as an over-declared length: {other}"),
        Ok(_) => panic!("255 roots declared against a short buffer and it was accepted"),
    }
}

#[test]
fn pools_out_of_order_are_rejected() {
    // Canonicality: one state, one encoding. Two bridges reporting identical
    // state must produce identical bytes, or the byte-for-byte comparison the
    // harness is built on means nothing.
    let bytes = populated().to_bytes();
    let codes: Vec<u8> = PoolId::ALL.into_iter().map(|p| p.code()).collect();

    // The pool section is the tail: each entry is code + 32-byte root + 8-byte
    // count. Swap the first two entries' codes to break the ordering.
    let entry = 1 + 32 + 8;
    let tail = bytes.len() - PoolId::ALL.len() * entry;
    let mut swapped = bytes.clone();
    swapped[tail] = codes[1];
    swapped[tail + entry] = codes[0];

    assert!(
        CompactState::from_bytes(&swapped).is_err(),
        "pools decoded out of order; the encoding is not canonical"
    );
}

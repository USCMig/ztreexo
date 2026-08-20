//! The bridge's wire codec against hostile input.
//!
//! Everything here decodes bytes a client or a bridge sent, which makes it the
//! crate's untrusted-input surface. `docs/design.md` D24 is the standing lesson:
//! a check with no test is a check that may already be unreachable, and the
//! coverage gate is what found this file's first gap — the pool-order rejection
//! in `Roots::read_body` was written and never exercised.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use zutreexo_accumulator::{CanonicalSerialize, Hash, PoolId, PROOF_FORMAT_VERSION};
use zutreexo_bridge::wire::Roots;
use zutreexo_bridge::WIRE_VERSION;

fn hash(n: u8) -> Hash {
    [n; 32]
}

fn roots() -> Roots {
    Roots {
        height: 987_654,
        depth: 40,
        utxo: vec![hash(1), hash(2), hash(3)],
        nullifiers: vec![
            (PoolId::Sprout, hash(10)),
            (PoolId::Sapling, hash(11)),
            (PoolId::Orchard, hash(12)),
            (PoolId::Ironwood, hash(13)),
        ],
    }
}

#[test]
fn roots_round_trip() {
    let original = roots();
    assert_eq!(Roots::from_bytes(&original.to_bytes()).unwrap(), original);
}

#[test]
fn roots_with_no_utxo_leaves_round_trip() {
    // An empty accumulator has no roots at all, which is a real state at
    // genesis and an easy one for a length-prefixed decoder to mishandle.
    let mut empty = roots();
    empty.utxo.clear();
    empty.height = 0;
    assert_eq!(Roots::from_bytes(&empty.to_bytes()).unwrap(), empty);
}

#[test]
fn nullifier_roots_out_of_pool_order_are_rejected() {
    // The encoding has to be canonical: a wallet's whole defence against a
    // single dishonest bridge is fetching roots from several and comparing
    // them, and that comparison is worthless if two byte strings can describe
    // the same state.
    let mut swapped = roots();
    swapped.nullifiers.swap(0, 1);

    let bytes = swapped.to_bytes();
    assert!(
        Roots::from_bytes(&bytes).is_err(),
        "out-of-order pool roots decoded; the encoding is not canonical"
    );
}

#[test]
fn a_repeated_pool_is_rejected() {
    // `>=` in the ordering check, not `>`, so a duplicate is caught too — a
    // response naming Orchard twice would otherwise decode with whichever root
    // came last silently winning.
    let mut duplicated = roots();
    duplicated.nullifiers = vec![(PoolId::Orchard, hash(20)), (PoolId::Orchard, hash(21))];
    assert!(Roots::from_bytes(&duplicated.to_bytes()).is_err());
}

#[test]
fn every_truncation_of_roots_is_an_error_not_a_panic() {
    let bytes = roots().to_bytes();
    for length in 0..bytes.len() {
        assert!(
            Roots::from_bytes(&bytes[..length]).is_err(),
            "a {length}-byte prefix decoded as a complete Roots"
        );
    }
}

#[test]
fn trailing_bytes_after_roots_are_rejected() {
    let mut bytes = roots().to_bytes();
    bytes.push(0);
    assert!(Roots::from_bytes(&bytes).is_err());
}

#[test]
fn an_unknown_pool_code_in_roots_is_rejected() {
    let bytes = roots().to_bytes();
    // Walk the encoding to the first pool code rather than hard-coding an
    // offset, so this test does not quietly stop testing anything if a field
    // is added ahead of it.
    let utxo_count = bytes[1 + 4 + 1] as usize;
    let pool_section = 1 + 4 + 1 + 1 + utxo_count * 32 + 1;
    let mut corrupted = bytes.clone();
    corrupted[pool_section] = 0xEE;
    assert!(Roots::from_bytes(&corrupted).is_err());
}

#[test]
fn a_declared_root_count_larger_than_the_input_is_rejected() {
    // The classic length-prefix attack: claim 255 roots and send none. It must
    // fail without first allocating for 255.
    let mut bytes = roots().to_bytes();
    bytes[1 + 4 + 1] = 0xFF; // utxo root count
    assert!(Roots::from_bytes(&bytes).is_err());
}

#[test]
fn an_unknown_payload_version_is_refused() {
    // `Roots` is a *payload*, so its version byte is PROOF_FORMAT_VERSION, not
    // WIRE_VERSION — the request envelope carries that one. This test first
    // used WIRE_VERSION + 1, which is 2, which is exactly the current format
    // version: it wrote the *correct* byte and then asserted the decode would
    // fail. It went red, which is how the ambiguity surfaced. The two versions
    // are now documented at `WIRE_VERSION`.
    let mut bytes = roots().to_bytes();
    assert_eq!(
        bytes[0], PROOF_FORMAT_VERSION,
        "Roots should be tagged with the payload format version"
    );
    bytes[0] = PROOF_FORMAT_VERSION.wrapping_add(1);
    assert!(Roots::from_bytes(&bytes).is_err());
}

#[test]
fn the_envelope_and_payload_versions_are_separate_concerns() {
    // Guards the invariant the comment at `WIRE_VERSION` describes. If these
    // ever collapse into one number, the tests above stop meaning what they
    // say and a reader will assume a single protocol version governs both.
    assert_ne!(
        u16::from(WIRE_VERSION),
        u16::from(PROOF_FORMAT_VERSION),
        "if these coincide, say so deliberately rather than by accident"
    );
}

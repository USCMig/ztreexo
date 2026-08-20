//! Regression seeds for `validate_utxo_proof_header`.
//!
//! `rustreexo`'s proof decoder allocates from a length prefix before checking
//! it against the input — `docs/design.md` D13, reported upstream and still
//! open. `decode_utxo_proof` guards it, and this file pins the guard.
//!
//! # Why these exist
//!
//! The guard was wrong. It checked that the declared hash count was not *too
//! small* for the bytes present and never that it was too large, while a
//! comment claimed the opposite — that "a header claiming a billion hashes in
//! forty bytes is rejected before anything is allocated." A single bit flip in
//! `zutreexo-chain`'s `bundle_codec.rs` sweep set the count to 2^32+1 and
//! aborted the test process on a 141,733,920,801-byte allocation.
//!
//! CLAUDE.md's rule is that every divergence becomes a permanent seed. The
//! sweep that found it is randomised over bit positions; these are the specific
//! vectors, named, so a future refactor cannot quietly reopen the hole and pass
//! because the sweep happened not to hit that byte.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use zutreexo_accumulator::proof::decode_utxo_proof;
use zutreexo_accumulator::PROOF_FORMAT_VERSION;

/// A proof header: version, then `targets_len` and `hashes_len` as
/// little-endian `u64`s, then the payload.
fn header(targets_len: u64, hashes_len: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![PROOF_FORMAT_VERSION];
    out.extend_from_slice(&targets_len.to_le_bytes());
    out.extend_from_slice(&hashes_len.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

#[test]
fn the_seed_that_aborted_the_process() {
    // 2^32 + 1 hashes declared, times 33 bytes each, is 141,733,920,801 — the
    // allocation that killed the test runner.
    let bytes = header(0, (1u64 << 32) + 1, &[0u8; 8]);
    assert!(
        decode_utxo_proof(&bytes).is_err(),
        "the 2^32+1 hash count was accepted again"
    );
}

#[test]
fn a_hash_count_beyond_the_input_is_rejected_at_every_scale() {
    // Each entry costs at least one byte, so any count above the bytes
    // remaining is unsatisfiable regardless of what those bytes hold.
    for declared in [
        9u64,
        100,
        u64::from(u16::MAX),
        u64::from(u32::MAX),
        (1u64 << 32) + 1,
        u64::MAX / 33,
        u64::MAX,
    ] {
        let bytes = header(0, declared, &[0u8; 8]);
        assert!(
            decode_utxo_proof(&bytes).is_err(),
            "declared {declared} hashes against 8 bytes and it was accepted"
        );
    }
}

#[test]
fn a_target_count_beyond_the_input_is_rejected() {
    // The targets half had this check from the start; pinned so a refactor
    // that consolidates the two cannot drop it.
    for declared in [2u64, u64::from(u32::MAX), u64::MAX] {
        let bytes = header(declared, 0, &[0u8; 8]);
        assert!(
            decode_utxo_proof(&bytes).is_err(),
            "declared {declared} targets against 8 bytes and it was accepted"
        );
    }
}

#[test]
fn a_truncated_header_is_an_error_not_a_panic() {
    let bytes = header(1, 1, &[0u8; 33]);
    for length in 0..bytes.len() {
        let _ = decode_utxo_proof(&bytes[..length]);
    }
}

#[test]
fn an_empty_proof_still_decodes() {
    // The guard must not reject the legitimate case it sits in front of: an
    // insert-only block carries a proof with no targets and no hashes.
    let empty = zutreexo_accumulator::UtxoProof::default();
    let bytes = zutreexo_accumulator::proof::encode_utxo_proof(&empty);
    assert_eq!(
        decode_utxo_proof(&bytes).unwrap(),
        empty,
        "the empty proof no longer round-trips; the bound is too tight"
    );
}

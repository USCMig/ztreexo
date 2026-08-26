//! `NonMembershipResponse::from_bytes` — the sparse proof encoding (D28).
//!
//! The sparse path is the interesting part. A presence bitmap decides which
//! sibling hashes are on the wire and which are rebuilt from the pool's
//! empty-subtree ladder, so the decoder is doing arithmetic on attacker-chosen
//! lengths and bit patterns to decide how much to read.
//!
//! A lying bitmap cannot forge *acceptance* — that is argued and tested in
//! `sparse_proofs.rs`. What this asks is whether it can crash the decoder
//! before verification ever gets a chance to reject it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zutreexo_accumulator::proof::NonMembershipResponse;
use zutreexo_accumulator::CanonicalSerialize;

fuzz_target!(|data: &[u8]| {
    if let Ok(response) = NonMembershipResponse::from_bytes(data) {
        let re = response.to_bytes();
        let again =
            NonMembershipResponse::from_bytes(&re).expect("a response we just encoded must decode");
        assert_eq!(again, response, "sparse response round trip is not stable");
    }
});

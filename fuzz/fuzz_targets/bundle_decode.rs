//! `BlockProofBundle::from_bytes` against arbitrary bytes.
//!
//! This is the highest-value target in the set: a bundle is the one thing a
//! compact state node accepts from a party it does not control, so its decoder
//! is the whole untrusted-input surface of the protocol.
//!
//! `zutreexo-chain/tests/bundle_codec.rs` already sweeps truncations and single
//! bit flips of a *valid* bundle, and that sweep is what found D29 — a declared
//! hash count of 2^32+1 reaching `with_capacity` and aborting the process on a
//! 141 GB allocation. What it cannot do is reach shapes no valid bundle is near.
//!
//! # What counts as a failure
//!
//! A panic, an abort, an OOM, or a hang. Decoding garbage into *something* is
//! fine and expected — the proofs inside will not verify. What is not fine is
//! the decoder deciding how much to allocate from a number the input chose.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zutreexo_accumulator::CanonicalSerialize;
use zutreexo_chain::BlockProofBundle;

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = BlockProofBundle::from_bytes(data) {
        // Re-encoding must be stable. If it is not, two byte strings decode to
        // the same bundle, and the "byte-identical roots" comparison the whole
        // harness rests on would be comparing things that are not canonical.
        let re = bundle.to_bytes();
        let again = BlockProofBundle::from_bytes(&re)
            .expect("a bundle we just encoded must decode again");
        assert_eq!(
            again.to_bytes(),
            re,
            "re-encoding is not a fixed point; the format has slack"
        );
    }
});

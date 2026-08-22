//! `CompactState::from_bytes` — a compact node's entire persistent state.
//!
//! New in Phase 5b, and small enough that the interesting failures are in the
//! length-prefixed sections rather than in sheer size: the transparent root
//! count and the per-pool table. Its unit tests already sweep bit flips of a
//! valid state; this reaches shapes no valid state is near.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zutreexo_accumulator::CanonicalSerialize;
use zutreexo_csn::CompactState;

fuzz_target!(|data: &[u8]| {
    if let Ok(state) = CompactState::from_bytes(data) {
        let re = state.to_bytes();
        let again = CompactState::from_bytes(&re).expect("a state we just encoded must decode");
        assert_eq!(again.to_bytes(), re, "compact state re-encoding is not stable");
    }
});

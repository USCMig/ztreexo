//! `decode_utxo_proof` — where D29 lived, and D13 still lives upstream.
//!
//! `rustreexo`'s proof decoder allocates from a length prefix before checking
//! it against the input (`docs/design.md` D13, reported upstream and still
//! open). `decode_utxo_proof` is the guard in front of it, and that guard was
//! itself wrong once: it checked only that the declared count was not too
//! *small* for the bytes present, while its comment claimed the opposite.
//!
//! So this target is fuzzing a wrapper whose entire job is to make an upstream
//! allocation bug unreachable. A crash here is either a hole in the guard or a
//! path into `rustreexo` the guard does not cover — both worth knowing, and the
//! second is worth reporting upstream.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zutreexo_accumulator::proof::{decode_utxo_proof, encode_utxo_proof};

fuzz_target!(|data: &[u8]| {
    if let Ok(proof) = decode_utxo_proof(data) {
        let re = encode_utxo_proof(&proof);
        let again = decode_utxo_proof(&re).expect("a proof we just encoded must decode again");
        assert_eq!(encode_utxo_proof(&again), re, "proof re-encoding is not stable");
    }
});

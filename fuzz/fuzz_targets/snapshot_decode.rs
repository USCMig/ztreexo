//! The Phase 3 on-disk snapshot format, **with the checksum resealed**.
//!
//! # Why the reseal is the whole point of this target
//!
//! `docs/design.md` D24: `load` verifies magic and a BLAKE2b checksum before it
//! calls `decode`, so the checksum stands in front of *every* structural check
//! in the parser. A fuzzer that mutates a snapshot and calls `load` bounces off
//! `ChecksumMismatch` on essentially every iteration and reaches none of the
//! code it is aiming at — then reports a clean 72 hours having tested nothing.
//!
//! This is not hypothetical. D24 records three Phase 3 tests that passed
//! exactly that way: they asserted `is_err()`, got `ChecksumMismatch`, and the
//! named arms they were written to exercise never ran once. The coverage floor
//! caught it, not the suite. `PLAN.md` carried the warning forward explicitly.
//!
//! So this target rebuilds a valid checksum over each mutated payload and calls
//! [`load_bytes`], which performs the identical magic, checksum and version
//! checks `load` does. The mutation is applied to the *payload*; the framing is
//! made consistent afterwards.
//!
//! # Proving the reseal works
//!
//! A reseal that silently failed would leave this target as useless as the
//! version it replaces, and it would look identical from outside — a clean run.
//! `fuzz/README.md` records the check: run with `ZUTREEXO_FUZZ_NO_RESEAL=1` and
//! the corpus stops growing almost immediately, because every input dies at the
//! checksum. That difference is the evidence the target reaches the parser.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zutreexo_accumulator::hash::store_checksum;
use zutreexo_chain::{load_bytes, MAGIC};

fuzz_target!(|data: &[u8]| {
    // A payload the framing will accept: magic, then whatever the fuzzer chose.
    // Prefixing the magic rather than hoping the fuzzer discovers eight exact
    // bytes is the difference between reaching `decode` in seconds and never.
    let mut payload = Vec::with_capacity(MAGIC.len() + data.len());
    payload.extend_from_slice(MAGIC);
    payload.extend_from_slice(data);

    let mut framed = payload.clone();
    if std::env::var_os("ZUTREEXO_FUZZ_NO_RESEAL").is_some() {
        // The control. Everything dies at the checksum, which is what makes the
        // resealed path demonstrably different rather than merely intended.
        framed.extend_from_slice(&[0u8; 32]);
    } else {
        framed.extend_from_slice(&store_checksum(&payload));
    }

    // Must not panic, abort, or allocate from a number the input chose.
    let _ = load_bytes(&framed);
});

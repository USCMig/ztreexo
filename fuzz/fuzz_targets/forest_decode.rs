//! `UtxoForest::from_bytes` — upstream `MemForest`, not our code.
//!
//! Included deliberately. The recursion is `rustreexo`'s, driven by a node
//! count the input chooses, and our own `ZcashNodeHash::read` sits inside it —
//! which is where D19 hid for two phases: a byte-symmetric encoding that lost
//! the variant, so an `Empty` node came back as `Some([0; 32])` and sent the
//! reader hunting for children that were never written.
//!
//! We are pinned to a fork (D25), so a crash here is something we can fix
//! rather than only report. It is also the target most likely to find a stack
//! overflow, since the format is recursive and nothing bounds the depth.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zutreexo_accumulator::UtxoForest;

fuzz_target!(|data: &[u8]| {
    if let Ok(forest) = UtxoForest::from_bytes(data) {
        // Roots must be computable on anything that decoded. A forest that
        // deserialises but panics on use is not meaningfully "decoded".
        let _ = forest.roots();
        let _ = forest.leaves();
    }
});

//! Test oracles, fixtures, and deterministic vectors for zutreexo.
//!
//! CLAUDE.md Phase 2 specifies two oracles, because they catch different bug
//! classes and neither alone is sufficient:
//!
//! 1. [`naive`] and [`state`] — deliberately dumb models that share zero code
//!    with `zutreexo-accumulator` and `zutreexo-chain`. They catch accumulator
//!    bugs: a dropped nullifier, a wrong leaf index, an incremental root
//!    drifting from a cold rebuild.
//! 2. [`checkpoints`] — counts as `zebrad` itself reported them. Catches
//!    *parsing* bugs, where both models agree because both were fed the same
//!    garbage.
//!
//! [`harness`] drives a replay against both, in three comparison tiers, and
//! [`vectors`] pins roots into the repo so a refactor cannot silently move
//! them.
//!
//! # The independence rule
//!
//! [`naive`] and [`state`] must not reference the crates they check. That is
//! not something the compiler can enforce — they sit in the same crate as
//! [`harness`], which necessarily does reference them — so `tests/independence.rs`
//! reads those two files as text and fails if either mentions the
//! implementation. Deleting that test does not relax the rule; it removes the
//! only thing keeping it true.

pub mod checkpoints;
pub mod harness;
pub mod measure;
pub mod naive;
pub mod reorg;
pub mod source;
pub mod state;
pub mod vectors;

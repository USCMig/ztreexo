//! Test oracles, fixtures, and deterministic vectors for zutreexo.
//!
//! CLAUDE.md Phase 2 specifies two oracles, because they catch different bug
//! classes and neither alone is sufficient:
//!
//! 1. [`naive`] — a deliberately dumb model that shares zero code with
//!    `zutreexo-accumulator`. Catches accumulator bugs.
//! 2. The validator — Zebra's `z_gettreestate`. Catches *parsing* bugs, where
//!    both models agree because both were fed the same garbage. Wired up in
//!    Phase 2, once there is a block replay to feed it.
//!
//! Phase 1 uses the first oracle alone, plus [`vectors`]: pinned roots checked
//! into the repo so a refactor cannot silently move them.

pub mod naive;
pub mod vectors;

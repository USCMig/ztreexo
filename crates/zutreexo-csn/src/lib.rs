//! Compact state node.
//!
//! **Phase 5 — not yet implemented.** Scaffolding only.
//!
//! A validating node that holds
//! [`UtxoRoots`](zutreexo_accumulator::UtxoRoots) and one
//! [`ImtState`](zutreexo_accumulator::ImtState) per pool — a few kilobytes —
//! plus a pollard cache, instead of a full transparent UTXO set and full
//! nullifier database.
//!
//! Phase 5 runs this behind a shadow-mode feature flag against a normal Zebra
//! node: both validate every block, results are compared, and any disagreement
//! is a hard failure and a loud log line. The accumulator path never gates
//! consensus during that phase.
//!
//! The measurement axes are chosen deliberately (CLAUDE.md §2.2, Phase 5).
//! Wall-clock wallet sync is *not* the headline: it is dominated by trial
//! decryption, which no accumulator changes. The headline is nullifier-check
//! cost as a function of gap length — linear scan today versus an `O(log n)`
//! non-membership proof independent of chain length — and the honest cost side
//! is proof bandwidth.

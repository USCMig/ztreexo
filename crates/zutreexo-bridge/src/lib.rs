//! Proof-serving bridge node.
//!
//! **Phase 4 — not yet implemented.** Scaffolding only.
//!
//! The bridge holds the *full* Utreexo forest and the full per-pool indexed
//! Merkle trees alongside a Zebra node, and serves proofs to peers that hold
//! only roots. It is the component that makes the whole design usable without
//! a consensus change: proofs travel out-of-band rather than in transactions,
//! so nothing about block validity changes.
//!
//! Planned service surface (CLAUDE.md Phase 4):
//!
//! * `GetUtxoInclusionProofs(outpoints) -> proofs`
//! * `GetNullifierNonMembershipProof(pool, nullifier) -> proof`
//! * `GetBlockProofBundle(height) -> BlockProofBundle`, batched for nodes
//!   doing initial block download
//! * `GetAccumulatorRoots(height) -> roots`
//!
//! Two constraints already known from Phase 1:
//!
//! * [`UtxoForest`](zutreexo_accumulator::UtxoForest) is not `Send` —
//!   `rustreexo` builds its forest from `Rc`. A threaded server has to own the
//!   forest on one thread and pass proofs across, not share the structure.
//! * Asking for a *specific* nullifier's non-membership proof is a metadata
//!   leak, and the privacy review in Phase 6 gates this crate's query API.
//!   Design it so that restricting wallets to nullifiers they are about to
//!   publish anyway remains possible.
//!
//! Integration target is Zaino rather than a `lightwalletd` fork.

//! Chain semantics over the zutreexo accumulators.
//!
//! **Phase 2 — not yet implemented.** This crate is scaffolding: the workspace
//! layout in CLAUDE.md §3 is fixed up front so later phases have somewhere to
//! land, but the logic below is deliberately absent until Phase 1's definition
//! of done passes.
//!
//! What lands here:
//!
//! * `pool.rs` — per-pool chain state. [`PoolId`] itself already lives in
//!   `zutreexo-accumulator`, because the hash domain separators are
//!   pool-specific and domain separation is a Phase 1 concern. It is
//!   re-exported below so chain code has one obvious import.
//! * `block_apply.rs` — the deterministic state transition function. The order
//!   of operations is specified in CLAUDE.md Phase 2 and is not negotiable:
//!   transparent inputs verified and deleted, then transparent outputs
//!   inserted, then per-pool nullifiers checked for non-membership and
//!   inserted, then note commitments appended, then a `StateDelta` emitted
//!   carrying every preimage needed to undo the block.
//! * `rollback.rs` — reorg handling. Utreexo deletion is not naturally
//!   invertible, so undo requires the deleted leaves *and* their positions,
//!   persisted in the `StateDelta`. This is the least-tested area of
//!   accumulator work generally and the invariant is total: apply, undo,
//!   re-apply a divergent branch must give byte-identical roots to a cold
//!   replay.
//!
//! Nothing in this crate may change which blocks a node accepts. Phases 0–5 are
//! consensus-neutral by construction: proofs arrive out-of-band from bridge
//! nodes rather than embedded in transactions (CLAUDE.md §1, §5 rule 1).

pub use zutreexo_accumulator::PoolId;

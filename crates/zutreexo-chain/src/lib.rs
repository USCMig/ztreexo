//! Chain semantics over the zutreexo accumulators.
//!
//! **Phase 2, in progress.** Stage 2a — block ingestion, state, and the
//! transition function — is implemented. Rollback (`rollback.rs`) and the
//! reorg fuzzer are stage 2c and are not here yet.
//!
//! # What this crate does
//!
//! [`extract::summarize_block`] turns a `zebra-chain` block into the per-pool
//! nullifiers, transparent inputs and outputs, and commitment counts that a
//! state transition needs. [`block_apply::apply_block`] then folds that
//! summary into [`pool::ChainAccumulators`] in the exact order CLAUDE.md
//! Phase 2 specifies, returning a [`block_apply::StateDelta`] carrying
//! everything needed to undo it.
//!
//! # Two properties worth knowing before using it
//!
//! **The shielded side replays from anywhere; the transparent side does not.**
//! Inserting a nullifier needs nothing but the nullifier, so a replay over any
//! window produces exact nullifier roots. Deleting a transparent leaf needs the
//! spent output's full contents — value, script, height, coinbase flag — which
//! only a genesis-forward replay will have observed. Replaying a window
//! therefore needs [`block_apply::ApplyOptions::window`], and its transparent
//! roots are not comparable to a full node's.
//!
//! **Nothing here changes what blocks a node accepts.** Phases 0–5 are
//! consensus-neutral by construction: proofs travel out-of-band from bridge
//! nodes rather than inside transactions (CLAUDE.md §1, §5 rule 1).

pub mod block_apply;
pub mod extract;
pub mod pool;

pub use block_apply::{apply_block, ApplyError, ApplyOptions, ApplyOutcome, StateDelta};
pub use extract::{summarize_block, BlockSummary, ExtractError, OutPoint};
pub use pool::{ChainAccumulators, StateCounts};
pub use zutreexo_accumulator::PoolId;

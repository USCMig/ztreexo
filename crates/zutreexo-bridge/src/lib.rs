//! Proof-serving bridge node: holds the full accumulator state and answers
//! membership and non-membership queries.
//!
//! **Phase 4b.** This is the component that makes the design usable *without a
//! consensus change*: proofs travel out-of-band from a bridge rather than
//! inside transactions (CLAUDE.md §1, §5 rule 1).
//!
//! # What a bridge is
//!
//! A [`Bridge`] wraps the full [`ChainAccumulators`] — the forest, every
//! nullifier tree, and the outpoint index — and serves the pieces a
//! roots-only node needs. It is the party that pays the storage cost so its
//! clients do not: 32.7 GiB at mainnet tip against a few hundred bytes
//! (`docs/benchmarks.md`).
//!
//! # Methods
//!
//! * [`Request::BlockProofBundle`] — everything needed to apply one block.
//! * [`Request::NullifierNonMembership`] — proof that one nullifier is unspent.
//! * [`Request::AccumulatorRoots`] — the roots a client anchors against.
//!
//! CLAUDE.md also lists `GetUtxoInclusionProofs(outpoints)`. It is deliberately
//! absent: every caller identified so far wants the inclusion proofs *for a
//! block*, which the bundle already batches, and Phase 4a measured that
//! batching at an 85.4% saving over proving inputs one at a time. Adding a
//! per-outpoint method would invite exactly the un-batched access pattern the
//! measurement says to avoid, and it is a denial-of-service lever besides
//! (Phase 6). It can be added when something needs it.
//!
//! # What a bridge is not trusted for
//!
//! Nothing it serves can make a compact node accept a wrong state transition —
//! see [`zutreexo_csn::CompactState::apply_bundle`]. It can refuse service, and
//! it learns which blocks and which nullifiers a client asks about. That second
//! one is a real metadata leak and is the Phase 6 privacy question; asking for
//! a *specific* nullifier's proof tells the bridge which note is about to be
//! spent.

pub mod server;
pub mod wire;

use std::collections::BTreeMap;

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::proof::NonMembershipResponse;
use zutreexo_accumulator::{Hash, PoolId};
use zutreexo_chain::{
    apply_and_prove, ApplyOptions, BlockProofBundle, BlockSummary, BundleError, ChainAccumulators,
};

pub use wire::{Request, Roots, WIRE_VERSION};

/// The full accumulator state, plus the bundles it has produced.
///
/// # Why bundles are retained
///
/// A bundle's inclusion proof is only valid against the accumulator as it stood
/// *before* its block. Once later blocks are applied the forest has moved on
/// and the proof cannot be regenerated — Utreexo deletion is not invertible
/// (`docs/design.md` D18). So a bridge that wants to serve height `H` after
/// reaching `H+1` has to have kept the bundle.
///
/// Retention is bounded by `keep`, because keeping all of them is keeping the
/// chain. A client asking for a height that has fallen out gets
/// [`status::NO_SUCH_HEIGHT`](wire::status::NO_SUCH_HEIGHT) and must sync from
/// a bridge with a longer window or from a snapshot. **This is the honest limit
/// on Phase 4's definition of done**: a compact node can complete IBD from a
/// bridge only if the bridge retained every bundle it will be asked for, which
/// for a genesis-forward sync means retaining all of them.
pub struct Bridge {
    state: ChainAccumulators,
    bundles: BTreeMap<u32, BlockProofBundle>,
    keep: usize,
}

impl Bridge {
    /// Wraps existing accumulator state, retaining `keep` recent bundles.
    pub fn new(state: ChainAccumulators, keep: usize) -> Bridge {
        Bridge {
            state,
            bundles: BTreeMap::new(),
            keep,
        }
    }

    /// The accumulators, for callers that need to inspect or persist them.
    pub fn state(&self) -> &ChainAccumulators {
        &self.state
    }

    /// Applies a block and retains the bundle it produced.
    pub fn apply(&mut self, summary: &BlockSummary) -> Result<(), BundleError> {
        let (_, bundle) = apply_and_prove(&mut self.state, summary, ApplyOptions::default())?;
        self.bundles.insert(summary.height, bundle);
        while self.bundles.len() > self.keep {
            // `BTreeMap` so this is the oldest, deterministically. A `HashMap`
            // would evict arbitrarily and two bridges fed the same chain would
            // answer differently (CLAUDE.md §5 rule 5).
            let oldest = match self.bundles.keys().next() {
                Some(height) => *height,
                None => break,
            };
            self.bundles.remove(&oldest);
        }
        Ok(())
    }

    /// The bundle for one height, if still retained.
    pub fn bundle(&self, height: u32) -> Option<&BlockProofBundle> {
        self.bundles.get(&height)
    }

    /// Height of the last block applied.
    pub fn tip(&self) -> Option<u32> {
        self.state.tip()
    }

    /// The roots a client anchors against.
    pub fn roots(&self) -> Roots {
        Roots {
            height: self.state.tip().unwrap_or(0),
            depth: self.state.depth(),
            utxo: self.state.utxo_roots(),
            nullifiers: self.state.nullifier_roots().into_iter().collect(),
        }
    }

    /// Proves a nullifier absent from its pool's tree at the current root.
    ///
    /// `Ok(None)` means the nullifier *is* present — already spent. That is a
    /// truthful answer rather than a failure, and for a wallet asking about its
    /// own note it is the answer it came for.
    pub fn prove_unspent(
        &self,
        pool: PoolId,
        nullifier: Value,
    ) -> Result<Option<NonMembershipResponse>, BridgeError> {
        let tree = self
            .state
            .tree(pool)
            .ok_or(BridgeError::MissingPool { pool })?;
        if tree.contains(&nullifier) {
            return Ok(None);
        }
        let proof = tree
            .prove_non_membership(nullifier)
            .map_err(|error| BridgeError::Prove {
                reason: error.to_string(),
            })?;
        Ok(Some(NonMembershipResponse {
            pool,
            depth: self.state.depth(),
            height: self.state.tip().unwrap_or(0),
            proof,
        }))
    }

    /// Every nullifier root, keyed by pool.
    pub fn nullifier_roots(&self) -> BTreeMap<PoolId, Hash> {
        self.state.nullifier_roots()
    }
}

/// Why a bridge could not answer.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum BridgeError {
    /// A pool has no tree, which should be impossible after construction.
    #[error("no tree for pool {pool}")]
    MissingPool {
        /// The pool with no tree.
        pool: PoolId,
    },

    /// The accumulator declined to produce a proof.
    #[error("could not prove: {reason}")]
    Prove {
        /// What the accumulator said.
        reason: String,
    },
}

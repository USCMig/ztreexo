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
//! * [`Request::PrefixCohort`] — every nullifier in one prefix bucket of one
//!   snapshot epoch, which is how a wallet settles spend-status **without
//!   naming the note**.
//! * [`Request::EpochManifest`] — which snapshots exist and how wide a bucket
//!   must be.
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
//!
//! [`Request::PrefixCohort`] is a partial answer to that. It replaces "which
//! note" with "which of ~12,298 notes", which `docs/design.md` D40 measured as
//! per-*note* anonymity of 12,302 and per-*wallet* anonymity of **1** — a
//! wallet's set of buckets fingerprints it even though no single bucket does.
//! D41 gives the condition under which spreading the queries across unlinkable
//! sessions recovers it. Neither the fingerprint nor the spreading rule is
//! enforced here: this crate serves the query, and how a client spaces its
//! queries is the client's problem.
//!
//! # Read this before reaching for the cohort as a privacy mechanism
//!
//! **It is not the best available answer for a light client, and D44 says so
//! with numbers.** `valargroup/spendability-pir` partitions the nullifier set
//! the same way and hides the bucket index with SimplePIR instead of with crowd
//! size, so D40's fingerprint does not arise at all — for 1.78x the bandwidth,
//! in deployed code.
//!
//! What this crate offers that PIR does not, and the only grounds on which to
//! choose it:
//!
//! * **Full history.** Their coverage is a ~289-day sliding window. This serves
//!   the set from genesis.
//! * **A proof, not an answer.** A cohort folds to a root the client can
//!   cross-check across bridges ([`Roots`]). A PIR response is the server's
//!   word.
//! * **Non-membership a third party can check**, which is what a validator
//!   needs and a hash table cannot give.
//!
//! Choosing this for the light-client spend-status query, on the strength of
//! the anonymity figure alone, would be the wrong call.

pub mod epoch;
pub mod limits;
pub mod server;
pub mod wire;

use std::collections::BTreeMap;

use zutreexo_accumulator::cohort::PrefixRange;
use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::proof::NonMembershipResponse;
use zutreexo_accumulator::sorted::SortedCohort;
use zutreexo_accumulator::{Hash, PoolId};
use zutreexo_chain::{
    apply_and_prove, ApplyOptions, BlockProofBundle, BlockSummary, BundleError, ChainAccumulators,
};

use crate::epoch::{EpochPolicy, EpochStore};

pub use wire::{EpochManifest, Request, Roots, WIRE_VERSION};

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
    /// Sorted snapshots, which are what cohort queries are answered from. The
    /// live IMT cannot answer them: its leaves are in insertion order, so a
    /// value-range is not contiguous there. See [`epoch`].
    epochs: EpochStore,
}

impl Bridge {
    /// Wraps existing accumulator state, retaining `keep` recent bundles.
    ///
    /// Cohort service is on, under [`EpochPolicy::default`]. A bridge that only
    /// serves bundles should use [`Bridge::with_epoch_policy`] and
    /// [`EpochPolicy::disabled`] rather than pay for snapshots it never serves.
    pub fn new(state: ChainAccumulators, keep: usize) -> Bridge {
        Bridge::with_epoch_policy(state, keep, EpochPolicy::default())
    }

    /// The same, with the snapshot policy chosen explicitly.
    pub fn with_epoch_policy(state: ChainAccumulators, keep: usize, policy: EpochPolicy) -> Bridge {
        Bridge {
            state,
            bundles: BTreeMap::new(),
            keep,
            epochs: EpochStore::new(policy),
        }
    }

    /// The accumulators, for callers that need to inspect or persist them.
    pub fn state(&self) -> &ChainAccumulators {
        &self.state
    }

    /// Applies a block, retains the bundle, and snapshots on an epoch boundary.
    ///
    /// The snapshot happens *after* the apply, so an epoch at height `H`
    /// describes the state including block `H` — which is what a client
    /// assumes when it scans blocks `H+1..tip` for the delta.
    pub fn apply(&mut self, summary: &BlockSummary) -> Result<(), BridgeError> {
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
        if self.epochs.due(summary.height) {
            self.epochs
                .snapshot(&self.state, summary.height)
                .map_err(|error| BridgeError::Snapshot {
                    reason: error.to_string(),
                })?;
        }
        Ok(())
    }

    /// The snapshot store, for callers that want to inspect retention.
    pub fn epochs(&self) -> &EpochStore {
        &self.epochs
    }

    /// Forces a snapshot at the current tip, outside the epoch schedule.
    ///
    /// For a bridge brought up from a restored state, which would otherwise
    /// serve nothing until it happened to reach a boundary.
    pub fn snapshot_now(&mut self) -> Result<usize, BridgeError> {
        let height = self.state.tip().unwrap_or(0);
        self.epochs
            .snapshot(&self.state, height)
            .map_err(|error| BridgeError::Snapshot {
                reason: error.to_string(),
            })
    }

    /// What snapshots this bridge holds, and the prefix floor for each.
    pub fn manifest(&self) -> EpochManifest {
        EpochManifest {
            min_anonymity: self.epochs.policy().min_anonymity,
            epochs: self.epochs.entries(),
        }
    }

    /// Answers a prefix-bucket query against one snapshot epoch.
    ///
    /// The bridge never learns which value in the returned run the client
    /// cared about — it is not told, and it cannot infer it from a run it
    /// returned whole.
    ///
    /// # Errors
    ///
    /// [`BridgeError::NoSuchEpoch`] for a snapshot that has been evicted or was
    /// never taken, and [`BridgeError::PrefixTooNarrow`] for a bucket whose
    /// expected occupancy is under the policy's anonymity floor. The second is
    /// a refusal rather than a silent widening: see
    /// [`status::PREFIX_TOO_NARROW`](wire::status::PREFIX_TOO_NARROW).
    pub fn prove_cohort(
        &self,
        pool: PoolId,
        epoch: u32,
        range: PrefixRange,
    ) -> Result<SortedCohort, BridgeError> {
        let snapshot = self
            .epochs
            .get(pool, epoch)
            .ok_or(BridgeError::NoSuchEpoch { pool, epoch })?;
        let max_bits =
            epoch::max_bits_for(snapshot.leaf_count(), self.epochs.policy().min_anonymity);
        if max_bits == 0 || range.bits() > max_bits {
            return Err(BridgeError::PrefixTooNarrow {
                asked: range.bits(),
                max: max_bits,
            });
        }
        snapshot
            .prove_prefix_cohort(range)
            .map_err(|error| BridgeError::Prove {
                reason: error.to_string(),
            })
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

    /// A block could not be applied or its bundle produced.
    #[error(transparent)]
    Bundle(#[from] BundleError),

    /// A snapshot could not be built at an epoch boundary.
    #[error("could not snapshot: {reason}")]
    Snapshot {
        /// What the sorted-tree builder said.
        reason: String,
    },

    /// No snapshot is retained for that pool at that height.
    #[error("no snapshot for pool {pool} at height {epoch}")]
    NoSuchEpoch {
        /// Pool asked about.
        pool: PoolId,
        /// Epoch height asked about.
        epoch: u32,
    },

    /// The bucket asked for is narrower than the anonymity floor allows.
    #[error("prefix of {asked} bits is narrower than the floor of {max}")]
    PrefixTooNarrow {
        /// Width the client asked for.
        asked: u8,
        /// Widest width the bridge will answer. Zero means none will do.
        max: u8,
    },
}

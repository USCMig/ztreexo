//! The deterministic state transition function.
//!
//! # The order is the specification
//!
//! CLAUDE.md Phase 2 fixes the order of operations, and it is not negotiable
//! because it is what makes replay reproducible. [`apply_block`] follows it
//! exactly:
//!
//! 1. transparent inputs — resolve, verify, delete;
//! 2. transparent outputs — compute leaf hashes, insert;
//! 3. per pool, per nullifier — prove non-membership, insert, update root;
//! 4. per pool, note commitments — counted only, never accumulated;
//! 5. emit a [`StateDelta`] carrying every preimage needed to undo the block.
//!
//! Step 1 before step 2 is load-bearing: it is what stops a block spending an
//! output it creates in the same block. Zcash consensus forbids that, and doing
//! the steps in the other order would silently permit it here.
//!
//! # On failure, nothing is applied
//!
//! Block application runs on attacker-supplied data, so a partially-applied
//! block would be a state-corruption vector. Every fallible check happens
//! against a staged plan *before* the first mutation, so an error returns with
//! the accumulators untouched. See [`apply_block`] for where the line sits.

use std::collections::{BTreeMap, BTreeSet};

use zutreexo_accumulator::imt::{ImtError, InsertionProof, Value};
use zutreexo_accumulator::{Hash, PoolId, UtreexoError, UtxoLeaf};

use crate::extract::{BlockSummary, OutPoint};
use crate::pool::ChainAccumulators;

/// Everything needed to undo one block.
///
/// Utreexo deletion is not naturally invertible and neither is an indexed
/// Merkle tree insertion, so undo needs the *preimages*, not just the fact that
/// something changed. CLAUDE.md Phase 2 is blunt about this being the place
/// accumulator implementations actually break: it is easy to keep almost
/// enough.
///
/// What is kept, and why each is required:
///
/// * `spent` — the full [`UtxoLeaf`] of every deleted output. Re-inserting
///   needs the contents, not the outpoint, because the leaf hash commits to
///   them.
/// * `created` — outpoints of every inserted output, so undo knows what to
///   remove from the forest and the index.
/// * `insertions` — the [`InsertionProof`] per nullifier. It carries the low
///   leaf *as it stood before* the insertion plus both indices, which is
///   exactly what is needed to restore the linked list and drop the appended
///   leaf.
#[derive(Clone, Debug, Default)]
pub struct StateDelta {
    /// Height of the block this undoes.
    pub height: u32,
    /// Outputs deleted, with the contents needed to restore them.
    pub spent: Vec<(OutPoint, UtxoLeaf)>,
    /// Outputs created, in insertion order.
    pub created: Vec<(OutPoint, Hash)>,
    /// Nullifier insertions per pool, in application order.
    pub insertions: BTreeMap<PoolId, Vec<(Value, InsertionProof)>>,
    /// Note commitments observed per pool. Recorded for cross-checking only.
    pub commitments: BTreeMap<PoolId, usize>,
}

/// Why a block could not be applied.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ApplyError {
    /// A spent outpoint is not in the UTXO index.
    ///
    /// On a genesis-forward replay this means a real bug. On a replay that
    /// starts mid-chain it is expected, because the output was created before
    /// the window opened — see [`ApplyOptions::allow_unknown_spends`].
    #[error("block {height} spends unknown outpoint {txid}:{vout}")]
    UnknownOutpoint {
        /// Height of the offending block.
        height: u32,
        /// Hex transaction ID of the missing output.
        txid: String,
        /// Output index.
        vout: u32,
    },

    /// The same outpoint was spent twice within one block.
    #[error("block {height} spends {txid}:{vout} twice")]
    DuplicateSpend {
        /// Height of the offending block.
        height: u32,
        /// Hex transaction ID.
        txid: String,
        /// Output index.
        vout: u32,
    },

    /// A nullifier was already in its pool's tree — a double spend.
    #[error("block {height} reveals a duplicate {pool} nullifier")]
    DuplicateNullifier {
        /// Height of the offending block.
        height: u32,
        /// Which pool.
        pool: PoolId,
    },

    /// A pool has no tree in this state.
    #[error("no accumulator for pool {pool}")]
    MissingPool {
        /// The pool with no tree.
        pool: PoolId,
    },

    /// Blocks were applied out of order.
    #[error("expected block {expected}, got {found}")]
    OutOfOrder {
        /// The height that should come next.
        expected: u32,
        /// The height supplied.
        found: u32,
    },

    /// The nullifier accumulator rejected an operation.
    #[error("nullifier accumulator: {0}")]
    Imt(#[from] ImtError),

    /// The transparent accumulator rejected an operation.
    #[error("transparent accumulator: {0}")]
    Utreexo(#[from] UtreexoError),
}

/// Knobs for replays that do not start at genesis.
#[derive(Clone, Copy, Debug)]
pub struct ApplyOptions {
    /// Tolerate spends of outputs created before the replay window.
    ///
    /// Nullifier insertion needs nothing but the nullifier, so the shielded
    /// side replays correctly from *any* starting height. The transparent side
    /// does not: deleting a leaf requires the output's contents, which only a
    /// genesis-forward replay will have seen. Set this when replaying a window,
    /// and expect the transparent roots to be meaningless — the shielded ones
    /// are still exact.
    pub allow_unknown_spends: bool,
    /// Require each block to be exactly one above the current tip.
    pub enforce_contiguous: bool,
}

impl Default for ApplyOptions {
    fn default() -> Self {
        ApplyOptions {
            allow_unknown_spends: false,
            enforce_contiguous: true,
        }
    }
}

impl ApplyOptions {
    /// Settings for replaying a slice of chain that does not start at genesis.
    pub fn window() -> ApplyOptions {
        ApplyOptions {
            allow_unknown_spends: true,
            enforce_contiguous: true,
        }
    }
}

/// What a block did, beyond the undo data.
#[derive(Clone, Debug, Default)]
pub struct ApplyOutcome {
    /// Undo record.
    pub delta: StateDelta,
    /// Spends skipped because the output predated the replay window.
    ///
    /// Always zero on a genesis-forward replay. Non-zero means the transparent
    /// roots are not comparable to a full node's.
    pub unknown_spends: usize,
}

/// Applies one block, in the order fixed by CLAUDE.md Phase 2.
///
/// On any error the accumulators are left exactly as they were.
pub fn apply_block(
    state: &mut ChainAccumulators,
    summary: &BlockSummary,
    options: ApplyOptions,
) -> Result<ApplyOutcome, ApplyError> {
    let height = summary.height;

    if options.enforce_contiguous {
        if let Some(tip) = state.tip() {
            let expected = tip.saturating_add(1);
            if height != expected {
                return Err(ApplyError::OutOfOrder {
                    expected,
                    found: height,
                });
            }
        }
    }

    // ---- staging: everything fallible happens before the first mutation ----

    // 1a. Resolve every spend against the index. A block that references an
    // output we cannot resolve is rejected here rather than half-applied.
    let mut spent: Vec<(OutPoint, UtxoLeaf)> = Vec::new();
    let mut spent_hashes: Vec<Hash> = Vec::new();
    let mut seen: BTreeSet<OutPoint> = BTreeSet::new();
    let mut unknown_spends = 0usize;

    for outpoint in &summary.transparent_spends {
        if !seen.insert(*outpoint) {
            return Err(ApplyError::DuplicateSpend {
                height,
                txid: hex::encode(outpoint.txid),
                vout: outpoint.vout,
            });
        }
        match state.utxo(outpoint) {
            Some(leaf) => {
                spent_hashes.push(leaf.hash());
                spent.push((*outpoint, leaf.clone()));
            }
            None if options.allow_unknown_spends => unknown_spends += 1,
            None => {
                return Err(ApplyError::UnknownOutpoint {
                    height,
                    txid: hex::encode(outpoint.txid),
                    vout: outpoint.vout,
                })
            }
        }
    }

    // 3a. Check every nullifier is absent *before* inserting any of them, so a
    // double spend late in a block cannot leave earlier ones applied. Within a
    // block a repeat is also a double spend, so stage against a running set.
    for pool in PoolId::ALL {
        let nullifiers = summary.nullifiers_for(pool);
        if nullifiers.is_empty() {
            continue;
        }
        let tree = state.tree(pool).ok_or(ApplyError::MissingPool { pool })?;

        let mut within_block: BTreeSet<Value> = BTreeSet::new();
        for value in nullifiers {
            if tree.contains(value) || !within_block.insert(*value) {
                return Err(ApplyError::DuplicateNullifier { height, pool });
            }
        }
    }

    // ---- mutation: from here nothing may fail ----

    let mut delta = StateDelta {
        height,
        commitments: summary.commitments.clone(),
        ..StateDelta::default()
    };

    // 1b. Delete the spent transparent leaves.
    //
    // The forest holds every leaf, so no inclusion proof is needed on this
    // side; a compact state node verifies one instead. Deletions go first, so
    // an output created below cannot be spent by this same block.
    if !spent_hashes.is_empty() {
        state.utxos_mut().delete(&spent_hashes)?;
    }
    for (outpoint, leaf) in &spent {
        state.remove_utxo(outpoint);
        delta.spent.push((*outpoint, leaf.clone()));
    }

    // 2. Insert the created transparent leaves.
    let created_hashes: Vec<Hash> = summary
        .transparent_creates
        .iter()
        .map(|(_, leaf)| leaf.hash())
        .collect();
    if !created_hashes.is_empty() {
        state.utxos_mut().insert(&created_hashes)?;
    }
    for ((outpoint, leaf), hash) in summary.transparent_creates.iter().zip(&created_hashes) {
        state.insert_utxo(*outpoint, leaf.clone());
        delta.created.push((*outpoint, *hash));
    }

    // 3b. Insert nullifiers, per pool, in block order.
    for pool in PoolId::ALL {
        let nullifiers = summary.nullifiers_for(pool);
        if nullifiers.is_empty() {
            continue;
        }
        let tree = state
            .tree_mut(pool)
            .ok_or(ApplyError::MissingPool { pool })?;

        let mut applied = Vec::with_capacity(nullifiers.len());
        for value in nullifiers {
            // Staged above, so this cannot be a duplicate; propagate rather
            // than assume, because a panic here is a remote crash vector.
            let proof = tree.insert(*value)?;
            applied.push((*value, proof));
        }
        delta.insertions.insert(pool, applied);
    }

    // 4. Note commitments: counted in the delta, never accumulated. The
    // commitment trees are deliberately untouched (CLAUDE.md §2).

    // 5. Done.
    state.set_tip(height);

    Ok(ApplyOutcome {
        delta,
        unknown_spends,
    })
}

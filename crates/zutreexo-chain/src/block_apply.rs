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
//! # Outputs created and spent in the same block
//!
//! A transaction may spend an output created by an **earlier transaction in the
//! same block**. Both Bitcoin and Zcash permit this; mainnet block 572 does it,
//! with `tx[10]` spending an output of `tx[8]`.
//!
//! This module previously claimed the opposite — that consensus forbade it —
//! and ordered every deletion before every insertion on that basis. The claim
//! was wrong, inferred from a Bitcoin analogy that runs the other way (CLAUDE.md
//! §5 rule 7). Stages 2a to 2c missed it because their fixture replays all ran
//! with `allow_unknown_spends`, which counted these as pre-window spends and
//! moved on. The genesis-forward replay in 2d hit it after 572 blocks.
//!
//! Such an output is **cancelled**: it never enters the accumulator at all,
//! rather than being inserted and immediately deleted. That is the same choice
//! Bitcoin's Utreexo makes, and it is a specification decision rather than an
//! optimisation — inserting then deleting would be well defined too, but the
//! resulting forest depends on the interleaving of the two operations, so it
//! would need an ordering rule that cancellation simply does not require. See
//! `docs/design.md` D21.
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
/// * `created` — the full [`UtxoLeaf`] of every inserted output, not just its
///   outpoint or its hash. The leaf hash is derivable, so storing only the hash
///   looks sufficient and is not: a rollback that restores a snapshot and
///   replays forward has to rebuild the *outpoint index*, and that needs the
///   output's value, script, height, and coinbase flag. With only the hash, the
///   forest would come back correct while the index came back short, and the
///   failure would surface much later as an `UnknownOutpoint` on some block
///   that spends a replayed output. Found while writing `rollback.rs`.
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
    /// Outputs created, in insertion order, with the contents needed to
    /// rebuild the outpoint index on replay.
    pub created: Vec<(OutPoint, UtxoLeaf)>,
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

    // 1a. Resolve every spend. A block that references an output we cannot
    // resolve is rejected here rather than half-applied.
    //
    // A spend may target an output this same block creates — see the module
    // docs. Those are *cancelled*: neither the create nor the delete reaches
    // the accumulator.
    let created_here: BTreeMap<OutPoint, UtxoLeaf> = summary
        .transparent_creates
        .iter()
        .map(|(outpoint, leaf)| (*outpoint, leaf.clone()))
        .collect();

    let mut spent: Vec<(OutPoint, UtxoLeaf)> = Vec::new();
    let mut spent_hashes: Vec<Hash> = Vec::new();
    let mut cancelled: BTreeSet<OutPoint> = BTreeSet::new();
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
        // The index is consulted first: a pre-existing output is what a spend
        // refers to, and only when there is none can the spend be intra-block.
        match state.utxo(outpoint) {
            Some(leaf) => {
                spent_hashes.push(leaf.hash());
                spent.push((*outpoint, leaf.clone()));
            }
            None if created_here.contains_key(outpoint) => {
                cancelled.insert(*outpoint);
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

    // 2. Insert the created transparent leaves, skipping any this block also
    // spends. A cancelled output never enters the accumulator or the index, so
    // there is nothing to undo for it and the delta does not record it.
    let surviving: Vec<(OutPoint, UtxoLeaf)> = summary
        .transparent_creates
        .iter()
        .filter(|(outpoint, _)| !cancelled.contains(outpoint))
        .map(|(outpoint, leaf)| (*outpoint, leaf.clone()))
        .collect();

    let created_hashes: Vec<Hash> = surviving.iter().map(|(_, leaf)| leaf.hash()).collect();
    if !created_hashes.is_empty() {
        state.utxos_mut().insert(&created_hashes)?;
    }
    for (outpoint, leaf) in surviving {
        state.insert_utxo(outpoint, leaf.clone());
        delta.created.push((outpoint, leaf));
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

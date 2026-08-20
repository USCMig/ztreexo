//! Undoing blocks, for reorgs.
//!
//! # The two halves need different mechanisms, and that is not a design choice
//!
//! CLAUDE.md Phase 2 says to persist "the deleted leaves *and their positions*"
//! in a [`StateDelta`] and undo from that. That plan assumes an accumulator API
//! that does not exist: `rustreexo` exposes only `modify(add, del)`, which
//! **appends**. There is no way to put a leaf back at the position it occupied,
//! so a Utreexo deletion cannot be inverted from a delta at any price.
//! [`StateDelta::spent`] was built in stage 2a for exactly that purpose and
//! cannot serve it.
//!
//! So:
//!
//! * **Shielded — delta undo, exact.** An indexed Merkle tree insertion rewrites
//!   one leaf and appends another, and
//!   [`InsertionProof`](zutreexo_accumulator::imt::InsertionProof) carries the
//!   low leaf as it stood beforehand. That is the whole pre-image, so
//!   [`undo_insert`](zutreexo_accumulator::imt::IndexedMerkleTree::undo_insert)
//!   inverts it exactly and cheaply.
//! * **Transparent — snapshot and replay.** Restore a serialised forest from a
//!   height at or below the target, then replay the intervening deltas forward.
//!
//! # Why snapshots are serialised rather than cloned
//!
//! `MemForest` derives `Clone`, and it is a trap: the struct holds `Rc<Node>`,
//! `Node` stores its hash in a `Cell`, so the "clone" shares nodes and mutating
//! either handle changes both. It compiles and reads correctly.
//! `serialize`/`deserialize` is the only mechanism that actually copies. The
//! aliasing is pinned in `zutreexo-accumulator`'s `tests/upstream_rustreexo.rs`
//! and reported upstream; if that test starts failing, this module can switch
//! to `clone()` and drop the round-trip.
//!
//! # Cost
//!
//! A snapshot is roughly 79 bytes per unspent output, which is why they are
//! taken at an interval rather than every block. Sizing that for mainnet needs
//! the transparent UTXO count, which is still a Phase 0 gap — Zebra does not
//! implement `gettxoutsetinfo`. See `PLAN.md`.

use std::collections::{BTreeMap, VecDeque};

use zutreexo_accumulator::imt::ImtError;
use zutreexo_accumulator::{Hash, PoolId, UtreexoError, UtxoForest, UtxoLeaf};

use crate::block_apply::StateDelta;
use crate::extract::OutPoint;
use crate::pool::ChainAccumulators;

/// How often to snapshot the transparent forest, in blocks.
///
/// Trades memory against rollback time: a wider interval stores fewer
/// snapshots but replays more blocks forward to reach a given height.
pub const DEFAULT_SNAPSHOT_INTERVAL: u32 = 100;

/// How far back a journal can roll, in blocks.
///
/// Zcash reorgs beyond a handful of blocks are not observed in practice, so 100
/// is generous. It is a separate knob from the interval on purpose — retention
/// is a *depth* requirement, and expressing it as a snapshot count silently
/// couples it to the interval. Keeping "two snapshots" gives 200 blocks of
/// reach at an interval of 100 and **one block** at an interval of 1, which is
/// the kind of surprise that only shows up when a reorg actually arrives.
pub const DEFAULT_MAX_ROLLBACK_DEPTH: u32 = 100;

/// A restorable copy of the transparent half at one height.
///
/// The shielded half is absent on purpose: it unwinds by delta, so snapshotting
/// it would be storing something that is never read.
#[derive(Clone, Debug)]
struct Snapshot {
    height: u32,
    forest: Vec<u8>,
    index: BTreeMap<OutPoint, UtxoLeaf>,
}

/// Why a rollback could not be performed.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum RollbackError {
    /// The target is above the current tip; there is nothing to undo.
    #[error("cannot roll back to {target}: tip is {tip:?}")]
    NotBehindTip {
        /// Requested height.
        target: u32,
        /// Current tip.
        tip: Option<u32>,
    },

    /// The target predates the oldest snapshot, so the transparent forest
    /// cannot be reconstructed.
    ///
    /// This is a capacity limit, not a bug: journals retain a bounded history.
    /// Recovering needs a replay from a lower height, not a deeper journal.
    #[error("cannot roll back to {target}: journal reaches back only to {earliest}")]
    BeyondJournal {
        /// Requested height.
        target: u32,
        /// Oldest height the journal can restore.
        earliest: u32,
    },

    /// Deltas are missing for a height inside the journal's range.
    #[error("journal is missing the delta for height {height}")]
    MissingDelta {
        /// The gap.
        height: u32,
    },

    /// Blocks were recorded out of order.
    #[error("journal expected height {expected}, got {found}")]
    OutOfOrder {
        /// Height that should come next.
        expected: u32,
        /// Height supplied.
        found: u32,
    },

    /// A nullifier tree refused an undo.
    #[error("nullifier accumulator: {0}")]
    Imt(#[from] ImtError),

    /// The transparent accumulator refused an operation.
    #[error("transparent accumulator: {0}")]
    Utreexo(#[from] UtreexoError),

    /// A pool named in a delta has no tree.
    #[error("no accumulator for pool {pool}")]
    MissingPool {
        /// The pool.
        pool: PoolId,
    },
}

/// Records what is needed to undo recent blocks.
///
/// Call [`RollbackJournal::record`] after every successful
/// [`apply_block`](crate::apply_block), then
/// [`RollbackJournal::rollback_to`] to unwind.
#[derive(Debug)]
pub struct RollbackJournal {
    interval: u32,
    max_depth: u32,
    /// Snapshots, oldest first. At least one is retained whenever any block
    /// has been recorded.
    snapshots: VecDeque<Snapshot>,
    /// Deltas from `snapshots.front().height + 1` upward, contiguous.
    deltas: VecDeque<StateDelta>,
}

impl Default for RollbackJournal {
    fn default() -> Self {
        RollbackJournal::new(DEFAULT_SNAPSHOT_INTERVAL, DEFAULT_MAX_ROLLBACK_DEPTH)
    }
}

impl RollbackJournal {
    /// A journal snapshotting every `interval` blocks and able to roll back at
    /// least `max_depth` of them.
    ///
    /// An interval of 0 is treated as 1 — snapshot every block. That is the
    /// expensive extreme rather than an invalid one, and the reorg fuzzer uses
    /// it deliberately.
    ///
    /// The two are independent. Retention is driven by `max_depth`, so a small
    /// interval costs memory but never costs reach.
    pub fn new(interval: u32, max_depth: u32) -> RollbackJournal {
        RollbackJournal {
            interval: interval.max(1),
            max_depth,
            snapshots: VecDeque::new(),
            deltas: VecDeque::new(),
        }
    }

    /// The oldest height this journal can restore, if any.
    pub fn earliest_rollback(&self) -> Option<u32> {
        self.snapshots.front().map(|s| s.height)
    }

    /// Highest height recorded.
    pub fn tip(&self) -> Option<u32> {
        self.deltas
            .back()
            .map(|d| d.height)
            .or_else(|| self.snapshots.back().map(|s| s.height))
    }

    /// Number of snapshots currently held. Exposed for tests and for anyone
    /// reasoning about memory.
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Records a block that has just been applied.
    ///
    /// Takes a snapshot first when this height is a snapshot boundary, because
    /// a snapshot must capture the state *at* its height — including the block
    /// being recorded.
    pub fn record(
        &mut self,
        state: &ChainAccumulators,
        delta: StateDelta,
    ) -> Result<(), RollbackError> {
        let height = delta.height;

        if let Some(previous) = self.tip() {
            let expected = previous.saturating_add(1);
            if height != expected {
                return Err(RollbackError::OutOfOrder {
                    expected,
                    found: height,
                });
            }
        }

        // The first recorded block needs a base to replay from, so it always
        // snapshots. Without this there would be no snapshot at or below the
        // earliest delta and nothing could be restored.
        let boundary = self.snapshots.is_empty() || height % self.interval == 0;
        if boundary {
            self.snapshots.push_back(Snapshot {
                height,
                forest: state.utxos().to_bytes()?,
                index: state.clone_utxo_index(),
            });
            self.prune();
        }

        self.deltas.push_back(delta);
        Ok(())
    }

    /// Drops snapshots and deltas that are no longer needed to reach
    /// `max_depth` blocks back.
    ///
    /// Retention is a depth requirement, not a count. A snapshot is droppable
    /// only once the *next* one is still at or below `tip - max_depth`, since
    /// that next one then covers the whole required range on its own. Anything
    /// looser loses reach; anything tighter keeps snapshots nothing can use.
    fn prune(&mut self) {
        let Some(tip) = self.snapshots.back().map(|s| s.height) else {
            return;
        };
        let horizon = tip.saturating_sub(self.max_depth);

        while self.snapshots.len() > 1 {
            // Is the second-oldest still old enough to serve the horizon? If
            // so the oldest is redundant.
            let second = match self.snapshots.get(1) {
                Some(snapshot) => snapshot.height,
                None => break,
            };
            if second <= horizon {
                self.snapshots.pop_front();
            } else {
                break;
            }
        }

        if let Some(oldest) = self.snapshots.front().map(|s| s.height) {
            while self.deltas.front().is_some_and(|d| d.height <= oldest) {
                self.deltas.pop_front();
            }
        }
    }

    /// Unwinds `state` to `height`, leaving it byte-identical to a cold replay
    /// of the chain up to that point.
    ///
    /// Rolling back to the current tip is a no-op and succeeds.
    pub fn rollback_to(
        &mut self,
        state: &mut ChainAccumulators,
        height: u32,
    ) -> Result<(), RollbackError> {
        let tip = state.tip();
        match tip {
            Some(current) if height <= current => {}
            _ => {
                return Err(RollbackError::NotBehindTip {
                    target: height,
                    tip,
                })
            }
        }
        if tip == Some(height) {
            return Ok(());
        }

        let earliest = self
            .earliest_rollback()
            .ok_or(RollbackError::BeyondJournal {
                target: height,
                earliest: height.saturating_add(1),
            })?;
        if height < earliest {
            return Err(RollbackError::BeyondJournal {
                target: height,
                earliest,
            });
        }

        // ---- shielded: unwind by delta, newest block first ----
        //
        // Within a block the nullifiers are undone in reverse insertion order,
        // because `undo_insert` is strictly last-in-first-out. Blocks are
        // undone newest first for the same reason.
        //
        // This runs before the transparent restore so that a refusal — a proof
        // that does not match, say — leaves the transparent half untouched
        // rather than half-rewound.
        let to_undo: Vec<&StateDelta> = self
            .deltas
            .iter()
            .filter(|d| d.height > height)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        for delta in &to_undo {
            for (pool, insertions) in delta.insertions.iter().rev() {
                let tree = state
                    .tree_mut(*pool)
                    .ok_or(RollbackError::MissingPool { pool: *pool })?;
                for (value, proof) in insertions.iter().rev() {
                    tree.undo_insert(*value, proof)?;
                }
            }
        }

        // ---- transparent: restore the newest snapshot at or below the target,
        // then replay forward ----
        let base = self
            .snapshots
            .iter()
            .rev()
            .find(|s| s.height <= height)
            .ok_or(RollbackError::BeyondJournal {
                target: height,
                earliest,
            })?;

        let forest = UtxoForest::from_bytes(&base.forest)?;
        state.restore_transparent(forest, base.index.clone());
        let base_height = base.height;

        for step in (base_height.saturating_add(1))..=height {
            let delta = self
                .deltas
                .iter()
                .find(|d| d.height == step)
                .ok_or(RollbackError::MissingDelta { height: step })?;
            replay_transparent(state, delta)?;
        }

        // ---- drop the undone deltas and settle the tip ----
        while self.deltas.back().is_some_and(|d| d.height > height) {
            self.deltas.pop_back();
        }
        while self.snapshots.back().is_some_and(|s| s.height > height) {
            self.snapshots.pop_back();
        }
        state.set_tip_to(Some(height));

        Ok(())
    }
}

/// Re-applies one block's transparent effect, in the order `apply_block` uses.
///
/// Deletions before insertions, so an output created by the block cannot be
/// spent by it — the same ordering constraint, for the same reason.
fn replay_transparent(
    state: &mut ChainAccumulators,
    delta: &StateDelta,
) -> Result<(), RollbackError> {
    let spent: Vec<Hash> = delta.spent.iter().map(|(_, leaf)| leaf.hash()).collect();
    if !spent.is_empty() {
        state.utxos_mut().delete(&spent)?;
    }
    for (outpoint, _) in &delta.spent {
        state.remove_utxo(outpoint);
    }

    let created: Vec<Hash> = delta.created.iter().map(|(_, leaf)| leaf.hash()).collect();
    if !created.is_empty() {
        state.utxos_mut().insert(&created)?;
    }
    // The index is rebuilt too, not just the forest. `StateDelta::created`
    // carries whole leaves for this reason — see the note on that field.
    for (outpoint, leaf) in &delta.created {
        state.insert_utxo(*outpoint, leaf.clone());
    }
    Ok(())
}

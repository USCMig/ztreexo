//! A deliberately dumb model of *whole chain* accumulator state.
//!
//! [`naive`](crate::naive) models one pool's nullifier set. This lifts that to
//! what a block actually touches: four pools plus the transparent output set.
//!
//! # The same rule applies here, and for the same reason
//!
//! This file shares zero code with `zutreexo-accumulator` and
//! `zutreexo-chain`. Not "shares little" — zero. An oracle's entire value is
//! being wrong in *different* ways than the thing it checks, and the moment it
//! imports a helper from the implementation it becomes a second copy of the
//! same bug.
//!
//! That is a property no compiler enforces, so it is enforced by a test:
//! `tests/independence.rs` reads this file and [`naive`](crate::naive) as text
//! and fails if either mentions the crates they are checking. Sibling modules
//! in this crate *do* import them — [`harness`](crate::harness) has to — which
//! is exactly why the check reads files rather than trusting the dependency
//! graph.
//!
//! # What this model can and cannot catch
//!
//! It catches accumulator bugs: a dropped nullifier, a wrong leaf index, an
//! incremental root drifting from a cold rebuild.
//!
//! It cannot catch parsing bugs. Both this model and the real accumulators are
//! fed from the same [`NaiveBlock`], translated from the same parse, so a
//! mis-read block produces two models that agree with each other and are both
//! wrong. That is not a flaw in the design — it is precisely why CLAUDE.md
//! Phase 2 requires a *second* oracle. See [`checkpoints`](crate::checkpoints).
//!
//! # Transparent outputs are tracked as a set, not as a forest
//!
//! There is no naive Utreexo here. A Utreexo root depends on the whole history
//! of insertions and deletions rather than on current membership, so a
//! from-scratch rebuild would mean reimplementing the forest — including
//! whichever deletion variant upstream chose — and getting that wrong yields
//! false divergences, which is worse than no oracle at all. So this model
//! tracks *which outpoints are unspent*, which is enough for the count tier and
//! is honest about being no more than that. See `PLAN.md`.

// See the note in `naive.rs`: this is an oracle, and panicking is the correct
// failure mode for an oracle, because it means the oracle itself is broken.
// Rewriting these as checked accesses would add error paths to code whose only
// virtue is being obviously correct at a glance.
#![allow(clippy::indexing_slicing)]

use std::collections::{BTreeMap, BTreeSet};

use crate::naive::{Hash, NaiveError, NaiveImt, NaivePool};

/// A transaction output reference. Restated rather than imported.
pub type NaiveOutPoint = ([u8; 32], u32);

/// The pools, in the fixed order this model iterates them.
pub const POOLS: [NaivePool; 4] = [
    NaivePool::Sprout,
    NaivePool::Sapling,
    NaivePool::Orchard,
    NaivePool::Ironwood,
];

/// One block's effect, in plain data.
///
/// Deliberately not `zutreexo_chain::BlockSummary`: that is the type under
/// test, and an oracle that consumes it directly would inherit any bug in it.
#[derive(Clone, Debug, Default)]
pub struct NaiveBlock {
    /// Block height.
    pub height: u32,
    /// Outputs consumed, in order.
    pub spends: Vec<NaiveOutPoint>,
    /// Outputs created, in order.
    pub creates: Vec<NaiveOutPoint>,
    /// Nullifiers revealed, tagged with their pool, in block order.
    ///
    /// Flat rather than grouped: grouping is the implementation's job, and
    /// mirroring its grouping here would mirror a bug in it. Relative order
    /// within a pool is what decides leaf indices, and that is preserved.
    pub nullifiers: Vec<(NaivePool, Hash)>,
}

/// Replay knobs, mirroring the real applier's.
#[derive(Clone, Copy, Debug, Default)]
pub struct NaiveOptions {
    /// Tolerate spending an outpoint this model never saw created.
    ///
    /// Necessary for any replay that does not start at genesis: the output was
    /// created before the window opened.
    pub allow_unknown_spends: bool,
}

/// Why the model rejected a block.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NaiveApplyError {
    /// Spent an outpoint that is not in the set.
    UnknownOutpoint {
        /// Block height.
        height: u32,
        /// The missing outpoint.
        outpoint: NaiveOutPoint,
    },
    /// The same outpoint was spent twice in one block.
    DuplicateSpend {
        /// Block height.
        height: u32,
        /// The repeated outpoint.
        outpoint: NaiveOutPoint,
    },
    /// A nullifier was already present, or repeated within the block.
    DuplicateNullifier {
        /// Block height.
        height: u32,
        /// Which pool.
        pool: NaivePool,
    },
    /// A pool's tree rejected the value.
    Imt {
        /// Block height.
        height: u32,
        /// Which pool.
        pool: NaivePool,
        /// The underlying reason.
        error: NaiveError,
    },
}

/// Counts, for the cheap every-block comparison tier.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NaiveCounts {
    /// Last applied height.
    pub height: Option<u32>,
    /// Unspent outputs tracked.
    pub utxos: usize,
    /// Nullifiers per pool, excluding sentinels.
    pub nullifiers: BTreeMap<&'static str, u64>,
}

/// The whole-chain model.
#[derive(Clone, Debug)]
pub struct NaiveState {
    depth: u8,
    pools: Vec<(NaivePool, NaiveImt)>,
    utxos: BTreeSet<NaiveOutPoint>,
    tip: Option<u32>,
    /// Spends of outputs created before the replay window.
    unknown_spends: usize,
}

impl NaiveState {
    /// An empty model with every pool's tree at `depth`.
    pub fn new(depth: u8) -> Result<NaiveState, NaiveError> {
        let mut pools = Vec::with_capacity(POOLS.len());
        for pool in POOLS {
            pools.push((pool, NaiveImt::new(pool, depth)?));
        }
        Ok(NaiveState {
            depth,
            pools,
            utxos: BTreeSet::new(),
            tip: None,
            unknown_spends: 0,
        })
    }

    /// Depth every tree uses.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Last applied height.
    pub fn tip(&self) -> Option<u32> {
        self.tip
    }

    /// Spends skipped because the output predated the window.
    pub fn unknown_spends(&self) -> usize {
        self.unknown_spends
    }

    /// Unspent outputs tracked.
    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }

    /// Nullifiers accumulated in one pool.
    pub fn nullifier_count(&self, pool: NaivePool) -> u64 {
        self.pools
            .iter()
            .find(|(candidate, _)| *candidate == pool)
            .map_or(0, |(_, tree)| tree.value_count())
    }

    /// Counts for the every-block tier.
    pub fn counts(&self) -> NaiveCounts {
        NaiveCounts {
            height: self.tip,
            utxos: self.utxos.len(),
            nullifiers: self
                .pools
                .iter()
                .map(|(pool, tree)| (pool_name(*pool), tree.value_count()))
                .collect(),
        }
    }

    /// Every pool's root, each **recomputed from scratch**.
    ///
    /// Nothing is cached between calls, by design. This is the load-bearing
    /// comparison: it proves the incremental path has not drifted from a
    /// from-scratch computation, which is the failure that accumulates silently
    /// over a long replay and surfaces only when somebody cannot spend.
    pub fn roots(&self) -> BTreeMap<&'static str, Hash> {
        self.pools
            .iter()
            .map(|(pool, tree)| (pool_name(*pool), tree.root()))
            .collect()
    }

    /// Applies one block, in the order the specification fixes.
    ///
    /// Spends before creates, so an output created by this block cannot be
    /// spent by it. Every check runs before the first mutation, so a rejected
    /// block leaves the model untouched — the real applier promises the same,
    /// and a model that did not would report false divergences after any
    /// legitimately rejected block.
    pub fn apply(
        &mut self,
        block: &NaiveBlock,
        options: NaiveOptions,
    ) -> Result<(), NaiveApplyError> {
        let height = block.height;

        // ---- staging ----
        let mut resolved: Vec<NaiveOutPoint> = Vec::new();
        let mut seen: BTreeSet<NaiveOutPoint> = BTreeSet::new();
        let mut unknown = 0usize;

        // A block may spend an output it creates — mainnet block 572 does, with
        // one transaction spending an earlier one's output. Such an output is
        // *cancelled*: it never enters the set at all.
        //
        // Derived here from the rule, not copied from the implementation. The
        // oracle's job is to reach the same answer by its own route, so this
        // scans the block's own creates rather than sharing any helper.
        let mut cancelled: BTreeSet<NaiveOutPoint> = BTreeSet::new();

        for outpoint in &block.spends {
            if !seen.insert(*outpoint) {
                return Err(NaiveApplyError::DuplicateSpend {
                    height,
                    outpoint: *outpoint,
                });
            }
            if self.utxos.contains(outpoint) {
                resolved.push(*outpoint);
            } else if block.creates.contains(outpoint) {
                cancelled.insert(*outpoint);
            } else if options.allow_unknown_spends {
                unknown += 1;
            } else {
                return Err(NaiveApplyError::UnknownOutpoint {
                    height,
                    outpoint: *outpoint,
                });
            }
        }

        for pool in POOLS {
            let mut within: BTreeSet<Hash> = BTreeSet::new();
            for (tagged, value) in &block.nullifiers {
                if *tagged != pool {
                    continue;
                }
                let present = self
                    .pools
                    .iter()
                    .find(|(candidate, _)| *candidate == pool)
                    .is_some_and(|(_, tree)| tree.contains(value));
                if present || !within.insert(*value) {
                    return Err(NaiveApplyError::DuplicateNullifier { height, pool });
                }
            }
        }

        // ---- mutation ----
        for outpoint in &resolved {
            self.utxos.remove(outpoint);
        }
        for outpoint in &block.creates {
            if !cancelled.contains(outpoint) {
                self.utxos.insert(*outpoint);
            }
        }

        for pool in POOLS {
            for (tagged, value) in &block.nullifiers {
                if *tagged != pool {
                    continue;
                }
                let slot = self
                    .pools
                    .iter_mut()
                    .find(|(candidate, _)| *candidate == pool);
                match slot {
                    Some((_, tree)) => {
                        tree.insert(*value).map_err(|error| NaiveApplyError::Imt {
                            height,
                            pool,
                            error,
                        })?;
                    }
                    None => {
                        return Err(NaiveApplyError::Imt {
                            height,
                            pool,
                            error: NaiveError::BadDepth(self.depth),
                        })
                    }
                }
            }
        }

        self.unknown_spends = self.unknown_spends.saturating_add(unknown);
        self.tip = Some(height);
        Ok(())
    }
}

/// Stable string name for a pool, used as a map key so comparisons across the
/// oracle boundary do not depend on either side's enum ordering.
pub fn pool_name(pool: NaivePool) -> &'static str {
    match pool {
        NaivePool::Sprout => "sprout",
        NaivePool::Sapling => "sapling",
        NaivePool::Orchard => "orchard",
        NaivePool::Ironwood => "ironwood",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn h(n: u64) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        bytes
    }

    fn op(n: u8, vout: u32) -> NaiveOutPoint {
        ([n; 32], vout)
    }

    #[test]
    fn applies_spends_before_creates() {
        let mut state = NaiveState::new(8).unwrap();

        let created = NaiveBlock {
            height: 1,
            creates: vec![op(1, 0)],
            ..NaiveBlock::default()
        };
        state.apply(&created, NaiveOptions::default()).unwrap();
        assert_eq!(state.utxo_count(), 1);

        // A block that both spends the existing output and creates a new one.
        let both = NaiveBlock {
            height: 2,
            spends: vec![op(1, 0)],
            creates: vec![op(2, 0)],
            ..NaiveBlock::default()
        };
        state.apply(&both, NaiveOptions::default()).unwrap();
        assert_eq!(state.utxo_count(), 1);
        assert_eq!(state.tip(), Some(2));
    }

    /// A block *may* spend an output it creates, and the output is cancelled.
    ///
    /// This test previously asserted the opposite, under the name
    /// `a_block_cannot_spend_what_it_creates`. The belief was wrong — mainnet
    /// block 572 spends an output created two transactions earlier — and
    /// writing it down as a test is part of why it went unquestioned for three
    /// stages. An oracle that encodes a false rule is worse than no oracle: it
    /// actively defends the bug.
    #[test]
    fn a_block_may_spend_what_it_creates_and_the_output_is_cancelled() {
        let mut state = NaiveState::new(8).unwrap();
        let block = NaiveBlock {
            height: 1,
            spends: vec![op(9, 0)],
            creates: vec![op(9, 0), op(8, 0)],
            ..NaiveBlock::default()
        };
        state.apply(&block, NaiveOptions::default()).unwrap();

        // The cancelled output is absent; the other survives.
        assert_eq!(state.utxo_count(), 1);
        assert_eq!(state.unknown_spends(), 0, "this is not an unknown spend");
    }

    /// Spending something neither present nor created here is still an error.
    #[test]
    fn an_unrelated_unknown_outpoint_is_still_rejected() {
        let mut state = NaiveState::new(8).unwrap();
        let block = NaiveBlock {
            height: 1,
            spends: vec![op(9, 0)],
            creates: vec![op(8, 0)],
            ..NaiveBlock::default()
        };
        assert_eq!(
            state.apply(&block, NaiveOptions::default()),
            Err(NaiveApplyError::UnknownOutpoint {
                height: 1,
                outpoint: op(9, 0)
            })
        );
    }

    #[test]
    fn rejects_duplicate_nullifiers_across_blocks() {
        let mut state = NaiveState::new(8).unwrap();
        let block = NaiveBlock {
            height: 1,
            nullifiers: vec![(NaivePool::Orchard, h(7))],
            ..NaiveBlock::default()
        };
        state.apply(&block, NaiveOptions::default()).unwrap();

        let again = NaiveBlock {
            height: 2,
            ..block.clone()
        };
        assert_eq!(
            state.apply(&again, NaiveOptions::default()),
            Err(NaiveApplyError::DuplicateNullifier {
                height: 2,
                pool: NaivePool::Orchard
            })
        );
    }

    #[test]
    fn rejects_duplicate_nullifiers_within_one_block() {
        let mut state = NaiveState::new(8).unwrap();
        let block = NaiveBlock {
            height: 1,
            nullifiers: vec![(NaivePool::Sapling, h(3)), (NaivePool::Sapling, h(3))],
            ..NaiveBlock::default()
        };
        assert_eq!(
            state.apply(&block, NaiveOptions::default()),
            Err(NaiveApplyError::DuplicateNullifier {
                height: 1,
                pool: NaivePool::Sapling
            })
        );
    }

    #[test]
    fn the_same_value_may_appear_in_different_pools() {
        // Nullifier sets are per-pool and entirely independent; a collision
        // across pools is not a double spend.
        let mut state = NaiveState::new(8).unwrap();
        let block = NaiveBlock {
            height: 1,
            nullifiers: vec![(NaivePool::Orchard, h(4)), (NaivePool::Ironwood, h(4))],
            ..NaiveBlock::default()
        };
        state.apply(&block, NaiveOptions::default()).unwrap();
        assert_eq!(state.nullifier_count(NaivePool::Orchard), 1);
        assert_eq!(state.nullifier_count(NaivePool::Ironwood), 1);
    }

    #[test]
    fn rejection_leaves_the_model_untouched() {
        let mut state = NaiveState::new(8).unwrap();
        let good = NaiveBlock {
            height: 1,
            creates: vec![op(1, 0)],
            nullifiers: vec![(NaivePool::Orchard, h(1))],
            ..NaiveBlock::default()
        };
        state.apply(&good, NaiveOptions::default()).unwrap();
        let roots = state.roots();
        let counts = state.counts();

        // Fails on the nullifier, but only after the creates would have landed
        // had staging not come first.
        let bad = NaiveBlock {
            height: 2,
            creates: vec![op(5, 0)],
            nullifiers: vec![(NaivePool::Orchard, h(1))],
            ..NaiveBlock::default()
        };
        assert!(state.apply(&bad, NaiveOptions::default()).is_err());
        assert_eq!(state.roots(), roots);
        assert_eq!(state.counts(), counts);
    }

    #[test]
    fn unknown_spends_are_counted_when_allowed() {
        let mut state = NaiveState::new(8).unwrap();
        let block = NaiveBlock {
            height: 100,
            spends: vec![op(3, 1)],
            ..NaiveBlock::default()
        };
        let options = NaiveOptions {
            allow_unknown_spends: true,
        };
        state.apply(&block, options).unwrap();
        assert_eq!(state.unknown_spends(), 1);
        assert_eq!(state.utxo_count(), 0);
    }

    #[test]
    fn ordering_within_a_pool_changes_the_root() {
        // The property the reorder fault injection relies on: same values, same
        // counts, different leaf indices, different root.
        let build = |values: Vec<Hash>| {
            let mut state = NaiveState::new(8).unwrap();
            let block = NaiveBlock {
                height: 1,
                nullifiers: values
                    .into_iter()
                    .map(|value| (NaivePool::Orchard, value))
                    .collect(),
                ..NaiveBlock::default()
            };
            state.apply(&block, NaiveOptions::default()).unwrap();
            state.roots()
        };
        assert_ne!(build(vec![h(1), h(2)]), build(vec![h(2), h(1)]));
    }
}

//! Snapshot epochs: what a bridge keeps so it can answer a cohort query.
//!
//! # Why a snapshot at all
//!
//! The live nullifier structure is an
//! [`IndexedMerkleTree`](zutreexo_accumulator::imt::IndexedMerkleTree), and its leaves sit
//! in **insertion** order. A prefix cohort needs the opposite — every value in
//! a value-range as one contiguous run — which is what
//! [`SortedTree`] provides, and why
//! `docs/design.md` D38 measured it at 14.2x the IMT cohort's efficiency.
//!
//! A sorted tree cannot be maintained incrementally the way the IMT is: a
//! nullifier lands in the middle of the value order, so every leaf above it
//! shifts. It is rebuilt whole, which is why it is an *epoch* snapshot rather
//! than a live view.
//!
//! # What the two knobs actually trade
//!
//! [`EpochPolicy::interval`] and [`EpochPolicy::keep`] pull in opposite
//! directions and neither has an obviously right value:
//!
//! * **interval** bounds how stale a snapshot can be. A wallet resolving a
//!   nullifier against the epoch at height `H` learns the answer *as of `H`*
//!   and must scan blocks `H+1..tip` itself for anything revealed since. That
//!   delta is public chain data it already has, so this is not a correctness
//!   problem — it is a cost, linear in the interval, paid by every client.
//!   Against it: each rebuild is `O(n log n)` over the whole pool, measured at
//!   16.8 s for Orchard's 50.4M values (D38).
//! * **keep** decides how far back a client can anchor. A wallet that fetched
//!   a manifest, went offline, and came back still has a root it can verify
//!   against — but only while that epoch is retained. Against it: an Orchard
//!   snapshot is **5.50 GB**, and all four pools at `keep = 2` come to
//!   **11.99 GB**.
//!
//! `crates/zutreexo-testkit/src/bin/epoch_cost.rs` measured both, and the
//! defaults below are what it said rather than what they were first set to.
//! Two results decided them (`docs/design.md` D43):
//!
//! * **The interval is bounded by the client, not the bridge.** Rebuilding
//!   every pool costs 25.5 s of a 20.8-hour epoch — a duty cycle of 0.03%. The
//!   bridge barely notices. What bounds it is the delta: at 9.264 nullifiers a
//!   block, a wallet arriving just before the next snapshot scans 289.5 KB,
//!   against a 384.9 KB cohort. Break-even is **1,330 blocks**, so 1,000 sits
//!   just inside it and 2,000 does not.
//! * **`keep` is expensive and buys very little.** It was first set to 2, to
//!   stop a rebuild landing between a client's manifest fetch and its query.
//!   That race costs a client one extra round trip, roughly once per 20.8
//!   hours, and it resolves itself: the client sees
//!   [`NO_SUCH_EPOCH`](crate::wire::status::NO_SUCH_EPOCH), refetches, retries.
//!   Paying **6 GB** for it is not a trade worth making, so the default is 1.
//!
//! # Peak memory is twice the steady state, briefly
//!
//! [`EpochStore::snapshot`] inserts the new snapshot before evicting the old
//! one, so a bridge at `keep = 1` still holds two Orchard trees — 11 GB — for
//! the ~23 s of the rebuild. Evicting first would halve the peak and leave the
//! bridge with **no snapshot at all** for those 23 s, answering
//! `NO_SUCH_EPOCH` to every client. A transient allocation is the cheaper
//! failure, but it has to be budgeted for rather than discovered.
//!
//! # The retention subtlety that is *not* about memory
//!
//! Serving several epochs at once is a privacy cost as well as a storage one.
//! Two queries for the same bucket against the *same* epoch are byte-identical
//! and tell the bridge nothing beyond the bucket. Two queries for the same
//! bucket against *different* epochs are still the same bucket — the epoch
//! adds a second coordinate the bridge can group on. D41's unlinkability
//! argument assumes a client picks the epoch the same way everyone else does,
//! so [`EpochStore::latest`] exists and clients should prefer it. Reaching
//! back to an older epoch is supported because a stale client needs it, not
//! because it is free.

use std::collections::BTreeMap;

use zutreexo_accumulator::cohort::CohortError;
use zutreexo_accumulator::sorted::SortedTree;
use zutreexo_accumulator::{Hash, PoolId};
use zutreexo_chain::ChainAccumulators;

/// The anonymity target every served cohort must reach.
///
/// `docs/design.md` D38 fixed this: 12,298 is the crowd size at which a
/// 12-bit prefix over Orchard costs 384.9 KB, and D39 confirmed every live
/// pool can reach it at some width. It is a *policy* number, not a protocol
/// one — a bridge operator may raise it, and lowering it below the figure the
/// privacy analysis was done at invalidates that analysis.
pub const DEFAULT_MIN_ANONYMITY: u64 = 12_298;

/// How often a bridge snapshots, and how much it keeps.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EpochPolicy {
    /// Blocks between snapshots. Zero disables snapshotting entirely, and a
    /// bridge with it disabled answers no cohort queries.
    pub interval: u32,
    /// Snapshots retained **per pool**. Zero is treated as one: a store that
    /// keeps nothing has no reason to build anything.
    pub keep: usize,
    /// Smallest cohort the bridge will serve. Drives the prefix floor.
    pub min_anonymity: u64,
}

impl Default for EpochPolicy {
    fn default() -> EpochPolicy {
        EpochPolicy {
            // ~20.8 hours at Zcash's 75-second blocks. Short enough that the
            // delta a wallet scans is a day rather than a month, long enough
            // that Orchard's 16.8 s rebuild is 0.02% of the bridge's time.
            interval: 1_000,
            // One. This was 2 — to stop a rebuild landing between a client's
            // manifest fetch and its query — until `epoch_cost` priced the
            // second copy at 6 GB against a race that costs one round trip a
            // day and recovers on its own. See the module docs and D43.
            //
            // It is also the better privacy answer: with one epoch there is no
            // choice of epoch to make, so a client cannot distinguish itself by
            // making an unusual one.
            keep: 1,
            min_anonymity: DEFAULT_MIN_ANONYMITY,
        }
    }
}

impl EpochPolicy {
    /// No snapshots, no cohort service. For a bridge that only serves bundles.
    pub fn disabled() -> EpochPolicy {
        EpochPolicy {
            interval: 0,
            keep: 0,
            min_anonymity: DEFAULT_MIN_ANONYMITY,
        }
    }

    /// Whether `height` is a snapshot boundary.
    ///
    /// Height zero is excluded: the genesis state holds nothing but sentinels,
    /// and a snapshot of it would be served as though it were an answer.
    pub fn due(&self, height: u32) -> bool {
        self.interval != 0 && height != 0 && height % self.interval == 0
    }

    /// Snapshots to retain per pool, never below one when enabled.
    pub fn effective_keep(&self) -> usize {
        if self.interval == 0 {
            0
        } else {
            self.keep.max(1)
        }
    }
}

/// The widest prefix over `leaf_count` values whose expected cohort still
/// reaches `min_anonymity`.
///
/// A `b`-bit prefix splits the value space into `2^b` buckets, so the expected
/// occupancy is `leaf_count / 2^b` and the answer is
/// `floor(log2(leaf_count / min_anonymity))`.
///
/// **Zero means no prefix query is permissible.** Not "use one bit": a pool
/// holding fewer than twice the target cannot be split at all without putting
/// the querying wallet in a crowd smaller than the policy promises. The honest
/// answer for such a pool is to download the whole nullifier set, which is
/// cheap precisely because the pool is small — 2.25 MB for Ironwood at the
/// counts in `docs/benchmarks.md`. That fallback is not built yet; see D42.
///
/// This is the arithmetic `pool_cohorts.rs` used to derive D39's per-pool
/// widths, moved here because the server has to *enforce* it rather than
/// merely report it.
pub fn max_bits_for(leaf_count: u64, min_anonymity: u64) -> u8 {
    if min_anonymity == 0 || leaf_count < min_anonymity {
        return 0;
    }
    let mut bits = 0u8;
    // Capped at 31 so the shift stays in range and so a width beyond
    // `MAX_PREFIX_BITS` is never advertised.
    while bits < 31 && leaf_count / (1u64 << bits.saturating_add(1)) >= min_anonymity {
        bits = bits.saturating_add(1);
    }
    bits
}

/// One retained snapshot, as advertised to clients.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EpochEntry {
    /// Which pool.
    pub pool: PoolId,
    /// Height the snapshot was taken at.
    pub height: u32,
    /// Depth of the sorted tree, so a client can size its fold.
    pub depth: u8,
    /// Occupied leaves, sentinel included.
    pub leaf_count: u64,
    /// Widest prefix this bridge will answer for this epoch. Zero means none.
    pub max_bits: u8,
    /// The snapshot root a returned cohort folds to.
    pub root: Hash,
}

/// Every snapshot a bridge retains, and the policy that governs them.
#[derive(Debug)]
pub struct EpochStore {
    policy: EpochPolicy,
    /// Keyed by `(pool, height)` so iteration is in pool-then-height order
    /// deterministically — the manifest's canonical ordering falls out of the
    /// map rather than being sorted back into place (CLAUDE.md §5 rule 5).
    snapshots: BTreeMap<(PoolId, u32), SortedTree>,
}

impl EpochStore {
    /// An empty store under `policy`.
    pub fn new(policy: EpochPolicy) -> EpochStore {
        EpochStore {
            policy,
            snapshots: BTreeMap::new(),
        }
    }

    /// The governing policy.
    pub fn policy(&self) -> &EpochPolicy {
        &self.policy
    }

    /// Whether `height` is a snapshot boundary under this policy.
    pub fn due(&self, height: u32) -> bool {
        self.policy.due(height)
    }

    /// How many snapshots are retained across all pools.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Whether anything is retained.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Rebuilds a snapshot of every pool at `height`, then evicts.
    ///
    /// Returns how many pools were snapshotted. A pool with no tree is skipped
    /// rather than failing the whole epoch: one missing pool must not cost the
    /// bridge its service for the other three.
    pub fn snapshot(
        &mut self,
        state: &ChainAccumulators,
        height: u32,
    ) -> Result<usize, CohortError> {
        if self.policy.effective_keep() == 0 {
            return Ok(0);
        }
        let mut built = 0usize;
        for pool in PoolId::ALL {
            let Some(tree) = state.tree(pool) else {
                continue;
            };
            let snapshot = SortedTree::from_imt(tree, height)?;
            self.snapshots.insert((pool, height), snapshot);
            built = built.saturating_add(1);
            self.evict(pool);
        }
        Ok(built)
    }

    /// Drops the oldest snapshots for `pool` beyond the retention limit.
    fn evict(&mut self, pool: PoolId) {
        let keep = self.policy.effective_keep();
        loop {
            let heights: Vec<u32> = self
                .snapshots
                .range((pool, u32::MIN)..=(pool, u32::MAX))
                .map(|((_, height), _)| *height)
                .collect();
            if heights.len() <= keep {
                return;
            }
            // `BTreeMap` range order, so this is the oldest deterministically.
            let Some(oldest) = heights.first().copied() else {
                return;
            };
            self.snapshots.remove(&(pool, oldest));
        }
    }

    /// One retained snapshot, by pool and exact height.
    pub fn get(&self, pool: PoolId, height: u32) -> Option<&SortedTree> {
        self.snapshots.get(&(pool, height))
    }

    /// The newest snapshot for a pool.
    ///
    /// Clients should prefer this. See the module docs: an epoch a client
    /// chooses differently from everyone else is a second coordinate the bridge
    /// can group its queries on.
    pub fn latest(&self, pool: PoolId) -> Option<&SortedTree> {
        self.snapshots
            .range((pool, u32::MIN)..=(pool, u32::MAX))
            .next_back()
            .map(|(_, tree)| tree)
    }

    /// The widest prefix this store will answer for one epoch.
    pub fn max_bits(&self, pool: PoolId, height: u32) -> Option<u8> {
        self.get(pool, height)
            .map(|tree| max_bits_for(tree.leaf_count(), self.policy.min_anonymity))
    }

    /// Every retained snapshot, in pool-then-height order.
    pub fn entries(&self) -> Vec<EpochEntry> {
        self.snapshots
            .iter()
            .map(|((pool, height), tree)| EpochEntry {
                pool: *pool,
                height: *height,
                depth: tree.depth(),
                leaf_count: tree.leaf_count(),
                max_bits: max_bits_for(tree.leaf_count(), self.policy.min_anonymity),
                root: tree.root(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zutreexo_accumulator::imt::Value;

    fn value(n: u64) -> Value {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
        bytes[31] = 1;
        Value::from_bytes(bytes)
    }

    /// A state holding `count` Orchard nullifiers, applied as a block rather
    /// than poked into the tree — there is no public mutator, and adding one
    /// for a test would be a hole in the accumulator's own encapsulation.
    fn state(count: u64) -> ChainAccumulators {
        let mut state = ChainAccumulators::new(20).expect("depth");
        let mut nullifiers = std::collections::BTreeMap::new();
        nullifiers.insert(
            PoolId::Orchard,
            (1..=count).map(value).collect::<Vec<Value>>(),
        );
        let summary = zutreexo_chain::BlockSummary {
            height: 10,
            transactions: 1,
            transparent_spends: Vec::new(),
            transparent_creates: Vec::new(),
            nullifiers,
            commitments: std::collections::BTreeMap::new(),
        };
        zutreexo_chain::apply_and_prove(
            &mut state,
            &summary,
            zutreexo_chain::ApplyOptions::default(),
        )
        .expect("applies");
        state
    }

    #[test]
    fn a_store_reports_what_it_holds_and_the_width_it_will_answer() {
        // `len` and `max_bits` are the two things an operator inspects to see
        // whether a bridge is actually serving. Exercised here rather than
        // left to the integration tests, which reach the same information
        // through the manifest and so would let these two rot.
        let mut store = EpochStore::new(EpochPolicy {
            interval: 10,
            keep: 1,
            min_anonymity: 100,
        });
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert_eq!(store.max_bits(PoolId::Orchard, 10), None);

        let state = state(1_000);
        assert_eq!(
            store.snapshot(&state, 10).expect("builds"),
            PoolId::ALL.len()
        );
        assert_eq!(store.len(), PoolId::ALL.len());
        assert!(!store.is_empty());

        // 1,001 leaves against a floor of 100 admits three bits (125 expected
        // per bucket) and not four (62).
        assert_eq!(store.max_bits(PoolId::Orchard, 10), Some(3));
        // A pool that received nothing holds only the sentinel, so no prefix
        // can reach the floor — but it still has a snapshot, so a query about
        // it is refused for the honest reason rather than for the absence of
        // an epoch, which would itself say something about the pool.
        assert_eq!(store.max_bits(PoolId::Ironwood, 10), Some(0));
        // An epoch that was never taken has no width at all, which is a
        // different answer from "zero".
        assert_eq!(store.max_bits(PoolId::Orchard, 20), None);
    }

    #[test]
    fn the_prefix_floor_matches_the_per_pool_widths_d39_measured() {
        // The same four numbers `pool_cohorts.rs` asserts, now enforced by the
        // server rather than only reported by a binary. If these drift, the
        // bridge and the published measurement disagree.
        for (leaf_count, want) in [
            (50_392_547u64, 12u8),
            (2_129_852, 7),
            (1_547_198, 6),
            (70_380, 2),
        ] {
            assert_eq!(
                max_bits_for(leaf_count, DEFAULT_MIN_ANONYMITY),
                want,
                "leaf_count={leaf_count}"
            );
        }
    }

    #[test]
    fn a_pool_below_twice_the_target_admits_no_prefix_at_all() {
        // One bit over 20,000 values leaves a crowd of 10,000, under the
        // policy's 12,298. Answering it would serve a smaller anonymity set
        // than advertised, which is worse than refusing.
        assert_eq!(max_bits_for(20_000, DEFAULT_MIN_ANONYMITY), 0);
        assert_eq!(max_bits_for(12_297, DEFAULT_MIN_ANONYMITY), 0);
        assert_eq!(max_bits_for(12_298, DEFAULT_MIN_ANONYMITY), 0);
        assert_eq!(max_bits_for(24_596, DEFAULT_MIN_ANONYMITY), 1);
    }

    #[test]
    fn the_advertised_width_never_exceeds_what_a_range_can_express() {
        // `PrefixRange` refuses anything above MAX_PREFIX_BITS. Advertising a
        // width the client cannot then use would be a self-inflicted outage.
        let bits = max_bits_for(u64::MAX, 1);
        assert!(bits <= 31, "advertised {bits} bits");
        assert!(
            bits <= zutreexo_accumulator::cohort::MAX_PREFIX_BITS,
            "advertised {bits} against a cap of {}",
            zutreexo_accumulator::cohort::MAX_PREFIX_BITS
        );
    }

    #[test]
    fn a_zero_target_is_refused_rather_than_dividing_by_zero() {
        assert_eq!(max_bits_for(50_392_547, 0), 0);
    }

    #[test]
    fn genesis_is_never_an_epoch_boundary() {
        // `0 % anything == 0`, so without the guard every bridge would take a
        // snapshot of a state holding nothing but sentinels and advertise it.
        let policy = EpochPolicy::default();
        assert!(!policy.due(0));
        assert!(policy.due(1_000));
        assert!(!policy.due(1_001));
    }

    #[test]
    fn the_defaults_are_the_ones_the_measurement_chose() {
        // Pinned so a change to either knob has to be deliberate and has to
        // come with a reason, rather than drifting back to a round number.
        //
        // `interval` must stay under the break-even `epoch_cost` measured:
        // 1,330 blocks, past which a wallet's worst-case delta scan exceeds
        // the 384.9 KB cohort it came for and the snapshot is carrying less
        // than half its weight.
        let policy = EpochPolicy::default();
        assert_eq!(policy.interval, 1_000);
        assert!(
            policy.interval < 1_330,
            "interval {} is past the measured break-even",
            policy.interval
        );
        // `keep` of 2 costs 6 GB (D43). If this ever goes back up, the reason
        // has to be written down next to it.
        assert_eq!(policy.keep, 1);
        assert_eq!(policy.min_anonymity, DEFAULT_MIN_ANONYMITY);
    }

    #[test]
    fn a_disabled_policy_is_never_due_and_keeps_nothing() {
        let policy = EpochPolicy::disabled();
        assert!(!policy.due(1_000));
        assert_eq!(policy.effective_keep(), 0);
    }

    #[test]
    fn keep_zero_with_an_interval_still_keeps_one() {
        // Building a snapshot and immediately discarding it is pure cost, so
        // the combination is read as "keep the newest" rather than honoured.
        let policy = EpochPolicy {
            interval: 100,
            keep: 0,
            min_anonymity: DEFAULT_MIN_ANONYMITY,
        };
        assert_eq!(policy.effective_keep(), 1);
    }
}

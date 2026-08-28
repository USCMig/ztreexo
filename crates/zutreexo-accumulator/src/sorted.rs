//! An epoch-sorted cohort tree: large anonymity sets at 32 bytes a member.
//!
//! # Why this exists
//!
//! [`crate::cohort`] made a private spend-status query possible and measured
//! what it costs: at Orchard's 50.4M nullifiers a 12-bit prefix gives a
//! **12,298-member** anonymity set for **5.35 MB** (`docs/design.md` D37). The
//! target chosen is 12,298. 5.35 MB per query is too much for it.
//!
//! The cost is structural, not incidental. An indexed Merkle tree stores leaves
//! in **insertion** order and threads sortedness through the `next_index`
//! linked list, so a value range is scattered across the tree and each member
//! drags its own partly-shared Merkle path — about 585 bytes a member after
//! deduplication.
//!
//! In a **value-ordered** tree a prefix range is one contiguous run. The proof
//! is the run plus the fringe siblings of the subtrees covering it, which is
//! `O(log n)` no matter how large the run. Per-member cost falls to the value
//! itself: **32 bytes**.
//!
//! # Why this is not just "reorder the IMT"
//!
//! Because insertion order is not an accident. Appending to an IMT is `O(1)`
//! and touches one path; inserting into the middle of a value-ordered tree of
//! 50.4M leaves shifts about 25M of them, each a path update. That is the
//! trade indexed Merkle trees exist to make, and taking it back per-block would
//! be ruinous.
//!
//! What makes a sorted tree affordable is that **nullifier sets are
//! append-only** — nothing is ever removed — so a sorted snapshot stays valid
//! for everything it contains, forever. It is rebuilt in bulk once an *epoch*,
//! and nullifiers revealed since travel separately as a small delta. Sorting
//! 50.4M values and hashing the tree over them is seconds of work against an
//! epoch measured in hours.
//!
//! So this is **derived, additive, bridge-side state**. The IMT is unchanged,
//! its on-disk format is unchanged (no Phase 3 version bump), and nothing here
//! touches consensus.
//!
//! # The omission attack disappears
//!
//! [`crate::cohort::resolve`] has to check for a short cohort by hand: a bridge
//! that drops an in-range leaf and recomputes the deduplication produces a
//! valid Merkle proof of a smaller set, so absence and omission look alike
//! until the linked list is consulted.
//!
//! Here they cannot. Cohort members occupy **consecutive positions**, and the
//! proof commits to those positions. [`verify_cohort`] requires every position
//! across the requested span to carry an actual value — an omitted member would
//! leave a position covered by an opaque node instead, which is refused — and
//! requires the span to bracket the whole prefix range. Completeness is
//! checkable rather than argued.

use std::collections::BTreeMap;

use crate::cohort::{CohortError, PrefixRange, Status};
use crate::hash::{self, Hash};
use crate::imt::{IndexedMerkleTree, Value};
use crate::pool::PoolId;

/// The largest tree this will build, as a power of two.
///
/// 2^32 is 4.29 billion nullifiers. Orchard holds 50.4M and NU7's possible 3×
/// block-time change (CLAUDE.md §7) does not approach this; the cap exists so a
/// corrupt leaf count cannot drive an allocation loop.
pub const MAX_SORTED_DEPTH: u8 = 32;

/// A value-sorted Merkle tree over one pool's nullifiers at one height.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SortedTree {
    pool: PoolId,
    /// Height whose nullifier set this snapshots.
    height: u32,
    /// `2^depth` leaf slots. Sized to the set, not fixed at 40 like the IMT:
    /// the tree is rebuilt whole each epoch, so there is nothing to grow into
    /// and a tighter tree means shorter paths.
    depth: u8,
    /// Ascending, no duplicates. Index 0 is the `Value::ZERO` sentinel, so
    /// every real value has a predecessor and the bottom of the range is
    /// always bracketed.
    values: Vec<Value>,
    /// Level 0 is leaves. `levels[depth][0]` is the root.
    levels: Vec<Vec<Hash>>,
}

impl SortedTree {
    /// Builds the snapshot from an IMT's current contents.
    ///
    /// Reads through the IMT's own value-ordered index, so the two structures
    /// cannot disagree about *membership* by construction — only about how they
    /// prove it, which is what the differential test checks.
    pub fn from_imt(tree: &IndexedMerkleTree, height: u32) -> Result<SortedTree, CohortError> {
        let values: Vec<Value> = tree.sorted_values().collect();
        SortedTree::from_sorted_values(tree.pool(), height, values)
    }

    /// Builds from an already-ascending, duplicate-free value list.
    ///
    /// The sentinel is prepended if absent, so a caller cannot accidentally
    /// build a tree in which the smallest real nullifier has no predecessor.
    pub fn from_sorted_values(
        pool: PoolId,
        height: u32,
        mut values: Vec<Value>,
    ) -> Result<SortedTree, CohortError> {
        if values.first() != Some(&Value::ZERO) {
            values.insert(0, Value::ZERO);
        }
        if values
            .windows(2)
            .any(|w| w.first().zip(w.get(1)).is_some_and(|(a, b)| a >= b))
        {
            return Err(CohortError::UnsortedValues);
        }

        let depth = depth_for(values.len())?;
        let slots = 1usize << depth;

        let pad = hash::sorted_pad_leaf(pool);
        let mut level: Vec<Hash> = Vec::with_capacity(slots);
        for value in &values {
            level.push(hash::sorted_leaf(pool, value.as_bytes()));
        }
        level.resize(slots, pad);

        let mut levels = Vec::with_capacity(usize::from(depth).saturating_add(1));
        for _ in 0..depth {
            let mut up = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                let left = pair.first().copied().unwrap_or(pad);
                let right = pair.get(1).copied().unwrap_or(pad);
                up.push(hash::sorted_node(pool, &left, &right));
            }
            levels.push(level);
            level = up;
        }
        levels.push(level);

        Ok(SortedTree {
            pool,
            height,
            depth,
            values,
            levels,
        })
    }

    /// Which pool.
    pub fn pool(&self) -> PoolId {
        self.pool
    }

    /// The height this snapshot was taken at.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Tree depth; `2^depth` leaf slots.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Occupied leaves, including the sentinel.
    pub fn leaf_count(&self) -> u64 {
        u64::try_from(self.values.len()).unwrap_or(u64::MAX)
    }

    /// The snapshot root.
    pub fn root(&self) -> Hash {
        self.levels
            .last()
            .and_then(|top| top.first())
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// Every value whose prefix matches `range`, plus the predecessor, as one
    /// contiguous run with a range proof.
    ///
    /// The span deliberately reaches one leaf *below* the range: for an `x`
    /// smaller than every in-range value, that predecessor is the bracketing
    /// leaf, and without it the query has no answer at the bottom of its own
    /// range.
    pub fn prove_prefix_cohort(&self, range: PrefixRange) -> Result<SortedCohort, CohortError> {
        let first_in_range = self.values.partition_point(|value| *value < range.lo());
        // `partition_point` on a list that always starts with the sentinel
        // cannot return 0 for a range above zero, so there is always a
        // predecessor to step back to.
        let start = first_in_range.saturating_sub(1);
        // One *past* the range, not up to it. The last in-range value cannot
        // witness its own completeness: a verifier shown a run ending at some
        // v < hi has no way to tell whether v is genuinely the largest in the
        // range or whether the bridge stopped early. Including the first value
        // at or above `hi` settles it, and costs 32 bytes.
        let end = match range.hi() {
            Some(hi) => self
                .values
                .partition_point(|value| *value < hi)
                .saturating_add(1),
            None => self.values.len(),
        };
        // Never below `start + 1`: the predecessor stays in the span even when
        // the range itself holds nothing.
        let end = end.max(start.saturating_add(1)).min(self.values.len());

        let values = self
            .values
            .get(start..end)
            .ok_or(CohortError::UnsortedValues)?
            .to_vec();
        let start_index = u64::try_from(start).unwrap_or(u64::MAX);
        let siblings = self.range_siblings(start, end)?;

        Ok(SortedCohort {
            pool: self.pool,
            depth: self.depth,
            height: self.height,
            leaf_count: self.leaf_count(),
            range,
            start_index,
            values,
            siblings,
        })
    }

    /// Fringe siblings needed to fold leaves `[start, end)` to the root.
    ///
    /// At most two per level — the run is contiguous, so everything interior
    /// is recomputed from the values themselves. This is why cost is
    /// `O(log n)` in the proof and `O(k)` only in the values.
    fn range_siblings(
        &self,
        start: usize,
        end: usize,
    ) -> Result<BTreeMap<(u8, u64), Hash>, CohortError> {
        let mut out = BTreeMap::new();
        let pad = hash::sorted_pad_leaf(self.pool);
        let (mut lo, mut hi) = (start, end.saturating_sub(1));

        for level in 0..self.depth {
            let row = self.levels.get(usize::from(level));
            let at =
                |index: usize| -> Hash { row.and_then(|r| r.get(index)).copied().unwrap_or(pad) };
            // A left edge on an odd index has an unknown left sibling; a right
            // edge on an even index has an unknown right sibling. Everything
            // between them is derivable.
            if lo % 2 == 1 {
                let sibling = lo.saturating_sub(1);
                out.insert(
                    (level, u64::try_from(sibling).unwrap_or(u64::MAX)),
                    at(sibling),
                );
            }
            if hi % 2 == 0 {
                let sibling = hi.saturating_add(1);
                out.insert(
                    (level, u64::try_from(sibling).unwrap_or(u64::MAX)),
                    at(sibling),
                );
            }
            lo /= 2;
            hi /= 2;
        }
        Ok(out)
    }

    /// Values ascending, sentinel first. For the differential test.
    pub fn values(&self) -> &[Value] {
        &self.values
    }
}

/// Smallest `depth` with `2^depth >= count`.
fn depth_for(count: usize) -> Result<u8, CohortError> {
    let mut depth = 0u8;
    while (1usize << depth) < count {
        depth = depth.saturating_add(1);
        if depth > MAX_SORTED_DEPTH {
            return Err(CohortError::InvalidPrefixBits {
                bits: depth,
                max: MAX_SORTED_DEPTH,
            });
        }
    }
    Ok(depth)
}

/// A contiguous run of sorted nullifiers, with the proof binding it to a root.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SortedCohort {
    /// Which pool.
    pub pool: PoolId,
    /// Depth of the snapshot tree.
    pub depth: u8,
    /// Height the snapshot was taken at.
    pub height: u32,
    /// Occupied leaves in the snapshot, so the verifier can tell "the run ends
    /// because the range ends" from "the run ends because the tree does".
    pub leaf_count: u64,
    /// The prefix range answered for.
    pub range: PrefixRange,
    /// Leaf index of `values[0]`.
    pub start_index: u64,
    /// Ascending values at consecutive positions from `start_index`.
    pub values: Vec<Value>,
    /// Fringe siblings, at most two per level.
    pub siblings: BTreeMap<(u8, u64), Hash>,
}

impl SortedCohort {
    /// Members the wallet reasons over. One is the predecessor, so the
    /// anonymity set is `member_count() - 1`.
    pub fn member_count(&self) -> usize {
        self.values.len()
    }
}

/// Checks a cohort against a trusted snapshot root and returns its values.
///
/// Three things are established, and the third is the one the IMT cohort could
/// not offer:
///
/// 1. **Authenticity** — the run folds to `root`.
/// 2. **Order** — values ascend, so bracketing is well defined.
/// 3. **Completeness** — the run spans the entire prefix range. Its first value
///    lies below `range.lo`, and it continues past `range.hi` or to the last
///    occupied leaf. A bridge cannot omit a member: doing so would leave a
///    position inside the span without a value, and the span is contiguous by
///    construction.
pub fn verify_cohort(root: &Hash, cohort: &SortedCohort) -> Result<Vec<Value>, CohortError> {
    if cohort.depth > MAX_SORTED_DEPTH {
        return Err(CohortError::InvalidPrefixBits {
            bits: cohort.depth,
            max: MAX_SORTED_DEPTH,
        });
    }
    if cohort.values.is_empty() {
        return Err(CohortError::UnsortedValues);
    }
    let slots = 1u64 << cohort.depth;
    let span = u64::try_from(cohort.values.len()).unwrap_or(u64::MAX);
    let end = cohort
        .start_index
        .checked_add(span)
        .ok_or(CohortError::UnorderedLeaves)?;
    if end > slots || cohort.leaf_count > slots {
        return Err(CohortError::UnorderedLeaves);
    }
    if cohort
        .values
        .windows(2)
        .any(|w| w.first().zip(w.get(1)).is_some_and(|(a, b)| a >= b))
    {
        return Err(CohortError::UnsortedValues);
    }

    // Completeness. The first value must sit below the range, or the run must
    // start at the sentinel; the last must sit at or above `hi`, or the run
    // must reach the final occupied leaf.
    let first = cohort.values.first().copied().unwrap_or(Value::ZERO);
    if cohort.range.contains(&first) && cohort.start_index != 0 {
        return Err(CohortError::LeafOutOfRange);
    }
    let reaches_end = end >= cohort.leaf_count;
    let past_hi = match cohort.range.hi() {
        Some(hi) => cohort.values.last().is_some_and(|last| *last >= hi),
        None => true,
    };
    if !reaches_end && !past_hi {
        return Err(CohortError::LeafOutOfRange);
    }

    // Fold the run.
    let pad = hash::sorted_pad_leaf(cohort.pool);
    let mut index = cohort.start_index;
    let mut level_nodes: Vec<Hash> = cohort
        .values
        .iter()
        .map(|value| hash::sorted_leaf(cohort.pool, value.as_bytes()))
        .collect();

    for level in 0..cohort.depth {
        let mut parents: Vec<Hash> = Vec::with_capacity(level_nodes.len().div_ceil(2) + 1);
        let mut cursor = index;
        let mut position = 0usize;

        // Left fringe: an odd start needs its left sibling supplied.
        if cursor % 2 == 1 {
            let sibling_index = cursor.saturating_sub(1);
            let sibling = fringe(cohort, level, sibling_index, &pad)?;
            let node = level_nodes.first().copied().unwrap_or(pad);
            parents.push(hash::sorted_node(cohort.pool, &sibling, &node));
            position = 1;
            cursor = cursor.saturating_add(1);
        }

        while position < level_nodes.len() {
            let left = level_nodes.get(position).copied().unwrap_or(pad);
            match level_nodes.get(position.saturating_add(1)) {
                Some(right) => parents.push(hash::sorted_node(cohort.pool, &left, right)),
                None => {
                    // Right fringe: an even end needs its right sibling.
                    let sibling = fringe(cohort, level, cursor.saturating_add(1), &pad)?;
                    parents.push(hash::sorted_node(cohort.pool, &left, &sibling));
                }
            }
            position = position.saturating_add(2);
            cursor = cursor.saturating_add(2);
        }

        index /= 2;
        level_nodes = parents;
    }

    let computed = level_nodes.first().ok_or(CohortError::RootMismatch)?;
    if computed != root {
        return Err(CohortError::RootMismatch);
    }
    Ok(cohort.values.clone())
}

/// A supplied fringe sibling, or the pad when the position is past the tree.
///
/// Falling back to the pad rather than erroring is what lets a run that reaches
/// the end of the occupied leaves verify without the encoder having to ship a
/// column of identical padding hashes.
fn fringe(cohort: &SortedCohort, level: u8, index: u64, pad: &Hash) -> Result<Hash, CohortError> {
    match cohort.siblings.get(&(level, index)) {
        Some(hash) => Ok(*hash),
        None => Ok(*pad),
    }
}

/// Settles `value` locally against a verified cohort.
///
/// No gap check is needed, unlike [`crate::cohort::resolve`]: completeness was
/// established in [`verify_cohort`], so the bracketing pair here is the
/// bracketing pair in the tree.
pub fn resolve(values: &[Value], range: &PrefixRange, value: Value) -> Result<Status, CohortError> {
    if !range.contains(&value) {
        return Err(CohortError::LeafOutOfRange);
    }
    match values.binary_search(&value) {
        Ok(_) => Ok(Status::Spent),
        Err(position) => {
            let below = position
                .checked_sub(1)
                .and_then(|i| values.get(i))
                .copied()
                .ok_or(CohortError::LeafOutOfRange)?;
            let above = values.get(position).copied();
            Ok(Status::Unspent {
                low: crate::imt::Leaf {
                    value: below,
                    next_value: above.unwrap_or(Value::ZERO),
                    next_index: 0,
                },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

    use super::*;

    const POOL: PoolId = PoolId::Orchard;

    fn value(a: u8, b: u8, tail: u8) -> Value {
        let mut bytes = [tail; 32];
        bytes[0] = a;
        bytes[1] = b;
        Value::from_bytes(bytes)
    }

    fn seeded() -> SortedTree {
        let mut values = Vec::new();
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..300 {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let mixed = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
            values.push(value(
                (mixed >> 56) as u8,
                (mixed >> 48) as u8,
                (mixed >> 40) as u8,
            ));
        }
        values.sort_unstable();
        values.dedup();
        SortedTree::from_sorted_values(POOL, 3_455_225, values).expect("builds")
    }

    #[test]
    fn depth_is_the_tightest_power_of_two() {
        assert_eq!(depth_for(1).expect("ok"), 0);
        assert_eq!(depth_for(2).expect("ok"), 1);
        assert_eq!(depth_for(3).expect("ok"), 2);
        assert_eq!(depth_for(1024).expect("ok"), 10);
        assert_eq!(depth_for(1025).expect("ok"), 11);
    }

    #[test]
    fn the_sentinel_is_always_present() {
        // Without it the smallest real nullifier has no predecessor and the
        // bottom of any range covering it cannot be answered.
        let tree = SortedTree::from_sorted_values(POOL, 0, vec![value(0x10, 0, 0)]).expect("ok");
        assert_eq!(tree.values()[0], Value::ZERO);
        assert_eq!(tree.leaf_count(), 2);
    }

    #[test]
    fn unsorted_input_is_refused() {
        let out = SortedTree::from_sorted_values(
            POOL,
            0,
            vec![Value::ZERO, value(0x20, 0, 0), value(0x10, 0, 0)],
        );
        assert_eq!(out, Err(CohortError::UnsortedValues));
    }

    #[test]
    fn duplicate_input_is_refused() {
        let out = SortedTree::from_sorted_values(
            POOL,
            0,
            vec![Value::ZERO, value(0x20, 0, 0), value(0x20, 0, 0)],
        );
        assert_eq!(out, Err(CohortError::UnsortedValues));
    }

    #[test]
    fn a_cohort_verifies_and_covers_its_whole_range() {
        let tree = seeded();
        for bits in [4u8, 8, 12] {
            for probe in [0x00u8, 0x40, 0x80, 0xc0, 0xff] {
                let range = PrefixRange::covering(value(probe, 0, 0), bits).expect("width");
                let cohort = tree.prove_prefix_cohort(range).expect("cohort");
                let values = verify_cohort(&tree.root(), &cohort).expect("folds");

                // Everything the tree holds in the range must be present.
                let expected: Vec<Value> = tree
                    .values()
                    .iter()
                    .copied()
                    .filter(|v| range.contains(v))
                    .collect();
                for want in expected {
                    assert!(
                        values.contains(&want),
                        "bits={bits} probe={probe:02x}: cohort dropped {want:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_cohort_answers_the_same_as_the_tree_itself() {
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0, 0), 8).expect("width");
        let cohort = tree.prove_prefix_cohort(range).expect("cohort");
        let values = verify_cohort(&tree.root(), &cohort).expect("folds");

        for b in 0..=0xffu8 {
            let probe = value(0x80, b, 0x00);
            let truth = tree.values().binary_search(&probe).is_ok();
            match resolve(&values, &range, probe).expect("settles") {
                Status::Spent => assert!(truth, "claimed spent, is not"),
                Status::Unspent { low } => {
                    assert!(!truth, "claimed unspent, is not");
                    assert!(low.value < probe, "bracket must be below");
                }
            }
        }
    }

    #[test]
    fn a_tampered_value_breaks_the_fold() {
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0, 0), 8).expect("width");
        let mut cohort = tree.prove_prefix_cohort(range).expect("cohort");
        let last = cohort.values.len() - 1;
        cohort.values[last] = value(0xfe, 0xfe, 0xfe);
        assert!(verify_cohort(&tree.root(), &cohort).is_err());
    }

    #[test]
    fn a_tampered_sibling_breaks_the_fold() {
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0, 0), 8).expect("width");
        let mut cohort = tree.prove_prefix_cohort(range).expect("cohort");
        if let Some((&key, _)) = cohort.siblings.iter().next() {
            cohort.siblings.insert(key, [0x5au8; 32]);
        }
        assert_eq!(
            verify_cohort(&tree.root(), &cohort),
            Err(CohortError::RootMismatch)
        );
    }

    #[test]
    fn omitting_a_member_cannot_pass_as_absence() {
        // The attack `cohort::resolve` has to catch by hand. Here it is
        // structural: members sit at consecutive positions, so removing one
        // shortens the run and the remaining values no longer fold from
        // `start_index` to the root.
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0, 0), 3).expect("width");
        let mut cohort = tree.prove_prefix_cohort(range).expect("cohort");
        assert!(cohort.values.len() > 3, "need a member to drop");

        let dropped = cohort.values.remove(2);
        assert!(
            verify_cohort(&tree.root(), &cohort).is_err(),
            "a run with a hole in it must not verify"
        );

        // And the value really was in the range, so this was a live attack.
        assert!(range.contains(&dropped));
    }

    #[test]
    fn a_truncated_run_that_stops_short_of_the_range_is_refused() {
        // Dropping from the *end* keeps the remaining positions contiguous, so
        // the fold can be made to work. Completeness is what rejects it.
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0, 0), 4).expect("width");
        let full = tree.prove_prefix_cohort(range).expect("cohort");
        assert!(full.values.len() > 4, "need room to truncate");

        let start = usize::try_from(full.start_index).expect("fits");
        let short_len = full.values.len() - 2;
        let rebuilt = tree
            .range_siblings(start, start + short_len)
            .expect("siblings");
        let short = SortedCohort {
            values: full.values[..short_len].to_vec(),
            siblings: rebuilt,
            ..full.clone()
        };

        // The truncated run is a perfectly good Merkle proof of what it holds.
        // It is refused for not reaching the top of the range.
        assert_eq!(
            verify_cohort(&tree.root(), &short),
            Err(CohortError::LeafOutOfRange),
            "a run that stops inside its own range must be refused"
        );
    }

    #[test]
    fn a_run_reaching_the_last_leaf_needs_no_upper_bound() {
        // The top bucket has no value above it. Requiring one would make the
        // highest nullifiers unanswerable.
        let tree = seeded();
        let range = PrefixRange::covering(Value::MAX, 4).expect("width");
        let cohort = tree.prove_prefix_cohort(range).expect("cohort");
        let values = verify_cohort(&tree.root(), &cohort).expect("folds");
        assert!(!values.is_empty());
    }

    #[test]
    fn the_snapshot_reports_what_it_is() {
        let tree = seeded();
        assert_eq!(tree.pool(), POOL);
        assert_eq!(tree.height(), 3_455_225);
    }

    #[test]
    fn verify_rejects_a_hand_built_cohort_that_the_codec_would_never_emit() {
        // These guards sit behind the codec, which rejects first, so nothing
        // reaches them through the wire today. They are still the last line if
        // a cohort ever arrives by another route -- a second codec, a test
        // helper, a future batched request -- and an unchecked `depth` drives
        // the fold loop while an empty `values` makes the fold meaningless.
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0, 0), 4).expect("width");
        let good = tree.prove_prefix_cohort(range).expect("cohort");

        let over_deep = SortedCohort {
            depth: MAX_SORTED_DEPTH + 1,
            ..good.clone()
        };
        assert_eq!(
            verify_cohort(&tree.root(), &over_deep),
            Err(CohortError::InvalidPrefixBits {
                bits: MAX_SORTED_DEPTH + 1,
                max: MAX_SORTED_DEPTH
            })
        );

        let empty = SortedCohort {
            values: Vec::new(),
            ..good.clone()
        };
        assert_eq!(
            verify_cohort(&tree.root(), &empty),
            Err(CohortError::UnsortedValues)
        );

        // Claiming a span that runs past the tree's own leaf slots.
        let overrun = SortedCohort {
            start_index: u64::MAX,
            ..good.clone()
        };
        assert_eq!(
            verify_cohort(&tree.root(), &overrun),
            Err(CohortError::UnorderedLeaves)
        );
    }

    #[test]
    fn a_cohort_missing_its_predecessor_is_refused() {
        // Dropping the leading witness leaves a run whose first value is inside
        // the range, so the bottom of that range has nothing bracketing it.
        // Without this check a wallet asking about a value below every member
        // would get an answer derived from no evidence.
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0, 0), 3).expect("width");
        let full = tree.prove_prefix_cohort(range).expect("cohort");
        assert!(full.start_index > 0, "fixture needs a real predecessor");

        let start = usize::try_from(full.start_index).expect("fits") + 1;
        let rebuilt = tree
            .range_siblings(start, start + full.values.len() - 1)
            .expect("siblings");
        let headless = SortedCohort {
            values: full.values[1..].to_vec(),
            start_index: full.start_index + 1,
            siblings: rebuilt,
            ..full.clone()
        };
        assert_eq!(
            verify_cohort(&tree.root(), &headless),
            Err(CohortError::LeafOutOfRange),
            "a run starting inside its own range must be refused"
        );
    }

    #[test]
    fn resolve_refuses_a_value_the_cohort_does_not_cover() {
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0, 0), 8).expect("width");
        let cohort = tree.prove_prefix_cohort(range).expect("cohort");
        let values = verify_cohort(&tree.root(), &cohort).expect("folds");
        assert_eq!(
            resolve(&values, &range, value(0x10, 0, 0)),
            Err(CohortError::LeafOutOfRange),
            "a cohort only answers for its own range"
        );
    }

    #[test]
    fn a_cohort_costs_thirty_two_bytes_a_member_plus_a_path() {
        // The claim the whole design rests on: proof size is O(log n), so cost
        // per member is the value and nothing else.
        let tree = seeded();
        let narrow = PrefixRange::covering(value(0x80, 0, 0), 12).expect("width");
        let wide = PrefixRange::covering(value(0x80, 0, 0), 2).expect("width");
        let a = tree.prove_prefix_cohort(narrow).expect("cohort");
        let b = tree.prove_prefix_cohort(wide).expect("cohort");

        assert!(b.member_count() > a.member_count(), "wide must hold more");
        assert!(
            b.siblings.len() <= 2 * usize::from(tree.depth()),
            "fringe is at most two per level regardless of members"
        );
        assert!(
            b.siblings.len() < b.member_count(),
            "a wide cohort must be dominated by values, not by proof"
        );
    }
}

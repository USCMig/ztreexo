//! Prefix-cohort non-membership: answering "is X spent?" without revealing X.
//!
//! # Why this exists
//!
//! `docs/design.md` D35 concluded that Phase 5a's headline capability — cheap
//! watch-only spend-status checking — cannot be delivered privately by asking a
//! bridge for one specific nullifier's non-membership proof. The request *is*
//! the leak. Every mitigation examined there was defeated except one, and this
//! module is that one, built so it can be measured rather than argued about.
//!
//! The wallet reveals a `b`-bit prefix instead of a value, and receives enough
//! of the tree to settle membership for **any** value sharing that prefix. The
//! bridge learns only that the value of interest lies among the roughly
//! `2^-b · |set|` real nullifiers in the range.
//!
//! ## Why this survives where decoys do not
//!
//! D35's objection to decoys is retrospective correlation: the real nullifier
//! eventually appears on-chain when the note is spent, and every decoy that
//! never appears is exposed as a decoy, collapsing the anonymity set to one
//! after the fact. A prefix cohort has no such collapse, because the other
//! members are **genuine nullifiers belonging to other people**. They appear
//! on-chain too. The ambiguity is permanent.
//!
//! # What the wallet needs, and why it is exactly this
//!
//! To settle non-membership of `X` the wallet needs the leaf `L` bracketing it:
//! `L.value < X < L.next_value`. For an arbitrary `X` in the range
//! `[lo, hi)`, that leaf is one of:
//!
//! * a leaf whose value lies in `[lo, X)` — necessarily in the cohort range; or
//! * if no such leaf exists, the **predecessor**: the greatest value below `lo`.
//!
//! No leaf outside `[lo, hi)` other than the predecessor can ever be the answer,
//! because any in-range leaf below `X` is a strictly better (larger) candidate.
//! So the cohort is *every in-range leaf, plus one*, and that is both sufficient
//! and minimal.
//!
//! The wallet also learns membership for free: if some cohort leaf's value
//! equals `X`, the nullifier is spent. That is the question actually being
//! asked.
//!
//! # Deduplication
//!
//! Cohort leaves sit at **insertion-order** indices, so a value range is not a
//! contiguous subtree (§2.1 — the IMT keeps sortedness in the `next_index`
//! linked list, not in the layout). Their Merkle paths are therefore scattered,
//! but they still converge toward the root, and near the top they converge
//! completely.
//!
//! [`CohortProof`] stores the union of those paths once. A node is on the wire
//! only if it is needed by some leaf's path *and* not itself recomputable from
//! nodes below it — and, reusing the argument in `proof.rs`, only if it differs
//! from the canonical empty-subtree hash for its level.
//!
//! Whether that dedup is worth anything is the measurement
//! `zutreexo-testkit/src/bin/cohort_cost.rs` exists to take.

use std::collections::{BTreeMap, BTreeSet};

use crate::hash::{self, Hash};
use crate::imt::{check_depth, empty_subtree_hashes, ImtError, IndexedMerkleTree, Leaf, Value};
use crate::pool::PoolId;

/// The widest prefix a cohort may be asked for.
///
/// A 0-bit prefix is the whole set, which is not a query. The cap is 32 because
/// beyond it the cohort is a single leaf for any pool this project will see —
/// at 2^32 buckets even Orchard's 50.4M nullifiers average 0.01 per bucket — so
/// the request degenerates into naming the value.
pub const MAX_PREFIX_BITS: u8 = 32;

/// Everything that can go wrong building or checking a cohort.
///
/// Typed rather than panicking, per CLAUDE.md §5 rule 3: these run on
/// bridge-supplied and wallet-supplied input.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum CohortError {
    /// Prefix width outside `1..=MAX_PREFIX_BITS`.
    #[error("prefix of {bits} bits is outside 1..={max}")]
    InvalidPrefixBits {
        /// The width asked for.
        bits: u8,
        /// The largest accepted.
        max: u8,
    },
    /// The tree could not answer.
    #[error("tree error: {0}")]
    Tree(#[from] ImtError),
    /// A cohort leaf's path could not be folded to the trusted root.
    #[error("cohort does not fold to the trusted root")]
    RootMismatch,
    /// A node the verifier needed was absent from the proof.
    #[error("proof omits node at level {level} index {index}")]
    MissingNode {
        /// Level, 0 at the leaves.
        level: u8,
        /// Node index within the level.
        index: u64,
    },
    /// Two leaves claimed the same index, or indices were not ascending.
    #[error("cohort leaf indices are not strictly ascending")]
    UnorderedLeaves,
    /// A leaf in the proof falls outside the range it was requested for.
    #[error("cohort contains a leaf outside the requested range")]
    LeafOutOfRange,
    /// The linked list through the cohort is inconsistent.
    #[error("cohort leaves are not sorted by value")]
    UnsortedValues,
}

/// A half-open range of nullifier values sharing a `bits`-wide prefix.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PrefixRange {
    /// Inclusive lower bound.
    lo: Value,
    /// Exclusive upper bound; `None` means "up to and including `Value::MAX`",
    /// which is the top bucket and has no representable successor.
    hi: Option<Value>,
    /// Prefix width in bits.
    bits: u8,
}

impl PrefixRange {
    /// The range of values whose top `bits` bits equal the top `bits` bits of
    /// `value`.
    ///
    /// Taking the bucket from a value rather than from a raw integer keeps the
    /// caller from having to think about bit order: nullifiers are big-endian
    /// 256-bit integers ([`Value`]), so the prefix is simply the leading bytes.
    pub fn covering(value: Value, bits: u8) -> Result<PrefixRange, CohortError> {
        if bits == 0 || bits > MAX_PREFIX_BITS {
            return Err(CohortError::InvalidPrefixBits {
                bits,
                max: MAX_PREFIX_BITS,
            });
        }

        let bytes = value.to_bytes();
        let mut lo = [0u8; 32];
        let full = usize::from(bits / 8);
        let rem = bits % 8;
        // `full <= 4` since bits <= MAX_PREFIX_BITS, so both slices exist; the
        // guarded form keeps the function total rather than relying on that.
        if let (Some(dst), Some(src)) = (lo.get_mut(..full), bytes.get(..full)) {
            dst.copy_from_slice(src);
        }
        if rem != 0 {
            // Keep the top `rem` bits of the straddled byte, clear the rest.
            let mask = 0xffu8 << (8 - rem);
            if let (Some(dst), Some(src)) = (lo.get_mut(full), bytes.get(full)) {
                *dst = *src & mask;
            }
        }

        // `hi = lo + 2^(256-bits)`, i.e. increment the last prefix bit. When
        // that carries off the top the bucket is the final one and has no
        // exclusive upper bound.
        let mut hi = lo;
        let carry_pos = if rem == 0 {
            full.checked_sub(1)
        } else {
            Some(full)
        };
        let step: u8 = if rem == 0 { 1 } else { 1 << (8 - rem) };

        let overflow = match carry_pos {
            None => true,
            Some(pos) => {
                let mut idx = pos;
                let mut add = step;
                loop {
                    let Some(slot) = hi.get_mut(idx) else {
                        break true;
                    };
                    let (sum, carried) = slot.overflowing_add(add);
                    *slot = sum;
                    if !carried {
                        break false;
                    }
                    let Some(next) = idx.checked_sub(1) else {
                        break true;
                    };
                    idx = next;
                    add = 1;
                }
            }
        };

        Ok(PrefixRange {
            lo: Value::from_bytes(lo),
            hi: if overflow {
                None
            } else {
                Some(Value::from_bytes(hi))
            },
            bits,
        })
    }

    /// Inclusive lower bound.
    pub fn lo(&self) -> Value {
        self.lo
    }

    /// Exclusive upper bound, or `None` for the topmost bucket.
    pub fn hi(&self) -> Option<Value> {
        self.hi
    }

    /// Prefix width in bits.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Whether `value` falls in this range.
    pub fn contains(&self, value: &Value) -> bool {
        *value >= self.lo && self.hi.is_none_or(|hi| *value < hi)
    }
}

/// A cohort of leaves and the deduplicated nodes proving all of them at once.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CohortProof {
    /// Which pool's tree.
    pub pool: PoolId,
    /// That tree's depth.
    pub depth: u8,
    /// The range the cohort answers for.
    pub range: PrefixRange,
    /// `(leaf index, leaf)` for the predecessor and every in-range leaf,
    /// ascending by index.
    ///
    /// Index order, not value order: the index is what places a leaf in the
    /// tree, and sorting by it makes the encoding canonical and the dedup walk
    /// straightforward. The wallet re-sorts by value locally.
    pub leaves: Vec<(u64, Leaf)>,
    /// The union of the leaves' sibling paths, minus everything derivable:
    /// nodes recomputable from the level below, and empty-subtree hashes.
    pub nodes: BTreeMap<(u8, u64), Hash>,
}

/// A [`CohortProof`] stated against the root at a specific height.
///
/// The wire type. Same split as [`crate::proof::NonMembershipResponse`] and for
/// the same reason: a proof is only meaningful against a root, a root only
/// exists at a height, and without the height a stale cohort is
/// indistinguishable from a fresh one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CohortResponse {
    /// Height whose root this is stated against.
    pub height: u32,
    /// The cohort itself.
    pub proof: CohortProof,
}

impl CohortProof {
    /// Pairs this cohort with the height its root belongs to.
    pub fn at_height(self, height: u32) -> CohortResponse {
        CohortResponse {
            height,
            proof: self,
        }
    }

    /// Number of leaves the wallet gets to reason over — the anonymity set.
    ///
    /// One of them is the predecessor, which is outside the range and is a
    /// witness rather than a candidate; the caller decides whether to count it.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Number of internal nodes actually on the wire.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl IndexedMerkleTree {
    /// Every leaf whose value lies in `range`, plus the greatest leaf below it.
    ///
    /// This is the bridge side of a private spend-status query. The set is
    /// derived from `index_by_value`, which the tree already maintains — the
    /// value-sorted index this needs is not new state.
    pub fn prove_prefix_cohort(&self, range: PrefixRange) -> Result<CohortProof, CohortError> {
        let mut indices: BTreeSet<u64> = BTreeSet::new();

        // The predecessor: greatest value strictly below `lo`. The sentinel at
        // `Value::ZERO` guarantees one exists for every range, which is exactly
        // why the sentinel is there.
        if let Some((_, index)) = self.values_below(range.lo).next_back() {
            indices.insert(index);
        }
        for (_, index) in self.values_in(range) {
            indices.insert(index);
        }

        let mut leaves = Vec::with_capacity(indices.len());
        for index in &indices {
            let leaf = self.leaf(*index).ok_or(ImtError::CorruptTree(
                "value index points at a missing leaf",
            ))?;
            leaves.push((*index, leaf));
        }

        let nodes = self.dedup_paths(&indices)?;

        Ok(CohortProof {
            pool: self.pool(),
            depth: self.depth(),
            range,
            leaves,
            nodes,
        })
    }

    /// The union of the sibling paths for `indices`, with derivable nodes cut.
    ///
    /// Walks bottom-up keeping the set of nodes the verifier can already
    /// compute at each level. A sibling is emitted only when the verifier
    /// cannot get it any other way: not computable from the level below (both
    /// children known), and not the canonical empty hash for its level.
    fn dedup_paths(&self, indices: &BTreeSet<u64>) -> Result<BTreeMap<(u8, u64), Hash>, ImtError> {
        let ladder = empty_subtree_hashes(self.pool(), self.depth())?;
        let mut out = BTreeMap::new();

        // Nodes the verifier holds at the current level. At level 0 those are
        // the cohort leaves themselves, which travel in `leaves`.
        let mut known: BTreeSet<u64> = indices.iter().copied().collect();

        for level in 0..self.depth() {
            let mut next: BTreeSet<u64> = BTreeSet::new();
            for index in &known {
                let sibling = index ^ 1;
                // Derivable: the sibling is itself a node the verifier holds,
                // so sending it would be redundant. This is where the sharing
                // between nearby cohort leaves is actually collected.
                if !known.contains(&sibling) {
                    let hash = self.node_at(level, sibling);
                    // Derivable: canonical empty subtree. Same argument as
                    // `proof.rs`'s sparse path — a lying encoder can omit a
                    // non-empty node, but then the fold misses the root.
                    if ladder.get(usize::from(level)) != Some(&hash) {
                        out.insert((level, sibling), hash);
                    }
                }
                next.insert(index >> 1);
            }
            known = next;
        }

        Ok(out)
    }
}

/// Checks a cohort against a trusted root and returns its leaves in value
/// order.
///
/// Verifying means recomputing the root from the cohort leaves and the supplied
/// nodes. Nothing about the *range* is trusted: a bridge that omits an in-range
/// leaf produces a cohort that still folds correctly, so the range check below
/// is what makes omission detectable — see [`resolve`].
pub fn verify_cohort(root: &Hash, proof: &CohortProof) -> Result<Vec<Leaf>, CohortError> {
    check_depth(proof.depth).map_err(CohortError::Tree)?;
    let ladder = empty_subtree_hashes(proof.pool, proof.depth).map_err(CohortError::Tree)?;

    // Strictly ascending indices: a repeated index would let a proof carry two
    // different leaves for one slot and pick whichever suits.
    let mut previous: Option<u64> = None;
    for (index, _) in &proof.leaves {
        if previous.is_some_and(|p| *index <= p) {
            return Err(CohortError::UnorderedLeaves);
        }
        previous = Some(*index);
    }

    let mut level_nodes: BTreeMap<u64, Hash> = proof
        .leaves
        .iter()
        .map(|(index, leaf)| (*index, leaf.hash(proof.pool)))
        .collect();

    for level in 0..proof.depth {
        let mut parents: BTreeMap<u64, Hash> = BTreeMap::new();
        for (index, hash) in &level_nodes {
            let sibling_index = index ^ 1;
            let sibling = match level_nodes.get(&sibling_index) {
                Some(known) => *known,
                None => match proof.nodes.get(&(level, sibling_index)) {
                    Some(sent) => *sent,
                    // Absent from both means the encoder judged it derivable,
                    // which can only mean the empty-subtree hash.
                    None => *ladder
                        .get(usize::from(level))
                        .ok_or(CohortError::MissingNode {
                            level,
                            index: sibling_index,
                        })?,
                },
            };
            let parent = if index & 1 == 0 {
                hash::imt_node(proof.pool, hash, &sibling)
            } else {
                hash::imt_node(proof.pool, &sibling, hash)
            };
            parents.insert(index >> 1, parent);
        }
        level_nodes = parents;
    }

    let computed = level_nodes.get(&0).ok_or(CohortError::RootMismatch)?;
    if computed != root {
        return Err(CohortError::RootMismatch);
    }

    let mut leaves: Vec<Leaf> = proof.leaves.iter().map(|(_, leaf)| *leaf).collect();
    leaves.sort_by_key(|leaf| leaf.value);
    Ok(leaves)
}

/// What a wallet learns about one value from a verified cohort.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// The nullifier is in the set — the note is spent.
    Spent,
    /// The nullifier is absent, witnessed by this bracketing leaf.
    Unspent {
        /// The leaf proving absence: `low.value < value < low.next_value`.
        low: Leaf,
    },
}

/// Settles `value` locally against a verified cohort.
///
/// This is the whole point: the bridge never sees `value`. It runs on the
/// wallet, over leaves already checked by [`verify_cohort`].
///
/// # What a hostile bridge can and cannot do
///
/// It cannot forge `Spent` — that needs a leaf holding `value`, which must fold
/// to the trusted root. It cannot forge `Unspent` for a spent value either: the
/// bracketing leaf would have to claim a `next_value` above `value` while the
/// real leaf holding `value` sits between, and the linked list is committed to
/// leaf by leaf.
///
/// It *can* omit in-range leaves. That is caught here rather than in
/// [`verify_cohort`], because an incomplete cohort is still a valid Merkle
/// proof of the leaves it does contain: the bracketing leaf's own
/// `next_value` must not point into the range at a value the cohort failed to
/// deliver. A gap means the cohort is short and the answer is refused.
pub fn resolve(leaves: &[Leaf], range: &PrefixRange, value: Value) -> Result<Status, CohortError> {
    if !range.contains(&value) {
        return Err(CohortError::LeafOutOfRange);
    }

    let mut low: Option<Leaf> = None;
    let mut previous: Option<Value> = None;
    for leaf in leaves {
        if previous.is_some_and(|p| leaf.value < p) {
            return Err(CohortError::UnsortedValues);
        }
        previous = Some(leaf.value);

        if leaf.value == value {
            return Ok(Status::Spent);
        }
        if leaf.value < value {
            low = Some(*leaf);
        }
    }

    let low = low.ok_or(CohortError::LeafOutOfRange)?;
    if !low.covers(&value) {
        // `low` is the greatest cohort value below `value`, yet it does not
        // bracket it — so a leaf between the two exists and was not delivered.
        return Err(CohortError::UnsortedValues);
    }
    Ok(Status::Unspent { low })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;

    const POOL: PoolId = PoolId::Orchard;
    const D: u8 = 10;

    fn value(byte0: u8, byte1: u8, tail: u8) -> Value {
        let mut bytes = [tail; 32];
        bytes[0] = byte0;
        bytes[1] = byte1;
        Value::from_bytes(bytes)
    }

    #[test]
    fn a_prefix_range_is_the_bucket_its_value_falls_in() {
        let range = PrefixRange::covering(value(0xab, 0xcd, 0x11), 16).expect("valid width");
        assert_eq!(
            range.lo(),
            Value::from_bytes({
                let mut b = [0u8; 32];
                b[0] = 0xab;
                b[1] = 0xcd;
                b
            })
        );
        assert!(range.contains(&value(0xab, 0xcd, 0x00)));
        assert!(range.contains(&value(0xab, 0xcd, 0xff)));
        assert!(!range.contains(&value(0xab, 0xce, 0x00)));
        assert!(!range.contains(&value(0xab, 0xcc, 0xff)));
    }

    #[test]
    fn a_straddled_byte_masks_rather_than_truncates() {
        // 12 bits: one whole byte plus the top nibble of the next.
        let range = PrefixRange::covering(value(0xab, 0xcd, 0x11), 12).expect("valid width");
        let lo = range.lo().to_bytes();
        assert_eq!(lo[0], 0xab);
        assert_eq!(
            lo[1], 0xc0,
            "low nibble must be cleared, not the whole byte"
        );
        let hi = range.hi().expect("not the top bucket").to_bytes();
        assert_eq!(hi[1], 0xd0);
    }

    #[test]
    fn the_top_bucket_has_no_exclusive_upper_bound() {
        // Incrementing the prefix carries off the end of the 256-bit integer,
        // so there is no representable `hi`. Left unhandled this is an
        // overflow panic or a wrapped range that matches nothing.
        let range = PrefixRange::covering(Value::MAX, 8).expect("valid width");
        assert_eq!(range.hi(), None);
        assert!(range.contains(&Value::MAX));
        assert!(range.contains(&value(0xff, 0x00, 0x00)));
        assert!(!range.contains(&value(0xfe, 0xff, 0xff)));
    }

    #[test]
    fn a_zero_width_prefix_is_refused() {
        // Zero bits is the whole set, which is not a query.
        assert_eq!(
            PrefixRange::covering(Value::MAX, 0),
            Err(CohortError::InvalidPrefixBits {
                bits: 0,
                max: MAX_PREFIX_BITS
            })
        );
        assert!(PrefixRange::covering(Value::MAX, MAX_PREFIX_BITS + 1).is_err());
    }

    /// A tree with values spread across three 8-bit buckets.
    fn seeded() -> IndexedMerkleTree {
        let mut tree = IndexedMerkleTree::with_depth(POOL, D).expect("depth is valid");
        // Insert in an order unrelated to value order, so index order and value
        // order genuinely differ — that difference is what the cohort walk has
        // to cope with.
        for (a, b) in [
            (0x40u8, 0x10u8),
            (0x80, 0x30),
            (0x40, 0x50),
            (0xc0, 0x70),
            (0x80, 0x10),
            (0x40, 0x90),
            (0x80, 0x50),
            (0xc0, 0x20),
        ] {
            tree.insert(value(a, b, 0x00)).expect("fresh value");
        }
        tree
    }

    #[test]
    fn a_cohort_holds_every_in_range_leaf_and_one_below() {
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0x00, 0x00), 8).expect("valid width");
        let proof = tree.prove_prefix_cohort(range).expect("cohort");

        let in_range: Vec<Value> = proof
            .leaves
            .iter()
            .map(|(_, leaf)| leaf.value)
            .filter(|v| range.contains(v))
            .collect();
        assert_eq!(in_range.len(), 3, "0x80 bucket holds three values");

        let below: Vec<Value> = proof
            .leaves
            .iter()
            .map(|(_, leaf)| leaf.value)
            .filter(|v| !range.contains(v))
            .collect();
        assert_eq!(below.len(), 1, "exactly one predecessor, no more");
        assert_eq!(below[0], value(0x40, 0x90, 0x00), "the greatest below 0x80");
    }

    #[test]
    fn a_cohort_verifies_against_the_real_root() {
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0x00, 0x00), 8).expect("valid width");
        let proof = tree.prove_prefix_cohort(range).expect("cohort");
        let leaves = verify_cohort(&tree.root(), &proof).expect("folds to the root");
        assert_eq!(leaves.len(), proof.leaf_count());
        assert!(
            leaves.windows(2).all(|w| w[0].value <= w[1].value),
            "returned in value order"
        );
    }

    #[test]
    fn a_cohort_settles_every_value_in_its_range() {
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0x00, 0x00), 8).expect("valid width");
        let proof = tree.prove_prefix_cohort(range).expect("cohort");
        let leaves = verify_cohort(&tree.root(), &proof).expect("folds");

        // Present.
        for b in [0x10u8, 0x30, 0x50] {
            assert_eq!(
                resolve(&leaves, &range, value(0x80, b, 0x00)),
                Ok(Status::Spent),
                "0x80{b:02x} was inserted"
            );
        }
        // Absent, at the bottom of the range, above it, and between members.
        for b in [0x00u8, 0x20, 0x40, 0xff] {
            let got = resolve(&leaves, &range, value(0x80, b, 0x00)).expect("settles");
            let Status::Unspent { low } = got else {
                panic!("0x80{b:02x} was never inserted");
            };
            assert!(
                low.covers(&value(0x80, b, 0x00)),
                "low leaf must bracket it"
            );
        }
    }

    #[test]
    fn the_answer_matches_a_direct_single_value_proof() {
        // The cohort is only useful if it agrees with the query it replaces.
        let tree = seeded();
        let target = value(0x80, 0x20, 0x00);
        let direct = tree.prove_non_membership(target).expect("absent");

        let range = PrefixRange::covering(target, 8).expect("valid width");
        let proof = tree.prove_prefix_cohort(range).expect("cohort");
        let leaves = verify_cohort(&tree.root(), &proof).expect("folds");

        let Status::Unspent { low } = resolve(&leaves, &range, target).expect("settles") else {
            panic!("target is absent");
        };
        assert_eq!(
            low, direct.low_leaf,
            "cohort must pick the same low leaf the direct proof does"
        );
    }

    #[test]
    fn a_cohort_for_an_empty_bucket_is_just_the_predecessor() {
        let tree = seeded();
        // Nothing was inserted in the 0x00 bucket.
        let range = PrefixRange::covering(value(0x20, 0x00, 0x00), 8).expect("valid width");
        let proof = tree.prove_prefix_cohort(range).expect("cohort");
        assert_eq!(proof.leaf_count(), 1, "sentinel only");

        let leaves = verify_cohort(&tree.root(), &proof).expect("folds");
        let got = resolve(&leaves, &range, value(0x20, 0x33, 0x00)).expect("settles");
        assert!(matches!(got, Status::Unspent { .. }));
    }

    #[test]
    fn a_tampered_leaf_breaks_the_fold() {
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0x00, 0x00), 8).expect("valid width");
        let mut proof = tree.prove_prefix_cohort(range).expect("cohort");

        // Claim a spent nullifier is something else.
        if let Some((_, leaf)) = proof.leaves.iter_mut().find(|(_, l)| !l.value.is_zero()) {
            leaf.value = value(0x80, 0x99, 0x00);
        }
        assert_eq!(
            verify_cohort(&tree.root(), &proof),
            Err(CohortError::RootMismatch)
        );
    }

    #[test]
    fn a_tampered_node_breaks_the_fold() {
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0x00, 0x00), 8).expect("valid width");
        let mut proof = tree.prove_prefix_cohort(range).expect("cohort");

        let Some((&key, _)) = proof.nodes.iter().next() else {
            panic!("cohort should carry at least one node");
        };
        proof.nodes.insert(key, [0x5au8; 32]);
        assert_eq!(
            verify_cohort(&tree.root(), &proof),
            Err(CohortError::RootMismatch)
        );
    }

    #[test]
    fn a_repeated_leaf_index_is_refused() {
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0x00, 0x00), 8).expect("valid width");
        let mut proof = tree.prove_prefix_cohort(range).expect("cohort");
        if let Some(first) = proof.leaves.first().copied() {
            proof.leaves.push(first);
        }
        assert_eq!(
            verify_cohort(&tree.root(), &proof),
            Err(CohortError::UnorderedLeaves)
        );
    }

    #[test]
    fn an_omitted_in_range_leaf_is_caught_at_resolve() {
        // The attack the fold cannot see: drop a leaf. What remains is a
        // perfectly valid proof of a *smaller* cohort, so `verify_cohort`
        // passes and the gap has to be caught when the answer is read off.
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0x00, 0x00), 8).expect("valid width");
        let mut proof = tree.prove_prefix_cohort(range).expect("cohort");

        // Model the attacker properly. Simply deleting a leaf and leaving the
        // node set alone breaks the fold, because that leaf was serving as a
        // derivable sibling for its neighbour -- so the naive version of this
        // attack is already caught by `verify_cohort`. A bridge that wants the
        // omission to stick recomputes the dedup for the shorter cohort, and
        // then the fold succeeds: what remains is a perfectly valid Merkle
        // proof of a smaller set. That is why `resolve` has to check for gaps.
        let dropped = value(0x80, 0x30, 0x00);
        proof.leaves.retain(|(_, leaf)| leaf.value != dropped);
        let reduced: BTreeSet<u64> = proof.leaves.iter().map(|(index, _)| *index).collect();
        proof.nodes = tree.dedup_paths(&reduced).expect("recomputed dedup");

        let leaves = verify_cohort(&tree.root(), &proof)
            .expect("a recomputed short cohort is still a valid Merkle proof");

        // Asking about the dropped value now gets a refusal, not "unspent".
        assert_eq!(
            resolve(&leaves, &range, dropped),
            Err(CohortError::UnsortedValues),
            "omission must not read as absence"
        );
    }

    #[test]
    fn a_value_outside_the_range_is_refused() {
        let tree = seeded();
        let range = PrefixRange::covering(value(0x80, 0x00, 0x00), 8).expect("valid width");
        let proof = tree.prove_prefix_cohort(range).expect("cohort");
        let leaves = verify_cohort(&tree.root(), &proof).expect("folds");
        assert_eq!(
            resolve(&leaves, &range, value(0x40, 0x10, 0x00)),
            Err(CohortError::LeafOutOfRange),
            "a cohort only answers for its own range"
        );
    }

    #[test]
    fn dedup_never_costs_more_than_independent_paths() {
        // The claim the measurement rests on. Sharing can be zero, but it can
        // never be negative.
        let tree = seeded();
        for bits in [8u8, 12, 16] {
            let range = PrefixRange::covering(value(0x80, 0x00, 0x00), bits).expect("valid");
            let proof = tree.prove_prefix_cohort(range).expect("cohort");
            let independent = proof.leaf_count() * usize::from(D);
            assert!(
                proof.node_count() <= independent,
                "bits={bits}: {} nodes vs {independent} for separate paths",
                proof.node_count()
            );
        }
    }
}

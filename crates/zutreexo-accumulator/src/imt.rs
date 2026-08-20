//! Indexed Merkle tree — the nullifier accumulator.
//!
//! # Why this and not Utreexo
//!
//! A Utreexo forest, a Merkle mountain range, and every other unordered hash
//! accumulator prove **membership**. Nullifier checking needs the opposite:
//! proving a nullifier has *never* appeared. There is no way to prove absence
//! from an unordered accumulator without holding the whole set, which defeats
//! the entire purpose (CLAUDE.md §2.1).
//!
//! An indexed Merkle tree solves this by keeping the set sorted. Each leaf
//! carries `(value, next_value, next_index)`, threading a linked list through
//! the leaves in ascending value order. Non-membership of `x` is proven by
//! exhibiting the *low leaf* `L` with `L.value < x < L.next_value` plus an
//! ordinary Merkle path to `L`: if such an `L` is in the tree, `x` cannot be,
//! because the list has no gap for it. Insertion splices `x` into the list —
//! update `L`, append the new leaf — which is two Merkle path updates.
//!
//! # Depth strategy: fixed, parameterised, default 32
//!
//! The tree has a fixed depth chosen at construction (CLAUDE.md §7 flagged
//! this as an open question; this is the resolution). Every proof is therefore
//! exactly `depth` siblings, one code path handles every insertion, and a
//! future ZIP can specify a constant proof size.
//!
//! The default of 40 gives 2^40 ≈ 1.1e12 leaves. That number comes from Phase 0
//! measurement, not estimation, and the earlier default of 32 was raised
//! *because* the measurement contradicted the reasoning behind it.
//!
//! Measured at mainnet tip: Orchard reveals 6.192 nullifiers per block,
//! Ironwood 2.934, Sapling 0.138. At 420,768 blocks/year the fastest-filling
//! pool would exhaust depth 32 in 1,648 years at today's rate — but only
//! 16.5 years at a sustained hundredfold increase in spend volume, and 5.5
//! years if NU7 triples block rate and volume follows. That is inside the
//! plausible lifetime of a consensus format, and an append-only tree never
//! reclaims space.
//!
//! Depth 40 costs +23% proof bytes and +25% verification time for 256× the
//! capacity: 4,220 years even at a hundredfold increase. The asymmetry decided
//! it — overshooting costs a fixed bandwidth premium, undershooting costs a
//! hard migration under time pressure.
//!
//! The ceiling is derived from *transaction* throughput, not block count, which
//! is what makes it robust to NU7's proposed 3× faster blocks: those triple the
//! block rate without tripling the number of shielded spends, which is bounded
//! by demand rather than block spacing.
//!
//! See `docs/design.md` D3 for the full derivation and the correction history.
//!
//! # Value ordering
//!
//! Values are ordered as big-endian 256-bit unsigned integers over the
//! canonical 32-byte nullifier encoding. `[u8; 32]`'s derived lexicographic
//! ordering is exactly that, which is why [`Value`] can derive `Ord`.
//!
//! # The zero sentinel
//!
//! Index 0 always holds `(0, 0, 0)`. `Value::ZERO` is reserved: it can never be
//! inserted, so it is free to double as the "no successor" marker in
//! `next_value`, meaning the leaf is the current maximum. A real nullifier of
//! all-zero bytes is cryptographically unreachable, and this module rejects it
//! explicitly rather than relying on that.

use std::collections::BTreeMap;

use crate::hash::{self, Hash};
use crate::pool::PoolId;

/// Smallest permitted tree depth.
pub const MIN_DEPTH: u8 = 1;

/// Largest permitted tree depth.
///
/// Capped at 63 so `1u64 << depth` is always well defined.
pub const MAX_DEPTH: u8 = 63;

/// Default tree depth: 2^40 leaves. See the module docs for the derivation.
pub const DEFAULT_DEPTH: u8 = 40;

/// A nullifier, ordered as a big-endian 256-bit unsigned integer.
///
/// The derived `Ord` is lexicographic over the byte array, which coincides with
/// numeric ordering for big-endian encoding. This is load-bearing: the whole
/// non-membership argument rests on the leaves being sorted by this order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Value([u8; 32]);

impl Value {
    /// The reserved sentinel. Occupies leaf 0 and marks "no successor".
    pub const ZERO: Value = Value([0u8; 32]);

    /// The largest representable value.
    pub const MAX: Value = Value([0xffu8; 32]);

    /// Wraps a 32-byte nullifier.
    pub const fn from_bytes(bytes: [u8; 32]) -> Value {
        Value(bytes)
    }

    /// The underlying bytes.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// The underlying bytes, by reference.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether this is the reserved sentinel.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

/// A leaf of the indexed Merkle tree.
///
/// `next_value == Value::ZERO` means this leaf currently holds the largest
/// value in the set; `next_index` is then meaningless and set to 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Leaf {
    /// The nullifier stored at this leaf.
    pub value: Value,
    /// The next larger nullifier in the set, or `ZERO` if this is the maximum.
    pub next_value: Value,
    /// The leaf index holding `next_value`, or 0 if this is the maximum.
    pub next_index: u64,
}

impl Leaf {
    /// The leaf that always occupies index 0.
    pub const SENTINEL: Leaf = Leaf {
        value: Value::ZERO,
        next_value: Value::ZERO,
        next_index: 0,
    };

    /// This leaf's digest under `pool`'s domain separator.
    pub fn hash(&self, pool: PoolId) -> Hash {
        hash::imt_leaf(
            pool,
            self.value.as_bytes(),
            self.next_value.as_bytes(),
            self.next_index,
        )
    }

    /// Whether this leaf brackets `value`, i.e. witnesses its absence.
    ///
    /// True when `self.value < value` and either `value < self.next_value` or
    /// this leaf is the current maximum.
    pub fn covers(&self, value: &Value) -> bool {
        self.value < *value && (self.next_value.is_zero() || *value < self.next_value)
    }
}

/// Everything that can go wrong in this module.
///
/// No variant is reachable by panicking: CLAUDE.md §5 rule 3 bans panics in
/// accumulator paths, because block application runs on attacker-supplied data.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ImtError {
    /// `Value::ZERO` is reserved for the sentinel and cannot be inserted or
    /// proven absent.
    #[error("value zero is reserved for the sentinel leaf")]
    ReservedValue,

    /// The value is already in the set.
    #[error("value is already present in the tree")]
    DuplicateValue,

    /// The value is present, so non-membership cannot hold.
    #[error("value is a member; non-membership cannot be proven")]
    ValueIsMember,

    /// The tree is full at this depth.
    #[error("tree of depth {depth} is full at {capacity} leaves")]
    CapacityExhausted {
        /// The tree's configured depth.
        depth: u8,
        /// The leaf capacity, `2^depth`.
        capacity: u64,
    },

    /// Depth outside [`MIN_DEPTH`]..=[`MAX_DEPTH`].
    #[error("depth {depth} is outside {MIN_DEPTH}..={MAX_DEPTH}")]
    InvalidDepth {
        /// The rejected depth.
        depth: u8,
    },

    /// The proof was built for a tree of a different depth.
    #[error("expected a {expected}-sibling path, got {found}")]
    WrongPathLength {
        /// Sibling count implied by the tree depth.
        expected: usize,
        /// Sibling count actually supplied.
        found: usize,
    },

    /// The proof's low leaf does not bracket the value.
    #[error("low leaf does not bracket the value")]
    LowLeafDoesNotCover,

    /// Undo was attempted on something other than the newest insertion.
    ///
    /// Undo is strictly last-in-first-out. Anything else would leave the linked
    /// list pointing at an index that no longer holds what the pointer claims,
    /// producing a tree that hashes to a plausible root while encoding a set
    /// nobody can reason about.
    #[error("undo is LIFO: asked for leaf {asked}, newest is {newest}")]
    NotMostRecent {
        /// Leaf index the caller tried to undo.
        asked: u64,
        /// Index of the newest leaf, the only undoable one.
        newest: u64,
    },

    /// The insertion proof does not describe this tree's current state.
    ///
    /// Raised when the leaf at the appended position is not the value being
    /// undone, when the low leaf no longer points at it, or when restoring the
    /// low leaf would leave a gap in the linked list. Each of those means the
    /// proof came from a different tree or a different point in its history.
    #[error("insertion proof does not match the current tree state")]
    ProofMismatch,

    /// The recomputed root disagrees with the expected one.
    #[error("root mismatch")]
    RootMismatch {
        /// The root the verifier was checking against.
        expected: Hash,
        /// The root recomputed from the proof.
        computed: Hash,
    },

    /// A leaf index is beyond the tree's capacity.
    #[error("leaf index {index} exceeds capacity {capacity}")]
    IndexOutOfRange {
        /// The offending index.
        index: u64,
        /// The tree's leaf capacity.
        capacity: u64,
    },

    /// An insertion claimed to append somewhere other than the append point.
    ///
    /// Without this check a proof could place a leaf at any unoccupied index,
    /// producing a tree that verifies but diverges from canonical replay.
    #[error("insertion must append at index {expected}, got {found}")]
    UnexpectedLeafIndex {
        /// The current leaf count, which is the only legal append index.
        expected: u64,
        /// The index the proof claimed.
        found: u64,
    },

    /// The low leaf and the new leaf cannot be the same position.
    #[error("low leaf and new leaf share index {index}")]
    AliasedLeafIndex {
        /// The shared index.
        index: u64,
    },

    /// An invariant that should be unreachable was violated.
    #[error("tree invariant violated: {0}")]
    CorruptTree(&'static str),
}

/// The compact state a node holds for one pool's nullifier set.
///
/// This is the whole point of the project on the shielded side: 40 bytes in
/// place of a full nullifier database. A compact state node holds one of these
/// per pool and validates insertions using bridge-supplied proofs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ImtState {
    /// The tree root.
    pub root: Hash,
    /// Number of occupied leaves, including the sentinel. Also the next
    /// append index.
    pub leaf_count: u64,
}

impl ImtState {
    /// The state of a freshly initialised tree: sentinel only.
    ///
    /// Computed directly rather than by materialising a tree. Leaf 0 is the
    /// leftmost position, so every sibling on its path is an empty subtree.
    pub fn new(pool: PoolId, depth: u8) -> Result<ImtState, ImtError> {
        check_depth(depth)?;
        let mut node = Leaf::SENTINEL.hash(pool);
        let mut empty = hash::imt_empty_leaf(pool);
        for _ in 0..depth {
            node = hash::imt_node(pool, &node, &empty);
            empty = hash::imt_node(pool, &empty, &empty);
        }
        Ok(ImtState {
            root: node,
            leaf_count: 1,
        })
    }

    /// Checks a non-membership proof against this state.
    pub fn verify_non_membership(
        &self,
        pool: PoolId,
        depth: u8,
        value: Value,
        proof: &NonMembershipProof,
    ) -> Result<(), ImtError> {
        verify_non_membership(pool, depth, &self.root, value, proof)
    }

    /// Verifies an insertion and advances this state to the resulting root.
    ///
    /// On error the state is left untouched, so a rejected block cannot
    /// half-apply.
    pub fn apply_insertion(
        &mut self,
        pool: PoolId,
        depth: u8,
        value: Value,
        proof: &InsertionProof,
    ) -> Result<(), ImtError> {
        let next = verify_insertion(pool, depth, self, value, proof)?;
        *self = next;
        Ok(())
    }
}

/// Proof that `value` is absent from a tree with a given root.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NonMembershipProof {
    /// The leaf bracketing the value.
    pub low_leaf: Leaf,
    /// That leaf's index.
    pub low_leaf_index: u64,
    /// Sibling hashes from leaf level upward. Length equals the tree depth.
    pub siblings: Vec<Hash>,
}

/// Proof that inserting `value` takes a tree from one root to another.
///
/// Carries no roots of its own. The verifier supplies the root it already
/// trusts and receives the resulting root; a proof that carried both would add
/// attack surface without adding information.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InsertionProof {
    /// The low leaf, as it stood *before* the insertion.
    pub low_leaf: Leaf,
    /// The low leaf's index.
    pub low_leaf_index: u64,
    /// Siblings on the low leaf's path, against the pre-insertion root.
    ///
    /// Also valid against the intermediate root: rewriting a leaf does not
    /// change that leaf's own siblings.
    pub low_leaf_siblings: Vec<Hash>,
    /// The index the new leaf is appended at. Must equal the current leaf count.
    pub new_leaf_index: u64,
    /// Siblings on the new leaf's path, against the *intermediate* root — the
    /// tree after the low leaf has been rewritten but before the append.
    ///
    /// Ordering matters here and is why the two updates cannot be swapped: the
    /// two paths share ancestors near the top of the tree.
    pub new_leaf_siblings: Vec<Hash>,
}

/// The canonical hash of an empty subtree at each level, bottom-up.
///
/// `out[0]` is the empty *leaf* hash, `out[1]` the hash of two empty leaves,
/// and so on for `depth` levels. Pool-specific, because every hash in this
/// crate is domain-separated (CLAUDE.md §5 rule 4) — an empty subtree in the
/// Orchard tree is not the same value as one in Sapling's.
///
/// # Why this is public
///
/// These values are *derivable*, which makes them compressible on the wire. A
/// depth-40 tree holding 2^25.7 nullifiers is overwhelmingly empty, so most
/// siblings on any path are one of these — 71.4% of them, measured
/// (`docs/benchmarks.md`, Phase 4a). The sparse proof encoding in `proof.rs`
/// omits them and the decoder puts them back from here, so both sides must
/// derive the identical ladder.
pub fn empty_subtree_hashes(pool: PoolId, depth: u8) -> Result<Vec<Hash>, ImtError> {
    check_depth(depth)?;
    let mut out = Vec::with_capacity(usize::from(depth));
    let mut empty = hash::imt_empty_leaf(pool);
    for _ in 0..depth {
        out.push(empty);
        empty = hash::imt_node(pool, &empty, &empty);
    }
    Ok(out)
}

/// Rejects depths outside the supported range.
pub fn check_depth(depth: u8) -> Result<(), ImtError> {
    if !(MIN_DEPTH..=MAX_DEPTH).contains(&depth) {
        return Err(ImtError::InvalidDepth { depth });
    }
    Ok(())
}

/// Leaf capacity of a tree of this depth. Assumes `depth` is already validated.
const fn capacity_of(depth: u8) -> u64 {
    if depth > MAX_DEPTH {
        u64::MAX
    } else {
        1u64 << depth
    }
}

/// Folds a leaf digest and its sibling path into a root.
fn root_from_path(pool: PoolId, leaf: Hash, index: u64, siblings: &[Hash]) -> Hash {
    let mut node = leaf;
    let mut idx = index;
    for sibling in siblings {
        node = if idx & 1 == 0 {
            hash::imt_node(pool, &node, sibling)
        } else {
            hash::imt_node(pool, sibling, &node)
        };
        idx >>= 1;
    }
    node
}

/// Shared prologue for both verifiers: depth, path length, and index range.
fn check_path(depth: u8, index: u64, siblings: &[Hash]) -> Result<(), ImtError> {
    check_depth(depth)?;
    if siblings.len() != usize::from(depth) {
        return Err(ImtError::WrongPathLength {
            expected: usize::from(depth),
            found: siblings.len(),
        });
    }
    let capacity = capacity_of(depth);
    if index >= capacity {
        return Err(ImtError::IndexOutOfRange { index, capacity });
    }
    Ok(())
}

/// Verifies that `value` is absent from the tree with root `root`.
///
/// The argument is: the low leaf is authenticated against the root by its
/// Merkle path, and it brackets `value`. Since the leaves form a sorted linked
/// list with no gaps, a value strictly between a leaf and its successor cannot
/// be in the tree.
pub fn verify_non_membership(
    pool: PoolId,
    depth: u8,
    root: &Hash,
    value: Value,
    proof: &NonMembershipProof,
) -> Result<(), ImtError> {
    if value.is_zero() {
        return Err(ImtError::ReservedValue);
    }
    check_path(depth, proof.low_leaf_index, &proof.siblings)?;

    if !proof.low_leaf.covers(&value) {
        return Err(ImtError::LowLeafDoesNotCover);
    }

    let computed = root_from_path(
        pool,
        proof.low_leaf.hash(pool),
        proof.low_leaf_index,
        &proof.siblings,
    );
    if computed != *root {
        return Err(ImtError::RootMismatch {
            expected: *root,
            computed,
        });
    }
    Ok(())
}

/// Verifies an insertion transition and returns the resulting state.
///
/// Checks, in order:
/// 1. the value is insertable at all;
/// 2. the append index is exactly the current leaf count — otherwise a valid
///    proof could place the leaf anywhere unoccupied and fork canonical replay;
/// 3. the low leaf is authenticated against the pre-state root and brackets
///    the value, which is the non-membership argument and so also the
///    duplicate check;
/// 4. the append position was genuinely *empty* in the intermediate tree,
///    which is what stops an insertion from overwriting an existing leaf.
pub fn verify_insertion(
    pool: PoolId,
    depth: u8,
    state: &ImtState,
    value: Value,
    proof: &InsertionProof,
) -> Result<ImtState, ImtError> {
    if value.is_zero() {
        return Err(ImtError::ReservedValue);
    }
    check_path(depth, proof.low_leaf_index, &proof.low_leaf_siblings)?;
    check_path(depth, proof.new_leaf_index, &proof.new_leaf_siblings)?;

    if proof.new_leaf_index != state.leaf_count {
        return Err(ImtError::UnexpectedLeafIndex {
            expected: state.leaf_count,
            found: proof.new_leaf_index,
        });
    }
    if proof.low_leaf_index == proof.new_leaf_index {
        return Err(ImtError::AliasedLeafIndex {
            index: proof.new_leaf_index,
        });
    }
    if !proof.low_leaf.covers(&value) {
        return Err(ImtError::LowLeafDoesNotCover);
    }

    // 3. The low leaf is really in the pre-insertion tree.
    let old_root = root_from_path(
        pool,
        proof.low_leaf.hash(pool),
        proof.low_leaf_index,
        &proof.low_leaf_siblings,
    );
    if old_root != state.root {
        return Err(ImtError::RootMismatch {
            expected: state.root,
            computed: old_root,
        });
    }

    // Splice the new value into the linked list: the low leaf now points at it.
    let updated_low = Leaf {
        value: proof.low_leaf.value,
        next_value: value,
        next_index: proof.new_leaf_index,
    };
    let intermediate = root_from_path(
        pool,
        updated_low.hash(pool),
        proof.low_leaf_index,
        &proof.low_leaf_siblings,
    );

    // 4. The append position held an empty leaf in that intermediate tree.
    let empty_root = root_from_path(
        pool,
        hash::imt_empty_leaf(pool),
        proof.new_leaf_index,
        &proof.new_leaf_siblings,
    );
    if empty_root != intermediate {
        return Err(ImtError::RootMismatch {
            expected: intermediate,
            computed: empty_root,
        });
    }

    // The new leaf inherits the low leaf's old successor.
    let new_leaf = Leaf {
        value,
        next_value: proof.low_leaf.next_value,
        next_index: proof.low_leaf.next_index,
    };
    let root = root_from_path(
        pool,
        new_leaf.hash(pool),
        proof.new_leaf_index,
        &proof.new_leaf_siblings,
    );

    let leaf_count = state
        .leaf_count
        .checked_add(1)
        .ok_or(ImtError::CorruptTree("leaf count overflow"))?;
    if leaf_count > capacity_of(depth) {
        return Err(ImtError::CapacityExhausted {
            depth,
            capacity: capacity_of(depth),
        });
    }

    Ok(ImtState { root, leaf_count })
}

/// A complete indexed Merkle tree: every leaf and every populated internal node.
///
/// This is the bridge-node side. A compact state node holds [`ImtState`]
/// instead. Internal nodes live in a sparse `BTreeMap` — `BTreeMap` rather than
/// `HashMap` per CLAUDE.md §5 rule 5, since nothing whose iteration order could
/// reach a root may be unordered.
///
/// Memory is proportional to the leaf count, so a full mainnet tree wants the
/// on-disk representation from Phase 3 rather than this.
#[derive(Clone, Debug)]
pub struct IndexedMerkleTree {
    pool: PoolId,
    depth: u8,
    /// Digest of an all-empty subtree, indexed by level. Length `depth + 1`.
    zeros: Vec<Hash>,
    /// Leaves in insertion order. Index 0 is always the sentinel.
    leaves: Vec<Leaf>,
    /// Value to leaf index. Ordered, so the low leaf is a range query.
    index_by_value: BTreeMap<Value, u64>,
    /// Populated internal nodes, keyed by `(level, index)`. Level 0 is leaves.
    nodes: BTreeMap<(u8, u64), Hash>,
}

impl IndexedMerkleTree {
    /// Creates an empty tree at [`DEFAULT_DEPTH`].
    pub fn new(pool: PoolId) -> Result<IndexedMerkleTree, ImtError> {
        IndexedMerkleTree::with_depth(pool, DEFAULT_DEPTH)
    }

    /// Creates an empty tree at an explicit depth.
    pub fn with_depth(pool: PoolId, depth: u8) -> Result<IndexedMerkleTree, ImtError> {
        check_depth(depth)?;

        let mut zeros = Vec::with_capacity(usize::from(depth).saturating_add(1));
        let mut current = hash::imt_empty_leaf(pool);
        zeros.push(current);
        for _ in 0..depth {
            current = hash::imt_node(pool, &current, &current);
            zeros.push(current);
        }

        let mut tree = IndexedMerkleTree {
            pool,
            depth,
            zeros,
            leaves: Vec::new(),
            index_by_value: BTreeMap::new(),
            nodes: BTreeMap::new(),
        };

        tree.leaves.push(Leaf::SENTINEL);
        tree.index_by_value.insert(Value::ZERO, 0);
        tree.write_leaf(0, Leaf::SENTINEL);

        Ok(tree)
    }

    /// Builds a tree by inserting `values` in the order given.
    ///
    /// Order matters: it determines leaf indices and therefore the root. This
    /// is a convenience, not an oracle — the differential harness's naive model
    /// shares no code with this crate on purpose (CLAUDE.md Phase 2).
    pub fn from_values(
        pool: PoolId,
        depth: u8,
        values: &[Value],
    ) -> Result<IndexedMerkleTree, ImtError> {
        let mut tree = IndexedMerkleTree::with_depth(pool, depth)?;
        for value in values {
            tree.insert(*value)?;
        }
        Ok(tree)
    }

    /// The pool this tree accumulates nullifiers for.
    pub fn pool(&self) -> PoolId {
        self.pool
    }

    /// The tree's fixed depth.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Leaf capacity, `2^depth`.
    pub fn capacity(&self) -> u64 {
        capacity_of(self.depth)
    }

    /// Occupied leaves, including the sentinel.
    pub fn leaf_count(&self) -> u64 {
        // `usize` is never wider than `u64` on any target this runs on; the
        // fallback keeps the function total rather than panicking.
        u64::try_from(self.leaves.len()).unwrap_or(u64::MAX)
    }

    /// Nullifiers actually inserted, excluding the sentinel.
    pub fn value_count(&self) -> u64 {
        self.leaf_count().saturating_sub(1)
    }

    /// The current root.
    pub fn root(&self) -> Hash {
        self.node(self.depth, 0)
    }

    /// The compact state corresponding to this tree.
    pub fn state(&self) -> ImtState {
        ImtState {
            root: self.root(),
            leaf_count: self.leaf_count(),
        }
    }

    /// Whether `value` is in the set. `Value::ZERO` counts as present: it is
    /// the sentinel, and refusing to insert it is the reason it can never be
    /// proven absent.
    pub fn contains(&self, value: &Value) -> bool {
        self.index_by_value.contains_key(value)
    }

    /// The leaf at `index`, if occupied.
    pub fn leaf(&self, index: u64) -> Option<Leaf> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.leaves.get(i))
            .copied()
    }

    /// Proves `value` is absent.
    ///
    /// Fails with [`ImtError::ValueIsMember`] if it is present — the caller
    /// asked a question with no true answer.
    pub fn prove_non_membership(&self, value: Value) -> Result<NonMembershipProof, ImtError> {
        if value.is_zero() {
            return Err(ImtError::ReservedValue);
        }
        let (low_leaf, low_leaf_index) = self.low_leaf(value)?;
        Ok(NonMembershipProof {
            low_leaf,
            low_leaf_index,
            siblings: self.siblings(low_leaf_index),
        })
    }

    /// Inserts `value`, returning a proof of the transition it caused.
    ///
    /// The returned proof verifies against the pre-insertion state via
    /// [`verify_insertion`] and yields the post-insertion state, which is what
    /// lets a compact state node follow along holding only roots.
    ///
    /// On error the tree is unmodified.
    pub fn insert(&mut self, value: Value) -> Result<InsertionProof, ImtError> {
        if value.is_zero() {
            return Err(ImtError::ReservedValue);
        }
        let new_leaf_index = self.leaf_count();
        if new_leaf_index >= self.capacity() {
            return Err(ImtError::CapacityExhausted {
                depth: self.depth,
                capacity: self.capacity(),
            });
        }

        // `low_leaf` returns DuplicateValue-equivalent errors before anything
        // is mutated, so the failure path leaves the tree untouched.
        let (low_leaf, low_leaf_index) = match self.low_leaf(value) {
            Ok(found) => found,
            Err(ImtError::ValueIsMember) => return Err(ImtError::DuplicateValue),
            Err(other) => return Err(other),
        };

        let low_leaf_siblings = self.siblings(low_leaf_index);

        // Rewrite the low leaf first. The new leaf's siblings must be read
        // against the resulting intermediate tree, because the two paths share
        // ancestors.
        let updated_low = Leaf {
            value: low_leaf.value,
            next_value: value,
            next_index: new_leaf_index,
        };
        self.set_leaf(low_leaf_index, updated_low)?;

        let new_leaf_siblings = self.siblings(new_leaf_index);

        let new_leaf = Leaf {
            value,
            next_value: low_leaf.next_value,
            next_index: low_leaf.next_index,
        };
        self.leaves.push(new_leaf);
        self.index_by_value.insert(value, new_leaf_index);
        self.write_leaf(new_leaf_index, new_leaf);

        Ok(InsertionProof {
            low_leaf,
            low_leaf_index,
            low_leaf_siblings,
            new_leaf_index,
            new_leaf_siblings,
        })
    }

    /// Recomputes the root from this tree's values, bottom-up, without using
    /// the cached internal nodes.
    ///
    /// # Why this exists
    ///
    /// The differential harness proves the incremental path has not drifted by
    /// rebuilding from scratch and comparing. Doing that with
    /// [`IndexedMerkleTree::from_values`] costs `2 * depth` hashes per value —
    /// 80 at depth 40 — because it replays every insertion including both
    /// Merkle path updates. Over 32 million Orchard nullifiers that is 2.6
    /// billion hashes, which is why the genesis replay could only afford the
    /// check below 200,000 values and skipped it 75 times out of 80.
    ///
    /// A final root does not need the journey. Leaves occupy indices `0..n`
    /// contiguously, so the tree can be folded a level at a time: `n` leaf
    /// hashes, then about `n` more to fold the dense prefix, then one hash per
    /// remaining level against a precomputed empty-subtree digest. Roughly
    /// `3n` hashes rather than `80n` — about **27× cheaper**, which moves the
    /// affordable ceiling from hundreds of thousands to tens of millions.
    ///
    /// # It is also a better check than it was
    ///
    /// The successor links are rebuilt by sorting the values, not copied from
    /// the stored leaves. So this catches a stale `next_value` or `next_index`
    /// as well as a stale internal node — two different ways the incremental
    /// path can rot — and it reaches the answer by a different route than
    /// insertion does.
    ///
    /// It still shares this crate's hashing, so it is not the independent
    /// oracle that `zutreexo-testkit`'s naive model provides at small scale.
    pub fn rebuild_root(&self) -> Result<Hash, ImtError> {
        // Sorted view of every value, paired with the leaf index holding it.
        // The sentinel participates: it is the head of the linked list.
        let mut sorted: Vec<(Value, u64)> = Vec::with_capacity(self.leaves.len());
        for (index, leaf) in self.leaves.iter().enumerate() {
            let index = u64::try_from(index)
                .map_err(|_| ImtError::CorruptTree("leaf index exceeds u64"))?;
            sorted.push((leaf.value, index));
        }
        sorted.sort_unstable_by_key(|(value, _)| *value);

        // Rebuild each leaf from its successor in sorted order, rather than
        // trusting the links the incremental path wrote.
        let mut rebuilt: Vec<Leaf> = vec![Leaf::SENTINEL; self.leaves.len()];
        for (position, (value, index)) in sorted.iter().enumerate() {
            let (next_value, next_index) = match sorted.get(position.saturating_add(1)) {
                Some((next, at)) => (*next, *at),
                // The maximum has no successor; zero means exactly that.
                None => (Value::ZERO, 0),
            };
            let slot = usize::try_from(*index)
                .ok()
                .and_then(|i| rebuilt.get_mut(i))
                .ok_or(ImtError::CorruptTree("value index out of range"))?;
            *slot = Leaf {
                value: *value,
                next_value,
                next_index,
            };
        }

        let mut level: Vec<Hash> = rebuilt.iter().map(|leaf| leaf.hash(self.pool)).collect();
        if level.is_empty() {
            return Ok(self.zero(self.depth));
        }

        for height in 0..self.depth {
            if level.len() == 1 {
                // The dense prefix has collapsed to one node covering
                // `2^height` leaves; everything above is empty subtrees.
                let mut node = *level.first().ok_or(ImtError::CorruptTree("empty level"))?;
                for remaining in height..self.depth {
                    node = hash::imt_node(self.pool, &node, &self.zero(remaining));
                }
                return Ok(node);
            }

            let filler = self.zero(height);
            let mut parents = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let left = *pair.first().ok_or(ImtError::CorruptTree("empty chunk"))?;
                let right = pair.get(1).copied().unwrap_or(filler);
                parents.push(hash::imt_node(self.pool, &left, &right));
            }
            level = parents;
        }

        level
            .first()
            .copied()
            .ok_or(ImtError::CorruptTree("fold produced no root"))
    }

    /// Builds a tree from values in insertion order, folding bottom-up.
    ///
    /// # Why this exists alongside `from_values`
    ///
    /// [`IndexedMerkleTree::from_values`] replays every insertion, costing
    /// `2 * depth` hashes per value — 80 at depth 40. Reloading a saved tip
    /// snapshot that way would take longer than fetching the chain again.
    /// Folding a level at a time costs roughly three hashes per value.
    ///
    /// The result is **identical**, not merely equivalent: same leaves, same
    /// value index, same internal node map. Persistence depends on that, since
    /// a reloaded tree has to be indistinguishable from a replayed one — undo
    /// and rollback compare exact state, not just roots. `bulk_matches_
    /// sequential` asserts it.
    ///
    /// This is what lets a snapshot store *only the values*: everything else
    /// here is derived, so there is no redundant state on disk that could
    /// disagree with itself.
    pub fn from_values_bulk(
        pool: PoolId,
        depth: u8,
        values: &[Value],
    ) -> Result<IndexedMerkleTree, ImtError> {
        let mut tree = IndexedMerkleTree::with_depth(pool, depth)?;

        let leaf_count = u64::try_from(values.len())
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or(ImtError::CorruptTree("value count overflows u64"))?;
        if leaf_count > tree.capacity() {
            return Err(ImtError::CapacityExhausted {
                depth,
                capacity: tree.capacity(),
            });
        }
        if values.is_empty() {
            return Ok(tree);
        }

        // Reject the same inputs `insert` would, before building anything.
        let mut sorted: Vec<(Value, u64)> = Vec::with_capacity(values.len().saturating_add(1));
        sorted.push((Value::ZERO, 0));
        for (position, value) in values.iter().enumerate() {
            if value.is_zero() {
                return Err(ImtError::ReservedValue);
            }
            let index = u64::try_from(position)
                .ok()
                .and_then(|p| p.checked_add(1))
                .ok_or(ImtError::CorruptTree("leaf index overflows u64"))?;
            sorted.push((*value, index));
        }
        sorted.sort_unstable_by_key(|(value, _)| *value);
        if sorted
            .windows(2)
            .any(|pair| pair.first().map(|p| p.0) == pair.get(1).map(|p| p.0))
        {
            return Err(ImtError::DuplicateValue);
        }

        // Successor links come from the sorted order, exactly as insertion
        // would have left them.
        let mut leaves = vec![Leaf::SENTINEL; sorted.len()];
        for (position, (value, index)) in sorted.iter().enumerate() {
            let (next_value, next_index) = match sorted.get(position.saturating_add(1)) {
                Some((next, at)) => (*next, *at),
                None => (Value::ZERO, 0),
            };
            let slot = usize::try_from(*index)
                .ok()
                .and_then(|i| leaves.get_mut(i))
                .ok_or(ImtError::CorruptTree("leaf index out of range"))?;
            *slot = Leaf {
                value: *value,
                next_value,
                next_index,
            };
        }

        for (position, leaf) in leaves.iter().enumerate() {
            let index = u64::try_from(position)
                .map_err(|_| ImtError::CorruptTree("leaf index overflows u64"))?;
            tree.nodes.insert((0, index), leaf.hash(pool));
            if index > 0 {
                tree.index_by_value.insert(leaf.value, index);
            }
        }
        tree.leaves = leaves;

        // Fold upward. The span at each level is the number of nodes covering
        // the dense leaf prefix, floored at one so the spine to the root is
        // written too — `root()` reads `(depth, 0)` and would otherwise fall
        // back to the empty digest.
        //
        // This writes exactly the set of entries the incremental path writes:
        // the ancestors of every occupied leaf, plus that spine.
        let occupied = tree.leaves.len() as u64;
        for level in 0..depth {
            let span = occupied
                .div_ceil(
                    1u64.checked_shl(u32::from(level).saturating_add(1))
                        .unwrap_or(u64::MAX),
                )
                .max(1);
            for parent in 0..span {
                let left = tree.node(level, parent.saturating_mul(2));
                let right = tree.node(level, parent.saturating_mul(2).saturating_add(1));
                let digest = hash::imt_node(pool, &left, &right);
                tree.nodes.insert((level.saturating_add(1), parent), digest);
            }
        }

        Ok(tree)
    }

    /// Reverses the most recent [`IndexedMerkleTree::insert`].
    ///
    /// # Why this is possible here and not for the transparent forest
    ///
    /// An indexed Merkle tree insertion touches exactly two leaves — the low
    /// leaf, rewritten to point at the new value, and the appended leaf — and
    /// [`InsertionProof`] carries the low leaf *as it stood before* the
    /// rewrite. That is the whole pre-image, so the operation inverts exactly.
    ///
    /// A Utreexo deletion does not: `rustreexo` offers no way to reinsert a
    /// leaf at its former position, so the transparent side needs a snapshot
    /// rather than a delta. See `zutreexo-chain`'s `rollback` module.
    ///
    /// # Undo is strictly last-in-first-out
    ///
    /// Only the newest insertion can be undone, and this rejects anything else
    /// rather than attempting it. Undoing out of order would leave the linked
    /// list pointing at a leaf index that no longer holds what the pointer
    /// claims — a tree that still hashes to a valid-looking root while encoding
    /// a set nobody can reason about. A reorg unwinds blocks newest-first and
    /// nullifiers within a block in reverse, which satisfies this naturally.
    ///
    /// On any error the tree is left untouched.
    pub fn undo_insert(&mut self, value: Value, proof: &InsertionProof) -> Result<(), ImtError> {
        // ---- checks, all before any mutation ----

        if value.is_zero() {
            return Err(ImtError::ReservedValue);
        }

        // The appended leaf must be the last one. `leaf_count` is never zero:
        // index 0 is the sentinel, which is not undoable.
        let last_index = self
            .leaf_count()
            .checked_sub(1)
            .ok_or(ImtError::CorruptTree("tree has no sentinel"))?;
        if proof.new_leaf_index != last_index || last_index == 0 {
            return Err(ImtError::NotMostRecent {
                asked: proof.new_leaf_index,
                newest: last_index,
            });
        }

        // The leaf actually sitting there must be the one being undone,
        // otherwise the proof belongs to a different insertion.
        let appended = self
            .leaf(last_index)
            .ok_or(ImtError::CorruptTree("leaf_count exceeds the leaf vector"))?;
        if appended.value != value {
            return Err(ImtError::ProofMismatch);
        }

        // The low leaf must currently point at the value being removed. If it
        // does not, this proof was produced against a different tree state.
        let current_low = self
            .leaf(proof.low_leaf_index)
            .ok_or(ImtError::CorruptTree("low leaf index out of range"))?;
        if current_low.next_value != value || current_low.next_index != proof.new_leaf_index {
            return Err(ImtError::ProofMismatch);
        }

        // ...and it must be the *same* low leaf. Insertion rewrites only
        // `next_value` and `next_index`, never the leaf's own value, so a proof
        // whose low leaf disagrees here came from a different tree.
        //
        // Checking the successor alone is not enough, and this is not a
        // theoretical gap: two trees whose newest leaf happens to be the same
        // value, inserted at the same index, with the same (often empty)
        // successor, agree on every other field. Restoring then silently
        // rewrites a live nullifier to a value from the other tree — a
        // corruption that still hashes to a well-formed root. Found by
        // `undo_with_a_proof_from_another_tree_is_refused`.
        if current_low.value != proof.low_leaf.value {
            return Err(ImtError::ProofMismatch);
        }

        // Restoring the low leaf must re-link it to what the appended leaf
        // points at, or the list would develop a gap.
        if proof.low_leaf.next_value != appended.next_value
            || proof.low_leaf.next_index != appended.next_index
        {
            return Err(ImtError::ProofMismatch);
        }

        // ---- mutation: from here nothing may fail ----
        //
        // Exactly the reverse of `insert`, which writes the low leaf and then
        // appends. The two paths can share ancestors, so both writes must
        // happen; doing them in reverse order keeps the intermediate states
        // mirror-images of the forward ones.

        self.leaves.pop();
        self.index_by_value.remove(&value);
        self.clear_leaf(last_index);

        self.set_leaf(proof.low_leaf_index, proof.low_leaf)?;

        Ok(())
    }

    /// Returns a leaf position to empty and rehashes the path above it.
    ///
    /// The mirror of [`IndexedMerkleTree::write_leaf`]: that writes a leaf
    /// digest upward, this writes the empty-subtree digest upward. Removing the
    /// node entry rather than storing a zero keeps `nodes` sparse, so an undone
    /// insertion leaves a tree byte-identical to one that never saw it — which
    /// is the property the reorg invariant rests on.
    fn clear_leaf(&mut self, index: u64) {
        self.nodes.remove(&(0, index));

        let mut node = self.zero(0);
        let mut idx = index;
        for level in 0..self.depth {
            let sibling = self.node(level, idx ^ 1);
            node = if idx & 1 == 0 {
                hash::imt_node(self.pool, &node, &sibling)
            } else {
                hash::imt_node(self.pool, &sibling, &node)
            };
            idx >>= 1;
            let parent_level = level.saturating_add(1);
            // Keep the map sparse: a subtree that is entirely empty should have
            // no entry at all, matching a tree that never had a leaf there.
            if node == self.zero(parent_level) {
                self.nodes.remove(&(parent_level, idx));
            } else {
                self.nodes.insert((parent_level, idx), node);
            }
        }
    }

    /// Inserts several values in order, returning one proof each.
    ///
    /// Equivalent to repeated [`IndexedMerkleTree::insert`] — a property the
    /// test suite asserts, since "batch equals sequential" is exactly the
    /// invariant an optimised batch path would break. On any error the tree is
    /// left with the successful prefix applied; callers that need
    /// all-or-nothing should clone first, which is what block application does
    /// by staging a `StateDelta`.
    pub fn insert_batch(&mut self, values: &[Value]) -> Result<Vec<InsertionProof>, ImtError> {
        let mut proofs = Vec::with_capacity(values.len());
        for value in values {
            proofs.push(self.insert(*value)?);
        }
        Ok(proofs)
    }

    /// Finds the leaf bracketing `value`.
    fn low_leaf(&self, value: Value) -> Result<(Leaf, u64), ImtError> {
        let (found_value, index) = self
            .index_by_value
            .range(..=value)
            .next_back()
            .ok_or(ImtError::CorruptTree("sentinel missing from value index"))?;

        if *found_value == value {
            return Err(ImtError::ValueIsMember);
        }

        let leaf = self.leaf(*index).ok_or(ImtError::CorruptTree(
            "value index points at a missing leaf",
        ))?;

        if !leaf.covers(&value) {
            return Err(ImtError::CorruptTree("linked list is not sorted"));
        }
        Ok((leaf, *index))
    }

    /// Sibling hashes on the path from `index` to the root, leaf level first.
    fn siblings(&self, index: u64) -> Vec<Hash> {
        let mut siblings = Vec::with_capacity(usize::from(self.depth));
        let mut idx = index;
        for level in 0..self.depth {
            siblings.push(self.node(level, idx ^ 1));
            idx >>= 1;
        }
        siblings
    }

    /// Replaces an existing leaf and rehashes its path.
    fn set_leaf(&mut self, index: u64, leaf: Leaf) -> Result<(), ImtError> {
        let slot = usize::try_from(index)
            .ok()
            .and_then(|i| self.leaves.get_mut(i))
            .ok_or(ImtError::CorruptTree("set_leaf on an unoccupied index"))?;
        *slot = leaf;
        self.write_leaf(index, leaf);
        Ok(())
    }

    /// Writes a leaf digest and rehashes every node above it.
    fn write_leaf(&mut self, index: u64, leaf: Leaf) {
        let mut node = leaf.hash(self.pool);
        self.nodes.insert((0, index), node);

        let mut idx = index;
        for level in 0..self.depth {
            let sibling = self.node(level, idx ^ 1);
            node = if idx & 1 == 0 {
                hash::imt_node(self.pool, &node, &sibling)
            } else {
                hash::imt_node(self.pool, &sibling, &node)
            };
            idx >>= 1;
            // `level < depth <= MAX_DEPTH`, so this cannot overflow a `u8`.
            self.nodes.insert((level.saturating_add(1), idx), node);
        }
    }

    /// The digest at `(level, index)`, falling back to the empty-subtree
    /// digest for that level.
    fn node(&self, level: u8, index: u64) -> Hash {
        match self.nodes.get(&(level, index)) {
            Some(hash) => *hash,
            None => self.zero(level),
        }
    }

    /// The all-empty subtree digest at `level`.
    fn zero(&self, level: u8) -> Hash {
        self.zeros
            .get(usize::from(level))
            .copied()
            .unwrap_or([0u8; 32])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;

    const POOL: PoolId = PoolId::Orchard;
    const D: u8 = 8;

    fn v(n: u64) -> Value {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        Value::from_bytes(bytes)
    }

    // ---- from_values_bulk ----

    /// **The property persistence rests on.** A bulk-built tree must be
    /// indistinguishable from a replayed one — every leaf, every value-index
    /// entry, every internal node — because a reloaded snapshot has to support
    /// undo and rollback, which compare exact state rather than roots.
    #[test]
    fn bulk_matches_sequential() {
        for depth in [1u8, 2, 5, 8, 12] {
            for count in [0u64, 1, 2, 3, 4, 7, 8, 9, 16, 17, 63, 100] {
                if count.saturating_add(1) > (1u64 << depth) {
                    continue;
                }
                let values: Vec<Value> = (1..=count).map(v).collect();

                let sequential = IndexedMerkleTree::from_values(POOL, depth, &values).unwrap();
                let bulk = IndexedMerkleTree::from_values_bulk(POOL, depth, &values).unwrap();

                assert_eq!(
                    fingerprint(&bulk),
                    fingerprint(&sequential),
                    "depth {depth}, {count} values: bulk build differs from replay"
                );
            }
        }
    }

    /// Insertion order decides leaf indices and therefore roots, so the bulk
    /// path must honour it rather than only the set of values.
    #[test]
    fn bulk_honours_insertion_order() {
        let a: Vec<Value> = [5u64, 1, 9, 3].into_iter().map(v).collect();
        let b: Vec<Value> = [9u64, 5, 3, 1].into_iter().map(v).collect();

        let bulk_a = IndexedMerkleTree::from_values_bulk(POOL, 8, &a).unwrap();
        let bulk_b = IndexedMerkleTree::from_values_bulk(POOL, 8, &b).unwrap();
        let seq_a = IndexedMerkleTree::from_values(POOL, 8, &a).unwrap();

        assert_eq!(fingerprint(&bulk_a), fingerprint(&seq_a));
        assert_ne!(bulk_a.root(), bulk_b.root());
    }

    /// A bulk-built tree must accept further insertions and stay in step, or a
    /// reloaded snapshot could not continue applying blocks.
    #[test]
    fn a_bulk_built_tree_can_be_extended() {
        let initial: Vec<Value> = (1..=20u64).map(v).collect();
        let mut bulk = IndexedMerkleTree::from_values_bulk(POOL, 10, &initial).unwrap();
        let mut sequential = IndexedMerkleTree::from_values(POOL, 10, &initial).unwrap();

        for n in 21..=30u64 {
            bulk.insert(v(n)).unwrap();
            sequential.insert(v(n)).unwrap();
        }
        assert_eq!(fingerprint(&bulk), fingerprint(&sequential));
    }

    /// And undo must work on it, since rollback after a restart is the whole
    /// point of persisting state.
    #[test]
    fn a_bulk_built_tree_can_be_undone() {
        let initial: Vec<Value> = (1..=20u64).map(v).collect();
        let mut bulk = IndexedMerkleTree::from_values_bulk(POOL, 10, &initial).unwrap();
        let before = fingerprint(&bulk);

        let proof = bulk.insert(v(99)).unwrap();
        bulk.undo_insert(v(99), &proof).unwrap();

        assert_eq!(fingerprint(&bulk), before);
    }

    #[test]
    fn bulk_rejects_what_insert_rejects() {
        assert_eq!(
            IndexedMerkleTree::from_values_bulk(POOL, 8, &[v(1), Value::ZERO]).unwrap_err(),
            ImtError::ReservedValue
        );
        assert_eq!(
            IndexedMerkleTree::from_values_bulk(POOL, 8, &[v(1), v(1)]).unwrap_err(),
            ImtError::DuplicateValue
        );
        // Depth 2 holds four leaves; the sentinel takes one.
        let too_many: Vec<Value> = (1..=4u64).map(v).collect();
        assert!(matches!(
            IndexedMerkleTree::from_values_bulk(POOL, 2, &too_many),
            Err(ImtError::CapacityExhausted { .. })
        ));
    }

    // ---- rebuild_root ----

    /// The fast bottom-up rebuild must agree with the incremental root, at
    /// every size and shape. If it does not, the cheaper check the genesis
    /// replay depends on is worthless.
    #[test]
    fn rebuild_agrees_with_the_incremental_root() {
        for depth in [1u8, 2, 5, 8, 12] {
            for count in [0u64, 1, 2, 3, 7, 8, 9, 31, 100] {
                let capacity = 1u64 << depth;
                if count.saturating_add(1) > capacity {
                    continue;
                }
                let mut tree = IndexedMerkleTree::with_depth(POOL, depth).unwrap();
                for n in 1..=count {
                    tree.insert(v(n)).unwrap();
                }
                assert_eq!(
                    tree.rebuild_root().unwrap(),
                    tree.root(),
                    "depth {depth}, {count} values: rebuild disagrees"
                );
            }
        }
    }

    /// Insertion order changes the root, so the rebuild must track it rather
    /// than depending only on the set of values.
    #[test]
    fn rebuild_tracks_insertion_order() {
        let build = |order: &[u64]| {
            let mut tree = IndexedMerkleTree::with_depth(POOL, 8).unwrap();
            for n in order {
                tree.insert(v(*n)).unwrap();
            }
            (tree.root(), tree.rebuild_root().unwrap())
        };
        let (root_a, rebuilt_a) = build(&[5, 1, 9, 3]);
        let (root_b, rebuilt_b) = build(&[9, 5, 3, 1]);

        assert_eq!(root_a, rebuilt_a);
        assert_eq!(root_b, rebuilt_b);
        assert_ne!(root_a, root_b, "order should change the root");
    }

    /// Values that stress the ordering: the maximum, and near-adjacent values.
    #[test]
    fn rebuild_handles_boundary_values() {
        let mut tree = IndexedMerkleTree::with_depth(POOL, 8).unwrap();
        tree.insert(Value::MAX).unwrap();
        tree.insert(v(1)).unwrap();
        tree.insert(v(2)).unwrap();
        assert_eq!(tree.rebuild_root().unwrap(), tree.root());
    }

    /// A corrupted successor pointer must be caught. This is the failure the
    /// rebuild exists to detect, and it is invisible to a root recomputed from
    /// the stored links.
    #[test]
    fn rebuild_detects_a_stale_successor_link() {
        let mut tree = IndexedMerkleTree::with_depth(POOL, 8).unwrap();
        for n in 1..=6u64 {
            tree.insert(v(n)).unwrap();
        }
        assert_eq!(tree.rebuild_root().unwrap(), tree.root());

        // Corrupt one leaf's link the way a drifting incremental path would,
        // rewriting the cached nodes so the tree stays self-consistent.
        let mut leaf = tree.leaf(3).unwrap();
        leaf.next_index = leaf.next_index.wrapping_add(1);
        tree.set_leaf(3, leaf).unwrap();

        assert_ne!(
            tree.rebuild_root().unwrap(),
            tree.root(),
            "a stale successor link went undetected"
        );
    }

    // ---- undo_insert ----
    //
    // These live inside the module rather than in tests/properties.rs because
    // the invariant is *byte-identical internal state*, not merely an equal
    // root. Two trees can agree on their root while differing in the sparse
    // node map, and the difference only surfaces later, in a proof generated
    // against the stale entry. Comparing roots alone would not catch that, and
    // an integration test cannot reach these fields.

    /// Every piece of state that decides future behaviour.
    ///
    /// The root alone is not enough. Two trees can share a root while differing
    /// in the sparse node map or the value index, and the difference only
    /// surfaces later in a proof generated against the stale entry — so the
    /// comparison covers all four.
    #[derive(PartialEq, Eq, Debug)]
    struct Fingerprint {
        root: Hash,
        leaves: Vec<Leaf>,
        index: Vec<(Value, u64)>,
        nodes: Vec<((u8, u64), Hash)>,
    }

    fn fingerprint(tree: &IndexedMerkleTree) -> Fingerprint {
        Fingerprint {
            root: tree.root(),
            leaves: tree.leaves.clone(),
            index: tree.index_by_value.iter().map(|(v, i)| (*v, *i)).collect(),
            nodes: tree.nodes.iter().map(|(k, h)| (*k, *h)).collect(),
        }
    }

    #[test]
    fn undo_restores_byte_identical_state() {
        let mut tree = IndexedMerkleTree::with_depth(POOL, D).unwrap();
        tree.insert(v(50)).unwrap();
        tree.insert(v(10)).unwrap();

        let before = fingerprint(&tree);

        let proof = tree.insert(v(30)).unwrap();
        assert_ne!(fingerprint(&tree), before, "insert did nothing");

        tree.undo_insert(v(30), &proof).unwrap();
        assert_eq!(
            fingerprint(&tree),
            before,
            "undo left the tree differing from before the insertion"
        );
    }

    #[test]
    fn undo_everything_returns_to_a_pristine_empty_tree() {
        // The strongest form: a tree built up and fully unwound must be
        // indistinguishable from one that was never touched, including the
        // sparse node map.
        let pristine = IndexedMerkleTree::with_depth(POOL, D).unwrap();
        let mut tree = IndexedMerkleTree::with_depth(POOL, D).unwrap();

        let values = [v(7), v(3), v(90), v(41), v(1)];
        let mut proofs = Vec::new();
        for value in values {
            proofs.push((value, tree.insert(value).unwrap()));
        }
        for (value, proof) in proofs.into_iter().rev() {
            tree.undo_insert(value, &proof).unwrap();
        }

        assert_eq!(fingerprint(&tree), fingerprint(&pristine));
    }

    #[test]
    fn reinserting_after_undo_reproduces_the_original_state() {
        let mut tree = IndexedMerkleTree::with_depth(POOL, D).unwrap();
        tree.insert(v(20)).unwrap();

        let proof = tree.insert(v(60)).unwrap();
        let after_first = fingerprint(&tree);

        tree.undo_insert(v(60), &proof).unwrap();
        tree.insert(v(60)).unwrap();

        assert_eq!(
            fingerprint(&tree),
            after_first,
            "insert -> undo -> insert must be identical to a single insert"
        );
    }

    #[test]
    fn undo_is_lifo() {
        let mut tree = IndexedMerkleTree::with_depth(POOL, D).unwrap();
        let first = tree.insert(v(10)).unwrap();
        let _second = tree.insert(v(20)).unwrap();

        // Undoing the older insertion while a newer one is still present must
        // be refused, not attempted.
        let before = fingerprint(&tree);
        let err = tree.undo_insert(v(10), &first).unwrap_err();
        assert!(
            matches!(err, ImtError::NotMostRecent { .. }),
            "expected NotMostRecent, got {err:?}"
        );
        assert_eq!(
            fingerprint(&tree),
            before,
            "a refused undo mutated the tree"
        );
    }

    #[test]
    fn undo_twice_is_refused() {
        let mut tree = IndexedMerkleTree::with_depth(POOL, D).unwrap();
        tree.insert(v(5)).unwrap();
        let proof = tree.insert(v(15)).unwrap();

        tree.undo_insert(v(15), &proof).unwrap();
        let before = fingerprint(&tree);

        let err = tree.undo_insert(v(15), &proof).unwrap_err();
        assert!(matches!(
            err,
            ImtError::NotMostRecent { .. } | ImtError::ProofMismatch
        ));
        assert_eq!(fingerprint(&tree), before);
    }

    #[test]
    fn undo_with_the_wrong_value_is_refused() {
        let mut tree = IndexedMerkleTree::with_depth(POOL, D).unwrap();
        tree.insert(v(5)).unwrap();
        let proof = tree.insert(v(15)).unwrap();
        let before = fingerprint(&tree);

        let err = tree.undo_insert(v(99), &proof).unwrap_err();
        assert_eq!(err, ImtError::ProofMismatch);
        assert_eq!(fingerprint(&tree), before);
    }

    #[test]
    fn undo_with_a_proof_from_another_tree_is_refused() {
        // Same value, same index, different history — the low leaf differs.
        let mut a = IndexedMerkleTree::with_depth(POOL, D).unwrap();
        a.insert(v(10)).unwrap();
        let proof_a = a.insert(v(50)).unwrap();

        let mut b = IndexedMerkleTree::with_depth(POOL, D).unwrap();
        b.insert(v(20)).unwrap();
        b.insert(v(50)).unwrap();
        let before = fingerprint(&b);

        let err = b.undo_insert(v(50), &proof_a).unwrap_err();
        assert_eq!(err, ImtError::ProofMismatch);
        assert_eq!(fingerprint(&b), before);
    }

    #[test]
    fn the_sentinel_cannot_be_undone() {
        let mut tree = IndexedMerkleTree::with_depth(POOL, D).unwrap();
        let fake = InsertionProof {
            low_leaf: Leaf::SENTINEL,
            low_leaf_index: 0,
            low_leaf_siblings: Vec::new(),
            new_leaf_index: 0,
            new_leaf_siblings: Vec::new(),
        };
        assert!(matches!(
            tree.undo_insert(Value::ZERO, &fake),
            Err(ImtError::ReservedValue)
        ));
        assert_eq!(tree.leaf_count(), 1, "the sentinel must survive");
    }

    #[test]
    fn undo_order_within_a_batch_is_the_reverse_of_insertion() {
        // The pattern block rollback uses: undo a block's nullifiers in reverse
        // and the tree returns to its pre-block state exactly.
        let mut tree = IndexedMerkleTree::with_depth(POOL, D).unwrap();
        tree.insert(v(100)).unwrap();
        let checkpoint = fingerprint(&tree);

        let block = [v(40), v(80), v(20), v(60)];
        let proofs = tree.insert_batch(&block).unwrap();

        for (value, proof) in block.iter().zip(&proofs).rev() {
            tree.undo_insert(*value, proof).unwrap();
        }
        assert_eq!(fingerprint(&tree), checkpoint);
    }

    fn tree() -> IndexedMerkleTree {
        IndexedMerkleTree::with_depth(POOL, D).unwrap()
    }

    #[test]
    fn empty_tree_state_matches_materialised_tree() {
        for depth in [1u8, 2, 8, 32] {
            let tree = IndexedMerkleTree::with_depth(POOL, depth).unwrap();
            let state = ImtState::new(POOL, depth).unwrap();
            assert_eq!(tree.state(), state, "depth {depth}");
        }
    }

    #[test]
    fn sentinel_occupies_index_zero() {
        let tree = tree();
        assert_eq!(tree.leaf(0), Some(Leaf::SENTINEL));
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.value_count(), 0);
        assert!(tree.contains(&Value::ZERO));
    }

    #[test]
    fn zero_is_reserved() {
        let mut tree = tree();
        assert_eq!(tree.insert(Value::ZERO), Err(ImtError::ReservedValue));
        assert_eq!(
            tree.prove_non_membership(Value::ZERO),
            Err(ImtError::ReservedValue)
        );
    }

    #[test]
    fn insert_then_prove_non_membership_fails() {
        let mut tree = tree();
        tree.insert(v(42)).unwrap();
        assert_eq!(
            tree.prove_non_membership(v(42)),
            Err(ImtError::ValueIsMember)
        );
    }

    #[test]
    fn absent_values_verify() {
        let mut tree = tree();
        for n in [10u64, 20, 30] {
            tree.insert(v(n)).unwrap();
        }
        for n in [1u64, 15, 25, 31, 1_000_000] {
            let proof = tree.prove_non_membership(v(n)).unwrap();
            tree.state()
                .verify_non_membership(POOL, D, v(n), &proof)
                .unwrap();
        }
    }

    #[test]
    fn duplicates_are_rejected() {
        let mut tree = tree();
        tree.insert(v(7)).unwrap();
        let root_before = tree.root();
        assert_eq!(tree.insert(v(7)), Err(ImtError::DuplicateValue));
        assert_eq!(tree.root(), root_before, "failed insert mutated the tree");
    }

    #[test]
    fn insertion_proofs_drive_a_root_only_state() {
        let mut tree = tree();
        let mut state = ImtState::new(POOL, D).unwrap();
        for n in [5u64, 3, 9, 1, 7] {
            let proof = tree.insert(v(n)).unwrap();
            state.apply_insertion(POOL, D, v(n), &proof).unwrap();
            assert_eq!(state, tree.state(), "state diverged after inserting {n}");
        }
    }

    #[test]
    fn max_value_is_insertable_and_becomes_the_maximum() {
        let mut tree = tree();
        tree.insert(Value::MAX).unwrap();
        let leaf = tree.leaf(1).unwrap();
        assert_eq!(leaf.value, Value::MAX);
        assert!(leaf.next_value.is_zero(), "MAX should have no successor");

        // Everything below MAX is still provably absent, bracketed by the
        // sentinel.
        let proof = tree.prove_non_membership(v(1)).unwrap();
        tree.state()
            .verify_non_membership(POOL, D, v(1), &proof)
            .unwrap();

        assert_eq!(
            tree.prove_non_membership(Value::MAX),
            Err(ImtError::ValueIsMember)
        );
    }

    #[test]
    fn sentinel_brackets_everything_in_an_empty_tree() {
        let tree = tree();
        let proof = tree.prove_non_membership(Value::MAX).unwrap();
        assert_eq!(proof.low_leaf, Leaf::SENTINEL);
        tree.state()
            .verify_non_membership(POOL, D, Value::MAX, &proof)
            .unwrap();
    }

    #[test]
    fn capacity_is_enforced() {
        // Depth 2 holds four leaves: sentinel plus three values.
        let mut tree = IndexedMerkleTree::with_depth(POOL, 2).unwrap();
        for n in 1..=3u64 {
            tree.insert(v(n)).unwrap();
        }
        assert_eq!(
            tree.insert(v(4)),
            Err(ImtError::CapacityExhausted {
                depth: 2,
                capacity: 4
            })
        );
    }

    #[test]
    fn depth_bounds_are_enforced() {
        assert_eq!(
            IndexedMerkleTree::with_depth(POOL, 0).err(),
            Some(ImtError::InvalidDepth { depth: 0 })
        );
        assert_eq!(
            IndexedMerkleTree::with_depth(POOL, 64).err(),
            Some(ImtError::InvalidDepth { depth: 64 })
        );
        assert!(IndexedMerkleTree::with_depth(POOL, MAX_DEPTH).is_ok());
    }

    #[test]
    fn batch_equals_sequential() {
        let values: Vec<Value> = [11u64, 4, 77, 2, 39].iter().map(|n| v(*n)).collect();

        let mut batched = tree();
        batched.insert_batch(&values).unwrap();

        let mut sequential = tree();
        for value in &values {
            sequential.insert(*value).unwrap();
        }

        assert_eq!(batched.root(), sequential.root());
    }

    #[test]
    fn insertion_order_changes_the_root() {
        // Not a defect — leaf indices are part of the commitment. Pinned so
        // nobody "fixes" it into order independence, which would make replay
        // ambiguous.
        let ascending = IndexedMerkleTree::from_values(POOL, D, &[v(1), v(2)]).unwrap();
        let descending = IndexedMerkleTree::from_values(POOL, D, &[v(2), v(1)]).unwrap();
        assert_ne!(ascending.root(), descending.root());
    }

    #[test]
    fn pools_produce_different_roots_for_identical_input() {
        let orchard = IndexedMerkleTree::from_values(PoolId::Orchard, D, &[v(1)]).unwrap();
        let ironwood = IndexedMerkleTree::from_values(PoolId::Ironwood, D, &[v(1)]).unwrap();
        assert_ne!(orchard.root(), ironwood.root());
    }

    // --- adversarial proof handling ------------------------------------

    #[test]
    fn non_membership_proof_for_the_wrong_value_is_rejected() {
        let mut tree = tree();
        tree.insert(v(10)).unwrap();
        tree.insert(v(20)).unwrap();

        let proof = tree.prove_non_membership(v(15)).unwrap();
        // 15's low leaf is 10, which does not bracket 25.
        assert_eq!(
            tree.state()
                .verify_non_membership(POOL, D, v(25), &proof)
                .err(),
            Some(ImtError::LowLeafDoesNotCover)
        );
    }

    #[test]
    fn forged_low_leaf_is_rejected() {
        let mut tree = tree();
        tree.insert(v(10)).unwrap();

        let mut proof = tree.prove_non_membership(v(5)).unwrap();
        // Claim a bracket the tree never contained.
        proof.low_leaf = Leaf {
            value: v(4),
            next_value: v(6),
            next_index: 99,
        };
        assert!(matches!(
            tree.state().verify_non_membership(POOL, D, v(5), &proof),
            Err(ImtError::RootMismatch { .. })
        ));
    }

    #[test]
    fn stale_non_membership_proof_is_rejected() {
        let mut tree = tree();
        tree.insert(v(10)).unwrap();
        let proof = tree.prove_non_membership(v(5)).unwrap();

        // The value is inserted after the proof was issued.
        tree.insert(v(5)).unwrap();
        assert!(matches!(
            tree.state().verify_non_membership(POOL, D, v(5), &proof),
            Err(ImtError::RootMismatch { .. })
        ));
    }

    #[test]
    fn wrong_depth_proof_is_rejected() {
        let mut tree = tree();
        tree.insert(v(10)).unwrap();
        let proof = tree.prove_non_membership(v(5)).unwrap();
        assert_eq!(
            verify_non_membership(POOL, D + 1, &tree.root(), v(5), &proof).err(),
            Some(ImtError::WrongPathLength {
                expected: usize::from(D) + 1,
                found: usize::from(D),
            })
        );
    }

    #[test]
    fn wrong_pool_proof_is_rejected() {
        let mut tree = IndexedMerkleTree::with_depth(PoolId::Orchard, D).unwrap();
        tree.insert(v(10)).unwrap();
        let proof = tree.prove_non_membership(v(5)).unwrap();
        assert!(matches!(
            verify_non_membership(PoolId::Ironwood, D, &tree.root(), v(5), &proof),
            Err(ImtError::RootMismatch { .. })
        ));
    }

    #[test]
    fn insertion_at_a_non_append_index_is_rejected() {
        let mut tree = tree();
        let state = tree.state();
        let mut proof = tree.insert(v(10)).unwrap();
        proof.new_leaf_index = 5;
        assert_eq!(
            verify_insertion(POOL, D, &state, v(10), &proof).err(),
            Some(ImtError::UnexpectedLeafIndex {
                expected: 1,
                found: 5
            })
        );
    }

    #[test]
    fn insertion_proof_replayed_against_the_new_state_is_rejected() {
        let mut tree = tree();
        let mut state = tree.state();
        let proof = tree.insert(v(10)).unwrap();
        state.apply_insertion(POOL, D, v(10), &proof).unwrap();

        assert!(verify_insertion(POOL, D, &state, v(10), &proof).is_err());
    }

    #[test]
    fn insertion_of_a_duplicate_cannot_be_proven() {
        let mut tree = tree();
        tree.insert(v(10)).unwrap();
        let state = tree.state();
        let proof = tree.insert(v(20)).unwrap();

        // Reuse 20's proof to claim an insertion of 10, which is present.
        assert_eq!(
            verify_insertion(POOL, D, &state, v(10), &proof).err(),
            Some(ImtError::LowLeafDoesNotCover)
        );
    }

    #[test]
    fn insertion_over_an_occupied_position_is_rejected() {
        let mut tree = tree();
        tree.insert(v(10)).unwrap();
        let state = tree.state();
        let mut proof = tree.insert(v(20)).unwrap();

        // Point the append at the occupied leaf 1, and supply that leaf's real
        // siblings. The emptiness check is what has to catch this.
        proof.new_leaf_index = 1;
        proof.new_leaf_siblings = tree.siblings(1);
        assert!(matches!(
            verify_insertion(POOL, D, &state, v(20), &proof),
            Err(ImtError::UnexpectedLeafIndex { .. } | ImtError::RootMismatch { .. })
        ));
    }

    #[test]
    fn aliased_leaf_index_is_rejected() {
        let mut tree = tree();
        let state = tree.state();
        let mut proof = tree.insert(v(10)).unwrap();
        proof.low_leaf_index = proof.new_leaf_index;
        assert_eq!(
            verify_insertion(POOL, D, &state, v(10), &proof).err(),
            Some(ImtError::AliasedLeafIndex { index: 1 })
        );
    }

    #[test]
    fn out_of_range_index_is_rejected() {
        let mut tree = tree();
        tree.insert(v(10)).unwrap();
        let mut proof = tree.prove_non_membership(v(5)).unwrap();
        proof.low_leaf_index = 1 << D;
        assert_eq!(
            tree.state()
                .verify_non_membership(POOL, D, v(5), &proof)
                .err(),
            Some(ImtError::IndexOutOfRange {
                index: 256,
                capacity: 256
            })
        );
    }

    #[test]
    fn linked_list_stays_sorted() {
        let mut tree = tree();
        let mut inserted = vec![0u64];
        for n in [50u64, 10, 90, 30, 70, 20] {
            tree.insert(v(n)).unwrap();
            inserted.push(n);
        }
        inserted.sort_unstable();

        // Walk the list from the sentinel and check it enumerates the set in
        // ascending order.
        let mut walked = Vec::new();
        let mut leaf = tree.leaf(0).unwrap();
        loop {
            walked.push(leaf.value);
            if leaf.next_value.is_zero() {
                break;
            }
            let next = tree.leaf(leaf.next_index).unwrap();
            assert_eq!(
                next.value, leaf.next_value,
                "next_index/next_value disagree"
            );
            leaf = next;
        }

        let expected: Vec<Value> = inserted.iter().map(|n| v(*n)).collect();
        assert_eq!(walked, expected);
    }
}

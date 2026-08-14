//! A deliberately dumb model of a nullifier set.
//!
//! # This file must never get clever
//!
//! It is an oracle. Its value comes entirely from being wrong in *different*
//! ways than `zutreexo-accumulator` is wrong, which is why CLAUDE.md Phase 2
//! requires it to share zero code with that crate — including the hashing,
//! (That crate is deliberately not even a dependency of this one's library
//! target, only of its tests, which is why the name above is not a link.)
//! which is re-derived from the specification below rather than imported. The
//! moment it starts sharing helpers, or gets optimised, it stops being an
//! oracle and becomes a second copy of the same bug.
//!
//! Concretely, this file:
//!
//! * stores values in a `BTreeSet` and insertion order in a `Vec`, and derives
//!   every `next_value`/`next_index` pointer **from scratch** on each root
//!   computation, rather than maintaining them incrementally;
//! * materialises the entire `2^depth` leaf array and folds it pairwise,
//!   rather than walking a sparse path;
//! * re-states the BLAKE2b personalization strings as literals.
//!
//! The first two are what make it the "recompute cold" tier of the harness:
//! the failure mode that matters is an incremental path drifting from a
//! from-scratch computation over a million-block replay, surfacing only when
//! somebody cannot spend.
//!
//! # Depth limit
//!
//! Materialising `2^depth` leaves is only viable for small trees, so
//! [`NaiveImt`] caps depth at [`MAX_NAIVE_DEPTH`]. That is not a limitation of
//! the oracle's authority: tree depth is a parameter, and structural agreement
//! at depth 12 is the same statement as structural agreement at depth 32.

// The workspace denies `indexing_slicing` because a panic in accumulator code
// is a remote crash vector. That reasoning does not reach here: this file is a
// test oracle that never sees network input, and rewriting `leaves[index]` as
// a checked `get` would add error paths to code whose only virtue is being
// obviously correct at a glance. Panicking is the right failure mode for an
// oracle — it means the oracle itself is broken, which should be loud.
#![allow(clippy::indexing_slicing)]

use std::collections::BTreeSet;

/// A 32-byte digest.
pub type Hash = [u8; 32];

/// Largest depth this model will materialise. `2^16` leaves is about two
/// million hashes per root, which is slow but tolerable in a test.
pub const MAX_NAIVE_DEPTH: u8 = 16;

/// The shielded pools, restated here rather than imported.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NaivePool {
    /// Sprout.
    Sprout,
    /// Sapling.
    Sapling,
    /// Orchard.
    Orchard,
    /// Ironwood.
    Ironwood,
}

impl NaivePool {
    /// Personalization strings, written out in full.
    ///
    /// Independently transcribed from `docs/design.md`. If these ever disagree
    /// with `zutreexo-accumulator`'s, one of the two drifted, and the test that
    /// compares them is the point.
    fn personal(self, role: &str) -> [u8; 16] {
        let pool = match self {
            NaivePool::Sprout => "Sprt",
            NaivePool::Sapling => "Sapl",
            NaivePool::Orchard => "Orch",
            NaivePool::Ironwood => "Iron",
        };
        let joined = format!("ZNullIMT{pool}{role}");
        let bytes = joined.as_bytes();
        assert_eq!(
            bytes.len(),
            16,
            "personalization must be 16 bytes: {joined}"
        );
        let mut out = [0u8; 16];
        out.copy_from_slice(bytes);
        out
    }
}

/// Hashes with an explicit personalization. No shared helper on purpose.
fn blake(personal: [u8; 16], parts: &[&[u8]]) -> Hash {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(&personal)
        .to_state();
    for part in parts {
        state.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

/// Errors the model can report. Kept minimal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NaiveError {
    /// Depth is zero or above [`MAX_NAIVE_DEPTH`].
    BadDepth(u8),
    /// The value is already present.
    Duplicate,
    /// All-zero values are reserved for the sentinel.
    Reserved,
    /// The tree is full.
    Full,
}

/// A naive model of one pool's nullifier set.
#[derive(Clone, Debug)]
pub struct NaiveImt {
    pool: NaivePool,
    depth: u8,
    /// Insertion order. Position `i` here is leaf index `i + 1`; index 0 is
    /// the sentinel.
    order: Vec<Hash>,
    /// The same values, sorted. Used only to look up successors.
    sorted: BTreeSet<Hash>,
}

impl NaiveImt {
    /// A model of an empty tree.
    pub fn new(pool: NaivePool, depth: u8) -> Result<NaiveImt, NaiveError> {
        if depth == 0 || depth > MAX_NAIVE_DEPTH {
            return Err(NaiveError::BadDepth(depth));
        }
        Ok(NaiveImt {
            pool,
            depth,
            order: Vec::new(),
            sorted: BTreeSet::new(),
        })
    }

    /// Number of nullifiers inserted, excluding the sentinel.
    pub fn value_count(&self) -> u64 {
        self.order.len() as u64
    }

    /// Number of occupied leaves, including the sentinel.
    pub fn leaf_count(&self) -> u64 {
        self.value_count() + 1
    }

    /// Whether the value is present. The all-zero sentinel always is.
    pub fn contains(&self, value: &Hash) -> bool {
        *value == [0u8; 32] || self.sorted.contains(value)
    }

    /// Inserts a nullifier.
    pub fn insert(&mut self, value: Hash) -> Result<(), NaiveError> {
        if value == [0u8; 32] {
            return Err(NaiveError::Reserved);
        }
        if self.sorted.contains(&value) {
            return Err(NaiveError::Duplicate);
        }
        if self.leaf_count() >= 1u64 << self.depth {
            return Err(NaiveError::Full);
        }
        self.order.push(value);
        self.sorted.insert(value);
        Ok(())
    }

    /// Recomputes the root from scratch. Nothing is cached between calls.
    ///
    /// This is the expensive, honest path: rebuild every leaf's successor
    /// pointers by searching the sorted set, materialise the whole leaf array,
    /// and fold.
    pub fn root(&self) -> Hash {
        let leaf_personal = self.pool.personal("Leaf");
        let node_personal = self.pool.personal("Node");
        let empty = blake(self.pool.personal("Empt"), &[]);

        // Leaf index -> value. Index 0 is the sentinel's all-zero value.
        let mut values_by_index: Vec<Hash> = vec![[0u8; 32]];
        values_by_index.extend(self.order.iter().copied());

        // Value -> leaf index, rebuilt by linear search. Quadratic and proud.
        let index_of = |needle: &Hash| -> u64 {
            let mut found = 0u64;
            for (i, value) in values_by_index.iter().enumerate() {
                if value == needle {
                    found = i as u64;
                }
            }
            found
        };

        let mut leaves: Vec<Hash> = vec![empty; 1usize << self.depth];
        for (index, value) in values_by_index.iter().enumerate() {
            // Successor: the smallest inserted value strictly greater than
            // this one. All-zero means "none", which is why zero is reserved.
            let next_value = self
                .sorted
                .iter()
                .find(|candidate| *candidate > value)
                .copied()
                .unwrap_or([0u8; 32]);
            let next_index = if next_value == [0u8; 32] {
                0u64
            } else {
                index_of(&next_value)
            };

            leaves[index] = blake(
                leaf_personal,
                &[value, &next_value, &next_index.to_le_bytes()],
            );
        }

        // Fold pairwise until one node remains.
        let mut level = leaves;
        while level.len() > 1 {
            let mut parents = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                let left = pair[0];
                let right = if pair.len() > 1 { pair[1] } else { empty };
                parents.push(blake(node_personal, &[&left, &right]));
            }
            level = parents;
        }
        level[0]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::*;

    fn v(n: u64) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        bytes
    }

    #[test]
    fn rejects_bad_depth() {
        assert_eq!(
            NaiveImt::new(NaivePool::Orchard, 0).err(),
            Some(NaiveError::BadDepth(0))
        );
        assert_eq!(
            NaiveImt::new(NaivePool::Orchard, MAX_NAIVE_DEPTH + 1).err(),
            Some(NaiveError::BadDepth(MAX_NAIVE_DEPTH + 1))
        );
    }

    #[test]
    fn rejects_duplicates_and_the_sentinel() {
        let mut model = NaiveImt::new(NaivePool::Orchard, 8).unwrap();
        model.insert(v(1)).unwrap();
        assert_eq!(model.insert(v(1)).err(), Some(NaiveError::Duplicate));
        assert_eq!(model.insert(v(0)).err(), Some(NaiveError::Reserved));
    }

    #[test]
    fn root_changes_with_insertion_order() {
        let mut a = NaiveImt::new(NaivePool::Orchard, 6).unwrap();
        a.insert(v(1)).unwrap();
        a.insert(v(2)).unwrap();

        let mut b = NaiveImt::new(NaivePool::Orchard, 6).unwrap();
        b.insert(v(2)).unwrap();
        b.insert(v(1)).unwrap();

        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn root_is_stable_across_calls() {
        let mut model = NaiveImt::new(NaivePool::Sapling, 6).unwrap();
        model.insert(v(5)).unwrap();
        assert_eq!(model.root(), model.root());
    }
}

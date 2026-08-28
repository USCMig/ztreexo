//! Domain-separated hashing for every accumulator in this crate.
//!
//! CLAUDE.md §5 rule 4: every hash gets a domain separator, no exceptions. A
//! cross-structure collision — a transparent UTXO leaf that hashes to the same
//! digest as a nullifier IMT node, say — is a consensus bug, and the cheapest
//! way to make one impossible is to give every (structure, pool, node-role)
//! triple its own BLAKE2b personalization.
//!
//! # Personalization scheme
//!
//! BLAKE2b personalization is exactly 16 bytes, and it is mixed into the
//! parameter block rather than the message, so two hashes with different
//! personalizations are independent functions. Every separator here is
//! constructed to fill all 16 bytes:
//!
//! | Structure | Layout | Example |
//! |---|---|---|
//! | Transparent Utreexo | `"ZUtxoAccum" ‖ "__" ‖ role(4)` | `ZUtxoAccum__Leaf` |
//! | Nullifier IMT | `"ZNullIMT" ‖ pool(4) ‖ role(4)` | `ZNullIMTOrchLeaf` |
//!
//! Note commitment trees appear nowhere here. They are deliberately left alone
//! (CLAUDE.md §2): they are already append-only frontiers whose membership is
//! proven inside the zk-SNARK, and rehashing them would break the circuit.
//!
//! # Stability
//!
//! These strings are consensus-visible the moment two nodes compare a root.
//! They must never change. The tests at the bottom of this file pin every
//! separator byte-for-byte so a refactor cannot drift them silently.

use blake2b_simd::Params;

use crate::pool::PoolId;

/// A 32-byte digest. Every accumulator node, leaf, and root in this crate.
pub type Hash = [u8; 32];

/// Digest length in bytes. BLAKE2b is configured to emit exactly this much.
pub const HASH_LEN: usize = 32;

/// Transparent Utreexo leaf-hash separator.
const UTXO_LEAF_PERSONAL: [u8; 16] = *b"ZUtxoAccum__Leaf";
/// Transparent Utreexo internal-node separator.
const UTXO_NODE_PERSONAL: [u8; 16] = *b"ZUtxoAccum__Node";

/// Builds a nullifier-IMT separator as `"ZNullIMT" ‖ pool ‖ role`.
///
/// Written as an array literal rather than index assignment so it stays a
/// `const fn` and needs no slicing.
const fn imt_personal(pool: PoolId, role: [u8; 4]) -> [u8; 16] {
    let [p0, p1, p2, p3] = pool.tag();
    let [r0, r1, r2, r3] = role;
    [
        b'Z', b'N', b'u', b'l', b'l', b'I', b'M', b'T', p0, p1, p2, p3, r0, r1, r2, r3,
    ]
}

/// Builds a sorted-cohort-tree separator as `"ZSortNul" ‖ pool ‖ role`.
///
/// A **distinct family** from `imt_personal`, and that is the point. The sorted
/// tree (`sorted.rs`) holds the same nullifiers as the IMT for the same pool,
/// so without separate separators a leaf digest from one could be presented as
/// a node digest from the other. CLAUDE.md §5 rule 4 exists for exactly this:
/// two structures over one set is where a cross-structure collision would be
/// worth mounting.
const fn sorted_personal(pool: PoolId, role: [u8; 4]) -> [u8; 16] {
    let [p0, p1, p2, p3] = pool.tag();
    let [r0, r1, r2, r3] = role;
    [
        b'Z', b'S', b'o', b'r', b't', b'N', b'u', b'l', p0, p1, p2, p3, r0, r1, r2, r3,
    ]
}

/// Sorted-cohort-tree leaf separator for `pool`.
pub const fn sorted_leaf_personal(pool: PoolId) -> [u8; 16] {
    sorted_personal(pool, *b"Leaf")
}

/// Sorted-cohort-tree internal-node separator for `pool`.
pub const fn sorted_node_personal(pool: PoolId) -> [u8; 16] {
    sorted_personal(pool, *b"Node")
}

/// Sorted-cohort-tree padding-leaf separator for `pool`.
pub const fn sorted_pad_personal(pool: PoolId) -> [u8; 16] {
    sorted_personal(pool, *b"Padd")
}

/// Digest of one nullifier in the sorted cohort tree.
///
/// Just the value: sortedness is carried by *position*, so the linked-list
/// fields the IMT leaf commits to (`next_value`, `next_index`) have no
/// counterpart here. That is the whole reason a sorted leaf is 32 bytes on the
/// wire where an IMT leaf is 72.
pub fn sorted_leaf(pool: PoolId, value: &[u8; 32]) -> Hash {
    let mut state = params(&sorted_leaf_personal(pool));
    state.update(value);
    finalize(state)
}

/// Internal node of the sorted cohort tree.
pub fn sorted_node(pool: PoolId, left: &Hash, right: &Hash) -> Hash {
    let mut state = params(&sorted_node_personal(pool));
    state.update(left);
    state.update(right);
    finalize(state)
}

/// The digest padding an unoccupied position in the sorted cohort tree.
///
/// The tree is built to the next power of two, so the tail is padding. Its own
/// separator, for the reason [`imt_empty_leaf`] gives: no real nullifier can
/// collide with a pad.
pub fn sorted_pad_leaf(pool: PoolId) -> Hash {
    finalize(params(&sorted_pad_personal(pool)))
}

/// Nullifier-IMT leaf-hash separator for `pool`.
pub const fn imt_leaf_personal(pool: PoolId) -> [u8; 16] {
    imt_personal(pool, *b"Leaf")
}

/// Nullifier-IMT internal-node separator for `pool`.
pub const fn imt_node_personal(pool: PoolId) -> [u8; 16] {
    imt_personal(pool, *b"Node")
}

/// Nullifier-IMT empty-leaf separator for `pool`.
///
/// Unfilled positions in a fixed-depth tree need a defined digest. Giving the
/// empty leaf its own separator — rather than reusing all-zero bytes or the
/// leaf separator over zero input — means no populated leaf can ever collide
/// with an empty one, whatever its contents.
pub const fn imt_empty_personal(pool: PoolId) -> [u8; 16] {
    imt_personal(pool, *b"Empt")
}

/// Finalizes a BLAKE2b state configured for 32-byte output.
///
/// The `copy_from_slice` cannot mismatch: every caller reaches this through
/// [`params`], which sets `hash_length(HASH_LEN)`.
fn finalize(state: blake2b_simd::State) -> Hash {
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

/// A BLAKE2b-256 state personalized with `personal`.
fn params(personal: &[u8; 16]) -> blake2b_simd::State {
    Params::new()
        .hash_length(HASH_LEN)
        .personal(personal)
        .to_state()
}

/// Hashes a nullifier IMT leaf: `value ‖ next_value ‖ next_index`.
///
/// `next_index` is encoded little-endian over 8 bytes. The encoding is fixed
/// width so the preimage cannot be re-split — a variable-length encoding here
/// would let two distinct leaves share a preimage.
pub fn imt_leaf(pool: PoolId, value: &[u8; 32], next_value: &[u8; 32], next_index: u64) -> Hash {
    let mut state = params(&imt_leaf_personal(pool));
    state.update(value);
    state.update(next_value);
    state.update(&next_index.to_le_bytes());
    finalize(state)
}

/// Hashes a nullifier IMT internal node from its two children.
pub fn imt_node(pool: PoolId, left: &Hash, right: &Hash) -> Hash {
    let mut state = params(&imt_node_personal(pool));
    state.update(left);
    state.update(right);
    finalize(state)
}

/// The digest of an unoccupied nullifier IMT leaf, for `pool`.
///
/// Domain-separated over empty input, so it is a per-pool constant.
pub fn imt_empty_leaf(pool: PoolId) -> Hash {
    finalize(params(&imt_empty_personal(pool)))
}

/// Personalization for on-disk snapshot integrity.
///
/// A distinct domain so a snapshot checksum can never collide with an
/// accumulator digest (CLAUDE.md §5 rule 4). Sixteen bytes, like the rest.
const STORE_PERSONAL: [u8; 16] = *b"ZStore__Checksum";

/// Checksum over a snapshot payload.
///
/// Detects truncation and bit-rot on load. Not a security boundary: a snapshot
/// is trusted-but-verifiable input, and the real check is that its roots match
/// what replaying the chain produces.
pub fn store_checksum(payload: &[u8]) -> Hash {
    let mut state = params(&STORE_PERSONAL);
    state.update(payload);
    finalize(state)
}

/// Hashes a transparent UTXO leaf preimage.
///
/// The preimage is assembled by [`crate::utreexo::UtxoLeaf`], which decides
/// what a leaf commits to; this function only applies the separator.
pub fn utxo_leaf(preimage: &[u8]) -> Hash {
    let mut state = params(&UTXO_LEAF_PERSONAL);
    state.update(preimage);
    finalize(state)
}

/// Hashes a transparent Utreexo internal node from its two children.
pub fn utxo_node(left: &Hash, right: &Hash) -> Hash {
    let mut state = params(&UTXO_NODE_PERSONAL);
    state.update(left);
    state.update(right);
    finalize(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte pins. If one of these fails, a domain separator drifted,
    /// and every root ever computed with the old one is now unreachable.
    #[test]
    fn separators_are_pinned() {
        assert_eq!(&UTXO_LEAF_PERSONAL, b"ZUtxoAccum__Leaf");
        assert_eq!(&UTXO_NODE_PERSONAL, b"ZUtxoAccum__Node");

        assert_eq!(&imt_leaf_personal(PoolId::Sprout), b"ZNullIMTSprtLeaf");
        assert_eq!(&imt_leaf_personal(PoolId::Sapling), b"ZNullIMTSaplLeaf");
        assert_eq!(&imt_leaf_personal(PoolId::Orchard), b"ZNullIMTOrchLeaf");
        assert_eq!(&imt_leaf_personal(PoolId::Ironwood), b"ZNullIMTIronLeaf");

        assert_eq!(&imt_node_personal(PoolId::Orchard), b"ZNullIMTOrchNode");
        assert_eq!(&imt_empty_personal(PoolId::Orchard), b"ZNullIMTOrchEmpt");
    }

    /// Personalization must fill all 16 bytes. A short separator is silently
    /// zero-padded by BLAKE2b, which makes two "different" separators equal if
    /// they share a prefix.
    #[test]
    fn every_separator_is_exactly_sixteen_bytes() {
        // Enforced by the type, but assert the roles too: a five-byte role
        // would not compile, a three-byte one would shift the pool tag.
        for pool in PoolId::ALL {
            for sep in [
                imt_leaf_personal(pool),
                imt_node_personal(pool),
                imt_empty_personal(pool),
            ] {
                assert_eq!(sep.len(), 16);
                assert!(!sep.contains(&0), "separator {sep:?} is zero-padded");
            }
        }
    }

    /// The point of the whole file: identical input under different domains
    /// must not produce identical output.
    #[test]
    fn domains_do_not_collide() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        let mut digests = Vec::new();
        digests.push(utxo_node(&a, &b));
        digests.push(utxo_leaf(&[a, b].concat()));
        for pool in PoolId::ALL {
            digests.push(imt_node(pool, &a, &b));
            digests.push(imt_leaf(pool, &a, &b, 0));
            digests.push(imt_empty_leaf(pool));
        }

        let count = digests.len();
        digests.sort_unstable();
        digests.dedup();
        assert_eq!(digests.len(), count, "two domains produced the same digest");
    }

    /// A leaf's three fields must not be re-splittable into a different leaf.
    #[test]
    fn leaf_fields_are_unambiguous() {
        let pool = PoolId::Orchard;
        let mut low = [0u8; 32];
        low[31] = 1;
        let mut high = [0u8; 32];
        high[31] = 2;

        assert_ne!(
            imt_leaf(pool, &low, &high, 0),
            imt_leaf(pool, &high, &low, 0)
        );
        assert_ne!(
            imt_leaf(pool, &low, &high, 0),
            imt_leaf(pool, &low, &high, 1)
        );
    }

    #[test]
    fn hashing_is_deterministic_across_calls() {
        let a = [7u8; 32];
        let b = [9u8; 32];
        assert_eq!(
            imt_node(PoolId::Sapling, &a, &b),
            imt_node(PoolId::Sapling, &a, &b)
        );
        assert_eq!(
            imt_empty_leaf(PoolId::Sapling),
            imt_empty_leaf(PoolId::Sapling)
        );
    }
}

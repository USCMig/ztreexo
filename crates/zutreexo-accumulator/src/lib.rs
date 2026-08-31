//! Accumulators for Zcash state compression.
//!
//! Pure library: no chain semantics, no I/O, no network. Phase 1 of the plan in
//! `CLAUDE.md`.
//!
//! # The three structures, and why they get different treatment
//!
//! Zcash is not one UTXO set. It has three growing structures with different
//! algebra, and the most common way to get this project wrong is to apply
//! Utreexo uniformly to all three (CLAUDE.md §2):
//!
//! | Structure | Operations | Primitive | Lives in |
//! |---|---|---|---|
//! | Transparent UTXO set | insert, delete, membership | Utreexo forest | [`utreexo`] |
//! | Nullifier set, per pool | insert, **non-membership** | Indexed Merkle tree | [`imt`] |
//! | Note commitment tree | append, membership-in-zk | *unchanged* | — nothing here |
//!
//! The note commitment tree appears nowhere in this crate on purpose. It is
//! already an append-only frontier and its membership is proven inside the
//! zk-SNARK; an accumulator would add nothing and would break the circuit.
//!
//! # Full and compact views
//!
//! Each accumulator has two types: one holding everything and able to generate
//! proofs (a bridge node), one holding only roots and able to verify them (a
//! compact state node).
//!
//! | | Full | Compact |
//! |---|---|---|
//! | Transparent | [`utreexo::UtxoForest`] | [`utreexo::UtxoRoots`] |
//! | Nullifiers | [`imt::IndexedMerkleTree`] | [`imt::ImtState`] |

pub mod cohort;
pub mod hash;
pub mod imt;
pub mod pool;
pub mod proof;
pub mod sorted;
pub mod utreexo;

pub use hash::{Hash, HASH_LEN};
pub use imt::{
    empty_subtree_hashes, ImtError, ImtState, IndexedMerkleTree, InsertionProof, Leaf,
    NonMembershipProof, Value, DEFAULT_DEPTH, MAX_DEPTH, MIN_DEPTH,
};
pub use pool::PoolId;
pub use proof::{CanonicalSerialize, NullifierProofBundle, ProofCodecError, PROOF_FORMAT_VERSION};
pub use utreexo::{UtreexoError, UtxoForest, UtxoLeaf, UtxoProof, UtxoRoots, ZcashNodeHash};

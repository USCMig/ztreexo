//! Per-pool chain state: the accumulators a bridge node maintains.
//!
//! [`PoolId`] itself lives in `zutreexo-accumulator`, because the hash domain
//! separators are pool-specific and domain separation is a Phase 1 concern.
//! What lives here is the *chain-side* state: one indexed Merkle tree per pool,
//! the transparent forest, and the outpoint index.
//!
//! # Why there is a UTXO index here at all
//!
//! It looks like a contradiction — the point of the project is to *not* hold a
//! UTXO set — so it is worth being explicit.
//!
//! A transparent leaf hash commits to the output's full contents: value,
//! script, height, coinbase flag (`docs/design.md` D9). A transaction that
//! *spends* an output carries none of that; it carries only an outpoint. So to
//! delete the right leaf, whoever applies the block must already know what the
//! output was.
//!
//! For a compact state node that information arrives in the proof bundle,
//! supplied by a bridge. For a bridge node — which is what replay is — it has
//! to be tracked. [`ChainAccumulators`] is the bridge-side type, so it keeps
//! the index. That is the cost of being the party that serves proofs, and it is
//! exactly the cost the design intends to concentrate rather than eliminate.

use std::collections::BTreeMap;

use zutreexo_accumulator::imt::{ImtError, ImtState, IndexedMerkleTree, DEFAULT_DEPTH};
use zutreexo_accumulator::{Hash, PoolId, UtxoForest, UtxoLeaf};

use crate::extract::OutPoint;

/// The full accumulator state for a chain, as a bridge node holds it.
#[derive(Debug)]
pub struct ChainAccumulators {
    /// Depth every nullifier tree is built at.
    depth: u8,
    /// One indexed Merkle tree per pool.
    nullifiers: BTreeMap<PoolId, IndexedMerkleTree>,
    /// The transparent Utreexo forest.
    utxos: UtxoForest,
    /// Outpoint to the leaf it created. See the module docs.
    utxo_index: BTreeMap<OutPoint, UtxoLeaf>,
    /// Height of the last block applied, if any.
    tip: Option<u32>,
}

impl Default for ChainAccumulators {
    fn default() -> Self {
        // `DEFAULT_DEPTH` is validated by construction, so this cannot fail;
        // the fallback keeps `Default` total rather than panicking.
        ChainAccumulators::new(DEFAULT_DEPTH).unwrap_or(ChainAccumulators {
            depth: DEFAULT_DEPTH,
            nullifiers: BTreeMap::new(),
            utxos: UtxoForest::new(),
            utxo_index: BTreeMap::new(),
            tip: None,
        })
    }
}

impl ChainAccumulators {
    /// Empty state, with every pool's tree initialised at `depth`.
    ///
    /// All pools are created up front, including those not yet activated. An
    /// empty tree has a well-defined root, and creating them lazily would make
    /// the state depend on activation-height logic that belongs in consensus,
    /// not here.
    pub fn new(depth: u8) -> Result<ChainAccumulators, ImtError> {
        let mut nullifiers = BTreeMap::new();
        for pool in PoolId::ALL {
            nullifiers.insert(pool, IndexedMerkleTree::with_depth(pool, depth)?);
        }
        Ok(ChainAccumulators {
            depth,
            nullifiers,
            utxos: UtxoForest::new(),
            utxo_index: BTreeMap::new(),
            tip: None,
        })
    }

    /// The depth every nullifier tree uses.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Height of the last applied block.
    pub fn tip(&self) -> Option<u32> {
        self.tip
    }

    /// Records the tip after a successful apply.
    pub(crate) fn set_tip(&mut self, height: u32) {
        self.tip = Some(height);
    }

    /// The nullifier tree for one pool.
    pub fn tree(&self, pool: PoolId) -> Option<&IndexedMerkleTree> {
        self.nullifiers.get(&pool)
    }

    /// Mutable access to one pool's tree.
    pub(crate) fn tree_mut(&mut self, pool: PoolId) -> Option<&mut IndexedMerkleTree> {
        self.nullifiers.get_mut(&pool)
    }

    /// The transparent forest.
    pub fn utxos(&self) -> &UtxoForest {
        &self.utxos
    }

    /// Mutable access to the transparent forest.
    pub(crate) fn utxos_mut(&mut self) -> &mut UtxoForest {
        &mut self.utxos
    }

    /// The leaf an outpoint created, if this state knows it.
    pub fn utxo(&self, outpoint: &OutPoint) -> Option<&UtxoLeaf> {
        self.utxo_index.get(outpoint)
    }

    /// Number of unspent outputs currently tracked.
    pub fn utxo_count(&self) -> usize {
        self.utxo_index.len()
    }

    /// Records a created output.
    pub(crate) fn insert_utxo(&mut self, outpoint: OutPoint, leaf: UtxoLeaf) {
        self.utxo_index.insert(outpoint, leaf);
    }

    /// Forgets a spent output, returning what it was.
    pub(crate) fn remove_utxo(&mut self, outpoint: &OutPoint) -> Option<UtxoLeaf> {
        self.utxo_index.remove(outpoint)
    }

    /// A copy of the outpoint index, for a rollback snapshot.
    ///
    /// Cloned rather than borrowed because the caller keeps it across
    /// subsequent mutations — that is the entire point of a snapshot.
    pub(crate) fn clone_utxo_index(&self) -> BTreeMap<OutPoint, UtxoLeaf> {
        self.utxo_index.clone()
    }

    /// Replaces the transparent half wholesale, as rollback does.
    ///
    /// The forest and the index must come from the same snapshot. They are
    /// replaced together for that reason: an index describing outputs the
    /// forest does not contain would let `apply_block` compute a leaf hash for
    /// a leaf that is not there, and the deletion would fail at a height with
    /// no obvious connection to the reorg that caused it.
    pub(crate) fn restore_transparent(
        &mut self,
        utxos: UtxoForest,
        index: BTreeMap<OutPoint, UtxoLeaf>,
    ) {
        self.utxos = utxos;
        self.utxo_index = index;
    }

    /// Rewinds the recorded tip. Rollback owns this; nothing else should.
    pub(crate) fn set_tip_to(&mut self, height: Option<u32>) {
        self.tip = height;
    }

    /// The compact per-pool state a light node would hold.
    pub fn imt_states(&self) -> BTreeMap<PoolId, ImtState> {
        self.nullifiers
            .iter()
            .map(|(pool, tree)| (*pool, tree.state()))
            .collect()
    }

    /// Every nullifier root, keyed by pool.
    pub fn nullifier_roots(&self) -> BTreeMap<PoolId, Hash> {
        self.nullifiers
            .iter()
            .map(|(pool, tree)| (*pool, tree.root()))
            .collect()
    }

    /// The transparent accumulator roots.
    pub fn utxo_roots(&self) -> Vec<Hash> {
        self.utxos.roots()
    }

    /// Nullifiers accumulated in one pool, excluding the sentinel.
    pub fn nullifier_count(&self, pool: PoolId) -> u64 {
        self.nullifiers.get(&pool).map_or(0, |t| t.value_count())
    }

    /// A compact fingerprint of the whole state, for cheap comparison.
    ///
    /// Counts only — the every-block tier of the CLAUDE.md Phase 2 harness,
    /// which is `O(1)` and catches a dropped output or nullifier immediately
    /// without the cost of comparing roots.
    pub fn counts(&self) -> StateCounts {
        StateCounts {
            height: self.tip,
            utxos: self.utxo_count(),
            nullifiers: PoolId::ALL
                .into_iter()
                .map(|pool| (pool, self.nullifier_count(pool)))
                .collect(),
        }
    }
}

/// Cheap structural summary of [`ChainAccumulators`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StateCounts {
    /// Height of the last applied block.
    pub height: Option<u32>,
    /// Unspent transparent outputs tracked.
    pub utxos: usize,
    /// Nullifiers per pool, excluding sentinels.
    pub nullifiers: BTreeMap<PoolId, u64>,
}

//! Utreexo forest — the transparent UTXO accumulator.
//!
//! This is the structure that ports directly from Bitcoin (CLAUDE.md §2). The
//! transparent UTXO set needs insert, delete, and membership, and Utreexo's
//! forest-of-perfect-trees exists precisely to make deletion cheap. Per the
//! dependency policy in §3 the accumulator algebra itself comes from
//! `rustreexo` rather than being reimplemented here; this module supplies the
//! Zcash-specific parts:
//!
//! * [`ZcashNodeHash`], so the forest hashes with our BLAKE2b domain separators
//!   instead of Bitcoin's SHA-512/256;
//! * [`UtxoLeaf`], which decides what a leaf commits to;
//! * typed wrappers that keep `rustreexo`'s `String`-typed and `Rc`-bearing
//!   surfaces out of the rest of the codebase.
//!
//! # Two views of the same forest
//!
//! [`UtxoForest`] holds every leaf and can generate proofs — the bridge node.
//! [`UtxoRoots`] holds only roots and verifies proofs — the compact state node.
//! They are the transparent-side analogues of
//! [`IndexedMerkleTree`](crate::imt::IndexedMerkleTree) and
//! [`ImtState`](crate::imt::ImtState).

use std::fmt;

use rustreexo::mem_forest::MemForest;
use rustreexo::node_hash::AccumulatorHash;
use rustreexo::proof::Proof;
use rustreexo::stump::Stump;

use crate::hash::{self, Hash};

/// Everything that can go wrong on the transparent side.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum UtreexoError {
    /// The proof does not verify against the current roots.
    #[error("utreexo proof is invalid")]
    InvalidProof,

    /// A leaf being deleted is not in the accumulator, or is not cached.
    #[error("leaf is absent from the accumulator")]
    UnknownLeaf,

    /// A forest snapshot could not be written or read back.
    ///
    /// Serialisation is the only way to copy a forest — see
    /// [`UtxoForest::to_bytes`] — so a failure here means rollback has no
    /// usable snapshot, not merely that an optimisation was unavailable.
    #[error("utreexo snapshot i/o: {0}")]
    Snapshot(String),

    /// `rustreexo` reported a failure. Its errors are `String`-typed, so they
    /// are carried across rather than re-modelled.
    #[error("utreexo backend error: {0}")]
    Backend(String),
}

/// A node hash in the transparent forest, domain-separated for Zcash.
///
/// `rustreexo` defaults to `BitcoinNodeHash`, which hashes with SHA-512/256 and
/// Bitcoin's conventions. Reusing it would violate CLAUDE.md §5 rule 4 and, more
/// concretely, would let a digest from Bitcoin's accumulator be replayed into
/// Zcash's. The `Empty`/`Placeholder` variants are required by the
/// [`AccumulatorHash`] contract: `Empty` marks a deleted position, `Placeholder`
/// a node whose value a partial forest does not know.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum ZcashNodeHash {
    /// A deleted or never-populated position.
    #[default]
    Empty,
    /// A node a partial forest is deliberately not tracking.
    Placeholder,
    /// A real digest.
    Some(Hash),
}

impl ZcashNodeHash {
    /// Wraps a digest.
    pub const fn new(inner: Hash) -> ZcashNodeHash {
        ZcashNodeHash::Some(inner)
    }

    /// The digest, if this is a real node.
    pub const fn to_bytes(self) -> Option<Hash> {
        match self {
            ZcashNodeHash::Some(inner) => Some(inner),
            _ => None,
        }
    }
}

impl fmt::Display for ZcashNodeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZcashNodeHash::Empty => f.write_str("empty"),
            ZcashNodeHash::Placeholder => f.write_str("placeholder"),
            ZcashNodeHash::Some(inner) => {
                for byte in inner {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for ZcashNodeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl AccumulatorHash for ZcashNodeHash {
    fn is_empty(&self) -> bool {
        matches!(self, ZcashNodeHash::Empty)
    }

    fn empty() -> Self {
        ZcashNodeHash::Empty
    }

    fn is_placeholder(&self) -> bool {
        matches!(self, ZcashNodeHash::Placeholder)
    }

    fn placeholder() -> Self {
        ZcashNodeHash::Placeholder
    }

    fn parent_hash(left: &Self, right: &Self) -> Self {
        let l = left.to_bytes().unwrap_or([0u8; 32]);
        let r = right.to_bytes().unwrap_or([0u8; 32]);
        ZcashNodeHash::Some(hash::utxo_node(&l, &r))
    }

    /// Tagged encoding: `[0]` empty, `[1]` placeholder, `[2]` + 32 bytes.
    ///
    /// # The tag is load-bearing, not decoration
    ///
    /// This originally wrote a bare 32 bytes and read them back as
    /// `Some(bytes)`, which is byte-symmetric and still wrong. `MemForest`'s
    /// deserializer only recurses into a branch's children when
    /// `!data.is_empty()`, so an `Empty` node writes no children — and a reader
    /// that resurrects it as `Some([0; 32])` reports `is_empty() == false`,
    /// goes looking for two children that were never written, and fails with
    /// "failed to fill whole buffer".
    ///
    /// The variant therefore has to survive the round trip, which means a tag.
    /// This matches upstream `BitcoinNodeHash` byte for byte.
    ///
    /// Latent since Phase 1 and invisible until stage 2c, because nothing
    /// serialised a forest before rollback snapshots needed to. Found by the
    /// reorg fuzzer at iteration 16,310 of seed 1.
    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match self {
            ZcashNodeHash::Empty => writer.write_all(&[0]),
            ZcashNodeHash::Placeholder => writer.write_all(&[1]),
            ZcashNodeHash::Some(hash) => {
                writer.write_all(&[2])?;
                writer.write_all(hash)
            }
        }
    }

    fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            0 => Ok(ZcashNodeHash::Empty),
            1 => Ok(ZcashNodeHash::Placeholder),
            2 => {
                let mut buf = [0u8; 32];
                reader.read_exact(&mut buf)?;
                Ok(ZcashNodeHash::Some(buf))
            }
            // Rejected rather than assumed: a snapshot is bytes from disk, and
            // CLAUDE.md §5 rule 3 bans panicking on input in these paths.
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown node hash tag {other}"),
            )),
        }
    }
}

/// A transparent UTXO, in the form the accumulator commits to.
///
/// # What a leaf must commit to
///
/// Enough that a valid proof cannot be replayed for a *different* output
/// (CLAUDE.md §7). Mirroring Bitcoin's Utreexo leaf design, that means:
///
/// * `outpoint` — which output this is. On its own this is not enough: two
///   chains, or a rolled-back and re-mined transaction, can reuse an outpoint.
/// * `script_pubkey` and `value` — the output's actual content, so a proof for
///   a 1-zat output cannot be presented for a 1000-ZEC one.
/// * `height` and `is_coinbase` — coinbase maturity is a consensus rule, and a
///   validator holding no UTXO set has nowhere else to learn either fact. Zcash
///   additionally requires coinbase outputs to be spent subject to its own
///   shielding rules, so getting this wrong is not merely a maturity bug.
///
/// # Not yet final
///
/// The preimage layout below is a Phase 1 placeholder. It must be confirmed
/// against the Zcash transparent transaction format and coinbase rules before
/// Phase 3 freezes anything on disk — CLAUDE.md §5 rule 7: consult the protocol
/// specification, do not infer from Bitcoin analogy.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UtxoLeaf {
    /// Transaction ID of the creating transaction.
    pub txid: [u8; 32],
    /// Output index within that transaction.
    pub vout: u32,
    /// Height of the block that created the output.
    pub height: u32,
    /// Whether the creating transaction was a coinbase.
    pub is_coinbase: bool,
    /// Value in zatoshis.
    pub value: u64,
    /// The output's `scriptPubKey`.
    pub script_pubkey: Vec<u8>,
}

impl UtxoLeaf {
    /// The leaf's digest.
    ///
    /// Fields are length-prefixed or fixed-width so the preimage admits exactly
    /// one parse; a bare concatenation of variable-length fields would let two
    /// distinct outputs share a digest.
    pub fn hash(&self) -> Hash {
        let mut preimage = Vec::with_capacity(64usize.saturating_add(self.script_pubkey.len()));
        preimage.extend_from_slice(&self.txid);
        preimage.extend_from_slice(&self.vout.to_le_bytes());
        preimage.extend_from_slice(&self.height.to_le_bytes());
        preimage.push(u8::from(self.is_coinbase));
        preimage.extend_from_slice(&self.value.to_le_bytes());
        let script_len = u64::try_from(self.script_pubkey.len()).unwrap_or(u64::MAX);
        preimage.extend_from_slice(&script_len.to_le_bytes());
        preimage.extend_from_slice(&self.script_pubkey);
        hash::utxo_leaf(&preimage)
    }

    /// The leaf as an accumulator node.
    pub fn node_hash(&self) -> ZcashNodeHash {
        ZcashNodeHash::Some(self.hash())
    }
}

/// A batch inclusion proof for transparent leaves.
///
/// Wraps `rustreexo`'s proof so the rest of the codebase never names it
/// directly. Proofs for inputs in the same block share internal nodes, which is
/// what makes batching worth doing — the deduplication measurement is Phase 4.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UtxoProof(Proof<ZcashNodeHash>);

impl Default for UtxoProof {
    /// The empty proof, which is what insert-only mutations carry.
    ///
    /// Hand-written because `rustreexo` only derives `Default` for its own
    /// Bitcoin hash type.
    fn default() -> UtxoProof {
        UtxoProof(Proof::new_with_hash(Vec::new(), Vec::new()))
    }
}

impl UtxoProof {
    /// Number of leaves this proof covers.
    pub fn target_count(&self) -> usize {
        self.0.n_targets()
    }

    /// Borrows the backing `rustreexo` proof.
    pub fn inner(&self) -> &Proof<ZcashNodeHash> {
        &self.0
    }

    /// Wraps a backing `rustreexo` proof.
    pub fn from_inner(proof: Proof<ZcashNodeHash>) -> UtxoProof {
        UtxoProof(proof)
    }
}

/// Roots-only view of the transparent accumulator: the compact state node side.
///
/// A few hundred bytes standing in for the whole UTXO set. Every mutation must
/// be accompanied by a proof, which is what a bridge node supplies.
#[derive(Clone, Debug)]
pub struct UtxoRoots {
    stump: Stump<ZcashNodeHash>,
}

impl Default for UtxoRoots {
    fn default() -> UtxoRoots {
        UtxoRoots::new()
    }
}

impl UtxoRoots {
    /// An empty accumulator.
    pub fn new() -> UtxoRoots {
        UtxoRoots {
            stump: Stump::new_with_hash(),
        }
    }

    /// Rebuilds a roots-only view from roots and a leaf counter.
    ///
    /// # This is a trust boundary, and it is the only one in this type
    ///
    /// Every other mutation carries a proof. This one does not: it exists so a
    /// compact node can *bootstrap* from a state someone else computed, which
    /// CLAUDE.md Phase 3 asks for — "a trusted-but-verifiable state at height
    /// H, then validate forward". The verifiable half is the caller's job:
    /// compare these roots against several independent bridges before adopting
    /// them, exactly as `wire::Roots` describes.
    ///
    /// `leaves` is the total ever inserted, not the unspent count. Utreexo
    /// assigns positions from that counter and never decrements it, so
    /// supplying the unspent count instead would place every subsequent leaf at
    /// the wrong position and fail on the first proof rather than silently.
    pub fn from_parts(roots: &[Hash], leaves: u64) -> UtxoRoots {
        UtxoRoots {
            stump: Stump {
                leaves,
                roots: roots.iter().copied().map(ZcashNodeHash::new).collect(),
            },
        }
    }

    /// The current roots, one per perfect tree in the forest.
    pub fn roots(&self) -> Vec<Hash> {
        self.stump
            .roots
            .iter()
            .filter_map(|root| root.to_bytes())
            .collect()
    }

    /// Total leaves ever added, including spent ones.
    ///
    /// Utreexo positions are assigned from this counter, so it does not
    /// decrease on deletion.
    pub fn leaves(&self) -> u64 {
        self.stump.leaves
    }

    /// Checks that `leaves` are all in the accumulator.
    pub fn verify(&self, proof: &UtxoProof, leaves: &[Hash]) -> Result<bool, UtreexoError> {
        let hashes: Vec<ZcashNodeHash> = leaves.iter().copied().map(ZcashNodeHash::new).collect();
        self.stump
            .verify(proof.inner(), &hashes)
            .map_err(|e| UtreexoError::Backend(e.to_string()))
    }

    /// Adds leaves. Insertion alone needs no proof.
    pub fn insert(&mut self, leaves: &[Hash]) -> Result<(), UtreexoError> {
        self.apply(leaves, &[], &UtxoProof::default())
    }

    /// Removes leaves, given a proof that they are present.
    pub fn delete(&mut self, leaves: &[Hash], proof: &UtxoProof) -> Result<(), UtreexoError> {
        self.apply(&[], leaves, proof)
    }

    /// Applies a block's worth of additions and deletions in one step.
    ///
    /// Deletions are processed before additions, matching the block
    /// application order in CLAUDE.md Phase 2: inputs are verified and removed
    /// before outputs are inserted.
    ///
    /// That ordering is **not** because a block cannot spend an output it
    /// creates — it can, and mainnet block 572 does. Such an output is
    /// cancelled by the caller and never reaches this function at all
    /// (`docs/design.md` D21), so by the time a batch arrives here, no
    /// deletion in it refers to an addition in it. An earlier version of this
    /// comment asserted the false rule; it survived three stages because the
    /// behaviour it justified happens to be correct for a different reason.
    pub fn apply(
        &mut self,
        additions: &[Hash],
        deletions: &[Hash],
        proof: &UtxoProof,
    ) -> Result<(), UtreexoError> {
        let adds: Vec<ZcashNodeHash> = additions.iter().copied().map(ZcashNodeHash::new).collect();
        let dels: Vec<ZcashNodeHash> = deletions.iter().copied().map(ZcashNodeHash::new).collect();

        let (next, _update) = self
            .stump
            .modify(&adds, &dels, proof.inner())
            .map_err(|e| UtreexoError::Backend(e.to_string()))?;
        self.stump = next;
        Ok(())
    }
}

/// Full transparent forest: the bridge node side.
///
/// Holds every leaf and can therefore generate proofs. Not `Send`: `rustreexo`
/// builds its forest out of `Rc`, so a bridge node has to own this on one
/// thread and hand out proofs rather than share the structure. Phase 4 has to
/// design around that.
pub struct UtxoForest {
    forest: MemForest<ZcashNodeHash>,
}

impl Default for UtxoForest {
    fn default() -> UtxoForest {
        UtxoForest::new()
    }
}

/// Prints roots rather than the forest, which has no useful `Debug` and could
/// be gigabytes.
impl fmt::Debug for UtxoForest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UtxoForest")
            .field("roots", &self.roots().len())
            .finish_non_exhaustive()
    }
}

impl UtxoForest {
    /// An empty forest.
    pub fn new() -> UtxoForest {
        UtxoForest {
            forest: MemForest::new_with_hash(),
        }
    }

    /// The current roots.
    pub fn roots(&self) -> Vec<Hash> {
        self.forest
            .get_roots()
            .iter()
            .filter_map(|node| node.get_data().to_bytes())
            .collect()
    }

    /// Total leaves ever added, including spent ones.
    ///
    /// Mirrors [`UtxoRoots::leaves`], and the two must agree for a compact node
    /// seeded from a full forest to verify anything: Utreexo derives positions
    /// from this counter, so a compact node given the *unspent* count instead
    /// would place every later leaf wrongly. Exposing it is what makes
    /// [`UtxoRoots::from_parts`] usable from a bridge.
    pub fn leaves(&self) -> u64 {
        self.forest.leaves
    }

    /// Proves that `leaves` are in the accumulator.
    ///
    /// One batch proof covers all of them, sharing internal nodes.
    pub fn prove(&self, leaves: &[Hash]) -> Result<UtxoProof, UtreexoError> {
        let hashes: Vec<ZcashNodeHash> = leaves.iter().copied().map(ZcashNodeHash::new).collect();
        self.forest
            .prove(&hashes)
            .map(UtxoProof::from_inner)
            .map_err(UtreexoError::Backend)
    }

    /// Checks a proof against this forest.
    pub fn verify(&self, proof: &UtxoProof, leaves: &[Hash]) -> Result<bool, UtreexoError> {
        let hashes: Vec<ZcashNodeHash> = leaves.iter().copied().map(ZcashNodeHash::new).collect();
        self.forest
            .verify(proof.inner(), &hashes)
            .map_err(|e| UtreexoError::Backend(e.to_string()))
    }

    /// Adds leaves.
    pub fn insert(&mut self, leaves: &[Hash]) -> Result<(), UtreexoError> {
        self.apply(leaves, &[])
    }

    /// Removes leaves. The forest knows every leaf, so no proof is needed.
    pub fn delete(&mut self, leaves: &[Hash]) -> Result<(), UtreexoError> {
        self.apply(&[], leaves)
    }

    /// Applies additions and deletions in one step, deletions first.
    pub fn apply(&mut self, additions: &[Hash], deletions: &[Hash]) -> Result<(), UtreexoError> {
        let adds: Vec<ZcashNodeHash> = additions.iter().copied().map(ZcashNodeHash::new).collect();
        let dels: Vec<ZcashNodeHash> = deletions.iter().copied().map(ZcashNodeHash::new).collect();
        self.forest
            .modify(&adds, &dels)
            .map_err(UtreexoError::Backend)
    }

    /// Serialises the whole forest to bytes.
    ///
    /// # Why this exists rather than `Clone`
    ///
    /// This is the only way to take an independent copy of the forest.
    /// `MemForest` derives `Clone`, but it holds `Rc<Node>` and `Node` stores
    /// its hash in a `Cell`, so the derived clone shares nodes — mutating
    /// either handle is visible through the other. It compiles, it reads like a
    /// snapshot, and it silently is not one. That behaviour is pinned in
    /// `tests/upstream_rustreexo.rs` and reported upstream.
    ///
    /// Costs roughly 79 bytes per leaf, so a caller snapshotting for rollback
    /// should do it at an interval rather than every block.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UtreexoError> {
        let mut bytes = Vec::new();
        self.forest
            .serialize(&mut bytes)
            .map_err(|error| UtreexoError::Snapshot(error.to_string()))?;
        Ok(bytes)
    }

    /// Restores a forest previously written by [`UtxoForest::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<UtxoForest, UtreexoError> {
        let forest = MemForest::deserialize(bytes)
            .map_err(|error| UtreexoError::Snapshot(error.to_string()))?;
        Ok(UtxoForest { forest })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;

    fn leaf(n: u8) -> UtxoLeaf {
        UtxoLeaf {
            txid: [n; 32],
            vout: u32::from(n),
            height: 1_000_000 + u32::from(n),
            is_coinbase: false,
            value: 100_000 * u64::from(n),
            script_pubkey: vec![0x76, 0xa9, n],
        }
    }

    #[test]
    fn leaf_commits_to_every_field() {
        let base = leaf(1);
        let baseline = base.hash();

        let mut other = base.clone();
        other.txid = [9u8; 32];
        assert_ne!(other.hash(), baseline, "txid not committed");

        let mut other = base.clone();
        other.vout = 7;
        assert_ne!(other.hash(), baseline, "vout not committed");

        let mut other = base.clone();
        other.height += 1;
        assert_ne!(other.hash(), baseline, "height not committed");

        let mut other = base.clone();
        other.is_coinbase = true;
        assert_ne!(other.hash(), baseline, "coinbase flag not committed");

        let mut other = base.clone();
        other.value += 1;
        assert_ne!(other.hash(), baseline, "value not committed");

        let mut other = base.clone();
        other.script_pubkey.push(0);
        assert_ne!(other.hash(), baseline, "scriptPubKey not committed");
    }

    /// The length prefix is what makes the preimage unambiguous. Without it a
    /// script boundary could be moved and two distinct outputs would collide.
    #[test]
    fn script_length_is_prefixed() {
        let mut a = leaf(1);
        a.script_pubkey = vec![0xaa, 0xbb];
        let mut b = leaf(1);
        b.script_pubkey = vec![0xaa, 0xbb, 0xcc];
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn insert_then_prove_verifies() {
        let mut forest = UtxoForest::new();
        let mut roots = UtxoRoots::new();

        let leaves: Vec<Hash> = (1..=8u8).map(|n| leaf(n).hash()).collect();
        forest.insert(&leaves).unwrap();
        roots.insert(&leaves).unwrap();

        assert_eq!(forest.roots(), roots.roots());
        assert_eq!(roots.leaves(), 8);

        let target = vec![leaves[3]];
        let proof = forest.prove(&target).unwrap();
        assert!(roots.verify(&proof, &target).unwrap());
    }

    #[test]
    fn delete_then_prove_fails() {
        let mut forest = UtxoForest::new();
        let mut roots = UtxoRoots::new();

        let leaves: Vec<Hash> = (1..=8u8).map(|n| leaf(n).hash()).collect();
        forest.insert(&leaves).unwrap();
        roots.insert(&leaves).unwrap();

        let target = vec![leaves[3]];
        let proof = forest.prove(&target).unwrap();

        roots.delete(&target, &proof).unwrap();
        forest.delete(&target).unwrap();
        assert_eq!(forest.roots(), roots.roots());

        // The stale proof must no longer verify against the new roots.
        assert!(!roots.verify(&proof, &target).unwrap_or(false));
    }

    #[test]
    fn batched_proof_covers_several_leaves() {
        let mut forest = UtxoForest::new();
        let mut roots = UtxoRoots::new();

        let leaves: Vec<Hash> = (1..=16u8).map(|n| leaf(n).hash()).collect();
        forest.insert(&leaves).unwrap();
        roots.insert(&leaves).unwrap();

        let targets = vec![leaves[1], leaves[2], leaves[9]];
        let proof = forest.prove(&targets).unwrap();
        assert_eq!(proof.target_count(), 3);
        assert!(roots.verify(&proof, &targets).unwrap());
    }

    #[test]
    fn forest_and_roots_agree_across_a_mixed_batch() {
        let mut forest = UtxoForest::new();
        let mut roots = UtxoRoots::new();

        let first: Vec<Hash> = (1..=8u8).map(|n| leaf(n).hash()).collect();
        forest.insert(&first).unwrap();
        roots.insert(&first).unwrap();

        let spent = vec![first[0], first[5]];
        let proof = forest.prove(&spent).unwrap();
        let created: Vec<Hash> = (100..=103u8).map(|n| leaf(n).hash()).collect();

        roots.apply(&created, &spent, &proof).unwrap();
        forest.apply(&created, &spent).unwrap();

        assert_eq!(forest.roots(), roots.roots());
    }

    #[test]
    fn a_forged_leaf_does_not_verify() {
        let mut forest = UtxoForest::new();
        let mut roots = UtxoRoots::new();

        let leaves: Vec<Hash> = (1..=8u8).map(|n| leaf(n).hash()).collect();
        forest.insert(&leaves).unwrap();
        roots.insert(&leaves).unwrap();

        let proof = forest.prove(&[leaves[3]]).unwrap();
        // Same proof, different claimed leaf.
        assert!(!roots.verify(&proof, &[leaf(200).hash()]).unwrap_or(false));
    }

    /// The whole reason [`ZcashNodeHash`] exists. If this ever passes with
    /// Bitcoin's hasher, domain separation has been lost.
    #[test]
    fn parent_hash_is_domain_separated() {
        let left = ZcashNodeHash::new([1u8; 32]);
        let right = ZcashNodeHash::new([2u8; 32]);
        let parent = ZcashNodeHash::parent_hash(&left, &right);
        assert_eq!(
            parent.to_bytes(),
            Some(hash::utxo_node(&[1u8; 32], &[2u8; 32]))
        );

        use rustreexo::node_hash::BitcoinNodeHash;
        let bitcoin = BitcoinNodeHash::parent_hash(
            &BitcoinNodeHash::new([1u8; 32]),
            &BitcoinNodeHash::new([2u8; 32]),
        );
        assert_ne!(parent.to_bytes().unwrap_or_default(), *bitcoin);
    }

    /// Every variant must survive a write/read round trip.
    ///
    /// Regression test. The original implementation wrote a bare 32 bytes and
    /// read them back as `Some`, which is byte-symmetric and loses the
    /// variant — `Empty` came back as `Some([0; 32])`. `MemForest`'s reader
    /// only descends into a branch's children when `!data.is_empty()`, so an
    /// empty node writes none; resurrecting it as `Some` sends the reader
    /// hunting for children that do not exist.
    #[test]
    fn node_hash_variants_round_trip() {
        for original in [
            ZcashNodeHash::Empty,
            ZcashNodeHash::Placeholder,
            ZcashNodeHash::Some([7u8; 32]),
            ZcashNodeHash::Some([0u8; 32]),
        ] {
            let mut bytes = Vec::new();
            original.write(&mut bytes).unwrap();
            let back = ZcashNodeHash::read(&mut bytes.as_slice()).unwrap();
            assert_eq!(back, original, "variant did not survive the round trip");
            assert_eq!(
                back.is_empty(),
                original.is_empty(),
                "is_empty() changed across the round trip, which is what breaks \
                 MemForest deserialization"
            );
        }

        // `Some([0; 32])` must stay distinct from `Empty`. Without the tag the
        // two are indistinguishable on the wire, which is the heart of the bug.
        let mut zeros = Vec::new();
        ZcashNodeHash::Some([0u8; 32]).write(&mut zeros).unwrap();
        let mut empty = Vec::new();
        ZcashNodeHash::Empty.write(&mut empty).unwrap();
        assert_ne!(zeros, empty);
    }

    #[test]
    fn an_unknown_node_hash_tag_is_rejected() {
        // Snapshots are bytes from disk; a bad tag must be an error, not a
        // panic and not a silent misparse.
        let bytes = [9u8, 0, 0, 0];
        assert!(ZcashNodeHash::read(&mut bytes.as_slice()).is_err());
    }

    /// A forest carrying empty nodes must snapshot and restore.
    ///
    /// This is the shape rollback actually needs, and the one the old encoding
    /// could not represent. Deletions are what create empty positions.
    #[test]
    fn a_forest_with_deletions_survives_a_snapshot() {
        let leaves: Vec<Hash> = (1..=8u8).map(|n| leaf(n).hash()).collect();
        let mut forest = UtxoForest::new();
        forest.insert(&leaves).unwrap();
        forest.delete(&leaves[..3]).unwrap();

        let bytes = forest.to_bytes().unwrap();
        let restored = UtxoForest::from_bytes(&bytes).unwrap();
        assert_eq!(restored.roots(), forest.roots());

        // And the restored forest must be independent, which is the whole
        // reason snapshots go through bytes rather than `clone()`.
        let mut forest = forest;
        forest.delete(&leaves[3..5]).unwrap();
        assert_ne!(restored.roots(), forest.roots());
    }
}

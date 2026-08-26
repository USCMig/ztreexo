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
    /// `leaves` is the total ever inserted, **not** the unspent count. Utreexo
    /// assigns positions from that counter and never decrements it.
    ///
    /// # A wrong counter is accepted silently
    ///
    /// An earlier version of this comment claimed a wrong counter "would place
    /// every subsequent leaf at the wrong position and fail on the first proof
    /// rather than silently". That was wrong twice over, and
    /// `a_wrong_leaf_counter_is_silent_and_sometimes_delayed` pins what actually
    /// happens: [`UtxoRoots::insert`] never rejects a bad counter — Utreexo has
    /// no way to notice, since the count is an input rather than a claim it can
    /// check — and divergence, while common, is not universal on the next
    /// block. Sixteen leaves seeded as twelve produce *identical* roots after
    /// one insert and diverge only later.
    ///
    /// So this is a genuine trust boundary and not a self-checking one. The
    /// mitigation is comparing the seed against independent bridges, which is
    /// what makes roots being a few hundred bytes matter.
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
    ///
    /// # Upstream panics are contained here
    ///
    /// `MemForest::deserialize` **panics** on a malformed node-type field —
    /// `panic!("Invalid node type")`, `mem_forest/mod.rs:144` — rather than
    /// returning the `io::Result` its signature promises. Twenty-five bytes are
    /// enough; Phase 6's fuzzer found it in under three thousand executions and
    /// reached the same panic through the snapshot loader, which is the path
    /// that matters: a corrupt snapshot file would take the process down.
    ///
    /// CLAUDE.md §5 rule 3 forbids a panic in these paths, and the rule binds
    /// this wrapper whether or not the panicking line is ours. So the call is
    /// wrapped and a panic becomes [`UtreexoError::Snapshot`], the same error a
    /// clean parse failure produces — because from a caller's position they are
    /// the same event: these bytes are not a forest.
    ///
    /// `AssertUnwindSafe` is sound here because everything the closure touches
    /// is dropped on the panicking path; nothing half-built escapes.
    ///
    /// **This is containment, not a fix.** The real repair belongs in the fork
    /// (`docs/design.md` D25) and upstream after that; `docs/design.md` D33
    /// records the reasoning and the patch. Remove this wrapper when the pinned
    /// revision returns an error instead — `a_bad_node_type_is_an_error_not_a_panic`
    /// keeps passing either way, which is the point of writing it against the
    /// public behaviour rather than against the panic.
    pub fn from_bytes(bytes: &[u8]) -> Result<UtxoForest, UtreexoError> {
        let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MemForest::deserialize(bytes)
        }))
        .map_err(|_| {
            UtreexoError::Snapshot("forest deserialiser panicked on malformed input".to_owned())
        })?;
        let forest = parsed.map_err(|error| UtreexoError::Snapshot(error.to_string()))?;
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

    /// A roots-only view seeded from a full forest verifies that forest's proofs.
    ///
    /// This is the bootstrap path a compact node takes (`CompactState::from_roots`,
    /// Phase 5b). It is a trust boundary — nothing in the seed is checked, because
    /// roots are opaque — so what has to hold is that a *correct* seed is
    /// immediately usable, and an incorrect one fails rather than drifting.
    #[test]
    fn a_seeded_roots_view_verifies_the_forest_it_came_from() {
        let leaves: Vec<Hash> = (1..=16u8).map(|n| leaf(n).hash()).collect();
        let mut forest = UtxoForest::new();
        forest.insert(&leaves).unwrap();
        forest.delete(&leaves[..3]).unwrap();

        let seeded = UtxoRoots::from_parts(&forest.roots(), forest.leaves());
        assert_eq!(seeded.roots(), forest.roots());
        assert_eq!(seeded.leaves(), forest.leaves());

        let proof = forest.prove(&leaves[5..8]).unwrap();
        assert!(
            seeded.verify(&proof, &leaves[5..8]).unwrap(),
            "a seeded view rejected a proof from the forest it was seeded from"
        );
    }

    /// **A wrong leaf counter is accepted silently, and may not diverge at once.**
    ///
    /// Measured, because the first version of `from_parts`'s documentation
    /// claimed the opposite — that seeding with the unspent count "would place
    /// every subsequent leaf at the wrong position and fail on the first proof
    /// rather than silently". Both halves were false, and a sweep over counts
    /// 0..=n+2 for forests of 3..16 leaves said so:
    ///
    /// * `insert` **never** returned an error for a wrong counter. Not once.
    ///   Utreexo has no way to notice; the count is an input, not a claim it
    ///   can check.
    /// * Divergence is common but **not universal on the next block**. With 16
    ///   leaves, seeding 12 instead of 16 produces *identical* roots after one
    ///   insert, because both counts have a clear low bit and the leaf is
    ///   simply appended in each case. It surfaces later.
    ///
    /// This is the same mistake as `docs/design.md` D29 — a comment asserting a
    /// protection the code does not provide — and it is why the seed is a trust
    /// boundary to be checked against independent bridges rather than something
    /// a compact node can validate on its own.
    #[test]
    fn a_wrong_leaf_counter_is_silent_and_sometimes_delayed() {
        let build = |count: u8| {
            let leaves: Vec<Hash> = (1..=count).map(|n| leaf(n).hash()).collect();
            let mut forest = UtxoForest::new();
            forest.insert(&leaves).unwrap();
            forest
        };
        let extra = [leaf(200).hash()];

        // Case 1: silent divergence. 8 leaves seeded as 7.
        let forest = build(8);
        let mut right = UtxoRoots::from_parts(&forest.roots(), forest.leaves());
        let mut wrong = UtxoRoots::from_parts(&forest.roots(), 7);
        right.insert(&extra).unwrap();
        wrong
            .insert(&extra)
            .expect("a wrong counter is not rejected — that is the point");
        assert_ne!(
            right.roots(),
            wrong.roots(),
            "8-seeded-as-7 should diverge on the next insert"
        );

        // Case 2: the delayed one, which is why "it fails fast" was wrong.
        // 16 leaves seeded as 12 gives identical roots after one insert.
        let forest = build(16);
        let mut right = UtxoRoots::from_parts(&forest.roots(), forest.leaves());
        let mut wrong = UtxoRoots::from_parts(&forest.roots(), 12);
        right.insert(&extra).unwrap();
        wrong.insert(&extra).unwrap();
        assert_eq!(
            right.roots(),
            wrong.roots(),
            "if this now diverges immediately, the delayed case is gone and the \
             from_parts documentation should be revisited"
        );
        assert_ne!(
            right.leaves(),
            wrong.leaves(),
            "the counters must still differ, or the case is not what it claims"
        );
    }

    /// The 25 bytes Phase 6's fuzzer used to abort the process.
    ///
    /// `MemForest::deserialize` panics with "Invalid node type" on an
    /// unrecognised node-type field rather than returning the `io::Result` its
    /// signature promises. libFuzzer found it in under 3,000 executions, and
    /// reached the identical panic through `store::load_bytes`, which is the
    /// path that matters: a corrupt snapshot file would take a node down.
    ///
    /// Deliberately written against the **public behaviour** — "this returns an
    /// error" — and not against the panic. When the fork stops panicking and
    /// `from_bytes` drops its `catch_unwind`, this test should keep passing
    /// unchanged. A test asserting a panic would have to be rewritten by
    /// whoever fixes it, which is how a regression seed gets quietly deleted.
    #[test]
    fn a_bad_node_type_is_an_error_not_a_panic() {
        let seed = hex_bytes("0a00007e7e000000000a000000000000000a00000000000000");
        match UtxoForest::from_bytes(&seed) {
            Err(UtreexoError::Snapshot(_)) => {}
            Err(other) => panic!("wrong error variant: {other}"),
            Ok(_) => panic!("25 bytes of fuzzer output decoded as a forest"),
        }
    }

    /// Every prefix and every single-bit mutation of that seed, none of which
    /// may panic. One seed proves the reported case; the sweep is what stops a
    /// neighbouring input reopening it.
    #[test]
    fn no_mutation_of_the_seed_panics() {
        let seed = hex_bytes("0a00007e7e000000000a000000000000000a00000000000000");
        for length in 0..=seed.len() {
            let _ = UtxoForest::from_bytes(&seed[..length]);
        }
        for index in 0..seed.len() {
            for bit in 0..8u8 {
                let mut corrupted = seed.clone();
                corrupted[index] ^= 1 << bit;
                let _ = UtxoForest::from_bytes(&corrupted);
            }
        }
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn an_empty_seed_equals_a_fresh_accumulator() {
        let seeded = UtxoRoots::from_parts(&[], 0);
        let fresh = UtxoRoots::new();
        assert_eq!(seeded.roots(), fresh.roots());
        assert_eq!(seeded.leaves(), fresh.leaves());
    }
}

//! The proof bundle a bridge node serves and a compact state node consumes.
//!
//! # What has to be in it, and why
//!
//! A compact state node holds roots and nothing else. To apply block `H` it
//! needs, for each thing the block changes, whatever the roots alone cannot
//! supply:
//!
//! * **Transparent spends.** A transaction that spends an output carries only
//!   an outpoint, but the leaf being deleted commits to the output's full
//!   contents — value, script, height, coinbase flag (`docs/design.md` D9). The
//!   verifier cannot reconstruct that from the block, so the bundle carries it.
//!   This is the single largest term in the bundle and the honest cost of the
//!   design; `docs/benchmarks.md` measures it.
//! * **One inclusion proof** covering every spent leaf at once. Utreexo proofs
//!   for targets in the same block share internal nodes, so a batched proof is
//!   substantially smaller than the sum of individual ones — the deduplication
//!   CLAUDE.md Phase 4 asks for is a property of the proof type rather than
//!   something layered on top, and the measurement quantifies it.
//! * **An insertion proof per nullifier.** These must be applied in order: each
//!   is stated against the root the previous one produced.
//!
//! # What is deliberately *not* in it
//!
//! **Created outputs.** They are in the block. A verifier that has the block
//! can compute their leaf hashes itself, and shipping them again would double
//! the largest term for nothing.
//!
//! **Nullifier values.** Likewise in the block.
//!
//! **Separate non-membership proofs.** An [`InsertionProof`] already carries the
//! low leaf and its path, and [`verify_insertion`] checks both that the low leaf
//! is in the tree at the current root and that it brackets the value — which is
//! exactly a non-membership proof. Carrying a second one would add bytes and a
//! second thing to keep consistent, with no additional assurance.
//!
//! [`NullifierProofBundle`](zutreexo_accumulator::NullifierProofBundle) does
//! carry both, and that is not a contradiction: it answers a *wallet's*
//! standalone "has this nullifier been spent?" query, where there is no
//! insertion to piggyback on.
//!
//! [`verify_insertion`]: zutreexo_accumulator::imt::verify_insertion

use std::collections::BTreeMap;

use zutreexo_accumulator::imt::InsertionProof;
use zutreexo_accumulator::proof::{
    decode_utxo_proof, encode_utxo_proof, CanonicalSerialize, ProofCodecError, Reader,
};
use zutreexo_accumulator::{Hash, PoolId, UtxoLeaf, UtxoProof};

use crate::block_apply::{apply_block, ApplyError, ApplyOptions, ApplyOutcome, StateDelta};
use crate::extract::BlockSummary;
use crate::pool::ChainAccumulators;

/// Everything a roots-only verifier needs to apply one block.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BlockProofBundle {
    /// Height of the block this bundle is for.
    pub height: u32,
    /// Contents of the outputs this block spends, in spend order.
    ///
    /// Only outputs created by *earlier* blocks appear. An output created and
    /// spent within this block is cancelled and never enters the accumulator
    /// (`docs/design.md` D21), so there is nothing to prove about it — and its
    /// absence here is what tells a verifier the cancellation happened.
    pub spent: Vec<UtxoLeaf>,
    /// One batched inclusion proof covering every leaf in `spent`.
    pub utxo_proof: UtxoProof,
    /// Nullifier insertions per pool, in application order.
    pub insertions: BTreeMap<PoolId, Vec<InsertionProof>>,
}

impl BlockProofBundle {
    /// Leaf hashes of the spent outputs, in order.
    pub fn spent_hashes(&self) -> Vec<Hash> {
        self.spent.iter().map(UtxoLeaf::hash).collect()
    }

    /// Total nullifier insertions across all pools.
    pub fn insertion_count(&self) -> usize {
        self.insertions.values().map(Vec::len).sum()
    }
}

/// Why a bundle could not be produced.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum BundleError {
    /// The block could not be applied at all.
    #[error(transparent)]
    Apply(#[from] ApplyError),

    /// The forest could not prove the spent leaves.
    #[error("could not prove block {height}'s spends: {reason}")]
    Prove {
        /// Height being proved.
        height: u32,
        /// What the accumulator said.
        reason: String,
    },

    /// The proof generated before applying does not describe what was applied.
    ///
    /// Structural, and it should be unreachable: the spends are resolved twice
    /// from the same state, once here and once inside [`apply_block`]. It is
    /// checked rather than assumed because the two resolutions are separate
    /// code, and a bundle that disagrees with the state transition it describes
    /// would surface as a root divergence on some later block instead of here.
    #[error("block {height}: proved {proved} spends but applied {applied}")]
    SpendMismatch {
        /// Height involved.
        height: u32,
        /// Spends the proof covers.
        proved: usize,
        /// Spends the transition performed.
        applied: usize,
    },
}

/// Applies a block to the bridge's full state **and** emits the bundle a
/// compact node needs to make the same transition from roots alone.
///
/// The two are produced together on purpose. An inclusion proof is only valid
/// against the accumulator as it stood *before* the block, so generating it
/// separately means either holding the pre-state or replaying to it. Doing both
/// in one call makes the ordering impossible to get wrong.
pub fn apply_and_prove(
    state: &mut ChainAccumulators,
    summary: &BlockSummary,
    options: ApplyOptions,
) -> Result<(ApplyOutcome, BlockProofBundle), BundleError> {
    let height = summary.height;

    // Resolve the spends against the pre-block state. This mirrors the staging
    // step in `apply_block`; the cross-check below is what keeps the two
    // honest, since they are separate code paths over the same input.
    let mut spent: Vec<UtxoLeaf> = Vec::new();
    for outpoint in &summary.transparent_spends {
        if let Some(leaf) = state.utxo(outpoint) {
            spent.push(leaf.clone());
        }
    }

    // Prove them all at once, before anything is deleted.
    let hashes: Vec<Hash> = spent.iter().map(UtxoLeaf::hash).collect();
    let utxo_proof = if hashes.is_empty() {
        UtxoProof::default()
    } else {
        state
            .utxos()
            .prove(&hashes)
            .map_err(|error| BundleError::Prove {
                height,
                reason: error.to_string(),
            })?
    };

    let outcome = apply_block(state, summary, options)?;

    if outcome.delta.spent.len() != spent.len() {
        return Err(BundleError::SpendMismatch {
            height,
            proved: spent.len(),
            applied: outcome.delta.spent.len(),
        });
    }

    let bundle = BlockProofBundle {
        height,
        spent,
        utxo_proof,
        insertions: insertions_from(&outcome.delta),
    };
    Ok((outcome, bundle))
}

/// Strips the nullifier values out of a delta's insertion records.
///
/// The values are in the block, so a bundle that repeated them would be paying
/// 32 bytes each to tell the verifier something it already knows.
fn insertions_from(delta: &StateDelta) -> BTreeMap<PoolId, Vec<InsertionProof>> {
    delta
        .insertions
        .iter()
        .map(|(pool, applied)| {
            (
                *pool,
                applied.iter().map(|(_, proof)| proof.clone()).collect(),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Serialization. Bundles cross a network in Phase 4b, and their size *is* the
// cost side of the whole design, so the encoding is measured rather than
// estimated.
// ---------------------------------------------------------------------------

/// Appends a length-prefixed byte string.
fn write_bytes(value: &[u8], out: &mut Vec<u8>) {
    let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value.get(..len as usize).unwrap_or(value));
}

/// Reads a little-endian `u32`.
fn read_u32(reader: &mut Reader<'_>) -> Result<u32, ProofCodecError> {
    let bytes = reader.take(4)?;
    let array: [u8; 4] = bytes.try_into().map_err(|_| ProofCodecError::Malformed {
        reason: "short u32",
    })?;
    Ok(u32::from_le_bytes(array))
}

/// Reads a length-prefixed byte string, bounded by what is actually left.
///
/// The bound is checked before allocating. `docs/design.md` D13 records the
/// same defect in upstream `rustreexo`'s decoder: a length prefix trusted ahead
/// of the data it describes is an unbounded allocation from a hostile peer, and
/// a bridge's clients are exactly that.
fn read_bytes(reader: &mut Reader<'_>) -> Result<Vec<u8>, ProofCodecError> {
    let len = read_u32(reader)? as usize;
    if len > reader.remaining() {
        return Err(ProofCodecError::DeclaredLengthExceedsInput {
            field: "byte string",
            declared: len,
            remaining: reader.remaining(),
        });
    }
    Ok(reader.take(len)?.to_vec())
}

fn write_leaf(leaf: &UtxoLeaf, out: &mut Vec<u8>) {
    out.extend_from_slice(&leaf.txid);
    out.extend_from_slice(&leaf.vout.to_le_bytes());
    out.extend_from_slice(&leaf.height.to_le_bytes());
    out.push(u8::from(leaf.is_coinbase));
    out.extend_from_slice(&leaf.value.to_le_bytes());
    write_bytes(&leaf.script_pubkey, out);
}

fn read_leaf(reader: &mut Reader<'_>) -> Result<UtxoLeaf, ProofCodecError> {
    let txid = reader.hash()?;
    let vout = read_u32(reader)?;
    let height = read_u32(reader)?;
    let flag = reader.u8()?;
    // Anything other than 0 or 1 means the encoder and decoder disagree about
    // the layout, which is worth failing on rather than coercing to `true`.
    let is_coinbase = match flag {
        0 => false,
        1 => true,
        _ => {
            return Err(ProofCodecError::Malformed {
                reason: "coinbase flag is neither 0 nor 1",
            })
        }
    };
    let value = reader.u64_le()?;
    let script_pubkey = read_bytes(reader)?;
    Ok(UtxoLeaf {
        txid,
        vout,
        height,
        is_coinbase,
        value,
        script_pubkey,
    })
}

impl CanonicalSerialize for BlockProofBundle {
    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.height.to_le_bytes());

        let spent = u32::try_from(self.spent.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&spent.to_le_bytes());
        for leaf in self.spent.iter().take(spent as usize) {
            write_leaf(leaf, out);
        }

        write_bytes(&encode_utxo_proof(&self.utxo_proof), out);

        let pools = u8::try_from(self.insertions.len()).unwrap_or(u8::MAX);
        out.push(pools);
        for (pool, proofs) in self.insertions.iter().take(pools as usize) {
            out.push(pool.code());
            let count = u32::try_from(proofs.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&count.to_le_bytes());
            for proof in proofs.iter().take(count as usize) {
                write_bytes(&proof.to_bytes(), out);
            }
        }
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, ProofCodecError> {
        let height = read_u32(reader)?;

        let spent_count = read_u32(reader)? as usize;
        // A leaf is at least 77 bytes, so a count larger than the remaining
        // bytes could allow is a lie and must not reach `with_capacity`.
        if spent_count > reader.remaining() {
            return Err(ProofCodecError::DeclaredLengthExceedsInput {
                field: "spent leaves",
                declared: spent_count,
                remaining: reader.remaining(),
            });
        }
        let mut spent = Vec::with_capacity(spent_count);
        for _ in 0..spent_count {
            spent.push(read_leaf(reader)?);
        }

        let utxo_proof = decode_utxo_proof(&read_bytes(reader)?)?;

        let pools = reader.u8()?;
        let mut insertions = BTreeMap::new();
        for _ in 0..pools {
            let code = reader.u8()?;
            let pool = PoolId::from_code(code).ok_or(ProofCodecError::UnknownPool { code })?;
            let count = read_u32(reader)? as usize;
            if count > reader.remaining() {
                return Err(ProofCodecError::DeclaredLengthExceedsInput {
                    field: "insertion proofs",
                    declared: count,
                    remaining: reader.remaining(),
                });
            }
            let mut proofs = Vec::with_capacity(count);
            for _ in 0..count {
                proofs.push(InsertionProof::from_bytes(&read_bytes(reader)?)?);
            }
            // A repeated pool code would silently drop the earlier entry.
            if insertions.insert(pool, proofs).is_some() {
                return Err(ProofCodecError::Malformed {
                    reason: "bundle repeats a pool",
                });
            }
        }

        Ok(BlockProofBundle {
            height,
            spent,
            utxo_proof,
            insertions,
        })
    }
}

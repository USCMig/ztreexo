//! Turning a deserialized Zcash block into the inputs `apply_block` needs.
//!
//! This is the layer where parsing bugs live, and CLAUDE.md Phase 2 is explicit
//! that they are a distinct bug class from accumulator bugs: two models fed the
//! same bad parse will agree with each other and both be wrong. So everything
//! here comes from `zebra-chain`'s consensus deserializer rather than from RPC
//! JSON or a hand-rolled reader — Zebra is the source of truth (CLAUDE.md §3),
//! and using its types means a transaction format we mis-handle fails to parse
//! rather than silently yielding the wrong nullifiers.
//!
//! Note commitments are counted but not accumulated. The commitment trees are
//! deliberately left alone (CLAUDE.md §2); the counts exist so the harness can
//! cross-check parsing against the node.

use std::collections::BTreeMap;

use zebra_chain::block::Block;
use zebra_chain::transparent;

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::{PoolId, UtxoLeaf};

/// A reference to a specific transaction output.
///
/// Defined here rather than reusing `zebra_chain::transparent::OutPoint` so
/// that `zebra-chain` types do not leak into this crate's public surface; the
/// accumulator crate knows nothing about Zebra and should stay that way.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct OutPoint {
    /// Transaction ID of the creating transaction.
    pub txid: [u8; 32],
    /// Index of the output within that transaction.
    pub vout: u32,
}

impl OutPoint {
    /// Converts from Zebra's representation.
    pub fn from_zebra(outpoint: &transparent::OutPoint) -> OutPoint {
        OutPoint {
            txid: outpoint.hash.0,
            vout: outpoint.index,
        }
    }
}

/// Everything one block contributes to accumulator state.
#[derive(Clone, Debug, Default)]
pub struct BlockSummary {
    /// Height of this block.
    pub height: u32,
    /// Number of transactions, coinbase included.
    pub transactions: usize,
    /// Outputs consumed by this block, in transaction and input order.
    ///
    /// Coinbase inputs are excluded: they reference no prior output.
    pub transparent_spends: Vec<OutPoint>,
    /// Outputs created by this block, paired with the leaf they become.
    pub transparent_creates: Vec<(OutPoint, UtxoLeaf)>,
    /// Nullifiers revealed, per pool, in transaction order.
    ///
    /// Order is consensus-visible: it decides leaf indices and therefore roots.
    pub nullifiers: BTreeMap<PoolId, Vec<Value>>,
    /// Note commitments created, per pool. Counted only — see the module docs.
    pub commitments: BTreeMap<PoolId, usize>,
}

impl BlockSummary {
    /// Total nullifiers across all pools.
    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.values().map(Vec::len).sum()
    }

    /// Nullifiers revealed for one pool.
    pub fn nullifiers_for(&self, pool: PoolId) -> &[Value] {
        self.nullifiers.get(&pool).map_or(&[], Vec::as_slice)
    }

    /// Note commitments created for one pool.
    pub fn commitments_for(&self, pool: PoolId) -> usize {
        self.commitments.get(&pool).copied().unwrap_or(0)
    }
}

/// Failures while reading a block.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ExtractError {
    /// The block carries no coinbase height.
    ///
    /// Every valid block since Overwinter encodes its height in the coinbase
    /// input. A block without one cannot be summarised, because the transparent
    /// leaf hash commits to height.
    #[error("block has no coinbase height")]
    MissingHeight,

    /// An output's value was negative, which `Amount<NonNegative>` should make
    /// unrepresentable.
    #[error("transaction {txid} output {vout} has a negative value")]
    NegativeValue {
        /// Hex transaction ID.
        txid: String,
        /// Output index.
        vout: u32,
    },

    /// A transaction had more outputs than `u32` can index.
    #[error("transaction {txid} has more outputs than u32 can index")]
    TooManyOutputs {
        /// Hex transaction ID.
        txid: String,
    },
}

/// Reads a block into the form `apply_block` consumes.
///
/// The height is taken from the coinbase rather than passed in, so a
/// mis-ordered replay cannot silently attribute outputs to the wrong height —
/// and height is committed to by every transparent leaf hash.
pub fn summarize_block(block: &Block) -> Result<BlockSummary, ExtractError> {
    let height = block
        .coinbase_height()
        .ok_or(ExtractError::MissingHeight)?
        .0;

    let mut summary = BlockSummary {
        height,
        transactions: block.transactions.len(),
        ..BlockSummary::default()
    };

    for transaction in &block.transactions {
        let txid = transaction.hash().0;
        let is_coinbase = transaction.is_coinbase();

        // Inputs. Coinbase inputs reference no prior output, so they are not
        // spends and must not be looked up in the accumulator.
        for input in transaction.inputs() {
            if let transparent::Input::PrevOut { outpoint, .. } = input {
                summary
                    .transparent_spends
                    .push(OutPoint::from_zebra(outpoint));
            }
        }

        // Outputs.
        for (index, output) in transaction.outputs().iter().enumerate() {
            let vout = u32::try_from(index).map_err(|_| ExtractError::TooManyOutputs {
                txid: hex::encode(txid),
            })?;
            let value = i64::from(output.value);
            let value = u64::try_from(value).map_err(|_| ExtractError::NegativeValue {
                txid: hex::encode(txid),
                vout,
            })?;

            let outpoint = OutPoint { txid, vout };
            let leaf = UtxoLeaf {
                txid,
                vout,
                height,
                is_coinbase,
                value,
                script_pubkey: output.lock_script.as_raw_bytes().to_vec(),
            };
            summary.transparent_creates.push((outpoint, leaf));
        }

        // Shielded. One entry per pool, per CLAUDE.md §2.3 — Orchard and
        // Ironwood are both live indefinitely, so neither is a special case.
        //
        // Each Sprout JoinSplit reveals two nullifiers; `sprout_nullifiers`
        // already flattens that, so no doubling here.
        let sprout = summary.nullifiers.entry(PoolId::Sprout).or_default();
        for nullifier in transaction.sprout_nullifiers() {
            sprout.push(Value::from_bytes((*nullifier).into()));
        }

        let sapling = summary.nullifiers.entry(PoolId::Sapling).or_default();
        for nullifier in transaction.sapling_nullifiers() {
            sapling.push(Value::from_bytes((*nullifier).into()));
        }

        let orchard = summary.nullifiers.entry(PoolId::Orchard).or_default();
        for nullifier in transaction.orchard_nullifiers() {
            orchard.push(Value::from_bytes((*nullifier).into()));
        }

        let ironwood = summary.nullifiers.entry(PoolId::Ironwood).or_default();
        for nullifier in transaction.ironwood_nullifiers() {
            ironwood.push(Value::from_bytes(nullifier.into()));
        }

        // Commitment counts, for the parsing cross-check only.
        bump(
            &mut summary.commitments,
            PoolId::Sprout,
            transaction.sprout_note_commitments().count(),
        );
        bump(
            &mut summary.commitments,
            PoolId::Sapling,
            transaction.sapling_note_commitments().count(),
        );
        bump(
            &mut summary.commitments,
            PoolId::Orchard,
            transaction.orchard_note_commitments().count(),
        );
        bump(
            &mut summary.commitments,
            PoolId::Ironwood,
            transaction.ironwood_note_commitments().count(),
        );
    }

    Ok(summary)
}

fn bump(counts: &mut BTreeMap<PoolId, usize>, pool: PoolId, by: usize) {
    let entry = counts.entry(pool).or_insert(0);
    *entry = entry.saturating_add(by);
}

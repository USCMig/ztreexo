//! Compact state node: validates Zcash blocks holding only accumulator roots.
//!
//! **Phase 4a.** The verification core is here; the network transport that
//! fetches bundles from a bridge is Phase 4b.
//!
//! # What this is for
//!
//! [`ChainAccumulators`](zutreexo_chain::ChainAccumulators) — the bridge-side
//! state — holds a full Utreexo forest, four complete indexed Merkle trees, and
//! an outpoint index. At mainnet tip that was 32.7 GiB
//! (`docs/benchmarks.md`). [`CompactState`] makes the same state transitions
//! holding a few hundred bytes, given a [`BlockProofBundle`] for each block.
//!
//! That difference is the entire thesis of the project, and this crate is where
//! it is either true or it is not.
//!
//! # What it does *not* do
//!
//! Nothing here changes what blocks a node accepts. A compact node reaches the
//! same accept/reject decision as a full node for the state-transition rules it
//! covers, and CLAUDE.md §5 rule 1 keeps that true through Phase 6. It also
//! validates strictly less than a full node does — no signatures, no
//! consensus-rule checks, no proof verification for shielded spends. It answers
//! one question: *does this block's effect on the accumulators match what the
//! bridge claims?*
//!
//! # Trust
//!
//! A bridge cannot make a compact node accept a wrong state transition. Every
//! deletion is checked against an inclusion proof, every nullifier against an
//! insertion proof, and the spent outputs the bridge supplies are checked to be
//! the outputs the block actually names — see [`CompactState::apply_bundle`].
//! A hostile bridge can *withhold* service, and it learns which blocks a node
//! is interested in, which is the Phase 6 privacy question.

use std::collections::{BTreeMap, BTreeSet};

use zutreexo_accumulator::imt::{ImtError, ImtState, DEFAULT_DEPTH};
use zutreexo_accumulator::{Hash, PoolId, UtreexoError, UtxoLeaf, UtxoRoots};
use zutreexo_chain::{BlockProofBundle, BlockSummary, OutPoint};

/// A validating node's entire persistent state.
///
/// Compare [`ChainAccumulators`](zutreexo_chain::ChainAccumulators), which holds
/// the same information in full.
#[derive(Clone, Debug)]
pub struct CompactState {
    depth: u8,
    utxos: UtxoRoots,
    nullifiers: BTreeMap<PoolId, ImtState>,
    tip: Option<u32>,
}

impl Default for CompactState {
    fn default() -> Self {
        CompactState::new(DEFAULT_DEPTH).unwrap_or(CompactState {
            depth: DEFAULT_DEPTH,
            utxos: UtxoRoots::new(),
            nullifiers: BTreeMap::new(),
            tip: None,
        })
    }
}

impl CompactState {
    /// An empty compact state, with every pool initialised at `depth`.
    ///
    /// `depth` must match the bridge's. It is a parameter rather than a
    /// constant because an insertion proof's path length is fixed by it, so a
    /// mismatch is a verification failure on the first nullifier rather than
    /// anything subtle.
    pub fn new(depth: u8) -> Result<CompactState, ImtError> {
        let mut nullifiers = BTreeMap::new();
        for pool in PoolId::ALL {
            nullifiers.insert(pool, ImtState::new(pool, depth)?);
        }
        Ok(CompactState {
            depth,
            utxos: UtxoRoots::new(),
            nullifiers,
            tip: None,
        })
    }

    /// Height of the last applied block.
    pub fn tip(&self) -> Option<u32> {
        self.tip
    }

    /// The depth every nullifier tree uses.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Every nullifier root, keyed by pool.
    ///
    /// Directly comparable to
    /// [`ChainAccumulators::nullifier_roots`](zutreexo_chain::ChainAccumulators::nullifier_roots),
    /// which is the point: the two must be byte-identical at every height.
    pub fn nullifier_roots(&self) -> BTreeMap<PoolId, Hash> {
        self.nullifiers
            .iter()
            .map(|(pool, state)| (*pool, state.root))
            .collect()
    }

    /// The transparent accumulator roots.
    pub fn utxo_roots(&self) -> Vec<Hash> {
        self.utxos.roots()
    }

    /// Leaves currently in the transparent accumulator.
    pub fn utxo_leaves(&self) -> u64 {
        self.utxos.leaves()
    }

    /// One pool's compact state.
    pub fn imt_state(&self, pool: PoolId) -> Option<&ImtState> {
        self.nullifiers.get(&pool)
    }

    /// Applies one block from its summary and the bridge's proof bundle.
    ///
    /// # Order
    ///
    /// Exactly the order in CLAUDE.md Phase 2, because the roots depend on it:
    /// verify and delete transparent inputs, insert transparent outputs, then
    /// per pool insert nullifiers in block order. Any other order produces
    /// different roots from the same block, which would show up as a
    /// divergence from the bridge with no obvious cause.
    ///
    /// # What is checked
    ///
    /// The bundle is untrusted. Three things could otherwise go wrong:
    ///
    /// * **A substituted leaf.** The bridge supplies the spent outputs'
    ///   contents, so it could supply a *different* output that happens to be
    ///   in the accumulator — the inclusion proof would verify and the wrong
    ///   leaf would be deleted. So each supplied leaf's outpoint is matched
    ///   against the outpoint the block actually spends.
    /// * **A fabricated cancellation.** A spend absent from `bundle.spent` is
    ///   taken to be an output this block also creates (`docs/design.md` D21).
    ///   That claim is checked against the block rather than believed.
    /// * **An unproven deletion.** The batched inclusion proof is verified
    ///   against the current roots before anything is removed.
    ///
    /// On any error the state is left untouched, so a rejected block cannot
    /// half-apply.
    pub fn apply_bundle(
        &mut self,
        summary: &BlockSummary,
        bundle: &BlockProofBundle,
    ) -> Result<(), CsnError> {
        let height = summary.height;

        if bundle.height != height {
            return Err(CsnError::HeightMismatch {
                block: height,
                bundle: bundle.height,
            });
        }
        if let Some(tip) = self.tip {
            let expected = tip.saturating_add(1);
            if height != expected {
                return Err(CsnError::OutOfOrder {
                    expected,
                    found: height,
                });
            }
        }

        // ---- staging: everything fallible happens before the first mutation ----

        let created_here: BTreeSet<OutPoint> = summary
            .transparent_creates
            .iter()
            .map(|(outpoint, _)| *outpoint)
            .collect();

        // Walk the block's spends alongside the bundle's leaves. The bundle is
        // in spend order with cancelled entries omitted, so a single cursor
        // over it is enough — and consuming it in lockstep is what detects both
        // substitution and a miscounted cancellation.
        let mut cursor = 0usize;
        let mut seen: BTreeSet<OutPoint> = BTreeSet::new();
        let mut cancelled: BTreeSet<OutPoint> = BTreeSet::new();

        for outpoint in &summary.transparent_spends {
            if !seen.insert(*outpoint) {
                return Err(CsnError::DuplicateSpend {
                    height,
                    txid: hex_txid(&outpoint.txid),
                    vout: outpoint.vout,
                });
            }

            match bundle.spent.get(cursor) {
                Some(leaf) if leaf_matches(leaf, outpoint) => {
                    cursor = cursor.saturating_add(1);
                }
                // The bundle does not claim this spend, so it must be an output
                // the block itself creates. Verified, not assumed: a bridge
                // that omitted a real spend would otherwise get the deletion
                // skipped and the roots would diverge later, somewhere else.
                _ if created_here.contains(outpoint) => {
                    cancelled.insert(*outpoint);
                }
                _ => {
                    return Err(CsnError::UnprovenSpend {
                        height,
                        txid: hex_txid(&outpoint.txid),
                        vout: outpoint.vout,
                    })
                }
            }
        }

        // Leaves the bundle carried that no spend claimed. A bridge cannot be
        // allowed to smuggle in an extra deletion.
        if cursor != bundle.spent.len() {
            return Err(CsnError::UnclaimedLeaves {
                height,
                extra: bundle.spent.len().saturating_sub(cursor),
            });
        }

        let deletions = bundle.spent_hashes();
        if !deletions.is_empty() && !self.utxos.verify(&bundle.utxo_proof, &deletions)? {
            return Err(CsnError::InclusionProofFailed { height });
        }

        let additions: Vec<Hash> = summary
            .transparent_creates
            .iter()
            .filter(|(outpoint, _)| !cancelled.contains(outpoint))
            .map(|(_, leaf)| leaf.hash())
            .collect();

        // Nullifiers are verified against a scratch copy first, so a bad proof
        // late in a block cannot leave earlier pools advanced. `ImtState` is
        // two words per pool, so copying it is free.
        let mut staged = self.nullifiers.clone();
        for pool in PoolId::ALL {
            let values = summary.nullifiers_for(pool);
            if values.is_empty() {
                continue;
            }
            let proofs = bundle
                .insertions
                .get(&pool)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if proofs.len() != values.len() {
                return Err(CsnError::InsertionCountMismatch {
                    height,
                    pool,
                    nullifiers: values.len(),
                    proofs: proofs.len(),
                });
            }
            let state = staged
                .get_mut(&pool)
                .ok_or(CsnError::MissingPool { pool })?;
            for (value, proof) in values.iter().zip(proofs) {
                state.apply_insertion(pool, self.depth, *value, proof)?;
            }
        }

        // A bundle carrying proofs for a pool the block never touches is
        // malformed, and silently ignoring them would let two different bundles
        // be accepted for the same block.
        for (pool, proofs) in &bundle.insertions {
            if !proofs.is_empty() && summary.nullifiers_for(*pool).is_empty() {
                return Err(CsnError::UnexpectedInsertions {
                    height,
                    pool: *pool,
                });
            }
        }

        // ---- mutation: from here nothing may fail ----

        self.utxos
            .apply(&additions, &deletions, &bundle.utxo_proof)?;
        self.nullifiers = staged;
        self.tip = Some(height);
        Ok(())
    }
}

/// Whether a supplied leaf really describes the output an outpoint names.
fn leaf_matches(leaf: &UtxoLeaf, outpoint: &OutPoint) -> bool {
    leaf.txid == outpoint.txid && leaf.vout == outpoint.vout
}

fn hex_txid(txid: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in txid {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Why a compact node rejected a block.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum CsnError {
    /// The bundle is for a different block than the summary.
    #[error("bundle is for height {bundle}, block is {block}")]
    HeightMismatch {
        /// The block's height.
        block: u32,
        /// The bundle's height.
        bundle: u32,
    },

    /// Blocks must arrive in order.
    #[error("expected block {expected}, got {found}")]
    OutOfOrder {
        /// Height that was due next.
        expected: u32,
        /// Height supplied.
        found: u32,
    },

    /// The same outpoint is spent twice in one block.
    #[error("block {height} spends {txid}:{vout} twice")]
    DuplicateSpend {
        /// Height of the offending block.
        height: u32,
        /// Hex transaction ID.
        txid: String,
        /// Output index.
        vout: u32,
    },

    /// A spend the bundle neither proved nor could have cancelled.
    ///
    /// Either the bridge omitted a leaf, or it supplied one describing a
    /// different output than the block spends.
    #[error("block {height} spends {txid}:{vout} with no matching proof")]
    UnprovenSpend {
        /// Height of the offending block.
        height: u32,
        /// Hex transaction ID.
        txid: String,
        /// Output index.
        vout: u32,
    },

    /// The bundle carried leaves no spend in the block accounts for.
    #[error("block {height}: bundle carries {extra} leaves no spend claims")]
    UnclaimedLeaves {
        /// Height involved.
        height: u32,
        /// How many were left over.
        extra: usize,
    },

    /// The batched inclusion proof does not verify against the current roots.
    #[error("block {height}: transparent inclusion proof failed")]
    InclusionProofFailed {
        /// Height involved.
        height: u32,
    },

    /// A pool's nullifier count and proof count disagree.
    #[error("block {height} pool {pool}: {nullifiers} nullifiers but {proofs} proofs")]
    InsertionCountMismatch {
        /// Height involved.
        height: u32,
        /// Which pool.
        pool: PoolId,
        /// Nullifiers the block reveals.
        nullifiers: usize,
        /// Proofs the bundle carries.
        proofs: usize,
    },

    /// The bundle carries proofs for a pool the block does not touch.
    #[error("block {height}: bundle carries insertions for unused pool {pool}")]
    UnexpectedInsertions {
        /// Height involved.
        height: u32,
        /// Which pool.
        pool: PoolId,
    },

    /// A pool has no state, which should be impossible after construction.
    #[error("no state for pool {pool}")]
    MissingPool {
        /// The pool with no state.
        pool: PoolId,
    },

    /// A nullifier insertion proof failed.
    #[error(transparent)]
    Imt(#[from] ImtError),

    /// The transparent accumulator rejected the transition.
    #[error(transparent)]
    Utreexo(#[from] UtreexoError),
}

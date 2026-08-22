//! Fork detection for a tip-following shadow run.
//!
//! `src/bin/shadow.rs` is an operational entry point and is not measured for
//! coverage (`scripts/check_coverage.py`), because its interesting path fires
//! only when mainnet reorgs. That is a fair description of the *reload and
//! replay* half — which is `load` plus a loop of `apply_block`, both covered
//! heavily elsewhere — but it is not a fair description of the half that
//! decides **where** to unwind to.
//!
//! Walking a history of applied blocks backwards against the hashes a node
//! currently reports is exactly the kind of code an off-by-one hides in, and
//! it needs no chain to test. So it lives here, as a pure function over a
//! history and a hash lookup, and `tests/shadow_fork.rs` drives it.

use std::collections::VecDeque;
use std::path::Path;
use std::time::Instant;

use zutreexo_chain::{apply_block, load, ApplyOptions, BlockSummary, ChainAccumulators};
use zutreexo_csn::CompactState;

/// A block a shadow run applied: its height and the hash it had at the time.
///
/// Height alone does not identify a block. A follower that tracked only
/// heights would apply a replacement block on top of the block it replaced and
/// diverge silently from then on.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AppliedBlock {
    /// Height applied.
    pub height: u32,
    /// The hash the node reported for it when it was applied.
    pub hash: String,
}

/// Where a fork was found, and how much has to come off.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Fork {
    /// The node still agrees with everything applied. Nothing to do.
    None,
    /// Unwind to `target`, discarding `undone` blocks above it.
    UnwindTo {
        /// Deepest height whose hash the node still agrees with.
        target: u32,
        /// How many blocks are being discarded.
        undone: u32,
    },
    /// Every remembered block is gone from the node's chain.
    ///
    /// Distinct from a deep-but-recoverable reorg, and it has to be: recovery
    /// only reaches back as far as the run's own history, so this is the case
    /// where a shadow run must stop rather than guess.
    BeyondHistory {
        /// How many were discarded before running out.
        undone: u32,
    },
}

/// Finds the deepest applied block the node still agrees with.
///
/// `node_hash` is asked for the node's *current* hash at a height; an error
/// from it aborts the search rather than being read as a mismatch, because
/// treating an unreachable node as a reorg would unwind a chain that never
/// forked.
///
/// The history is consumed from the back only as far as necessary — blocks the
/// node still agrees with are left in place, since they are the states the
/// compact node rewinds to.
pub fn find_fork<E, F>(history: &mut VecDeque<AppliedBlock>, mut node_hash: F) -> Result<Fork, E>
where
    F: FnMut(u32) -> Result<String, E>,
{
    let mut undone = 0u32;

    loop {
        let Some(applied) = history.back() else {
            // Ran out. If nothing was ever there, there is no fork; if we
            // discarded everything, the fork is deeper than we can reach.
            return Ok(if undone == 0 {
                Fork::None
            } else {
                Fork::BeyondHistory { undone }
            });
        };

        let current = node_hash(applied.height)?;
        if current == applied.hash {
            return Ok(if undone == 0 {
                Fork::None
            } else {
                Fork::UnwindTo {
                    target: applied.height,
                    undone,
                }
            });
        }

        history.pop_back();
        undone = undone.saturating_add(1);
    }
}

/// What `unwind` needs from a chain, and nothing more.
///
/// # Why a trait, and why summaries rather than bytes
///
/// `unwind` used to take `&RpcSource` directly, which made the only path that
/// composes fork detection, snapshot reload and replay untestable without a
/// node that actually reorgs — and mainnet supplies those on its own schedule.
/// A 500-block shadow run on 2026-08-22 saw none in 12h39m.
///
/// The trait hands back a [`BlockSummary`] rather than raw block bytes on
/// purpose. Deserialisation is covered thoroughly elsewhere (`extract.rs`, the
/// differential harness, the genesis replay), and requiring it here would force
/// any test to fabricate consensus-encoded Zcash blocks for two divergent
/// chains — which is a great deal of machinery to exercise a control-flow path
/// that never touches a byte.
pub trait ChainView {
    /// The node's current hash at `height`.
    fn block_hash(&self, height: u32) -> Result<String, String>;

    /// The block at `height`, already parsed.
    fn summary_at(&self, height: u32) -> Result<BlockSummary, String>;
}

/// One block a shadow run applied, and the compact state it produced.
pub struct Applied {
    /// Height applied.
    pub height: u32,
    /// The hash the node reported when it was applied.
    pub hash: String,
    /// The compact state *after* this block — a few hundred bytes, which is
    /// why keeping hundreds of them is affordable and a full node's equivalent
    /// is not (`docs/design.md` D31).
    pub csn: CompactState,
}

/// Walks back to the deepest block the node still agrees with and unwinds both
/// sides to it. Returns how many blocks were undone.
///
/// # The two sides undo very differently, and that is the measurement
///
/// Utreexo deletion is not invertible (`docs/design.md` D18), so the bridge
/// cannot step backwards. It reloads the snapshot the run resumed from and
/// replays the common prefix — heights at or below a fork are unchanged by
/// definition, so refetching them is safe.
///
/// The compact node takes an older state off a queue. No deltas, no positions,
/// no forest, no replay.
///
/// # Reported progress
///
/// Timings go to the `progress` callback rather than to `println!`, so a test
/// can drive this without writing to stdout and a binary can print exactly
/// what it printed before.
pub fn unwind<V: ChainView>(
    view: &V,
    snapshot: &Path,
    depth: u8,
    bridge: &mut ChainAccumulators,
    csn: &mut CompactState,
    history: &mut VecDeque<Applied>,
    mut progress: impl FnMut(&str),
) -> Result<u32, String> {
    // Fork detection is `find_fork` above, tested in `tests/shadow_fork.rs`.
    // Keeping a second copy here would leave the tested one decorative.
    let mut marks: VecDeque<AppliedBlock> = history
        .iter()
        .map(|applied| AppliedBlock {
            height: applied.height,
            hash: applied.hash.clone(),
        })
        .collect();
    let fork = find_fork(&mut marks, |height| view.block_hash(height))?;

    let (target, undone) = match fork {
        Fork::None => return Ok(0),
        Fork::BeyondHistory { undone } => {
            return Err(format!(
                "unwound {undone} block(s) and ran out of history; the fork predates this run"
            ))
        }
        Fork::UnwindTo { target, undone } => (target, undone),
    };
    // Bring the real history — which carries the compact states — into line
    // with what the search decided.
    while history
        .back()
        .is_some_and(|applied| applied.height > target)
    {
        history.pop_back();
    }

    // ---- the bridge: reload, then replay the common prefix ----
    let began = Instant::now();
    let mut restored = load(snapshot).map_err(|e| format!("reload {}: {e}", snapshot.display()))?;
    if restored.depth() != depth {
        return Err(format!(
            "reloaded snapshot depth {} does not match {depth}",
            restored.depth()
        ));
    }
    let base = restored.tip().map_or(0, |tip| tip.saturating_add(1));
    if base > target.saturating_add(1) {
        return Err(format!(
            "snapshot is at {:?}, past the fork point {target}",
            restored.tip()
        ));
    }

    for height in base..=target {
        let summary = view.summary_at(height)?;
        apply_block(&mut restored, &summary, ApplyOptions::default())
            .map_err(|e| format!("reapply {height}: {e}"))?;
    }
    *bridge = restored;
    progress(&format!(
        "  bridge rebuilt to {target} in {:.1}s ({} blocks replayed)",
        began.elapsed().as_secs_f64(),
        target.saturating_sub(base).saturating_add(1),
    ));

    // ---- the compact node: one clone off the queue ----
    let began_csn = Instant::now();
    match history.back() {
        Some(applied) => *csn = applied.csn.clone(),
        None => return Err("no compact state to restore".to_owned()),
    }
    progress(&format!(
        "  compact node rewound in {} us",
        began_csn.elapsed().as_micros()
    ));

    // The invariant CLAUDE.md Phase 2 refuses to soften: byte-identical, not
    // equivalent. If the sides disagree after unwinding, the rollback is wrong
    // and carrying on would measure a protocol that does not work.
    if csn.utxo_roots() != bridge.utxo_roots() || csn.nullifier_roots() != bridge.nullifier_roots()
    {
        return Err(format!(
            "after unwinding to {target} the two sides disagree - rollback is not byte-identical"
        ));
    }

    Ok(undone)
}

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

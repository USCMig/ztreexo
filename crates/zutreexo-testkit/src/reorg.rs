//! The reorg fuzzer.
//!
//! CLAUDE.md Phase 2 calls reorgs "the single most under-tested area of
//! accumulator work" and sets the bar at 10⁶ randomised reorgs with zero
//! divergence. The invariant it demands is total:
//!
//! > `apply(A..N)`, undo to `K`, apply the divergent `K..M` must produce
//! > **byte-identical** roots to a cold replay of the final chain. Do not
//! > soften this to "equivalent" or "same balance".
//!
//! So that is what this checks, mechanically, every iteration.
//!
//! # Synthetic blocks, and why
//!
//! Reorgs are a property of the state machine, not of parsing. Real blocks
//! would make each iteration hundreds of times more expensive while testing the
//! deserializer for the thousandth time, and no captured window is guaranteed
//! to contain the shapes that matter — a spend of an output created just before
//! a fork, a nullifier reused on a competing branch. Parsing is tier 3's job in
//! `harness`; this generates exactly the shapes it needs.
//!
//! # Reproducibility
//!
//! Everything derives from a single `u64` seed through a xorshift64\* generator
//! written out below. No external RNG, no thread-local state, no `HashMap`
//! iteration. A divergence therefore reproduces from one number, which is what
//! makes a corpus seed possible at all.

use std::collections::{BTreeMap, BTreeSet};

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::{PoolId, UtxoLeaf};
use zutreexo_chain::{
    apply_block, ApplyOptions, BlockSummary, ChainAccumulators, OutPoint, RollbackJournal,
};

/// xorshift64\*, written out rather than pulled in.
///
/// A dependency would be fine, but the seed-to-sequence mapping has to stay
/// stable forever or every committed corpus seed silently stops reproducing
/// what it was recorded for. Pinning it here makes that impossible to break by
/// upgrading something.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    /// Seeds the generator. Zero is remapped, since xorshift is degenerate at
    /// zero and would return zero forever.
    pub fn new(seed: u64) -> Rng {
        Rng(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-enough in `0..bound`. Modulo bias is irrelevant here: the values
    /// pick block shapes, not keys.
    fn below(&mut self, bound: u32) -> u32 {
        if bound == 0 {
            return 0;
        }
        u32::try_from(self.next_u64() % u64::from(bound)).unwrap_or(0)
    }

    fn in_range(&mut self, low: u32, high: u32) -> u32 {
        if high <= low {
            return low;
        }
        low.saturating_add(self.below(high.saturating_sub(low).saturating_add(1)))
    }
}

/// How the fuzzer should run.
#[derive(Clone, Debug)]
pub struct ReorgConfig {
    /// Tree depth for every pool.
    pub depth: u8,
    /// The height the chain is held at.
    ///
    /// Every iteration rolls back below this and extends straight back up to
    /// it, so the tip is `chain_len` at the end of each one.
    ///
    /// # Why the chain is pinned rather than allowed to grow
    ///
    /// The first version let each iteration pick a rollback depth and an
    /// extension length independently. Both averaged about four blocks, so the
    /// tip drifted upward roughly half a block per iteration — reaching height
    /// 15,722 by iteration 24,523, at which point the depth-12 tree hit its
    /// 4,096-leaf ceiling and the run died on a capacity error that looked, at
    /// first glance, like a rollback bug.
    ///
    /// It also destroyed the performance. A cold replay is linear in chain
    /// length, so the validating step got steadily more expensive; most of the
    /// 5m41s that 100,000 iterations took was replaying a chain thousands of
    /// blocks long, not exercising reorgs.
    ///
    /// Pinning the height fixes both, and costs nothing in coverage: the state
    /// machine does not care about absolute height, and the *content* of every
    /// block still varies each iteration.
    pub chain_len: u32,
    /// Deepest reorg the fuzzer will attempt.
    pub max_reorg_depth: u32,
    /// Snapshot cadence for the journal under test.
    pub snapshot_interval: u32,
    /// Run the full cold replay every this many reorgs.
    ///
    /// # Why this is not 1
    ///
    /// A cold replay rebuilds the whole chain from empty, so it costs
    /// `chain_len` block applications. At every iteration that put 10⁵ reorgs
    /// past ten minutes and 10⁶ — the definition of done — beyond an hour and a
    /// half. A check that expensive stops being run.
    ///
    /// So the same tiering as the block harness: a cheap structural check on
    /// **every** iteration, and the full byte-for-byte cold replay
    /// periodically. The cheap tier catches a lost or duplicated item
    /// immediately; the cold replay catches everything else, including the
    /// order-dependent corruption that counts are blind to.
    ///
    /// The last iteration is always checked as well, so a run cannot finish
    /// without the expensive tier having executed at least once.
    ///
    /// Set to 1 when bisecting. Set to **0** to disable the tier outright —
    /// that exists only to demonstrate what the cheap tier misses on its own,
    /// and should never be used for a real run. Same convention as
    /// `root_check_every` in [`harness`](crate::harness).
    pub cold_check_every: u64,
    /// Fault to inject, for proving the fuzzer detects one.
    pub fault: Option<ReorgFault>,
}

impl Default for ReorgConfig {
    fn default() -> Self {
        ReorgConfig {
            depth: 12,
            chain_len: 30,
            max_reorg_depth: 8,
            snapshot_interval: 4,
            cold_check_every: 32,
            fault: None,
        }
    }
}

/// A deliberately incomplete rollback, used to prove the fuzzer catches one.
///
/// A fuzzer that has never caught anything is unproven, and 10⁶ green
/// iterations look identical whether the invariant is being checked or not.
///
/// # These must leave the tip correct
///
/// The first version of these faults desynchronised the height, and both
/// "passed" — by making the *next* block fail a contiguity check, before any
/// cold replay ran. The tests were green for a reason unrelated to the thing
/// they claimed to prove, which is the precise failure mode fault injection
/// exists to rule out.
///
/// So each fault now leaves the tip exactly where a correct rollback would and
/// corrupts only the content. Nothing but the byte-for-byte comparison against
/// a cold replay can notice, which is what makes these evidence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReorgFault {
    /// Leave behind one nullifier that should have been undone.
    ///
    /// The shape of a real `undo_insert` bug: shielded roots differ, everything
    /// else agrees.
    LeftoverNullifier,
    /// Leave behind one transparent output that should have been undone.
    ///
    /// The subtler case — half a rollback. Nullifier roots come back correct,
    /// so anything checking only those would pass.
    LeftoverOutput,
    /// Change one surviving block's nullifier to a different value, once.
    ///
    /// **The fault that justifies the expensive tier.** Nothing is added or
    /// removed, so every count still matches and the cheap per-iteration check
    /// is structurally blind to it. Only the byte-for-byte comparison against a
    /// cold replay notices, which is the same argument the block harness makes
    /// for its cold rebuild.
    ///
    /// Unlike the other two this perturbs the *chain model* rather than the
    /// accumulator, because a count-preserving corruption cannot be produced
    /// through the public applier — inserting always increments something. The
    /// claim being tested is the detector's reach, and a disagreement between
    /// state and model exercises that identically from either side.
    AlteredHistory,
}

/// What a clean run did.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ReorgReport {
    /// Reorgs performed.
    pub reorgs: u64,
    /// Blocks applied across all branches.
    pub blocks_applied: u64,
    /// Deepest reorg actually attempted.
    pub deepest: u32,
    /// Times the state was compared against a cold replay.
    pub cold_checks: u64,
    /// Reorgs skipped because the journal could not reach that far back.
    pub out_of_reach: u64,
    /// Highest tip observed at any point.
    ///
    /// Reported so an unbounded-growth regression is visible in the output
    /// rather than only as a capacity error tens of thousands of iterations
    /// later. It should equal `chain_len`.
    pub highest_tip: u32,
}

/// A mismatch between the reorged state and a cold replay.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ReorgDivergence {
    /// The invariant failed: reorged state differs from a cold replay.
    #[error(
        "seed {seed}, iteration {iteration}: reorged to {height} but state \
         differs from a cold replay\n  incremental: {actual}\n  cold replay:  {expected}"
    )]
    NotColdReplay {
        /// Seed that produced this run.
        seed: u64,
        /// Iteration number.
        iteration: u64,
        /// Height reorged to.
        height: u32,
        /// Fingerprint of the incrementally-maintained state.
        actual: String,
        /// Fingerprint of the cold replay.
        expected: String,
    },
    /// The cheap per-iteration tier: a count disagrees with the chain model.
    #[error(
        "seed {seed}, iteration {iteration}: after reorg to {height}, {field} \
         is {actual} but the chain implies {expected}"
    )]
    CountMismatch {
        /// Seed that produced this run.
        seed: u64,
        /// Iteration number.
        iteration: u64,
        /// Height reorged to.
        height: u32,
        /// Which count.
        field: String,
        /// What the state says.
        actual: u64,
        /// What the chain model implies.
        expected: u64,
    },

    /// A block failed to apply during the run.
    #[error("seed {seed}, iteration {iteration}: applying height {height} failed: {reason}")]
    ApplyFailed {
        /// Seed that produced this run.
        seed: u64,
        /// Iteration number.
        iteration: u64,
        /// Height that failed.
        height: u32,
        /// Why.
        reason: String,
    },
    /// Rollback itself failed.
    #[error("seed {seed}, iteration {iteration}: rollback to {height} failed: {reason}")]
    RollbackFailed {
        /// Seed that produced this run.
        seed: u64,
        /// Iteration number.
        iteration: u64,
        /// Target height.
        height: u32,
        /// Why.
        reason: String,
    },
}

/// One generated block, in the form the model keeps.
#[derive(Clone, Debug)]
struct GenBlock {
    height: u32,
    /// Unique ids for outputs this block creates.
    creates: Vec<u64>,
    /// Ids of outputs this block spends.
    spends: Vec<u64>,
    /// Nullifiers revealed, per pool.
    nullifiers: Vec<(PoolId, u64)>,
}

fn bytes32(tag: u8, n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = tag;
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}

fn summary_of(block: &GenBlock) -> BlockSummary {
    let mut nullifiers: BTreeMap<PoolId, Vec<Value>> = BTreeMap::new();
    for (pool, n) in &block.nullifiers {
        nullifiers
            .entry(*pool)
            .or_default()
            .push(Value::from_bytes(bytes32(0xBB, *n)));
    }

    BlockSummary {
        height: block.height,
        transactions: 1,
        transparent_spends: block
            .spends
            .iter()
            .map(|n| OutPoint {
                txid: bytes32(0xAA, *n),
                vout: 0,
            })
            .collect(),
        transparent_creates: block
            .creates
            .iter()
            .map(|n| {
                (
                    OutPoint {
                        txid: bytes32(0xAA, *n),
                        vout: 0,
                    },
                    UtxoLeaf {
                        txid: bytes32(0xAA, *n),
                        vout: 0,
                        height: block.height,
                        is_coinbase: false,
                        value: 1_000 + *n,
                        script_pubkey: vec![0x76, 0xA9, (*n % 251) as u8],
                    },
                )
            })
            .collect(),
        nullifiers,
        commitments: BTreeMap::new(),
    }
}

/// Everything about the state that decides future behaviour.
fn fingerprint(state: &ChainAccumulators) -> String {
    let mut out = format!("tip={:?} utxos={}", state.tip(), state.utxo_count());
    for (pool, root) in state.nullifier_roots() {
        out.push_str(&format!(" {pool}:{}", hex::encode(root)));
    }
    for root in state.utxo_roots() {
        out.push_str(&format!(" t:{}", hex::encode(root)));
    }
    out
}

/// Replays a chain from empty. The oracle every iteration is checked against.
fn cold_replay(chain: &[GenBlock], depth: u8) -> Result<ChainAccumulators, String> {
    let mut state = ChainAccumulators::new(depth).map_err(|e| e.to_string())?;
    for block in chain {
        apply_block(&mut state, &summary_of(block), ApplyOptions::default())
            .map_err(|e| format!("height {}: {e}", block.height))?;
    }
    Ok(state)
}

/// The outputs unspent after `chain`, in deterministic order.
fn unspent(chain: &[GenBlock]) -> Vec<u64> {
    let mut live: BTreeSet<u64> = BTreeSet::new();
    for block in chain {
        for id in &block.spends {
            live.remove(id);
        }
        for id in &block.creates {
            live.insert(*id);
        }
    }
    live.into_iter().collect()
}

/// Generates the next block for a chain, spending only outputs that are
/// actually live on it.
///
/// `branch` distinguishes competing forks: two branches at the same height must
/// not generate the same nullifier, or the second would be rejected as a double
/// spend for reasons that have nothing to do with rollback.
fn generate(rng: &mut Rng, chain: &[GenBlock], height: u32, branch: u64) -> GenBlock {
    let id_base = u64::from(height)
        .wrapping_mul(1_000)
        .wrapping_add(branch.wrapping_mul(1_000_000));

    let create_count = rng.in_range(1, 3);
    let creates: Vec<u64> = (0..create_count)
        .map(|i| id_base.wrapping_add(u64::from(i)))
        .collect();

    // Spend at most one live output, and only sometimes, so the live set both
    // grows and shrinks over a run.
    let live = unspent(chain);
    let spends = if !live.is_empty() && rng.below(3) > 0 {
        let index = rng.below(u32::try_from(live.len()).unwrap_or(u32::MAX));
        live.get(usize::try_from(index).unwrap_or(0))
            .copied()
            .map(|id| vec![id])
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let pool = match rng.below(4) {
        0 => PoolId::Sprout,
        1 => PoolId::Sapling,
        2 => PoolId::Orchard,
        _ => PoolId::Ironwood,
    };
    let nullifier_count = rng.below(3);
    let nullifiers = (0..nullifier_count)
        .map(|i| (pool, id_base.wrapping_add(500).wrapping_add(u64::from(i))))
        .collect();

    GenBlock {
        height,
        creates,
        spends,
        nullifiers,
    }
}

/// Runs `iterations` randomised reorgs from `seed`.
///
/// Every iteration rolls back to a random height within the journal's reach,
/// extends a fresh branch, and compares the result against a cold replay of the
/// chain that now exists. Returns on the first divergence.
pub fn run(
    seed: u64,
    iterations: u64,
    config: &ReorgConfig,
) -> Result<ReorgReport, ReorgDivergence> {
    let mut rng = Rng::new(seed);
    let mut report = ReorgReport::default();

    let mut state =
        ChainAccumulators::new(config.depth).map_err(|e| ReorgDivergence::ApplyFailed {
            seed,
            iteration: 0,
            height: 0,
            reason: e.to_string(),
        })?;
    let mut journal = RollbackJournal::new(
        config.snapshot_interval,
        config.max_reorg_depth.saturating_mul(2).max(8),
    );
    let mut chain: Vec<GenBlock> = Vec::new();
    let mut branch: u64 = 0;

    // Build the initial chain.
    for height in 1..=config.chain_len {
        let block = generate(&mut rng, &chain, height, branch);
        let outcome = apply_block(&mut state, &summary_of(&block), ApplyOptions::default())
            .map_err(|e| ReorgDivergence::ApplyFailed {
                seed,
                iteration: 0,
                height,
                reason: e.to_string(),
            })?;
        journal
            .record(&state, outcome.delta)
            .map_err(|e| ReorgDivergence::ApplyFailed {
                seed,
                iteration: 0,
                height,
                reason: e.to_string(),
            })?;
        chain.push(block);
        report.blocks_applied = report.blocks_applied.saturating_add(1);
    }

    for iteration in 1..=iterations {
        let tip = match state.tip() {
            Some(tip) => tip,
            None => break,
        };

        // Strictly below the tip, so every iteration performs a real reorg
        // rather than sometimes rolling back to where it already is.
        let shallowest = tip.saturating_sub(config.max_reorg_depth).max(1);
        let deepest_target = tip.saturating_sub(1).max(shallowest);
        let target = rng.in_range(shallowest, deepest_target);

        let reachable = journal.earliest_rollback().unwrap_or(tip);
        if target < reachable {
            report.out_of_reach = report.out_of_reach.saturating_add(1);
            continue;
        }

        let depth_undone = tip.saturating_sub(target);
        report.deepest = report.deepest.max(depth_undone);

        journal
            .rollback_to(&mut state, target)
            .map_err(|e| ReorgDivergence::RollbackFailed {
                seed,
                iteration,
                height: target,
                reason: e.to_string(),
            })?;

        // Injected faults run *after* a correct rollback and re-apply a
        // fragment at the height the tip already sits at. Applying at the
        // current height leaves the tip unchanged, so the state stays
        // structurally plausible and only its contents are wrong — which is
        // the only way this proves the cold-replay comparison is doing the
        // detecting.
        match config.fault {
            None => {}
            Some(ReorgFault::AlteredHistory) => {
                // Applied once, to a block in the surviving prefix, so the
                // divergence persists rather than being undone next iteration.
                if iteration == 1 {
                    if let Some(block) = chain
                        .iter_mut()
                        .find(|b| b.height <= target && !b.nullifiers.is_empty())
                    {
                        if let Some((_, value)) = block.nullifiers.first_mut() {
                            *value = value.wrapping_add(0x0F00_0000);
                        }
                    }
                }
            }
            Some(fault) => {
                if let Some(undone) = chain.iter().find(|b| b.height > target) {
                    let mut fragment = BlockSummary {
                        height: target,
                        transactions: 0,
                        ..BlockSummary::default()
                    };
                    match fault {
                        ReorgFault::LeftoverNullifier => {
                            fragment.nullifiers = summary_of(undone).nullifiers;
                        }
                        ReorgFault::LeftoverOutput => {
                            fragment.transparent_creates = summary_of(undone).transparent_creates;
                        }
                        ReorgFault::AlteredHistory => {}
                    }
                    let _ = apply_block(
                        &mut state,
                        &fragment,
                        ApplyOptions {
                            enforce_contiguous: false,
                            ..ApplyOptions::default()
                        },
                    );
                }
            }
        }

        chain.retain(|block| block.height <= target);
        report.reorgs = report.reorgs.saturating_add(1);
        branch = branch.saturating_add(1);

        // Extend a fresh branch back up to the pinned height. Not a random
        // length: an extension independent of the rollback depth makes the tip
        // random-walk upward, which is what previously drove the chain to
        // 15,000 blocks and exhausted the tree. See `ReorgConfig::chain_len`.
        for height in (target.saturating_add(1))..=config.chain_len {
            let block = generate(&mut rng, &chain, height, branch);
            let outcome = apply_block(&mut state, &summary_of(&block), ApplyOptions::default())
                .map_err(|e| ReorgDivergence::ApplyFailed {
                    seed,
                    iteration,
                    height,
                    reason: e.to_string(),
                })?;
            journal
                .record(&state, outcome.delta)
                .map_err(|e| ReorgDivergence::ApplyFailed {
                    seed,
                    iteration,
                    height,
                    reason: e.to_string(),
                })?;
            chain.push(block);
            report.blocks_applied = report.blocks_applied.saturating_add(1);
        }

        report.highest_tip = report.highest_tip.max(state.tip().unwrap_or(0));

        // ---- cheap tier: counts, every iteration ----
        //
        // Derived from the chain model rather than from any accumulator, so it
        // is an independent statement rather than a restatement. O(chain), no
        // hashing.
        let live = unspent(&chain).len() as u64;
        if state.utxo_count() as u64 != live {
            return Err(ReorgDivergence::CountMismatch {
                seed,
                iteration,
                height: target,
                field: "utxos".to_owned(),
                actual: state.utxo_count() as u64,
                expected: live,
            });
        }
        for pool in PoolId::ALL {
            let expected: u64 = chain
                .iter()
                .flat_map(|b| b.nullifiers.iter())
                .filter(|(p, _)| *p == pool)
                .count() as u64;
            let actual = state.nullifier_count(pool);
            if actual != expected {
                return Err(ReorgDivergence::CountMismatch {
                    seed,
                    iteration,
                    height: target,
                    field: format!("{pool} nullifiers"),
                    actual,
                    expected,
                });
            }
        }

        // ---- expensive tier: byte-for-byte against a cold replay ----
        let enabled = config.cold_check_every > 0;
        let due =
            enabled && (config.cold_check_every == 1 || iteration % config.cold_check_every == 0);
        let last = enabled && iteration == iterations;
        if due || last {
            let expected = cold_replay(&chain, config.depth).map_err(|reason| {
                ReorgDivergence::ApplyFailed {
                    seed,
                    iteration,
                    height: target,
                    reason,
                }
            })?;
            report.cold_checks = report.cold_checks.saturating_add(1);

            let actual = fingerprint(&state);
            let wanted = fingerprint(&expected);
            if actual != wanted {
                return Err(ReorgDivergence::NotColdReplay {
                    seed,
                    iteration,
                    height: target,
                    actual,
                    expected: wanted,
                });
            }
        }
    }

    Ok(report)
}

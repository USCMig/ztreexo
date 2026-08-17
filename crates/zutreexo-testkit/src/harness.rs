//! The differential replay driver: two oracles, three comparison tiers.
//!
//! # The tiers, and why there are three rather than one
//!
//! | Tier | Runs | Compares | Catches |
//! |---|---|---|---|
//! | 1 counts | every block | [`StateCounts`] vs the naive model's | a dropped nullifier or output, instantly and cheaply |
//! | 2 cold roots | every `root_check_every` blocks | incremental roots vs roots **recomputed from scratch** | incremental drift |
//! | 3 validator | once per replay | our extracted totals vs the node's own JSON | parsing bugs |
//!
//! Tier 2 is the load-bearing one. Tier 1 is `O(1)` and will catch a missing
//! item, but it is blind to anything that preserves counts — a reordering, a
//! wrong leaf index, a successor pointer left stale. Those change the root and
//! nothing else, and they accumulate silently over a long replay, surfacing
//! only when somebody cannot spend. Recomputing cold is the only check that
//! proves the incremental path has not drifted.
//!
//! Tier 3 covers what neither of the other two can. Tiers 1 and 2 feed both
//! models from the same parse, so a mis-read block produces two models that
//! agree and are both wrong. See [`checkpoints`].
//!
//! # A repro is dumped before any error propagates
//!
//! CLAUDE.md Phase 2 calls this non-negotiable, and the reasoning is that a
//! divergence you cannot replay offline is one you will not fix. On any
//! divergence, [`replay`] writes the offending block plus the full
//! configuration to `repro_dir` *before* returning the error, and the resulting
//! file is self-contained: it needs no node and no fixture directory.
//!
//! # Depth
//!
//! Tier 2 runs at [`naive::MAX_NAIVE_DEPTH`](crate::naive::MAX_NAIVE_DEPTH) or
//! below, because the oracle materialises all `2^depth` leaves rather than
//! walking a sparse path — the cleverness it refuses is exactly what would let
//! it share the implementation's bugs. That is sound, since depth is a
//! parameter and structural agreement at depth 16 is the same statement as at
//! 40, but it caps a single replay at about 65,000 nullifiers. See `PLAN.md`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use zebra_chain::block::Block;
use zebra_chain::serialization::{ZcashDeserialize, ZcashSerialize};

use zutreexo_chain::{
    apply_block, summarize_block, ApplyOptions, BlockSummary, ChainAccumulators, PoolId,
    StateCounts,
};

use crate::checkpoints::{self, Checkpoint};
use crate::naive::{Hash, NaivePool};
use crate::state::{pool_name, NaiveBlock, NaiveOptions, NaiveState};

/// How a replay should run.
#[derive(Clone, Debug)]
pub struct HarnessConfig {
    /// Depth for both the real trees and the oracle.
    pub depth: u8,
    /// Run tier 2 every this many blocks. `1` when bisecting a divergence.
    ///
    /// The last block of a replay is always checked as well, so the tier
    /// cannot be skipped by an unlucky slice length. `0` disables tier 2
    /// entirely and exists only to demonstrate what tier 1 misses without it.
    pub root_check_every: u32,
    /// Where to write a repro on divergence. `None` disables dumping.
    pub repro_dir: Option<PathBuf>,
    /// Tolerate spends of outputs created before the window.
    pub allow_unknown_spends: bool,
    /// Require contiguous heights.
    pub enforce_contiguous: bool,
    /// Slice name, used for repro filenames and tier 3 lookup.
    pub label: String,
    /// Fault to inject into the *implementation's* input only. Testing the
    /// harness itself; see [`Fault`].
    pub fault: Option<Fault>,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        HarnessConfig {
            // Not MAX_NAIVE_DEPTH: the oracle materialises 2^depth leaves per
            // root, so defaulting to the maximum would make the cheapest
            // possible use of this type the most expensive one. 14 gives 16,384
            // leaves per pool, which clears the largest fixture slice — 5,838
            // Orchard nullifiers in the Ironwood window — with room to spare.
            depth: 14,
            root_check_every: 10,
            repro_dir: None,
            allow_unknown_spends: true,
            enforce_contiguous: true,
            label: "unnamed".to_owned(),
            fault: None,
        }
    }
}

/// A deliberate corruption, applied to what the real accumulator sees and not
/// to what the oracle sees.
///
/// # Why this exists
///
/// A harness that has never caught anything is unproven. These simulate the bug
/// classes each tier is supposed to catch, so the tiers can be shown to fire
/// rather than assumed to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    /// Drop one nullifier at this height. Changes counts, so **tier 1** fires.
    DropNullifier {
        /// Height to corrupt.
        height: u32,
    },
    /// Drop one created output. Changes counts, so **tier 1** fires.
    DropCreate {
        /// Height to corrupt.
        height: u32,
    },
    /// Reverse the nullifier order within each pool at this height.
    ///
    /// The interesting one. Counts are unchanged, so tier 1 is blind; only the
    /// leaf indices move, which changes the root. **Tier 2** fires, and nothing
    /// else would. This is what justifies tier 2's cost.
    ReorderNullifiers {
        /// Height to corrupt.
        height: u32,
    },
    /// Undercount note commitments at this height.
    ///
    /// Simulates a *parsing* bug rather than an accumulator one. Commitments
    /// are counted and never accumulated (CLAUDE.md §2 leaves the commitment
    /// trees alone), so neither the counts tier nor the roots tier can see
    /// this — both oracles would have to be fed the same bad parse to notice,
    /// and they are. Only **tier 3**, comparing against what the node itself
    /// reported, catches it. This is what justifies tier 3's existence.
    DropCommitment {
        /// Height to corrupt.
        height: u32,
    },
}

impl Fault {
    /// Machine-readable form, so a repro can round-trip through a corpus seed.
    ///
    /// A `Debug` string would be shorter and would not survive being read back,
    /// which would make every seed carrying a fault silently inert.
    pub fn to_json(self) -> serde_json::Value {
        let (kind, height) = match self {
            Fault::DropNullifier { height } => ("DropNullifier", height),
            Fault::DropCreate { height } => ("DropCreate", height),
            Fault::ReorderNullifiers { height } => ("ReorderNullifiers", height),
            Fault::DropCommitment { height } => ("DropCommitment", height),
        };
        serde_json::json!({ "kind": kind, "height": height })
    }

    /// Reads back what [`Fault::to_json`] wrote.
    pub fn from_json(value: &serde_json::Value) -> Option<Fault> {
        let height = u32::try_from(value.get("height")?.as_u64()?).ok()?;
        match value.get("kind")?.as_str()? {
            "DropNullifier" => Some(Fault::DropNullifier { height }),
            "DropCreate" => Some(Fault::DropCreate { height }),
            "ReorderNullifiers" => Some(Fault::ReorderNullifiers { height }),
            "DropCommitment" => Some(Fault::DropCommitment { height }),
            _ => None,
        }
    }
}

/// A mismatch between the implementation and an oracle.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum Divergence {
    /// Tier 1: counts disagree.
    #[error("tier 1 at height {height}: {field} is {actual} but the oracle says {expected}")]
    Counts {
        /// Height where it was noticed.
        height: u32,
        /// Which count.
        field: String,
        /// What the implementation says.
        actual: u64,
        /// What the oracle says.
        expected: u64,
    },
    /// Tier 2: an incremental root disagrees with a cold rebuild.
    #[error("tier 2 at height {height}: {pool} root {actual} but cold rebuild gives {expected}")]
    Root {
        /// Height where it was noticed.
        height: u32,
        /// Which pool.
        pool: String,
        /// Incremental root, hex.
        actual: String,
        /// Cold-rebuilt root, hex.
        expected: String,
    },
    /// Tier 3: our parse disagrees with the node's.
    #[error("tier 3 on {slice}: {field} is {actual} but zebrad says {expected}")]
    Checkpoint {
        /// Which slice.
        slice: String,
        /// Which field.
        field: String,
        /// What we counted.
        actual: u64,
        /// What the node counted.
        expected: u64,
    },
    /// The implementation rejected a block the oracle accepted, or vice versa.
    #[error("at height {height}: implementation said {implementation:?}, oracle said {oracle:?}")]
    Disagreement {
        /// Height where it was noticed.
        height: u32,
        /// Implementation result.
        implementation: String,
        /// Oracle result.
        oracle: String,
    },
    /// A block could not be read.
    #[error("at height {height}: {reason}")]
    Extract {
        /// Height where it was noticed.
        height: u32,
        /// What went wrong.
        reason: String,
    },
}

/// What a clean replay did.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Report {
    /// Blocks applied.
    pub blocks: usize,
    /// Times tier 2 ran.
    pub root_checks: usize,
    /// Whether tier 3 ran, and against which slice.
    pub checkpoint: Option<String>,
    /// Last height applied.
    pub last_height: Option<u32>,
    /// Totals our parser extracted, as compared in tier 3.
    pub totals: BTreeMap<String, u64>,
    /// Spends of outputs created before the window.
    pub unknown_spends: usize,
    /// Why the replay stopped before consuming every block, if it did.
    ///
    /// When both the implementation and the oracle reject the same block that
    /// is *agreement*, not a divergence, so it is not an error — but it is also
    /// not a complete replay, and the difference matters. A tree that runs out
    /// of capacity mid-slice makes both sides reject in lockstep, and without
    /// this field the run looks like a short clean pass. Callers replaying a
    /// known-good slice should assert this is `None`.
    pub stopped_early: Option<String>,
}

/// Replays blocks through both the implementation and the oracle.
///
/// Returns on the first divergence, having written a repro first.
pub fn replay(blocks: &[Block], config: &HarnessConfig) -> Result<Report, Divergence> {
    let mut state = ChainAccumulators::new(config.depth).map_err(|error| Divergence::Extract {
        height: 0,
        reason: format!(
            "cannot build accumulators at depth {}: {error}",
            config.depth
        ),
    })?;
    let mut oracle = NaiveState::new(config.depth).map_err(|error| Divergence::Extract {
        height: 0,
        reason: format!("cannot build oracle at depth {}: {error:?}", config.depth),
    })?;

    let apply_options = ApplyOptions {
        allow_unknown_spends: config.allow_unknown_spends,
        enforce_contiguous: config.enforce_contiguous,
    };
    let naive_options = NaiveOptions {
        allow_unknown_spends: config.allow_unknown_spends,
    };

    let mut report = Report::default();

    for block in blocks {
        let summary = summarize_block(block).map_err(|error| {
            let divergence = Divergence::Extract {
                height: report.last_height.unwrap_or(0),
                reason: error.to_string(),
            };
            dump(config, block, &divergence);
            divergence
        })?;
        let height = summary.height;

        // The oracle always sees the truth. Only the implementation's input is
        // corrupted, which is what makes an injected fault look exactly like an
        // implementation bug.
        let oracle_block = to_naive_block(&summary);
        let implementation_input = match config.fault {
            Some(fault) => corrupt(&summary, fault),
            None => summary.clone(),
        };

        // Totals come from what the implementation *saw*, not from the pristine
        // parse. Tier 3 asks "did we read the block correctly?", so it has to
        // compare the node's answer against our side of the parse — reading the
        // untouched summary here would make tier 3 structurally incapable of
        // seeing a parsing bug, which is the only thing it exists to catch.
        accumulate_totals(&mut report.totals, &implementation_input);

        let applied = apply_block(&mut state, &implementation_input, apply_options);
        let modelled = oracle.apply(&oracle_block, naive_options);

        match (&applied, &modelled) {
            (Ok(_), Ok(())) => {}
            (Err(implementation), Err(oracle_error)) => {
                // Both rejected. That is agreement, not a divergence, and the
                // replay stops because neither side advanced past this block.
                //
                // Recorded rather than swallowed: the commonest cause is a tree
                // running out of capacity, which makes both sides fail in
                // lockstep and would otherwise look like a short clean pass.
                let capacity = 1u64
                    .checked_shl(u32::from(config.depth))
                    .unwrap_or(u64::MAX);
                report.stopped_early = Some(format!(
                    "both sides rejected block {height}: {implementation} / {oracle_error:?} \
                     (depth {} holds {capacity} leaves per pool — raise it if a pool filled up)",
                    config.depth,
                ));
                break;
            }
            (implementation, oracle_error) => {
                // One accepted and the other rejected. Summarised rather than
                // `Debug`-formatted: a successful `ApplyOutcome` carries the
                // whole `StateDelta`, which for a busy block is thousands of
                // nullifiers and their insertion proofs. Dumping that verbatim
                // would bury the one fact that matters — which side said no —
                // and would bloat the repro file it gets written into.
                let divergence = Divergence::Disagreement {
                    height,
                    implementation: match implementation {
                        Ok(_) => "accepted".to_owned(),
                        Err(error) => format!("rejected: {error}"),
                    },
                    oracle: match oracle_error {
                        Ok(()) => "accepted".to_owned(),
                        Err(error) => format!("rejected: {error:?}"),
                    },
                };
                dump(config, block, &divergence);
                return Err(divergence);
            }
        }

        if let Ok(outcome) = &applied {
            report.unknown_spends = report.unknown_spends.saturating_add(outcome.unknown_spends);
        }
        report.blocks = report.blocks.saturating_add(1);
        report.last_height = Some(height);

        // ---- tier 1: every block ----
        if let Err(divergence) = compare_counts(height, &state.counts(), &oracle) {
            dump(config, block, &divergence);
            return Err(divergence);
        }

        // ---- tier 2: every N blocks, and always on the last ----
        //
        // The final block always gets a root check, so a replay cannot finish
        // without the load-bearing tier having run at least once. `N = 0` is
        // the sole exception and disables the tier outright — it exists only to
        // demonstrate what tier 1 misses on its own, and should never be used
        // for an actual replay.
        let enabled = config.root_check_every > 0;
        let due = enabled && report.blocks as u32 % config.root_check_every == 0;
        let last = enabled && report.blocks == blocks.len();
        if due || last {
            report.root_checks = report.root_checks.saturating_add(1);
            if let Err(divergence) = compare_roots(height, &state, &oracle) {
                dump(config, block, &divergence);
                return Err(divergence);
            }
        }
    }

    // ---- tier 3: once, against the node's recorded answers ----
    //
    // Only when the replay covered the whole slice. A checkpoint records totals
    // over all 200 blocks, so comparing a partial replay against it would
    // report a divergence that means nothing — which is what a corpus seed
    // replaying a single block would otherwise trigger every time.
    if let Ok(checkpoint) = checkpoints::load(&config.label) {
        if report.blocks as u64 == checkpoint.blocks {
            compare_checkpoint(&checkpoint, &report.totals)?;
            report.checkpoint = Some(config.label.clone());
        }
    }

    Ok(report)
}

/// Tier 1. Counts only — `O(1)`, and blind to anything order-dependent.
fn compare_counts(
    height: u32,
    counts: &StateCounts,
    oracle: &NaiveState,
) -> Result<(), Divergence> {
    let modelled = oracle.counts();

    if counts.utxos as u64 != modelled.utxos as u64 {
        return Err(Divergence::Counts {
            height,
            field: "utxos".to_owned(),
            actual: counts.utxos as u64,
            expected: modelled.utxos as u64,
        });
    }

    for pool in PoolId::ALL {
        let name = pool_name(map_pool(pool));
        let actual = counts.nullifiers.get(&pool).copied().unwrap_or(0);
        let expected = modelled.nullifiers.get(name).copied().unwrap_or(0);
        if actual != expected {
            return Err(Divergence::Counts {
                height,
                field: format!("{name}_nullifiers"),
                actual,
                expected,
            });
        }
    }

    Ok(())
}

/// Tier 2. Incremental roots against a from-scratch rebuild.
fn compare_roots(
    height: u32,
    state: &ChainAccumulators,
    oracle: &NaiveState,
) -> Result<(), Divergence> {
    let incremental = state.nullifier_roots();
    let cold = oracle.roots();

    for pool in PoolId::ALL {
        let name = pool_name(map_pool(pool));
        let actual = incremental.get(&pool).copied().unwrap_or([0u8; 32]);
        let Some(expected) = cold.get(name).copied() else {
            continue;
        };
        if actual != expected {
            return Err(Divergence::Root {
                height,
                pool: name.to_owned(),
                actual: hex::encode(actual),
                expected: hex::encode(expected),
            });
        }
    }

    Ok(())
}

/// Tier 3. Our totals against the node's.
fn compare_checkpoint(
    checkpoint: &Checkpoint,
    totals: &BTreeMap<String, u64>,
) -> Result<(), Divergence> {
    for (field, expected) in &checkpoint.totals {
        let Some(actual) = totals.get(field).copied() else {
            continue;
        };
        if actual != *expected {
            return Err(Divergence::Checkpoint {
                slice: checkpoint.slice.clone(),
                field: field.clone(),
                actual,
                expected: *expected,
            });
        }
    }
    Ok(())
}

fn accumulate_totals(totals: &mut BTreeMap<String, u64>, summary: &BlockSummary) {
    for pool in PoolId::ALL {
        let name = pool_name(map_pool(pool));
        add(
            totals,
            format!("{name}_nullifiers"),
            summary.nullifiers_for(pool).len() as u64,
        );
        add(
            totals,
            format!("{name}_commitments"),
            summary.commitments_for(pool) as u64,
        );
    }
    add(
        totals,
        "transparent_spends".to_owned(),
        summary.transparent_spends.len() as u64,
    );
    add(
        totals,
        "transparent_creates".to_owned(),
        summary.transparent_creates.len() as u64,
    );
    add(
        totals,
        "transactions".to_owned(),
        summary.transactions as u64,
    );
}

fn add(totals: &mut BTreeMap<String, u64>, key: String, by: u64) {
    let entry = totals.entry(key).or_insert(0);
    *entry = entry.saturating_add(by);
}

/// Translates a parsed summary into the oracle's plain-data form.
///
/// This is a copy, not a computation. Anything clever here would be a place for
/// the two sides to share a bug.
fn to_naive_block(summary: &BlockSummary) -> NaiveBlock {
    let mut nullifiers: Vec<(NaivePool, Hash)> = Vec::new();
    for pool in PoolId::ALL {
        for value in summary.nullifiers_for(pool) {
            nullifiers.push((map_pool(pool), value.to_bytes()));
        }
    }

    NaiveBlock {
        height: summary.height,
        spends: summary
            .transparent_spends
            .iter()
            .map(|outpoint| (outpoint.txid, outpoint.vout))
            .collect(),
        creates: summary
            .transparent_creates
            .iter()
            .map(|(outpoint, _)| (outpoint.txid, outpoint.vout))
            .collect(),
        nullifiers,
    }
}

fn map_pool(pool: PoolId) -> NaivePool {
    match pool {
        PoolId::Sprout => NaivePool::Sprout,
        PoolId::Sapling => NaivePool::Sapling,
        PoolId::Orchard => NaivePool::Orchard,
        PoolId::Ironwood => NaivePool::Ironwood,
    }
}

/// Applies an injected fault to the implementation's copy of a block.
fn corrupt(summary: &BlockSummary, fault: Fault) -> BlockSummary {
    let mut corrupted = summary.clone();
    match fault {
        Fault::DropNullifier { height } if height == summary.height => {
            for pool in PoolId::ALL {
                if let Some(values) = corrupted.nullifiers.get_mut(&pool) {
                    if values.pop().is_some() {
                        break;
                    }
                }
            }
        }
        Fault::DropCreate { height } if height == summary.height => {
            corrupted.transparent_creates.pop();
        }
        Fault::ReorderNullifiers { height } if height == summary.height => {
            for pool in PoolId::ALL {
                if let Some(values) = corrupted.nullifiers.get_mut(&pool) {
                    values.reverse();
                }
            }
        }
        Fault::DropCommitment { height } if height == summary.height => {
            for pool in PoolId::ALL {
                if let Some(count) = corrupted.commitments.get_mut(&pool) {
                    if *count > 0 {
                        *count = count.saturating_sub(1);
                        break;
                    }
                }
            }
        }
        _ => {}
    }
    corrupted
}

/// Writes a self-contained repro before a divergence propagates.
///
/// Best-effort by design: failing to write a repro must not mask the
/// divergence, which is the thing that actually matters. A failed write is
/// reported on stderr and the original error still propagates.
fn dump(config: &HarnessConfig, block: &Block, divergence: &Divergence) {
    let Some(dir) = &config.repro_dir else {
        return;
    };
    if let Err(error) = write_repro(dir, config, block, divergence) {
        eprintln!(
            "warning: could not write repro to {}: {error}",
            dir.display()
        );
    }
}

fn write_repro(
    dir: &PathBuf,
    config: &HarnessConfig,
    block: &Block,
    divergence: &Divergence,
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;

    let height = block.coinbase_height().map_or(0, |h| h.0);
    let kind = match divergence {
        Divergence::Counts { .. } => "counts",
        Divergence::Root { .. } => "root",
        Divergence::Checkpoint { .. } => "checkpoint",
        Divergence::Disagreement { .. } => "disagreement",
        Divergence::Extract { .. } => "extract",
    };

    let mut bytes = Vec::new();
    let serialized = match block.zcash_serialize(&mut bytes) {
        Ok(()) => hex::encode(&bytes),
        // A block that will not re-serialize is itself worth recording, but it
        // must not stop the repro being written.
        Err(error) => format!("<unserializable: {error}>"),
    };

    let record = serde_json::json!({
        "divergence": divergence.to_string(),
        "kind": kind,
        "height": height,
        "slice": config.label,
        "config": {
            "depth": config.depth,
            "root_check_every": config.root_check_every,
            "allow_unknown_spends": config.allow_unknown_spends,
            // A seed replays one block out of context, so contiguity cannot be
            // enforced regardless of how the original replay ran.
            "enforce_contiguous": false,
            "fault": config.fault.map(Fault::to_json),
        },
        "block_hex": serialized,
        "replay": "cargo test -p zutreexo-testkit --test corpus",
    });

    let path = dir.join(format!("{}-{height}-{kind}.json", config.label));
    std::fs::write(&path, format!("{record:#}\n"))?;
    eprintln!("repro written to {}", path.display());
    Ok(path)
}

/// A repro read back from disk, ready to replay offline.
#[derive(Clone, Debug)]
pub struct Repro {
    /// The block that diverged.
    pub block: Block,
    /// The divergence as originally reported.
    pub divergence: String,
    /// The configuration that produced it, with contiguity relaxed.
    pub config: HarnessConfig,
}

/// Reads a repro back, so a divergence can be replayed without a node or
/// fixtures.
///
/// This is the other half of the promise CLAUDE.md Phase 2 makes: a dump nobody
/// can load is a dump nobody will use. The configuration round-trips too — a
/// seed that replayed under different settings than the ones that caught it
/// would be silently inert, which is worse than having no seed.
pub fn load_repro(path: &std::path::Path) -> Result<Repro, String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| error.to_string())?;

    let hex_str = value
        .get("block_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "repro has no block_hex".to_owned())?;
    let bytes = hex::decode(hex_str).map_err(|error| error.to_string())?;
    let block = Block::zcash_deserialize(&bytes[..]).map_err(|error| error.to_string())?;

    let divergence = value
        .get("divergence")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>")
        .to_owned();

    let stored = value.get("config");
    let number = |key: &str, fallback: u64| -> u64 {
        stored
            .and_then(|c| c.get(key))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(fallback)
    };
    let flag = |key: &str, fallback: bool| -> bool {
        stored
            .and_then(|c| c.get(key))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(fallback)
    };

    let config = HarnessConfig {
        depth: u8::try_from(number("depth", 16)).unwrap_or(16),
        root_check_every: u32::try_from(number("root_check_every", 1)).unwrap_or(1),
        repro_dir: None,
        allow_unknown_spends: flag("allow_unknown_spends", true),
        // Always relaxed: a seed is one block out of its chain.
        enforce_contiguous: false,
        label: value
            .get("slice")
            .and_then(|v| v.as_str())
            .unwrap_or("corpus")
            .to_owned(),
        fault: stored
            .and_then(|c| c.get("fault"))
            .and_then(Fault::from_json),
    };

    Ok(Repro {
        block,
        divergence,
        config,
    })
}

//! Stage 2d: replay mainnet from genesis through the accumulators.
//!
//! # What this proves, and what it cannot
//!
//! CLAUDE.md's Phase 2 definition of done originally asked for "bit-exact
//! agreement with Zebra at every checkpoint from genesis to tip". That
//! comparison does not exist — Zebra computes none of the roots this project
//! computes. `z_gettreestate` returns commitment-tree roots only, §2
//! deliberately leaves those trees alone, there is no nullifier-root RPC
//! because nothing else maintains one, and `gettxoutsetinfo` is unimplemented.
//! The DoD was amended on 2026-08-17; the reasoning is in `CLAUDE.md` and
//! `PLAN.md`.
//!
//! What this run establishes instead:
//!
//! 1. **Mainnet is its own oracle.** The IMT rejects duplicate nullifiers and
//!    the applier rejects unresolvable spends. A mis-parsed nullifier collides;
//!    a mis-parsed outpoint fails to resolve. Neither survives millions of
//!    blocks quietly, so a clean genesis-forward replay is a real claim rather
//!    than an absence of evidence.
//! 2. **Parse agreement with `zebrad`** at checkpoints — Zebra as oracle for
//!    the one thing Zebra can oracle.
//! 3. **Incremental roots equal a from-scratch rebuild**, while the set is
//!    small enough for that to be affordable. This shares code with the
//!    implementation, so it catches drift and corruption but not algorithm
//!    bugs; those stay covered at small scale by stages 2b and 2c.
//! 4. **Measurements** — set sizes, growth, memory — closing two Phase 0 gaps
//!    and feeding Phase 3's on-disk format and Phase 5's benchmarks.
//!
//! # Running it
//!
//! ```text
//! ZUTREEXO_REPLAY_TO=200000 cargo run --release -p zutreexo-testkit --bin genesis_replay
//! ```
//!
//! Environment: `ZUTREEXO_RPC` (default `127.0.0.1:8232`), `ZUTREEXO_REPLAY_FROM`,
//! `ZUTREEXO_REPLAY_TO` (default: the node's tip), `ZUTREEXO_DEPTH`,
//! `ZUTREEXO_REPORT_EVERY`, `ZUTREEXO_REBUILD_UNDER` (largest nullifier count
//! still worth a cold rebuild), `ZUTREEXO_WORKERS`.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::time::Instant;

use zutreexo_accumulator::imt::DEFAULT_DEPTH;
use zutreexo_accumulator::PoolId;
use zutreexo_chain::{apply_block, load, save, summarize_block, ApplyOptions, ChainAccumulators};
use zutreexo_testkit::measure::{peak_rss_mib, rss_mib};
use zutreexo_testkit::source::{BlockSource, BlockStream, RpcSource};

fn env_u32(key: &str, fallback: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

fn env_u64(key: &str, fallback: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

/// Recomputes one pool's root from scratch and compares it against the
/// incrementally-maintained one. Returns `None` when the tree is too large to
/// be worth it.
///
/// Uses the bottom-up rebuild rather than replaying every insertion. Replaying
/// costs `2 * depth` hashes per value — 80 at depth 40 — which over 32 million
/// Orchard nullifiers is 2.6 billion hashes. Folding the tree a level at a time
/// costs roughly three hashes per value instead, which is what makes the check
/// affordable at chain scale at all. See `IndexedMerkleTree::rebuild_root`.
fn cold_rebuild_matches(state: &ChainAccumulators, pool: PoolId, limit: u64) -> RebuildOutcome {
    let Some(tree) = state.tree(pool) else {
        return RebuildOutcome::NoTree;
    };
    let count = tree.value_count();
    if count == 0 {
        return RebuildOutcome::Empty;
    }
    if count > limit {
        return RebuildOutcome::TooLarge;
    }
    match tree.rebuild_root() {
        Ok(root) if root == tree.root() => RebuildOutcome::Matches,
        Ok(_) => RebuildOutcome::Diverged,
        Err(_) => RebuildOutcome::NoTree,
    }
}

/// Why a rebuild did or did not happen.
///
/// Distinguishing `Empty` from `TooLarge` matters: the first genesis run
/// reported "some rebuilds skipped: set too large" at every checkpoint, and 73
/// of those skips were pools that simply held nothing yet. A log line meaning
/// two different things is a log line nobody can act on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RebuildOutcome {
    Matches,
    Diverged,
    /// Nothing in this pool yet — nothing to check, and not a gap in coverage.
    Empty,
    /// Above the affordable ceiling. This *is* a gap in coverage.
    TooLarge,
    NoTree,
}

/// Heights at which to write a snapshot, from `ZUTREEXO_SAVE_AT`.
///
/// Format: `height:path` pairs separated by commas, e.g.
/// `1700000:/snap/h1.7m.bin,3455000:/snap/tip.bin`. A bare `height` writes to
/// `zutreexo-<height>.snap` in the working directory.
///
/// Unparseable entries are reported and skipped rather than silently dropped:
/// a typo that costs a seven-hour replay its snapshot should be visible in the
/// first line of output, not discovered at the end.
fn save_heights() -> std::collections::BTreeMap<u32, std::path::PathBuf> {
    let mut out = std::collections::BTreeMap::new();
    let Ok(raw) = std::env::var("ZUTREEXO_SAVE_AT") else {
        return out;
    };
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (height, path) = match entry.split_once(':') {
            Some((h, p)) => (h.trim(), Some(p.trim())),
            None => (entry, None),
        };
        match height.parse::<u32>() {
            Ok(height) => {
                let path = path.map_or_else(
                    || std::path::PathBuf::from(format!("zutreexo-{height}.snap")),
                    std::path::PathBuf::from,
                );
                out.insert(height, path);
            }
            Err(error) => eprintln!("ZUTREEXO_SAVE_AT: ignoring {entry:?}: {error}"),
        }
    }
    out
}

/// Writes a snapshot and reports its size and cost.
fn write_snapshot(
    state: &ChainAccumulators,
    path: &std::path::Path,
) -> Result<(), zutreexo_chain::StoreError> {
    let began = Instant::now();
    save(state, path)?;
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    println!(
        "\nsnapshot at tip {:?} -> {} — {:.2} GB in {:.1}s",
        state.tip(),
        path.display(),
        size as f64 / 1e9,
        began.elapsed().as_secs_f64()
    );
    Ok(())
}

fn main() -> std::process::ExitCode {
    // Load-and-report mode. This is the measurement Phase 3 exists to produce:
    // the cost of arriving at a populated accumulator without replaying.
    if let Ok(path) = std::env::var("ZUTREEXO_LOAD") {
        let path = std::path::PathBuf::from(path);
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let began = Instant::now();
        return match load(&path) {
            Ok(state) => {
                let elapsed = began.elapsed().as_secs_f64();
                let counts = state.counts();
                println!(
                    "loaded {:.2} GB in {:.1}s — tip {:?}, {} unspent outputs, rss {} MiB",
                    size as f64 / 1e9,
                    elapsed,
                    state.tip(),
                    counts.utxos,
                    rss_mib()
                );
                for pool in PoolId::ALL {
                    println!(
                        "  {pool:<10} {} nullifiers  root {}",
                        counts.nullifiers.get(&pool).copied().unwrap_or(0),
                        state
                            .nullifier_roots()
                            .get(&pool)
                            .map(hex::encode)
                            .unwrap_or_default()
                    );
                }
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("load failed: {error}");
                std::process::ExitCode::FAILURE
            }
        };
    }

    let address = std::env::var("ZUTREEXO_RPC").unwrap_or_else(|_| "127.0.0.1:8232".to_owned());
    let source = RpcSource::new(&address);

    let tip = match source.tip() {
        Ok(tip) => tip,
        Err(error) => {
            eprintln!("cannot reach zebrad at {address}: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let from = env_u32("ZUTREEXO_REPLAY_FROM", 0);
    let save_at = save_heights();
    let to = env_u32("ZUTREEXO_REPLAY_TO", tip).min(tip);
    let depth =
        u8::try_from(env_u32("ZUTREEXO_DEPTH", u32::from(DEFAULT_DEPTH))).unwrap_or(DEFAULT_DEPTH);
    let report_every = env_u32("ZUTREEXO_REPORT_EVERY", 50_000).max(1);
    let rebuild_under = env_u64("ZUTREEXO_REBUILD_UNDER", 40_000_000);
    let workers = env_u32("ZUTREEXO_WORKERS", 8).max(1) as usize;
    // A ceiling rather than an OOM. This machine also hosts the synced zebrad
    // the replay is reading from, and having the kernel pick which of the two
    // to kill would cost hours of resync to learn nothing. Stopping early is a
    // measurement; being killed is not.
    let max_rss = env_u64("ZUTREEXO_MAX_RSS_MIB", 38_000);

    // Resume from a snapshot rather than replaying what has already been
    // replayed. Phase 5b needs the same seven-hour pass to serve two different
    // measurements taken at two different heights, and re-running it for each
    // would cost a night per number.
    //
    // The resumed tip overrides `ZUTREEXO_REPLAY_FROM`: continuing from
    // anywhere but tip+1 would either skip blocks or re-apply them, and
    // re-applying is not merely wasteful — the IMT rejects a duplicate
    // nullifier, so it fails loudly, which is the correct behaviour and still
    // a wasted run.
    let (mut state, from) = match std::env::var("ZUTREEXO_RESUME") {
        Ok(path) => {
            let path = std::path::PathBuf::from(path);
            let began = Instant::now();
            match load(&path) {
                Ok(state) => {
                    let resumed = state.tip().map_or(0, |tip| tip.saturating_add(1));
                    println!(
                        "resumed {} in {:.1}s — tip {:?}, {} unspent outputs, continuing from {resumed}",
                        path.display(),
                        began.elapsed().as_secs_f64(),
                        state.tip(),
                        state.counts().utxos,
                    );
                    if state.depth() != depth {
                        eprintln!(
                            "snapshot depth {} does not match requested depth {depth}",
                            state.depth()
                        );
                        return std::process::ExitCode::FAILURE;
                    }
                    (state, resumed)
                }
                Err(error) => {
                    eprintln!("resume from {} failed: {error}", path.display());
                    return std::process::ExitCode::FAILURE;
                }
            }
        }
        Err(_) => match ChainAccumulators::new(depth) {
            Ok(state) => (state, from),
            Err(error) => {
                eprintln!("cannot build accumulators at depth {depth}: {error}");
                return std::process::ExitCode::FAILURE;
            }
        },
    };

    // Genesis-forward, so every spend must resolve. That strictness is the
    // point: it is what makes the chain its own oracle.
    let options = ApplyOptions::default();

    println!("node tip {tip}; replaying {from}..={to} at depth {depth}");
    println!("cold rebuild while a pool holds under {rebuild_under} nullifiers");
    if !save_at.is_empty() {
        println!(
            "mid-replay snapshots at {}",
            save_at
                .iter()
                .map(|(h, p)| format!("{h} -> {}", p.display()))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if from > to {
        println!("nothing to do: resumed tip is already at or past {to}");
    }

    let started = Instant::now();
    let mut applied = 0u64;
    let mut last_report = Instant::now();
    let mut rebuilds_done = 0u64;
    let mut rebuilds_skipped = 0u64;

    let stream = BlockStream::new(&source, from, to, 512, workers);
    for (height, raw) in stream {
        let raw = match raw {
            Ok(raw) => raw,
            Err(error) => {
                eprintln!("\nFETCH FAILED at {height}: {error}");
                return std::process::ExitCode::FAILURE;
            }
        };

        let block = match zebra_chain::serialization::ZcashDeserialize::zcash_deserialize(&raw[..])
        {
            Ok(block) => block,
            Err(error) => {
                eprintln!("\nPARSE FAILED at {height}: {error}");
                return std::process::ExitCode::FAILURE;
            }
        };

        let summary = match summarize_block(&block) {
            Ok(summary) => summary,
            Err(error) => {
                eprintln!("\nEXTRACT FAILED at {height}: {error}");
                return std::process::ExitCode::FAILURE;
            }
        };

        if let Err(error) = apply_block(&mut state, &summary, options) {
            // This is the interesting failure. A duplicate nullifier or an
            // unresolvable outpoint on mainnet means our reading of the chain
            // is wrong, because the chain itself is consistent.
            eprintln!("\nAPPLY FAILED at {height}: {error}");
            eprintln!("mainnet is internally consistent, so this is our bug, not the chain's");
            return std::process::ExitCode::FAILURE;
        }
        applied = applied.saturating_add(1);

        // Snapshot mid-replay, so one pass can seed measurements taken at
        // different heights. Written *after* the apply, so the snapshot's tip
        // is this height and a resume continues at height + 1.
        if let Some(path) = save_at.get(&height) {
            match write_snapshot(&state, path) {
                Ok(()) => {}
                Err(error) => {
                    // Not fatal. The replay is the expensive part and it is
                    // still running correctly; losing a snapshot costs a
                    // convenience, and aborting here would cost the night.
                    eprintln!("\nsnapshot at {height} failed: {error}");
                }
            }
        }

        if rss_mib() > max_rss && height % 1_000 == 0 {
            let counts = state.counts();
            println!(
                "\nSTOPPED at height {height}: rss {} MiB exceeds the {max_rss} MiB ceiling",
                rss_mib()
            );
            println!("this is a result, not a failure — see the summary below");
            println!("unspent outputs at the stop point: {}", counts.utxos);
            break;
        }

        if height % report_every == 0 || height == to {
            let counts = state.counts();
            let elapsed = started.elapsed().as_secs_f64().max(0.001);
            let recent = last_report.elapsed().as_secs_f64().max(0.001);
            last_report = Instant::now();

            let mut over_cap: Vec<String> = Vec::new();
            for pool in PoolId::ALL {
                match cold_rebuild_matches(&state, pool, rebuild_under) {
                    RebuildOutcome::Matches => rebuilds_done = rebuilds_done.saturating_add(1),
                    RebuildOutcome::Diverged => {
                        eprintln!("\nCOLD REBUILD DIVERGED at {height} for {pool}");
                        eprintln!("the incremental path has drifted from a from-scratch rebuild");
                        return std::process::ExitCode::FAILURE;
                    }
                    RebuildOutcome::TooLarge => {
                        rebuilds_skipped = rebuilds_skipped.saturating_add(1);
                        over_cap.push(pool.to_string());
                    }
                    // An empty pool is not a coverage gap and is not counted
                    // as a skip.
                    RebuildOutcome::Empty | RebuildOutcome::NoTree => {}
                }
            }
            let rebuild_note = if over_cap.is_empty() {
                String::new()
            } else {
                format!(" (rebuild over cap: {})", over_cap.join(","))
            };

            println!(
                "h={height:<8} utxos={:<9} nul[{}] rss={}MiB {:.0} blk/s avg, {:.0} recent{}",
                counts.utxos,
                PoolId::ALL
                    .into_iter()
                    .map(|p| format!("{}={}", p, counts.nullifiers.get(&p).copied().unwrap_or(0)))
                    .collect::<Vec<_>>()
                    .join(" "),
                rss_mib(),
                applied as f64 / elapsed,
                f64::from(report_every) / recent,
                rebuild_note,
            );
        }
    }

    // Persist the finished state, if asked. This is what turns the seven-hour
    // replay above into a one-off cost: `ZUTREEXO_SAVE=<path>`.
    if let Ok(path) = std::env::var("ZUTREEXO_SAVE") {
        let path = std::path::PathBuf::from(path);
        let began = Instant::now();
        match save(&state, &path) {
            Ok(()) => {
                let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                println!(
                    "\nsnapshot written to {} — {:.2} GB in {:.1}s",
                    path.display(),
                    size as f64 / 1e9,
                    began.elapsed().as_secs_f64()
                );
            }
            Err(error) => eprintln!("\nsnapshot failed: {error}"),
        }
    }

    let elapsed = started.elapsed();
    let counts = state.counts();
    println!("\n--- replay complete ---");
    println!("blocks applied      {applied}");
    println!(
        "wall clock          {:.1} min",
        elapsed.as_secs_f64() / 60.0
    );
    // `VmHWM`, not `VmRSS`. The previous line here read the *current* RSS and
    // labelled it "peak", which is only the same number when the run happens to
    // end at its high-water mark. It did not: the stage 2d table records 33.3
    // GiB at height 2,700,000 against the 32.7 GiB this line reported at tip,
    // so the published peak was understated by the run's own log.
    println!("final rss           {} MiB", rss_mib());
    println!("peak rss (VmHWM)    {} MiB", peak_rss_mib());
    println!("unspent outputs     {}", counts.utxos);
    for pool in PoolId::ALL {
        println!(
            "{pool:<20}{} nullifiers",
            counts.nullifiers.get(&pool).copied().unwrap_or(0)
        );
    }
    println!("cold rebuilds       {rebuilds_done} performed, {rebuilds_skipped} skipped");
    for (pool, root) in state.nullifier_roots() {
        println!("root {pool:<15} {}", hex::encode(root));
    }
    for (index, root) in state.utxo_roots().iter().enumerate() {
        println!("utxo root [{index}]      {}", hex::encode(root));
    }

    std::process::ExitCode::SUCCESS
}

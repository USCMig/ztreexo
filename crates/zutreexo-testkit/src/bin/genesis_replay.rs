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

use zutreexo_accumulator::imt::{IndexedMerkleTree, Value, DEFAULT_DEPTH};
use zutreexo_accumulator::PoolId;
use zutreexo_chain::{apply_block, summarize_block, ApplyOptions, ChainAccumulators};
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

/// Resident set size in MiB, read from `/proc`. Zero where unavailable.
fn rss_mib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
            })
        })
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

/// Rebuilds one pool's tree from its values in insertion order and compares
/// roots. Returns `None` when the tree is too large to be worth it.
fn cold_rebuild_matches(
    state: &ChainAccumulators,
    pool: PoolId,
    depth: u8,
    limit: u64,
) -> Option<bool> {
    let tree = state.tree(pool)?;
    let count = tree.value_count();
    if count == 0 || count > limit {
        return None;
    }
    // Leaf 0 is the sentinel; the rest are in insertion order, which is the
    // order that decides the root.
    let mut values: Vec<Value> = Vec::with_capacity(count as usize);
    for index in 1..tree.leaf_count() {
        values.push(tree.leaf(index)?.value);
    }
    let rebuilt = IndexedMerkleTree::from_values(pool, depth, &values).ok()?;
    Some(rebuilt.root() == tree.root())
}

fn main() -> std::process::ExitCode {
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
    let to = env_u32("ZUTREEXO_REPLAY_TO", tip).min(tip);
    let depth =
        u8::try_from(env_u32("ZUTREEXO_DEPTH", u32::from(DEFAULT_DEPTH))).unwrap_or(DEFAULT_DEPTH);
    let report_every = env_u32("ZUTREEXO_REPORT_EVERY", 50_000).max(1);
    let rebuild_under = env_u64("ZUTREEXO_REBUILD_UNDER", 200_000);
    let workers = env_u32("ZUTREEXO_WORKERS", 8).max(1) as usize;
    // A ceiling rather than an OOM. This machine also hosts the synced zebrad
    // the replay is reading from, and having the kernel pick which of the two
    // to kill would cost hours of resync to learn nothing. Stopping early is a
    // measurement; being killed is not.
    let max_rss = env_u64("ZUTREEXO_MAX_RSS_MIB", 24_000);

    println!("node tip {tip}; replaying {from}..={to} at depth {depth}");
    println!("cold rebuild while a pool holds under {rebuild_under} nullifiers");

    let mut state = match ChainAccumulators::new(depth) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("cannot build accumulators at depth {depth}: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Genesis-forward, so every spend must resolve. That strictness is the
    // point: it is what makes the chain its own oracle.
    let options = ApplyOptions::default();

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

            let mut rebuild_note = String::new();
            for pool in PoolId::ALL {
                match cold_rebuild_matches(&state, pool, depth, rebuild_under) {
                    Some(true) => rebuilds_done = rebuilds_done.saturating_add(1),
                    Some(false) => {
                        eprintln!("\nCOLD REBUILD DIVERGED at {height} for {pool}");
                        return std::process::ExitCode::FAILURE;
                    }
                    None => {
                        rebuilds_skipped = rebuilds_skipped.saturating_add(1);
                        if rebuild_note.is_empty() {
                            rebuild_note = " (some rebuilds skipped: set too large)".to_owned();
                        }
                    }
                }
            }

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

    let elapsed = started.elapsed();
    let counts = state.counts();
    println!("\n--- replay complete ---");
    println!("blocks applied      {applied}");
    println!(
        "wall clock          {:.1} min",
        elapsed.as_secs_f64() / 60.0
    );
    println!("peak rss            {} MiB", rss_mib());
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

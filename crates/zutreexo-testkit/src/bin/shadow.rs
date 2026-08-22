//! Phase 5b: a compact state node shadowing a live `zebrad` at the chain tip.
//!
//! # What CLAUDE.md asks for, and what this actually is
//!
//! Phase 5 says to run the compact path *"behind a shadow-mode feature flag
//! against a normal Zebra node: both validate every block, results compared,
//! any disagreement is a hard failure and a loud log line. Never let the
//! accumulator path gate consensus during this phase."*
//!
//! **This is an external shadow, not an in-process one, and the difference is
//! worth stating rather than glossing.** A feature flag inside Zebra would mean
//! a patched `zebrad`, which is a much larger undertaking than this phase and
//! would put us in the business of maintaining a consensus node fork. What runs
//! here observes an unmodified `zebrad` over its RPC instead. The
//! never-gate-consensus requirement is satisfied trivially and uninterestingly:
//! this process cannot influence what Zebra accepts, because Zebra does not
//! know it exists.
//!
//! What is genuinely gained over the historical replays:
//!
//! 1. **Real reorgs.** `tests/reorg_fuzz.rs` ran 10⁶ reorgs, every one of them
//!    of our own construction, on chains we generated. Rollback has never met
//!    one it did not design. At tip they arrive on the chain's schedule.
//! 2. **Blocks nobody chose.** Fixtures were picked for being interesting.
//!    Tip blocks are whatever miners produce.
//! 3. **The parse oracle on every block.** Committed checkpoints cover four
//!    200-block slices; here `getblock` verbosity 2 is compared per block, so
//!    zebrad oracles the parse continuously rather than at sampled points.
//!
//! # The finding this run is built to expose
//!
//! A full node's reorg handling needs undo data — `StateDelta` carries the
//! deleted leaves *and their positions*, because Utreexo deletion is not
//! invertible (`docs/design.md` D18). A compact node needs none of it: its
//! entire state is a few hundred bytes, so it can simply keep the last N of
//! them and step back. This run holds that history and reports what it costs,
//! because "reorg handling is free for a compact node" is a claim in the
//! design's favour and should be measured rather than asserted.
//!
//! # Running
//!
//! Needs a bridge snapshot at or near tip — see `genesis_replay`'s
//! `ZUTREEXO_SAVE_AT` / `ZUTREEXO_SAVE`.
//!
//! ```text
//! ZUTREEXO_RESUME=/snap/tip.snap ZUTREEXO_SHADOW_BLOCKS=500 \
//!   cargo run --release -p zutreexo-testkit --bin shadow
//! ```
//!
//! Environment: `ZUTREEXO_RPC` (default `127.0.0.1:8232`), `ZUTREEXO_RESUME`
//! (required), `ZUTREEXO_SHADOW_BLOCKS` (default 500), `ZUTREEXO_DEPTH`,
//! `ZUTREEXO_POLL_SECS` (default 15), `ZUTREEXO_HISTORY` (compact states
//! retained for rollback, default 512), `ZUTREEXO_SHADOW_LOG` (JSONL path).

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::time::{Duration, Instant};

use zebra_chain::block::Block;
use zebra_chain::serialization::ZcashDeserialize;

use zutreexo_accumulator::imt::DEFAULT_DEPTH;
use zutreexo_accumulator::{CanonicalSerialize, PoolId};
use zutreexo_chain::{
    apply_and_prove, apply_block, load, summarize_block, ApplyOptions, BlockProofBundle,
    BlockSummary, ChainAccumulators,
};
use zutreexo_csn::CompactState;
use zutreexo_testkit::measure::{peak_rss_mib, rss_mib, Latencies};
use zutreexo_testkit::shadow::{find_fork, AppliedBlock, Fork};
use zutreexo_testkit::source::{BlockSource, RpcSource};

/// One block this run applied, and the compact state it produced.
///
/// The `hash` is what makes reorg detection possible: height alone does not
/// identify a block, and a follower tracking only heights would stack a
/// replacement block on top of the one it replaced.
struct Applied {
    height: u32,
    hash: String,
    /// The compact state *after* this block. A few hundred bytes, which is why
    /// keeping hundreds of them is affordable and a full node's equivalent is
    /// not.
    csn: CompactState,
}

fn env_u32(key: &str, fallback: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

/// Counts one block the way `zebrad`'s own JSON describes it.
///
/// Deliberately mirrors `scripts/capture_checkpoints.py`, field for field, so
/// the live check and the committed checkpoints are the same comparison. Each
/// field is an *independent* statement of a fact our deserializer extracts:
/// a JoinSplit reveals exactly two nullifiers, Sapling spends and outputs are
/// separate arrays, an Orchard or Ironwood action carries one nullifier, and a
/// `vin` bearing a `coinbase` key references no prior output.
fn node_counts(block: &serde_json::Value) -> BTreeMap<&'static str, u64> {
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let array = |tx: &serde_json::Value, key: &str| -> u64 {
        tx.get(key)
            .and_then(serde_json::Value::as_array)
            .map_or(0, |a| a.len() as u64)
    };
    let nested = |tx: &serde_json::Value, outer: &str| -> u64 {
        tx.get(outer)
            .and_then(|o| o.get("actions"))
            .and_then(serde_json::Value::as_array)
            .map_or(0, |a| a.len() as u64)
    };

    let empty = Vec::new();
    let txs = block
        .get("tx")
        .and_then(serde_json::Value::as_array)
        .unwrap_or(&empty);

    let mut transparent_spends = 0u64;
    let mut transparent_creates = 0u64;
    let (mut sprout, mut sapling, mut orchard, mut ironwood) = (0u64, 0u64, 0u64, 0u64);

    for tx in txs {
        sprout = sprout.saturating_add(array(tx, "vjoinsplit").saturating_mul(2));
        sapling = sapling.saturating_add(array(tx, "vShieldedSpend"));
        orchard = orchard.saturating_add(nested(tx, "orchard"));
        ironwood = ironwood.saturating_add(nested(tx, "ironwood"));

        if let Some(vin) = tx.get("vin").and_then(serde_json::Value::as_array) {
            for input in vin {
                if input.get("coinbase").is_none() {
                    transparent_spends = transparent_spends.saturating_add(1);
                }
            }
        }
        transparent_creates = transparent_creates.saturating_add(array(tx, "vout"));
    }

    counts.insert("transactions", txs.len() as u64);
    counts.insert("transparent_spends", transparent_spends);
    counts.insert("transparent_creates", transparent_creates);
    counts.insert("sprout_nullifiers", sprout);
    counts.insert("sapling_nullifiers", sapling);
    counts.insert("orchard_nullifiers", orchard);
    counts.insert("ironwood_nullifiers", ironwood);
    counts
}

/// The same counts as our parser sees them.
fn our_counts(summary: &BlockSummary) -> BTreeMap<&'static str, u64> {
    let pool = |p: PoolId| summary.nullifiers.get(&p).map_or(0, |v| v.len() as u64);
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    counts.insert("transactions", summary.transactions as u64);
    counts.insert(
        "transparent_spends",
        summary.transparent_spends.len() as u64,
    );
    counts.insert(
        "transparent_creates",
        summary.transparent_creates.len() as u64,
    );
    counts.insert("sprout_nullifiers", pool(PoolId::Sprout));
    counts.insert("sapling_nullifiers", pool(PoolId::Sapling));
    counts.insert("orchard_nullifiers", pool(PoolId::Orchard));
    counts.insert("ironwood_nullifiers", pool(PoolId::Ironwood));
    counts
}

fn main() -> std::process::ExitCode {
    let address = std::env::var("ZUTREEXO_RPC").unwrap_or_else(|_| "127.0.0.1:8232".to_owned());
    let want = env_u32("ZUTREEXO_SHADOW_BLOCKS", 500);
    let poll = u64::from(env_u32("ZUTREEXO_POLL_SECS", 15).max(1));
    let history_cap = env_u32("ZUTREEXO_HISTORY", 512).max(1) as usize;
    let depth =
        u8::try_from(env_u32("ZUTREEXO_DEPTH", u32::from(DEFAULT_DEPTH))).unwrap_or(DEFAULT_DEPTH);

    let Ok(snapshot) = std::env::var("ZUTREEXO_RESUME") else {
        eprintln!("ZUTREEXO_RESUME is required: a shadow run needs bridge state at tip.");
        eprintln!("Produce one with genesis_replay's ZUTREEXO_SAVE.");
        return std::process::ExitCode::FAILURE;
    };

    let source = RpcSource::new(&address);

    let began = Instant::now();
    let mut bridge = match load(std::path::Path::new(&snapshot)) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("resume from {snapshot} failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if bridge.depth() != depth {
        eprintln!(
            "snapshot depth {} does not match requested depth {depth}",
            bridge.depth()
        );
        return std::process::ExitCode::FAILURE;
    }
    println!(
        "loaded {snapshot} in {:.1}s — tip {:?}, {} unspent outputs, rss {} MiB",
        began.elapsed().as_secs_f64(),
        bridge.tip(),
        bridge.counts().utxos,
        rss_mib()
    );

    let mut csn = match CompactState::from_roots(
        depth,
        &bridge.utxo_roots(),
        bridge.utxos().leaves(),
        &bridge.imt_states(),
        bridge.tip(),
    ) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("cannot seed the compact node: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if csn.utxo_roots() != bridge.utxo_roots() || csn.nullifier_roots() != bridge.nullifier_roots()
    {
        eprintln!("the seeded compact node does not match the snapshot it came from");
        return std::process::ExitCode::FAILURE;
    }
    println!(
        "compact node seeded: {} B of state against the bridge's {} MiB resident",
        csn.to_bytes().len(),
        rss_mib()
    );

    // ---- how the bridge unwinds, and why not with `RollbackJournal` ----
    //
    // The obvious choice was the journal built in stage 2c. It is the wrong
    // tool *at tip*, and measurably so: `RollbackJournal::record` snapshots the
    // forest and clones the whole outpoint index, and a smoke run at height
    // 2,000 grew 14 MiB per block doing it. At tip that index holds 27.5M
    // entries at roughly 550 bytes each, so a single retained snapshot is on
    // the order of 15 GiB on top of the 33 GiB the state already occupies —
    // more than this machine has, for a path that may never fire.
    //
    // Instead the bridge unwinds by reloading the on-disk snapshot and
    // replaying forward to the fork point. That costs a ~21 s load and a few
    // hundred blocks of replay at ~1,500 blk/s, paid only when a reorg actually
    // happens, and costs nothing at all when none does.
    //
    // The asymmetry with the compact node is the point, and it gets sharper
    // under this scheme rather than softer: the full node reloads gigabytes and
    // replays; the compact node takes a few hundred bytes off a queue.
    let mut history: VecDeque<Applied> = VecDeque::new();

    let mut log = std::env::var("ZUTREEXO_SHADOW_LOG")
        .ok()
        .and_then(|path| std::fs::File::create(path).ok());

    let mut bridge_latency = Latencies::new();
    let mut csn_latency = Latencies::new();
    let mut validated = 0u32;
    // Blocks applied while already at the node's tip, i.e. genuinely waited
    // for. Distinguished from catch-up because they are different evidence: a
    // catch-up block is history the node already settled, and only a followed
    // block can expose a reorg. Reporting one total would let a run that
    // spent its whole budget catching up read as a tip-following run.
    let mut followed = 0u32;
    let mut reorgs = 0u32;
    let mut deepest_reorg = 0u32;
    let started = Instant::now();

    println!("\nfollowing tip for {want} blocks (catch-up not counted), polling every {poll}s\n");

    // **Counted in blocks followed at tip, not blocks validated.**
    //
    // A run resumed from a snapshot taken hours earlier starts well behind —
    // roughly 390 blocks after a seven-hour replay, at Zcash's 75 s spacing.
    // Counting those toward the target would spend most of the budget on
    // history the node had already settled, and settled history cannot expose
    // a reorg, which is most of the reason to follow the tip at all.
    //
    // Catch-up blocks are still applied, still compared against the bridge and
    // against zebrad's parse, and still reported. They are simply not what the
    // run is measured in.
    while followed < want {
        let our_tip = bridge.tip();
        let node_tip = match source.tip() {
            Ok(tip) => tip,
            Err(error) => {
                // A node that is briefly unreachable is not a divergence.
                // Treating it as one would abandon an overnight run over a
                // restarted container.
                eprintln!("tip query failed ({error}); retrying in {poll}s");
                std::thread::sleep(Duration::from_secs(poll));
                continue;
            }
        };

        // ---- reorg check, before extending ----
        //
        // Verify the block we last applied is still the block the node has at
        // that height. This is the only thing standing between a reorg and
        // silent permanent divergence.
        if let Some(tip) = our_tip {
            match source.block_hash(tip) {
                Ok(current) => {
                    let recorded = history.back().filter(|a| a.height == tip).map(|a| &a.hash);
                    if let Some(recorded) = recorded {
                        if *recorded != current {
                            reorgs = reorgs.saturating_add(1);
                            match unwind(
                                &source,
                                &snapshot,
                                depth,
                                &mut bridge,
                                &mut csn,
                                &mut history,
                            ) {
                                Ok(depth) => {
                                    deepest_reorg = deepest_reorg.max(depth);
                                    println!(
                                        "REORG #{reorgs}: unwound {depth} block(s) to height {:?}",
                                        bridge.tip()
                                    );
                                    continue;
                                }
                                Err(reason) => {
                                    eprintln!("\nREORG DEEPER THAN THIS RUN CAN UNWIND: {reason}");
                                    eprintln!("recovery only reaches back to the resumed snapshot");
                                    return std::process::ExitCode::FAILURE;
                                }
                            }
                        }
                    }
                }
                Err(error) => {
                    eprintln!("hash query at {tip} failed ({error}); retrying in {poll}s");
                    std::thread::sleep(Duration::from_secs(poll));
                    continue;
                }
            }
        }

        let next = our_tip.map_or(0, |tip| tip.saturating_add(1));
        if next > node_tip {
            std::thread::sleep(Duration::from_secs(poll));
            continue;
        }

        // ---- fetch and parse ----
        let raw = match source.raw_block(next) {
            Ok(raw) => raw,
            Err(error) => {
                eprintln!("fetch {next} failed ({error}); retrying in {poll}s");
                std::thread::sleep(Duration::from_secs(poll));
                continue;
            }
        };
        let block = match Block::zcash_deserialize(&raw[..]) {
            Ok(block) => block,
            Err(error) => {
                eprintln!("\nPARSE FAILED at {next}: {error}");
                return std::process::ExitCode::FAILURE;
            }
        };
        let summary = match summarize_block(&block) {
            Ok(summary) => summary,
            Err(error) => {
                eprintln!("\nEXTRACT FAILED at {next}: {error}");
                return std::process::ExitCode::FAILURE;
            }
        };
        let hash = match source.block_hash(next) {
            Ok(hash) => hash,
            Err(error) => {
                eprintln!("hash {next} failed ({error}); retrying in {poll}s");
                std::thread::sleep(Duration::from_secs(poll));
                continue;
            }
        };

        // ---- oracle: zebrad's own JSON, every block ----
        match source.block_json(next, 2) {
            Ok(json) => {
                let theirs = node_counts(&json);
                let ours = our_counts(&summary);
                if theirs != ours {
                    eprintln!("\nPARSE DISAGREEMENT WITH ZEBRAD at height {next}");
                    for (field, expected) in &theirs {
                        let actual = ours.get(field).copied().unwrap_or(0);
                        if actual != *expected {
                            eprintln!("  {field}: we say {actual}, zebrad says {expected}");
                        }
                    }
                    return std::process::ExitCode::FAILURE;
                }
            }
            Err(error) => {
                // Not fatal. The oracle is an extra, and losing it should not
                // end a run that is still validating correctly — but it must be
                // visible, or a silently-degraded run reads as a clean one.
                eprintln!("  (oracle unavailable at {next}: {error})");
            }
        }

        // ---- both sides apply ----
        let began_bridge = Instant::now();
        let applied = apply_and_prove(&mut bridge, &summary, ApplyOptions::default());
        // Held in a variable rather than re-read later. Calling `elapsed()` a
        // second time at log time measures from the same start instant to
        // *now*, so the JSONL was recording bridge-apply plus the codec plus
        // the compact verify plus the root comparisons — inflating the bridge
        // p99 by roughly 60% and its max from 33 ms to 53 ms against the
        // in-memory summary, which was right all along.
        let bridge_took = began_bridge.elapsed();
        bridge_latency.record(bridge_took);

        let (_outcome, bundle) = match applied {
            Ok(pair) => pair,
            Err(error) => {
                eprintln!("\nBRIDGE REJECTED BLOCK {next}: {error}");
                return std::process::ExitCode::FAILURE;
            }
        };

        let encoded = bundle.to_bytes();
        let received = match BlockProofBundle::from_bytes(&encoded) {
            Ok(bundle) => bundle,
            Err(error) => {
                eprintln!("\nBUNDLE WOULD NOT DECODE at {next}: {error}");
                return std::process::ExitCode::FAILURE;
            }
        };

        let began_csn = Instant::now();
        let verified = csn.apply_bundle(&summary, &received);
        let csn_took = began_csn.elapsed();
        csn_latency.record(csn_took);

        if let Err(error) = verified {
            eprintln!("\nCOMPACT NODE REJECTED BLOCK {next}: {error}");
            return std::process::ExitCode::FAILURE;
        }

        // ---- the comparison this run exists for ----
        if csn.utxo_roots() != bridge.utxo_roots() {
            eprintln!("\nTRANSPARENT ROOTS DIVERGED at height {next}");
            return std::process::ExitCode::FAILURE;
        }
        if csn.nullifier_roots() != bridge.nullifier_roots() {
            eprintln!("\nNULLIFIER ROOTS DIVERGED at height {next}");
            return std::process::ExitCode::FAILURE;
        }

        history.push_back(Applied {
            height: next,
            hash: hash.clone(),
            csn: csn.clone(),
        });
        while history.len() > history_cap {
            history.pop_front();
        }

        validated = validated.saturating_add(1);
        if next >= node_tip {
            followed = followed.saturating_add(1);
        }
        let state_bytes = csn.to_bytes().len();

        println!(
            "h={next} {} txs={} spends={} nul={} bundle={}B csn_state={}B rss={}MiB [{followed}/{want} at tip]",
            &hash[..16.min(hash.len())],
            summary.transactions,
            summary.transparent_spends.len(),
            summary.nullifier_count(),
            encoded.len(),
            state_bytes,
            rss_mib(),
        );

        if let Some(file) = log.as_mut() {
            let _ = writeln!(
                file,
                r#"{{"height":{next},"hash":"{hash}","txs":{},"spends":{},"nullifiers":{},"bundle_bytes":{},"block_bytes":{},"csn_state_bytes":{},"bridge_micros":{},"csn_micros":{}}}"#,
                summary.transactions,
                summary.transparent_spends.len(),
                summary.nullifier_count(),
                encoded.len(),
                raw.len(),
                state_bytes,
                bridge_took.as_micros(),
                csn_took.as_micros(),
            );
        }
    }

    // ---- report ----
    let elapsed = started.elapsed().as_secs_f64();
    let history_bytes: usize = history.iter().map(|a| a.csn.to_bytes().len()).sum();

    println!("\n--- shadow run complete ---");
    println!("blocks followed     {followed}  (at tip, waited for)");
    println!(
        "blocks validated    {validated}  (including {} of catch-up)",
        validated.saturating_sub(followed)
    );
    println!("wall clock          {:.1} min", elapsed / 60.0);
    println!("reorgs handled      {reorgs}");
    if reorgs > 0 {
        println!("deepest reorg       {deepest_reorg} block(s)");
    } else {
        // Said explicitly, because "0 reorgs" and "reorg handling verified"
        // look identical in a summary and are not the same claim.
        println!("                    (none occurred; the rollback path was not exercised)");
    }
    println!("final tip           {:?}", bridge.tip());
    println!();
    println!("compact node state  {} B", csn.to_bytes().len());
    println!(
        "rollback history    {} states, {history_bytes} B total",
        history.len()
    );
    println!(
        "                    the bridge's equivalent is reloading {} and replaying",
        snapshot
    );
    println!();
    for (label, latencies) in [
        ("bridge apply+prove", &bridge_latency),
        ("compact node verify", &csn_latency),
    ] {
        match latencies.summary() {
            Some(summary) => println!("{label:<20} {summary}"),
            None => println!("{label:<20} no samples"),
        }
    }
    println!();
    println!("peak rss (VmHWM)    {} MiB", peak_rss_mib());

    std::process::ExitCode::SUCCESS
}

/// Walks back to the deepest block whose hash the node still agrees with, and
/// unwinds both sides to it. Returns how many blocks were undone.
///
/// # Both sides, and they undo very differently
///
/// Utreexo deletion is not invertible (`docs/design.md` D18), so the bridge
/// cannot simply step backwards. It reloads the snapshot this run resumed from
/// and replays the common prefix — heights at or below the fork are unchanged
/// by definition, so refetching them from the node is safe.
///
/// The compact node takes an older state off a queue. No deltas, no positions,
/// no forest, no replay. That asymmetry is the measurement.
fn unwind(
    source: &RpcSource,
    snapshot: &str,
    depth: u8,
    bridge: &mut ChainAccumulators,
    csn: &mut CompactState,
    history: &mut VecDeque<Applied>,
) -> Result<u32, String> {
    // Fork detection is `zutreexo_testkit::shadow::find_fork`, which is a pure
    // walk over the history and is tested in `tests/shadow_fork.rs`. Keeping a
    // second copy of it here would leave the tested one decorative.
    let mut marks: VecDeque<AppliedBlock> = history
        .iter()
        .map(|a| AppliedBlock {
            height: a.height,
            hash: a.hash.clone(),
        })
        .collect();
    let fork = find_fork(&mut marks, |height| {
        source
            .block_hash(height)
            .map_err(|e| format!("hash query at {height}: {e}"))
    })?;

    let (target, undone) = match fork {
        Fork::None => return Ok(0),
        Fork::BeyondHistory { undone } => {
            return Err(format!(
                "unwound {undone} block(s) and ran out of history; the fork predates this run"
            ))
        }
        Fork::UnwindTo { target, undone } => (target, undone),
    };
    // Bring the real history (which carries the compact states) into line with
    // what the search decided.
    while history.back().is_some_and(|a| a.height > target) {
        history.pop_back();
    }

    // ---- the bridge: reload, then replay the common prefix ----
    let began = Instant::now();
    let mut restored =
        load(std::path::Path::new(snapshot)).map_err(|e| format!("reload {snapshot}: {e}"))?;
    let base = restored.tip().map_or(0, |tip| tip.saturating_add(1));
    if base > target.saturating_add(1) {
        return Err(format!(
            "snapshot is at {:?}, past the fork point {target}",
            restored.tip()
        ));
    }

    for height in base..=target {
        let raw = source
            .raw_block(height)
            .map_err(|e| format!("refetch {height}: {e}"))?;
        let block =
            Block::zcash_deserialize(&raw[..]).map_err(|e| format!("reparse {height}: {e}"))?;
        let summary = summarize_block(&block).map_err(|e| format!("reextract {height}: {e}"))?;
        apply_block(&mut restored, &summary, ApplyOptions::default())
            .map_err(|e| format!("reapply {height}: {e}"))?;
    }
    if restored.depth() != depth {
        return Err(format!(
            "reloaded snapshot depth {} does not match {depth}",
            restored.depth()
        ));
    }
    *bridge = restored;
    println!(
        "  bridge rebuilt to {target} in {:.1}s ({} blocks replayed)",
        began.elapsed().as_secs_f64(),
        target.saturating_sub(base).saturating_add(1),
    );

    // ---- the compact node: one clone off the queue ----
    let began_csn = Instant::now();
    match history.back() {
        Some(applied) => *csn = applied.csn.clone(),
        None => return Err("no compact state to restore".to_owned()),
    }
    println!(
        "  compact node rewound in {} us",
        began_csn.elapsed().as_micros()
    );

    // The invariant CLAUDE.md Phase 2 refuses to soften: byte-identical, not
    // equivalent. If the two sides disagree after unwinding, the rollback is
    // wrong and carrying on would measure a protocol that does not work.
    if csn.utxo_roots() != bridge.utxo_roots() || csn.nullifier_roots() != bridge.nullifier_roots()
    {
        return Err(format!(
            "after unwinding to {target} the two sides disagree - rollback is not byte-identical"
        ));
    }

    Ok(undone)
}

//! Phase 4a measurement: a compact state node kept in lockstep with a bridge
//! over real mainnet blocks, from genesis, reporting what the proofs cost.
//!
//! # What this answers
//!
//! CLAUDE.md Phase 5 asks for **bandwidth overhead from proofs** — the cost
//! side of the trade, and the number most likely to sink the design. Bitcoin's
//! Utreexo work saw roughly a quarter more download in early simulations.
//! Zcash's number is different and had to be measured rather than assumed.
//!
//! It also answers the batching question. CLAUDE.md Phase 4 asks for proof
//! aggregation across a block's inputs, on the grounds that their proofs share
//! internal nodes. In `rustreexo` a `Proof` is natively multi-target, so the
//! sharing is a property of the type rather than something layered on top; what
//! remained was to measure how much it actually saves. This reports the batched
//! size against the sum of one-proof-per-input for the same block.
//!
//! # Running it
//!
//! Needs a synced `zebrad` with RPC on 127.0.0.1:8232.
//!
//! ```text
//! ZUTREEXO_RPC=127.0.0.1:8232 ZUTREEXO_END=250000 \
//!   cargo run --release -p zutreexo-testkit --bin csn_replay
//! ```
//!
//! Every block is applied twice — once by a bridge holding full state, once by
//! a compact node holding roots — and the roots are compared after each. A
//! divergence stops the run and names the height, because a run that carried on
//! would report bandwidth for a protocol that does not work.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::time::Instant;

use zebra_chain::block::Block;
use zebra_chain::serialization::ZcashDeserialize;

use zutreexo_accumulator::imt::DEFAULT_DEPTH;
use zutreexo_accumulator::{CanonicalSerialize, UtxoLeaf};
use zutreexo_chain::{
    apply_and_prove, summarize_block, ApplyOptions, BlockProofBundle, ChainAccumulators,
};
use zutreexo_csn::CompactState;
use zutreexo_testkit::source::{BlockStream, RpcSource};

fn env_u32(key: &str, fallback: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

/// Running totals. Everything here is a byte count except the counters.
#[derive(Default)]
struct Totals {
    blocks: u64,
    block_bytes: u64,
    bundle_bytes: u64,
    spent_leaf_bytes: u64,
    utxo_proof_bytes: u64,
    insertion_bytes: u64,
    spends: u64,
    nullifiers: u64,
    /// Sum over blocks of one-proof-per-input encoded sizes, for the batching
    /// comparison. Only accumulated for blocks with at least two inputs, since
    /// a single-input block cannot demonstrate sharing.
    unbatched_bytes: u64,
    batched_bytes: u64,
    batchable_blocks: u64,
    /// Sibling hashes in nullifier proofs, and how many of them are the
    /// empty-subtree hash for their level.
    imt_siblings: u64,
    imt_empty_siblings: u64,
}

/// The empty-subtree hash at each level, for one pool.
///
/// A depth-40 tree holding a few million nullifiers is overwhelmingly empty:
/// above roughly `log2(leaf_count)` every sibling on a path is the canonical
/// hash of an empty subtree, which both sides can derive rather than transmit.
/// This measures how much of a proof is that derivable filler.
fn empty_ladder(pool: zutreexo_accumulator::PoolId, depth: u8) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(usize::from(depth));
    let mut empty = zutreexo_accumulator::hash::imt_empty_leaf(pool);
    for _ in 0..depth {
        out.push(empty);
        empty = zutreexo_accumulator::hash::imt_node(pool, &empty, &empty);
    }
    out
}

fn main() {
    let address = std::env::var("ZUTREEXO_RPC").unwrap_or_else(|_| "127.0.0.1:8232".to_string());
    let start = env_u32("ZUTREEXO_START", 0);
    let end = env_u32("ZUTREEXO_END", 100_000);
    let depth =
        u8::try_from(env_u32("ZUTREEXO_DEPTH", u32::from(DEFAULT_DEPTH))).unwrap_or(DEFAULT_DEPTH);
    let report_every = env_u32("ZUTREEXO_REPORT_EVERY", 25_000);
    // Off by default: it re-proves every input individually, which roughly
    // doubles the run.
    let measure_batching = std::env::var("ZUTREEXO_MEASURE_BATCHING").is_ok();

    println!("csn_replay: heights {start}..={end} against {address}, depth {depth}");

    let source = RpcSource::new(&address);
    let mut bridge = match ChainAccumulators::new(depth) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("bad depth {depth}: {error}");
            std::process::exit(2);
        }
    };
    let mut csn = match CompactState::new(depth) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("bad depth {depth}: {error}");
            std::process::exit(2);
        }
    };

    let mut totals = Totals::default();
    let began = Instant::now();

    for (height, fetched) in BlockStream::new(&source, start, end, 256, 8) {
        let raw = match fetched {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("height {height}: fetch failed: {error}");
                std::process::exit(1);
            }
        };
        let block = match Block::zcash_deserialize(&raw[..]) {
            Ok(block) => block,
            Err(error) => {
                eprintln!("height {height}: parse failed: {error}");
                std::process::exit(1);
            }
        };
        let summary = match summarize_block(&block) {
            Ok(summary) => summary,
            Err(error) => {
                eprintln!("height {height}: summarize failed: {error}");
                std::process::exit(1);
            }
        };

        // Before applying: what would one proof per input have cost? This has
        // to happen here, not after. `apply_and_prove` deletes the spent
        // leaves, and a leaf that is gone cannot be proved individually — the
        // first version of this measured afterwards and silently skipped every
        // block, reporting "no block had two or more provable inputs" over a
        // range containing 1.6 million spends.
        let unbatched = if measure_batching {
            unbatched_proof_bytes(&bridge, &summary)
        } else {
            None
        };

        let (_, bundle) = match apply_and_prove(&mut bridge, &summary, ApplyOptions::default()) {
            Ok(pair) => pair,
            Err(error) => {
                eprintln!("height {height}: bridge failed: {error}");
                std::process::exit(1);
            }
        };

        // Through the wire encoding, as a real client would receive it.
        let encoded = bundle.to_bytes();
        let received = match BlockProofBundle::from_bytes(&encoded) {
            Ok(bundle) => bundle,
            Err(error) => {
                eprintln!("height {height}: bundle would not decode: {error}");
                std::process::exit(1);
            }
        };

        if let Err(error) = csn.apply_bundle(&summary, &received) {
            eprintln!("height {height}: compact node rejected the block: {error}");
            std::process::exit(1);
        }

        if csn.utxo_roots() != bridge.utxo_roots() {
            eprintln!("height {height}: TRANSPARENT ROOTS DIVERGED");
            std::process::exit(1);
        }
        if csn.nullifier_roots() != bridge.nullifier_roots() {
            eprintln!("height {height}: NULLIFIER ROOTS DIVERGED");
            std::process::exit(1);
        }

        if let Some(unbatched) = unbatched {
            totals.unbatched_bytes += unbatched;
            totals.batched_bytes +=
                zutreexo_accumulator::proof::encode_utxo_proof(&bundle.utxo_proof).len() as u64;
            totals.batchable_blocks += 1;
        }
        accumulate(&mut totals, &raw, &bundle, &encoded, depth);

        if report_every > 0 && height % report_every == 0 && height > start {
            report(&totals, height, began.elapsed().as_secs_f64(), false);
        }
    }

    report(&totals, end, began.elapsed().as_secs_f64(), true);
}

/// Sum of one-proof-per-input encoded sizes, or `None` when the block has
/// fewer than two resolvable inputs and so cannot demonstrate sharing.
fn unbatched_proof_bytes(
    bridge: &ChainAccumulators,
    summary: &zutreexo_chain::BlockSummary,
) -> Option<u64> {
    let leaves: Vec<UtxoLeaf> = summary
        .transparent_spends
        .iter()
        .filter_map(|outpoint| bridge.utxo(outpoint).cloned())
        .collect();
    if leaves.len() < 2 {
        return None;
    }
    let mut total = 0u64;
    for leaf in &leaves {
        let proof = bridge.utxos().prove(&[UtxoLeaf::hash(leaf)]).ok()?;
        total += zutreexo_accumulator::proof::encode_utxo_proof(&proof).len() as u64;
    }
    Some(total)
}

fn accumulate(
    totals: &mut Totals,
    raw: &[u8],
    bundle: &BlockProofBundle,
    encoded: &[u8],
    depth: u8,
) {
    totals.blocks += 1;
    totals.block_bytes += raw.len() as u64;
    totals.bundle_bytes += encoded.len() as u64;
    totals.spends += bundle.spent.len() as u64;
    totals.nullifiers += bundle.insertion_count() as u64;

    // Component breakdown, so the dominant term is visible rather than
    // inferred. These are the payload sizes, excluding the few bytes of framing
    // the whole-bundle figure includes.
    for leaf in &bundle.spent {
        // txid + vout + height + coinbase flag + value + length-prefixed script
        totals.spent_leaf_bytes += 32 + 4 + 4 + 1 + 8 + 4 + leaf.script_pubkey.len() as u64;
    }
    totals.utxo_proof_bytes +=
        zutreexo_accumulator::proof::encode_utxo_proof(&bundle.utxo_proof).len() as u64;
    for (pool, proofs) in &bundle.insertions {
        let ladder = empty_ladder(*pool, depth);
        for proof in proofs {
            totals.insertion_bytes += proof.to_bytes().len() as u64;
            for path in [&proof.low_leaf_siblings, &proof.new_leaf_siblings] {
                for (level, sibling) in path.iter().enumerate() {
                    totals.imt_siblings += 1;
                    if ladder.get(level) == Some(sibling) {
                        totals.imt_empty_siblings += 1;
                    }
                }
            }
        }
    }
}

fn report(totals: &Totals, height: u32, elapsed: f64, final_report: bool) {
    let blocks = totals.blocks.max(1);
    let overhead = if totals.block_bytes == 0 {
        0.0
    } else {
        100.0 * totals.bundle_bytes as f64 / totals.block_bytes as f64
    };

    if !final_report {
        println!(
            "  h={height:>8}  {:.0} blk/s  bundle {:>6} B/blk  overhead {overhead:>5.1}%",
            blocks as f64 / elapsed.max(1e-9),
            totals.bundle_bytes / blocks,
        );
        return;
    }

    println!("\n=== csn_replay, through height {height} ===");
    println!("blocks              {}", totals.blocks);
    println!("elapsed             {elapsed:.1}s");
    println!("transparent spends  {}", totals.spends);
    println!("nullifiers          {}", totals.nullifiers);
    println!();
    println!("block bytes         {:>14}", totals.block_bytes);
    println!("bundle bytes        {:>14}", totals.bundle_bytes);
    println!("proof overhead      {overhead:>13.1}%  (bundle as a share of block download)");
    println!();
    println!("bundle composition, as a share of bundle bytes:");
    let bundle = totals.bundle_bytes.max(1);
    let share = |x: u64| 100.0 * x as f64 / bundle as f64;
    println!(
        "  spent leaf contents {:>12} B  {:>5.1}%",
        totals.spent_leaf_bytes,
        share(totals.spent_leaf_bytes)
    );
    println!(
        "  utreexo proofs      {:>12} B  {:>5.1}%",
        totals.utxo_proof_bytes,
        share(totals.utxo_proof_bytes)
    );
    println!(
        "  nullifier proofs    {:>12} B  {:>5.1}%",
        totals.insertion_bytes,
        share(totals.insertion_bytes)
    );

    if totals.imt_siblings > 0 {
        let empty_share = 100.0 * totals.imt_empty_siblings as f64 / totals.imt_siblings as f64;
        println!();
        println!("nullifier proof paths:");
        println!("  sibling hashes      {:>12}", totals.imt_siblings);
        println!(
            "  empty-subtree       {:>12}  {empty_share:>5.1}%  (derivable, need not be sent)",
            totals.imt_empty_siblings
        );
        println!(
            "  compressible        {:>12} B of {} B in nullifier proofs",
            totals.imt_empty_siblings * 32,
            totals.insertion_bytes
        );
    }

    if totals.batchable_blocks > 0 {
        let saving =
            100.0 * (1.0 - totals.batched_bytes as f64 / totals.unbatched_bytes.max(1) as f64);
        println!();
        println!(
            "batching, over {} blocks with 2+ inputs:",
            totals.batchable_blocks
        );
        println!("  one proof per input {:>12} B", totals.unbatched_bytes);
        println!("  one batched proof   {:>12} B", totals.batched_bytes);
        println!("  saving              {saving:>12.1}%");
    } else {
        println!("\nbatching: no block in this range had two or more provable inputs.");
    }
}

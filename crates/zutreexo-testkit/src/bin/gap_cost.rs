//! Phase 5a, the headline measurement: **what does it cost a wallet to learn
//! its notes were spent, as a function of how long it has been offline?**
//!
//! CLAUDE.md Phase 5 states the claim: today a wallet scans every block's
//! revealed nullifiers, which is linear in the gap since last sync; an IMT
//! non-membership proof is `O(log n)` per note, independent of chain length.
//! Plot both against gap length and the crossover is the finding.
//!
//! # Two framings, because the honest answer depends on which question is asked
//!
//! **Framing A — the wallet only wants spend status.** It knows its notes and
//! wants to know whether any has been spent: a watch-only balance, or the check
//! before attempting a spend. Scanning means pulling every nullifier revealed in
//! the gap. Proofs mean one non-membership proof per note. This is the
//! comparison CLAUDE.md describes, and the accumulator should win it decisively
//! because one side is `O(gap)` and the other is `O(1)`.
//!
//! **Framing B — the wallet is doing a full sync.** It also wants to find notes
//! *received* during the gap, which means trial decryption, which means pulling
//! the compact block for every block in the gap regardless. The nullifiers are
//! already inside that download. So proofs do not replace the download — they
//! are *added* to it, and the saving is only the nullifier fraction of bytes the
//! wallet was going to fetch anyway.
//!
//! Framing B is the one that matters for "how long does my wallet take to
//! sync", and §2.2 already warns that trial decryption dominates it and no
//! accumulator changes that. Reporting only framing A would be choosing the
//! flattering question.
//!
//! # A caveat that belongs on the result, not in a footnote
//!
//! A non-membership proof is only meaningful against a **trusted root**, and
//! nothing commits accumulator roots to the Zcash chain today — that is the
//! Phase 7 hard fork. So a wallet takes the root from the bridge, and a wallet
//! that trusts a bridge for the root could just as well ask "is this nullifier
//! spent?" and be told, with no accumulator involved.
//!
//! The proof is not worthless without the fork: roots are a few hundred bytes,
//! so a wallet can fetch them from several independent bridges and compare,
//! reducing the trust to "not all of them are colluding" rather than "this one
//! is honest". But that is a weaker claim than trustlessness and the numbers
//! below do not establish it.
//!
//! # Running
//!
//! ```text
//! ZUTREEXO_RPC=127.0.0.1:8232 ZUTREEXO_GAP_BLOCKS=50000 \
//!   ZUTREEXO_GAP_END=1700000 \
//!   cargo run --release -p zutreexo-testkit --bin gap_cost
//! ```

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::time::Instant;

use zebra_chain::block::Block;
use zebra_chain::serialization::ZcashDeserialize;

use zutreexo_accumulator::imt::{IndexedMerkleTree, Value, DEFAULT_DEPTH};
use zutreexo_accumulator::{CanonicalSerialize, PoolId};
use zutreexo_testkit::source::{BlockSource, BlockStream, RpcSource};

/// Bytes a compact block spends per shielded output, by pool.
///
/// From the `CompactBlock` shape light wallets actually receive (ZIP 307 and
/// `lightwalletd`'s protocol): enough of each output to attempt trial
/// decryption, and the nullifier of each spend.
///
/// Sapling: `cmu` 32 + `ephemeralKey` 32 + first 52 bytes of `encCiphertext`.
/// Orchard and Ironwood actions carry the same three plus the nullifier, but
/// the nullifier is counted separately below so it can be reported on its own.
const COMPACT_OUTPUT_BYTES: u64 = 32 + 32 + 52;
/// A nullifier as it appears on the wire.
const NULLIFIER_BYTES: u64 = 32;
/// Each transaction in a compact block carries its txid and index.
const COMPACT_TX_BYTES: u64 = 32 + 4;

fn env_u32(key: &str, fallback: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

/// Per-block costs, kept in block order so any suffix is a gap.
struct Sampled {
    nullifier_bytes: Vec<u64>,
    compact_bytes: Vec<u64>,
    nullifiers: Vec<u64>,
}

fn main() {
    let address = std::env::var("ZUTREEXO_RPC").unwrap_or_else(|_| "127.0.0.1:8232".to_string());
    let span = env_u32("ZUTREEXO_GAP_BLOCKS", 50_000);
    let depth =
        u8::try_from(env_u32("ZUTREEXO_DEPTH", u32::from(DEFAULT_DEPTH))).unwrap_or(DEFAULT_DEPTH);

    let source = RpcSource::new(&address);
    let tip = match source.tip() {
        Ok(height) => height,
        Err(error) => {
            eprintln!("cannot reach zebrad at {address}: {error}");
            std::process::exit(1);
        }
    };
    // The window ends at tip unless told otherwise.
    //
    // **`ZUTREEXO_GAP_END` exists because the original could only measure one
    // era, and `docs/design.md` D32 is about exactly that mistake.** The
    // transparent-bandwidth figure in Phase 4b was measured over heights
    // 0-150,000 and read as a property of the design; measured at tip it
    // inverted, and it nearly decided what this project ships. D32's closing
    // note flags this binary's own headline as needing the same check, since
    // Zcash's history is not homogeneous — a pre-NU5 window reveals almost no
    // nullifiers per block, and the comparison against scanning turns on that
    // rate.
    let end = env_u32("ZUTREEXO_GAP_END", tip).min(tip);
    let start = end.saturating_sub(span);

    println!("gap_cost: sampling heights {start}..={end} (node tip is {tip})");
    println!("proof depth {depth}\n");

    let sampled = sample(&source, start, end);
    let proof = measure_proof_size(depth);
    report(&sampled, &proof, depth, start, end);
}

/// Walks the range and records what each block would cost a scanning wallet.
fn sample(source: &RpcSource, start: u32, end: u32) -> Sampled {
    let began = Instant::now();
    let mut out = Sampled {
        nullifier_bytes: Vec::new(),
        compact_bytes: Vec::new(),
        nullifiers: Vec::new(),
    };

    for (height, fetched) in BlockStream::new(source, start, end, 128, 8) {
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
        let summary = match zutreexo_chain::summarize_block(&block) {
            Ok(summary) => summary,
            Err(error) => {
                eprintln!("height {height}: summarize failed: {error}");
                std::process::exit(1);
            }
        };

        let nullifiers: u64 = PoolId::ALL
            .into_iter()
            .map(|pool| summary.nullifiers_for(pool).len() as u64)
            .sum();
        let outputs: u64 = PoolId::ALL
            .into_iter()
            .map(|pool| summary.commitments.get(&pool).copied().unwrap_or(0) as u64)
            .sum();

        let nullifier_bytes = nullifiers * NULLIFIER_BYTES;
        out.nullifier_bytes.push(nullifier_bytes);
        out.nullifiers.push(nullifiers);
        out.compact_bytes.push(
            nullifier_bytes
                + outputs * COMPACT_OUTPUT_BYTES
                + summary.transactions as u64 * COMPACT_TX_BYTES,
        );

        if height % 10_000 == 0 && height > start {
            eprintln!(
                "  h={height} ({:.0} blk/s)",
                out.nullifier_bytes.len() as f64 / began.elapsed().as_secs_f64().max(1e-9)
            );
        }
    }
    out
}

/// What a non-membership proof actually costs, measured rather than derived.
struct ProofSize {
    /// What a bridge actually sends: the sparse encoding, with the derivable
    /// empty-subtree siblings replaced by a presence bitmap. Every crossover
    /// below is computed from this.
    encoded: u64,
    /// What it cost before Phase 4b, kept so the saving stays visible.
    dense: u64,
    leaves: u64,
}

fn measure_proof_size(depth: u8) -> ProofSize {
    // The tree must hold the number of nullifiers the pool actually holds.
    //
    // This used to build 2^16 leaves, justified by a comment reading "2^16
    // keeps the build fast while putting the occupied levels well below the
    // depth, which is the regime the whole chain is in". That reasoning is
    // wrong, and it understated every ratio this tool reports by 45%.
    //
    // The sparse encoding omits siblings equal to the empty-subtree hash. How
    // many siblings are *non*-empty is `log2(occupied leaves)` — it does not
    // depend on how far occupancy sits below `depth`. So the proof grows 32
    // bytes per doubling of the set, measured:
    //
    // | occupied | sparse proof |
    // |---|---|
    // | 65,536 (2^16)     | 637 B |
    // | 1,000,000 (2^20)  | 733 B |
    // | 8,000,000 (2^23)  | 829 B |
    // | 50,392,547 (2^25.6) | 925 B |
    //
    // Orchard holds 50,392,547 (`docs/benchmarks.md`), so 637 B was a figure
    // for a pool 768x smaller than the one being claimed about.
    //
    // Overridable because the right count is per pool: Ironwood's 70,380
    // genuinely is a 2^16-scale tree, and its proofs genuinely are ~637 B.
    let count: u32 = env_u32("ZUTREEXO_PROOF_TREE_LEAVES", 50_392_547);
    let pool = PoolId::Orchard;
    let values: Vec<Value> = (1..=count)
        .map(|n| {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&n.to_le_bytes());
            bytes[31] = 0x01;
            Value::from_bytes(bytes)
        })
        .collect();

    let tree = match IndexedMerkleTree::from_values_bulk(pool, depth, &values) {
        Ok(tree) => tree,
        Err(error) => {
            eprintln!("could not build the sample tree: {error}");
            std::process::exit(1);
        }
    };

    // A value that is absent: the wallet's own note nullifier, unspent.
    let mut absent = [0u8; 32];
    absent[..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    absent[31] = 0x01;
    let proof = match tree.prove_non_membership(Value::from_bytes(absent)) {
        Ok(proof) => proof,
        Err(error) => {
            eprintln!("could not prove non-membership: {error}");
            std::process::exit(1);
        }
    };

    // The dense form: what a proof cost before Phase 4b, kept as the baseline.
    let dense = proof.to_bytes().len() as u64;

    // The sparse form, measured rather than projected: this is what a bridge
    // actually puts on the wire now.
    let sparse = zutreexo_accumulator::proof::NonMembershipResponse {
        pool,
        depth,
        height: 0,
        proof,
    }
    .to_bytes()
    .len() as u64;

    ProofSize {
        encoded: sparse,
        dense,
        leaves: u64::from(count),
    }
}

/// Sum of the last `take` entries — the cost of a gap of that many blocks
/// ending at the tip. Uses `get` rather than a slice index because the caller
/// derives `take` from a gap length that may exceed the sample.
fn suffix_sum(values: &[u64], take: usize) -> u64 {
    let from = values.len().saturating_sub(take);
    values.get(from..).map(|s| s.iter().sum()).unwrap_or(0)
}

fn report(sampled: &Sampled, proof: &ProofSize, depth: u8, start: u32, tip: u32) {
    let blocks = sampled.nullifier_bytes.len() as u64;
    let total_nullifiers: u64 = sampled.nullifiers.iter().sum();
    let total_nullifier_bytes: u64 = sampled.nullifier_bytes.iter().sum();
    let total_compact: u64 = sampled.compact_bytes.iter().sum();

    println!("\n=== sampled {blocks} blocks, heights {start}..={tip} ===");
    println!("nullifiers revealed   {total_nullifiers}");
    println!(
        "  per block            {:.1}",
        total_nullifiers as f64 / blocks.max(1) as f64
    );
    println!("nullifier bytes       {total_nullifier_bytes}");
    println!("compact-block bytes   {total_compact}");
    println!(
        "  nullifiers are       {:.1}% of a compact-block sync",
        100.0 * total_nullifier_bytes as f64 / total_compact.max(1) as f64
    );

    println!(
        "\n=== non-membership proof, depth {depth}, tree of {} leaves ===",
        proof.leaves
    );
    println!("sparse (on the wire)  {} bytes", proof.encoded);
    println!(
        "dense (pre-4b)        {} bytes  -> {:.1}% saved",
        proof.dense,
        100.0 * (1.0 - proof.encoded as f64 / proof.dense.max(1) as f64)
    );

    // Suffix sums: the cost of a gap of G blocks ending at the tip.
    let gaps: [u64; 7] = [10, 100, 1_000, 10_000, 50_000, 100_000, 400_000];
    let wallets: [u64; 3] = [1, 10, 100];

    println!("\n=== FRAMING A: the wallet only wants spend status ===");
    println!("Scanning is O(gap). Proofs are O(notes), flat in gap.\n");
    print!(
        "{:>10} {:>12} {:>14}",
        "gap blocks", "nullifiers", "scan bytes"
    );
    for w in wallets {
        print!("{:>14}", format!("{w} notes"));
    }
    println!();
    for gap in gaps {
        let taken = (gap.min(blocks)) as usize;
        let scanned = suffix_sum(&sampled.nullifier_bytes, taken);
        let counted = suffix_sum(&sampled.nullifiers, taken);
        let note = if gap > blocks { " *" } else { "" };
        print!(
            "{:>10} {:>12} {:>14}",
            format!("{gap}{note}"),
            counted,
            scanned
        );
        for w in wallets {
            let proofs = w * proof.encoded;
            print!(
                "{:>14}",
                if scanned > proofs {
                    format!("proofs {:.1}x", scanned as f64 / proofs as f64)
                } else {
                    format!("scan {:.1}x", proofs as f64 / scanned.max(1) as f64)
                }
            );
        }
        println!();
    }
    if gaps.iter().any(|g| *g > blocks) {
        println!("\n* gap exceeds the sampled range; the row is the whole sample, not the gap.");
    }

    // Crossover: where scan bytes overtake proof bytes.
    println!("\ncrossover, at the sampled rate:");
    let rate = total_nullifier_bytes as f64 / blocks.max(1) as f64;
    for w in wallets {
        let proofs = (w * proof.encoded) as f64;
        println!(
            "  {w:>3} notes: proofs win beyond a gap of {:.0} blocks (~{:.1} hours at 75s/block)",
            proofs / rate.max(1e-9),
            proofs / rate.max(1e-9) * 75.0 / 3600.0
        );
    }

    println!("\n=== FRAMING B: the wallet is doing a full sync ===");
    println!("Trial decryption for received notes needs the compact blocks anyway,");
    println!("so the nullifiers come along for free and proofs are an addition.\n");
    for gap in gaps {
        let taken = (gap.min(blocks)) as usize;
        let compact = suffix_sum(&sampled.compact_bytes, taken);
        let nullifiers = suffix_sum(&sampled.nullifier_bytes, taken);
        let note = if gap > blocks { " *" } else { "" };
        println!(
            "  gap {:>8}: compact sync {:>12} B, of which nullifiers {:>11} B ({:.1}%)",
            format!("{gap}{note}"),
            compact,
            nullifiers,
            100.0 * nullifiers as f64 / compact.max(1) as f64
        );
        for w in wallets {
            let saved = nullifiers as i64;
            let added = (w * proof.encoded) as i64;
            let net = added - saved;
            println!(
                "      {w:>3} notes: drop nullifiers, add proofs -> {}{} B",
                if net > 0 { "+" } else { "" },
                net
            );
        }
    }
}

//! Phase 6: what does it cost a bridge to answer proof requests?
//!
//! CLAUDE.md Phase 6 asks for an explicit denial-of-service analysis, naming
//! one scenario: *"cost to a bridge node of a peer requesting proofs for every
//! UTXO"*. This measures the unit cost against real tip state and extrapolates,
//! rather than reasoning about it.
//!
//! Two costs are separated because they are paid by different resources and
//! defended differently:
//!
//! * **Transparent inclusion proofs** — a walk of the forest per outpoint. CPU
//!   on the single serving thread.
//! * **Nullifier non-membership proofs** — a walk of one indexed Merkle tree.
//!   Also CPU, but `O(depth)` rather than `O(log n)` in the set, so its cost is
//!   flat where the transparent side's is not.
//!
//! # Running
//!
//! ```text
//! ZUTREEXO_RESUME=~/zutreexo-snapshots/tip.snap \
//!   cargo run --release -p zutreexo-testkit --bin dos_cost
//! ```

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::time::Instant;

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::proof::NonMembershipResponse;
use zutreexo_accumulator::{CanonicalSerialize, PoolId, UtxoLeaf};
use zutreexo_chain::load;
use zutreexo_testkit::measure::{peak_rss_mib, rss_mib, Latencies};

fn env_u32(key: &str, fallback: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

fn main() -> std::process::ExitCode {
    let Ok(path) = std::env::var("ZUTREEXO_RESUME") else {
        eprintln!("ZUTREEXO_RESUME is required: a cost measured on an empty forest is not a cost.");
        return std::process::ExitCode::FAILURE;
    };
    let samples = env_u32("ZUTREEXO_SAMPLES", 2_000) as usize;

    let began = Instant::now();
    let state = match load(std::path::Path::new(&path)) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("load {path} failed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let counts = state.counts();
    println!(
        "loaded {path} in {:.1}s — tip {:?}, {} unspent outputs, rss {} MiB",
        began.elapsed().as_secs_f64(),
        state.tip(),
        counts.utxos,
        rss_mib()
    );

    // ---- transparent inclusion proofs ----
    //
    // Sampled from the live index rather than generated, so the walk lengths
    // are the real distribution and not a uniform guess.
    let index = state.utxo_index_for_test();
    if index.is_empty() {
        eprintln!("the snapshot holds no transparent outputs");
        return std::process::ExitCode::FAILURE;
    }
    // Evenly spaced rather than random: deterministic, and it spans the whole
    // index instead of clustering (CLAUDE.md §5 rule 5).
    let stride = (index.len() / samples.max(1)).max(1);

    let mut utxo_latency = Latencies::new();
    let mut utxo_bytes = 0u64;
    let mut proved = 0u64;
    for (_, leaf) in index.iter().step_by(stride).take(samples) {
        let hash = UtxoLeaf::hash(leaf);
        let began = Instant::now();
        let proof = state.utxos().prove(&[hash]);
        utxo_latency.record(began.elapsed());
        if let Ok(proof) = proof {
            utxo_bytes += zutreexo_accumulator::proof::encode_utxo_proof(&proof).len() as u64;
            proved += 1;
        }
    }

    // ---- nullifier non-membership proofs ----
    let mut imt_latency = Latencies::new();
    let mut imt_bytes = 0u64;
    let mut absent_proved = 0u64;
    for pool in PoolId::ALL {
        let Some(tree) = state.tree(pool) else {
            continue;
        };
        for n in 0..(samples / PoolId::ALL.len()).max(1) {
            // A value no real nullifier will collide with, so this measures the
            // absence path — the one a wallet actually asks for.
            let mut bytes = [0xEEu8; 32];
            bytes[..8].copy_from_slice(&(n as u64).to_le_bytes());
            let value = Value::from_bytes(bytes);

            let began = Instant::now();
            let proof = tree.prove_non_membership(value);
            imt_latency.record(began.elapsed());
            if let Ok(proof) = proof {
                // Through the response wrapper, which is what a client
                // actually receives — the sparse encoding lives there (D28),
                // so measuring the bare proof would overstate the wire cost.
                let response = NonMembershipResponse {
                    pool,
                    depth: state.depth(),
                    height: state.tip().unwrap_or(0),
                    proof,
                };
                imt_bytes += response.to_bytes().len() as u64;
                absent_proved += 1;
            }
        }
    }

    // ---- report ----
    let line = |label: &str, l: &Latencies| match l.summary() {
        Some(s) => println!("  {label:<28} {s}"),
        None => println!("  {label:<28} no samples"),
    };

    println!("\n=== per-proof cost at tip ===");
    line("transparent inclusion", &utxo_latency);
    line("nullifier non-membership", &imt_latency);
    println!(
        "  mean proof size            utxo {} B, nullifier {} B",
        utxo_bytes / proved.max(1),
        imt_bytes / absent_proved.max(1),
    );

    // Extrapolation. Uses the mean rather than the p50 deliberately: an
    // attacker sends the whole distribution, not the median of it.
    let utxo_mean_us = utxo_latency.summary().map_or(0, |s| s.mean_micros);
    let total_secs = (utxo_mean_us as f64 * counts.utxos as f64) / 1e6;
    let total_bytes = (utxo_bytes as f64 / proved.max(1) as f64) * counts.utxos as f64;

    println!("\n=== proving every UTXO, the Phase 6 scenario ===");
    println!("  unspent outputs            {}", counts.utxos);
    println!(
        "  serial CPU                 {:.0} s  ({:.2} h)",
        total_secs,
        total_secs / 3600.0
    );
    println!("  bytes served               {:.2} GB", total_bytes / 1e9);
    println!(
        "  at the default 600 req/min it takes an attacker {:.1} h of *allowed* requests",
        counts.utxos as f64 / 600.0 / 60.0
    );
    println!(
        "\n  The bridge is single-threaded (docs/design.md D27), so that CPU is\n  \
         not shared — it is the whole service, queued. Rate limiting is the\n  \
         defence that matters here; a proof-size cap does not help, because\n  \
         each individual proof is small and legitimate."
    );
    println!("\npeak rss (VmHWM)             {} MiB", peak_rss_mib());
    std::process::ExitCode::SUCCESS
}

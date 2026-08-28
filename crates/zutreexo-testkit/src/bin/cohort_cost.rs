//! What a private spend-status query actually costs.
//!
//! `docs/design.md` D35 left one privacy mitigation standing — reveal a `b`-bit
//! prefix instead of a nullifier, and settle membership locally from the cohort
//! that comes back — and estimated it at "roughly 760 × 631 B ≈ 480 KB", which
//! is one leaf's proof multiplied by the cohort size. That estimate ignores the
//! sharing between the cohort's Merkle paths.
//!
//! This measures the real number, so the viability question is settled with
//! bytes rather than arithmetic.
//!
//! # What is real here and what is modelled
//!
//! **Real:** the tree, the cohort selection, the path deduplication, and the
//! wire encoding. Every byte reported comes from `CohortResponse::to_bytes` on
//! a cohort taken from an actual `IndexedMerkleTree` at production depth 40.
//!
//! **Modelled:** the nullifier *values*. Real nullifiers are hash outputs and
//! so uniform over the 256-bit space, which is the only property cohort sizes
//! and path scatter depend on — a seeded uniform draw is statistically
//! identical for this purpose and does not require a synced node. Insertion
//! order is likewise independent of value, which is exactly the property that
//! makes a value range non-contiguous in the tree.
//!
//! # Usage
//!
//! ```text
//! ZUTREEXO_COHORT_N=1000000 cargo run --release --bin cohort_cost
//! ZUTREEXO_COHORT_N=50392547 ZUTREEXO_COHORT_SAMPLES=200 cargo run --release --bin cohort_cost
//! ```
//!
//! `N` defaults to a size that builds in seconds. Mainnet's Orchard pool is
//! 50,392,547 (`docs/benchmarks.md`); that run needs roughly 15 GB and tens of
//! minutes, so it is opt-in.

use std::collections::BTreeSet;
use std::env;
use std::time::Instant;

use zutreexo_accumulator::cohort::{verify_cohort, PrefixRange};
use zutreexo_accumulator::imt::{IndexedMerkleTree, Value};
use zutreexo_accumulator::pool::PoolId;
use zutreexo_accumulator::proof::{CanonicalSerialize, NonMembershipResponse};

/// Production depth (`docs/design.md` D3).
const DEPTH: u8 = 40;
const POOL: PoolId = PoolId::Orchard;
const HEIGHT: u32 = 3_455_225;

/// The prefix widths worth reporting. Below 8 the cohort is a large fraction of
/// the pool; above 24 it is a single leaf and the query names the value.
const WIDTHS: &[u8] = &[8, 12, 16, 20, 24];

/// xorshift64*, so the corpus is reproducible with no dependency and no
/// system time — CLAUDE.md §5 rule 5.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn next_value(&mut self) -> Value {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            let take = chunk.len().min(word.len());
            if let (Some(dst), Some(src)) = (chunk.get_mut(..take), word.get(..take)) {
                dst.copy_from_slice(src);
            }
        }
        // Zero is the sentinel and cannot be inserted. Astronomically unlikely,
        // handled anyway so the tool is total.
        if bytes.iter().all(|b| *b == 0) {
            bytes[31] = 1;
        }
        Value::from_bytes(bytes)
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}

/// Mean and the largest observation, which is what a size cap has to be set
/// against.
struct Summary {
    mean: f64,
    max: u64,
}

fn summarize(samples: &[u64]) -> Summary {
    if samples.is_empty() {
        return Summary { mean: 0.0, max: 0 };
    }
    let total: u128 = samples.iter().map(|s| u128::from(*s)).sum();
    Summary {
        mean: total as f64 / samples.len() as f64,
        max: samples.iter().copied().max().unwrap_or(0),
    }
}

fn human_bytes(bytes: f64) -> String {
    if bytes >= 1_048_576.0 {
        format!("{:.2} MB", bytes / 1_048_576.0)
    } else if bytes >= 1024.0 {
        format!("{:.1} KB", bytes / 1024.0)
    } else {
        format!("{bytes:.0} B")
    }
}

fn main() {
    let n = env_usize("ZUTREEXO_COHORT_N", 250_000);
    let samples = env_usize("ZUTREEXO_COHORT_SAMPLES", 64);
    let seed = env_usize("ZUTREEXO_COHORT_SEED", 0x5eed_1234) as u64;

    println!("cohort_cost — pool {POOL:?}, depth {DEPTH}, n = {n}, {samples} samples per width");
    println!("values are seeded uniform draws; nullifiers are hash outputs, so this is the real distribution\n");

    let mut rng = Rng(seed | 1);
    let started = Instant::now();
    let mut values: Vec<Value> = Vec::with_capacity(n);
    for _ in 0..n {
        values.push(rng.next_value());
    }
    println!(
        "generated {n} values in {:.1}s",
        started.elapsed().as_secs_f64()
    );

    let started = Instant::now();
    let tree = match IndexedMerkleTree::from_values_bulk(POOL, DEPTH, &values) {
        Ok(tree) => tree,
        Err(error) => {
            eprintln!("could not build the tree: {error}");
            std::process::exit(1);
        }
    };
    println!(
        "built a {}-leaf tree in {:.1}s\n",
        tree.value_count(),
        started.elapsed().as_secs_f64()
    );

    // The thing being replaced: one non-membership proof for one named value.
    // Measured rather than quoted, so the comparison is against this build.
    let baseline = {
        let mut probe = Rng(seed ^ 0xabcd);
        let mut sizes = Vec::new();
        for _ in 0..samples {
            let value = probe.next_value();
            if let Ok(proof) = tree.prove_non_membership(value) {
                sizes.push(
                    NonMembershipResponse {
                        pool: POOL,
                        depth: DEPTH,
                        height: HEIGHT,
                        proof,
                    }
                    .to_bytes()
                    .len() as u64,
                );
            }
        }
        summarize(&sizes)
    };
    println!(
        "baseline — one non-membership proof, value revealed: {:.0} B mean, {} B max",
        baseline.mean, baseline.max
    );
    println!("           this is the query D35 says a wallet should not make\n");

    println!(
        "{:>5}  {:>10}  {:>10}  {:>11}  {:>11}  {:>9}  {:>8}",
        "bits", "cohort k", "nodes", "encoded", "naive k×base", "dedup", "vs base"
    );
    println!("{}", "-".repeat(76));

    for bits in WIDTHS {
        let mut probe = Rng(seed ^ (u64::from(*bits) << 32) ^ 0x1357);
        let mut leaf_counts = Vec::new();
        let mut node_counts = Vec::new();
        let mut encoded = Vec::new();
        let mut verified = 0usize;

        for _ in 0..samples {
            let target = probe.next_value();
            let Ok(range) = PrefixRange::covering(target, *bits) else {
                continue;
            };
            let Ok(proof) = tree.prove_prefix_cohort(range) else {
                continue;
            };

            leaf_counts.push(proof.leaf_count() as u64);
            node_counts.push(proof.node_count() as u64);

            // Verify a handful rather than all of them: the fold is the
            // expensive part and correctness is covered by the unit tests. What
            // this guards against is the measurement drifting away from proofs
            // that actually work.
            if verified < 4 {
                if verify_cohort(&tree.root(), &proof).is_ok() {
                    verified += 1;
                } else {
                    eprintln!("a cohort at bits={bits} did not fold to the root");
                    std::process::exit(1);
                }
            }

            encoded.push(proof.at_height(HEIGHT).to_bytes().len() as u64);
        }

        let k = summarize(&leaf_counts);
        let nodes = summarize(&node_counts);
        let size = summarize(&encoded);
        let naive = k.mean * baseline.mean;
        let dedup = if naive > 0.0 {
            1.0 - (size.mean / naive)
        } else {
            0.0
        };
        let vs_base = if baseline.mean > 0.0 {
            size.mean / baseline.mean
        } else {
            0.0
        };

        println!(
            "{:>5}  {:>10.1}  {:>10.0}  {:>11}  {:>11}  {:>8.1}%  {:>7.0}×",
            bits,
            k.mean,
            nodes.mean,
            human_bytes(size.mean),
            human_bytes(naive),
            dedup * 100.0,
            vs_base
        );
    }

    println!(
        "\ncohort k includes the predecessor leaf, which is a witness rather than a candidate:"
    );
    println!("the anonymity set is k − 1.");
    println!("\"dedup\" is the saving against sending each cohort leaf its own full proof —");
    println!("the naive figure D35 estimated with.");

    // Worst case matters more than the mean for a size cap and for D34's rate
    // limiter, so report the tail separately rather than burying it.
    let widest = WIDTHS.first().copied().unwrap_or(8);
    if let Ok(range) = PrefixRange::covering(Rng(seed ^ 0x99).next_value(), widest) {
        if let Ok(proof) = tree.prove_prefix_cohort(range) {
            let distinct_levels: BTreeSet<u8> =
                proof.nodes.keys().map(|(level, _)| *level).collect();
            println!(
                "\nat bits={widest}: {} leaves, {} nodes across {} of {DEPTH} levels",
                proof.leaf_count(),
                proof.node_count(),
                distinct_levels.len()
            );
        }
    }
}

//! Can every pool actually deliver the target anonymity set, and at what cost?
//!
//! `docs/design.md` D37 raised this as the finding most likely to decide the
//! whole approach, and did so on arithmetic rather than measurement:
//!
//! > At 16 bits an Ironwood query names a single note. Reaching `k ≈ 760` there
//! > means a prefix so wide it pulls 1.1% of the pool — and the entire Ironwood
//! > nullifier set is only 2.25 MB, so shipping the whole thing is competitive
//! > with any cohort large enough to hide in.
//!
//! That reasoning fixed the prefix width and asked what anonymity fell out. The
//! question is the other way round: **fix the anonymity target and ask what the
//! prefix and the cost have to be.** A pool with few nullifiers does not need a
//! narrow prefix, it needs a *wide* one — and a wide prefix over a small pool
//! is cheap precisely because the pool is small.
//!
//! Against each pool's real nullifier count this measures, at the chosen target
//! of `k = 12,298` (D38):
//!
//! * the widest prefix that still yields the target;
//! * what that cohort costs on the wire, measured, not projected;
//! * what shipping the pool's entire nullifier set would cost instead;
//! * which of the two a bridge should actually serve.
//!
//! # Usage
//!
//! ```text
//! cargo run --release --bin pool_cohorts
//! ZUTREEXO_TARGET_K=50000 cargo run --release --bin pool_cohorts
//! ```
//!
//! Orchard dominates the runtime and memory: roughly 6 GB and a minute. The
//! other three together are noise.

use std::env;
use std::time::Instant;

use zutreexo_accumulator::cohort::PrefixRange;
use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::pool::PoolId;
use zutreexo_accumulator::proof::CanonicalSerialize;
use zutreexo_accumulator::sorted::{self, SortedTree};

/// Real mainnet counts, `docs/benchmarks.md` Phase 0 at tip 2026-08-12.
const POOLS: &[(PoolId, u64)] = &[
    (PoolId::Orchard, 50_392_547),
    (PoolId::Sapling, 2_129_852),
    (PoolId::Sprout, 1_547_198),
    (PoolId::Ironwood, 70_380),
];

/// A nullifier on the wire in a whole-set download: the value, nothing else.
const NULLIFIER_BYTES: u64 = 32;

const HEIGHT: u32 = 3_455_225;

/// xorshift64*, seeded per pool. No system time, no dependency.
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
        if bytes.iter().all(|b| *b == 0) {
            bytes[31] = 1;
        }
        Value::from_bytes(bytes)
    }
}

fn human(bytes: f64) -> String {
    if bytes >= 1_048_576.0 {
        format!("{:.2} MB", bytes / 1_048_576.0)
    } else if bytes >= 1024.0 {
        format!("{:.1} KB", bytes / 1024.0)
    } else {
        format!("{bytes:.0} B")
    }
}

/// The widest prefix whose expected cohort still reaches `target`.
///
/// Expected cohort at `b` bits over `n` values is `n / 2^b`, so the answer is
/// `floor(log2(n / target))`. Zero means even a one-bit prefix cannot reach the
/// target and the whole pool is the only cohort large enough.
fn widest_prefix(n: u64, target: u64) -> u8 {
    if target == 0 || n < target {
        return 0;
    }
    let mut bits = 0u8;
    while n / (1u64 << (bits + 1)) >= target && bits < 31 {
        bits = bits.saturating_add(1);
    }
    bits
}

fn main() {
    let target: u64 = env::var("ZUTREEXO_TARGET_K")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(12_298);
    let samples: usize = env::var("ZUTREEXO_COHORT_SAMPLES")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(16);

    println!("pool_cohorts — target anonymity set k = {target}, {samples} samples per pool");
    println!("values are seeded uniform draws; nullifiers are hash outputs\n");

    println!(
        "{:>9}  {:>11}  {:>5}  {:>10}  {:>11}  {:>11}  {:>9}",
        "pool", "nullifiers", "bits", "members", "cohort", "whole set", "serve"
    );
    println!("{}", "-".repeat(80));

    for (pool, count) in POOLS {
        let bits = widest_prefix(*count, target);
        let whole_set = (*count * NULLIFIER_BYTES) as f64;

        if bits == 0 {
            // Even one bit splits the pool below the target, so no prefix
            // cohort can hide a note among `target` others. The whole set is
            // the only honest answer, and for a pool this small it is cheap.
            println!(
                "{:>9?}  {:>11}  {:>5}  {:>10}  {:>11}  {:>11}  {:>9}",
                pool,
                count,
                "—",
                "—",
                "n/a",
                human(whole_set),
                "whole set"
            );
            continue;
        }

        let started = Instant::now();
        let mut rng = Rng(0x5eed_0000u64.wrapping_add(u64::from(pool.code())) | 1);
        let mut values: Vec<Value> = Vec::with_capacity(*count as usize);
        for _ in 0..*count {
            values.push(rng.next_value());
        }
        values.sort_unstable();
        values.dedup();

        let tree = match SortedTree::from_sorted_values(*pool, HEIGHT, values) {
            Ok(tree) => tree,
            Err(error) => {
                eprintln!("could not build {pool:?}: {error}");
                std::process::exit(1);
            }
        };

        let mut probe = Rng(0xc0ffee ^ u64::from(pool.code()) | 1);
        let mut members = 0u64;
        let mut encoded = 0u64;
        let mut taken = 0u64;
        let mut checked = false;

        for _ in 0..samples {
            let target_value = probe.next_value();
            let Ok(range) = PrefixRange::covering(target_value, bits) else {
                continue;
            };
            let Ok(cohort) = tree.prove_prefix_cohort(range) else {
                continue;
            };
            if !checked {
                // Fold one, so the bytes being reported belong to a proof that
                // works. A size measured off a broken proof is worse than none.
                match sorted::verify_cohort(&tree.root(), &cohort) {
                    Ok(_) => checked = true,
                    Err(error) => {
                        eprintln!("{pool:?} cohort did not fold: {error}");
                        std::process::exit(1);
                    }
                }
            }
            members = members.saturating_add(cohort.member_count() as u64);
            encoded = encoded.saturating_add(cohort.to_bytes().len() as u64);
            taken = taken.saturating_add(1);
        }

        let mean_members = members as f64 / taken.max(1) as f64;
        let mean_encoded = encoded as f64 / taken.max(1) as f64;
        let serve = if mean_encoded < whole_set {
            "cohort"
        } else {
            "whole set"
        };

        println!(
            "{:>9?}  {:>11}  {:>5}  {:>10.0}  {:>11}  {:>11}  {:>9}  ({:.0}s)",
            pool,
            count,
            bits,
            mean_members,
            human(mean_encoded),
            human(whole_set),
            serve,
            started.elapsed().as_secs_f64()
        );
    }

    println!("\n\"bits\" is the widest prefix whose expected cohort still reaches the target,");
    println!("so a smaller pool gets a wider prefix rather than a smaller anonymity set.");
    println!("\"whole set\" is every nullifier in the pool at 32 bytes — the alternative a");
    println!("bridge can always fall back to, and the ceiling on what a cohort should cost.");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]

    use super::*;

    #[test]
    fn the_widest_prefix_is_the_last_one_that_still_reaches_the_target() {
        // Each pool's answer, checked against the arithmetic rather than
        // against the measurement it produces.
        for (n, target, want) in [
            (50_392_547u64, 12_298u64, 12u8),
            (2_129_852, 12_298, 7),
            (1_547_198, 12_298, 6),
            (70_380, 12_298, 2),
        ] {
            let bits = widest_prefix(n, target);
            assert_eq!(bits, want, "n={n}");
            assert!(
                n / (1u64 << bits) >= target,
                "n={n}: {bits} bits must reach the target"
            );
            assert!(
                n / (1u64 << (bits + 1)) < target,
                "n={n}: {} bits must overshoot, or {bits} was not the widest",
                bits + 1
            );
        }
    }

    #[test]
    fn a_pool_smaller_than_the_target_gets_no_prefix_at_all() {
        // Zero means no prefix can hide a note among `target` others, so the
        // whole set is the only honest answer. Returning 1 here would quietly
        // serve half a pool while claiming the target had been met.
        assert_eq!(widest_prefix(5_000, 12_298), 0);
        assert_eq!(widest_prefix(12_297, 12_298), 0);
        // Exactly the target fits in one bucket, which is the whole pool.
        assert_eq!(widest_prefix(12_298, 12_298), 0);
        assert_eq!(widest_prefix(24_596, 12_298), 1);
    }

    #[test]
    fn a_zero_target_does_not_loop_or_divide_by_zero() {
        assert_eq!(widest_prefix(50_392_547, 0), 0);
    }
}

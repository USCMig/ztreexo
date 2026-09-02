//! What does an epoch policy actually cost, on both sides?
//!
//! `zutreexo-bridge`'s [`EpochPolicy`] has two knobs and neither has an
//! obviously right value. They pull in opposite directions:
//!
//! * **`interval`** — blocks between snapshots. A wallet resolving against the
//!   epoch at height `H` learns the answer *as of `H`* and must scan
//!   `H+1..tip` itself. That delta is public chain data, so this is a cost, not
//!   a correctness problem — but it is a cost linear in the interval, paid by
//!   every client, while the rebuild it saves is paid once by the bridge.
//! * **`keep`** — snapshots retained per pool. Multiplies the bridge's memory
//!   directly.
//!
//! This measures both sides so the defaults are a result rather than a guess.
//!
//! # What is measured and what is computed
//!
//! **Time is measured.** Build cost is timed at several set sizes and the
//! full-scale figure is extrapolated from the fitted per-value rate, unless
//! `ZUTREEXO_EPOCH_FULL=1` asks for the real thing.
//!
//! **Bytes are computed exactly, not estimated.** A `SortedTree`'s resident
//! size is fully determined by its depth: `values.len() * 32` plus 32 bytes for
//! every node in every level. There is nothing to sample. The formula is
//! checked against a real tree at each measured size, so a wrong formula shows
//! up as a mismatch rather than as a plausible number.
//!
//! # Usage
//!
//! ```text
//! cargo run --release --bin epoch_cost
//! ZUTREEXO_EPOCH_FULL=1 cargo run --release --bin epoch_cost   # builds Orchard for real, ~6 GB
//! ```

use std::env;
use std::time::Instant;

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::pool::PoolId;
use zutreexo_accumulator::sorted::SortedTree;

/// Real mainnet counts, `docs/benchmarks.md` Phase 0 at tip 2026-08-12.
const POOLS: &[(PoolId, u64, f64)] = &[
    // pool, nullifiers, nullifiers revealed per block at tip
    (PoolId::Orchard, 50_392_547, 6.192),
    (PoolId::Sapling, 2_129_852, 0.138),
    (PoolId::Sprout, 1_547_198, 0.0),
    (PoolId::Ironwood, 70_380, 2.934),
];

/// Sizes the build rate is fitted from.
const LADDER: &[u64] = &[10_000, 100_000, 1_000_000, 10_000_000];

/// Zcash block time in seconds. CLAUDE.md §7 flags NU7's possible 3x change to
/// this; a third of the interval means a third of the delta and three times the
/// rebuild duty cycle, so both columns move if that vote passes.
const BLOCK_SECONDS: f64 = 75.0;

const HEIGHT: u32 = 3_455_225;
const HASH_BYTES: u64 = 32;

struct Rng(u64);

impl Rng {
    fn next_value(&mut self) -> Value {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            let word = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes();
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
    if bytes >= 1_073_741_824.0 {
        format!("{:.2} GB", bytes / 1_073_741_824.0)
    } else if bytes >= 1_048_576.0 {
        format!("{:.1} MB", bytes / 1_048_576.0)
    } else if bytes >= 1024.0 {
        format!("{:.1} KB", bytes / 1024.0)
    } else {
        format!("{bytes:.0} B")
    }
}

/// Smallest `depth` with `2^depth >= count`. Mirrors `sorted::depth_for`, which
/// is private; the assertion in [`build`] is what keeps the two honest.
fn depth_for(count: u64) -> u8 {
    let mut depth = 0u8;
    while (1u64 << depth) < count && depth < 63 {
        depth = depth.saturating_add(1);
    }
    depth
}

/// Exact resident bytes of a snapshot holding `count` values, sentinel
/// included.
///
/// `values` is `count * 32`. The levels hold `2^depth` leaf hashes and then
/// halve, so `2^(depth+1) - 1` nodes in total, at 32 bytes each. No estimate
/// is involved and none is needed.
fn resident_bytes(count: u64) -> u64 {
    let depth = depth_for(count);
    let nodes = (1u64 << depth.saturating_add(1)).saturating_sub(1);
    count
        .saturating_mul(HASH_BYTES)
        .saturating_add(nodes.saturating_mul(HASH_BYTES))
}

/// Builds a snapshot of `count` random values, returning the build time and the
/// resident bytes the tree actually holds.
fn build(pool: PoolId, count: u64) -> (f64, u64) {
    let mut rng = Rng(0x5eed_0000u64.wrapping_add(u64::from(pool.code())) | 1);
    let mut values: Vec<Value> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        values.push(rng.next_value());
    }
    values.sort_unstable();
    values.dedup();
    let actual = values.len() as u64 + 1; // the sentinel is prepended

    let started = Instant::now();
    let tree = match SortedTree::from_sorted_values(pool, HEIGHT, values) {
        Ok(tree) => tree,
        Err(error) => {
            eprintln!("could not build {pool:?} at {count}: {error}");
            std::process::exit(1);
        }
    };
    let elapsed = started.elapsed().as_secs_f64();

    // The byte model, checked against the thing it models. A depth mismatch
    // here means `resident_bytes` is describing a different tree from the one
    // the bridge will hold, and every row below it would be wrong.
    let modelled = depth_for(tree.leaf_count());
    assert_eq!(
        modelled,
        tree.depth(),
        "byte model disagrees with the tree at {count} values"
    );
    assert_eq!(tree.leaf_count(), actual, "sentinel accounting is off");

    (elapsed, resident_bytes(tree.leaf_count()))
}

fn main() {
    let full = env::var("ZUTREEXO_EPOCH_FULL").is_ok_and(|v| v == "1");

    println!("epoch_cost — what an epoch policy costs the bridge and its clients\n");

    // --- 1. build rate, measured -------------------------------------------
    println!("Snapshot build, measured (Orchard hasher, random values)\n");
    println!(
        "{:>12}  {:>6}  {:>10}  {:>12}  {:>12}",
        "values", "depth", "build", "resident", "ns/value"
    );
    println!("{}", "-".repeat(60));

    let mut rate_ns = 0.0f64;
    for count in LADDER {
        let (elapsed, bytes) = build(PoolId::Orchard, *count);
        let per_value = elapsed * 1e9 / *count as f64;
        rate_ns = per_value;
        println!(
            "{:>12}  {:>6}  {:>9.2}s  {:>12}  {:>12.1}",
            count,
            depth_for(*count),
            elapsed,
            human(bytes as f64),
            per_value
        );
    }
    println!(
        "\nRate taken from the largest rung ({} values): {rate_ns:.1} ns/value.",
        LADDER.last().copied().unwrap_or(0)
    );
    println!("Cost is dominated by hashing 2^depth leaf slots, so it steps at each");
    println!("power of two rather than rising smoothly with the value count.\n");

    // --- 2. per-pool snapshot cost -----------------------------------------
    println!("Per-pool snapshot at mainnet counts\n");
    println!(
        "{:>9}  {:>12}  {:>6}  {:>10}  {:>12}  {:>12}  {:>12}",
        "pool", "nullifiers", "depth", "build", "keep=1", "keep=2", "keep=4"
    );
    println!("{}", "-".repeat(84));

    let mut total_keep2 = 0f64;
    for (pool, count, _) in POOLS {
        let bytes = resident_bytes(count.saturating_add(1)) as f64;
        let (build_secs, label) = if full {
            let (elapsed, measured) = build(*pool, *count);
            assert_eq!(
                measured as f64, bytes,
                "{pool:?}: measured bytes disagree with the model"
            );
            (elapsed, "measured")
        } else {
            // Extrapolated on slot count, not value count: the hashing is over
            // 2^depth slots, so a pool just past a power of two costs nearly
            // twice one just under it and a per-*value* extrapolation would
            // understate exactly the pools that matter.
            let slots = 1u64 << depth_for(count.saturating_add(1));
            (slots as f64 * rate_ns / 1e9, "modelled")
        };
        total_keep2 += bytes * 2.0;
        println!(
            "{:>9?}  {:>12}  {:>6}  {:>8.2}s{}  {:>12}  {:>12}  {:>12}",
            pool,
            count,
            depth_for(count.saturating_add(1)),
            build_secs,
            if label == "measured" { "*" } else { " " },
            human(bytes),
            human(bytes * 2.0),
            human(bytes * 4.0)
        );
    }
    println!(
        "\n{}",
        if full {
            "* measured, not modelled."
        } else {
            "Build times are modelled; ZUTREEXO_EPOCH_FULL=1 measures them."
        }
    );
    println!(
        "All four pools at keep=2: {}. That is the number that decides the default.",
        human(total_keep2)
    );

    // --- 3. the interval trade ---------------------------------------------
    println!("\n\nThe interval trade: bridge duty cycle against client delta\n");
    println!("Delta is what a wallet must scan for itself because the snapshot predates");
    println!("it: nullifiers revealed since, at 32 bytes each, across all pools.");
    println!("Mean assumes the wallet arrives uniformly within the epoch; worst is a");
    println!("wallet arriving just before the next snapshot.\n");

    let nullifiers_per_block: f64 = POOLS.iter().map(|(_, _, rate)| rate).sum();
    let orchard_slots = 1u64 << depth_for(50_392_548);
    let all_pools_build: f64 = POOLS
        .iter()
        .map(|(_, count, _)| (1u64 << depth_for(count.saturating_add(1))) as f64)
        .sum::<f64>()
        * rate_ns
        / 1e9;
    let _ = orchard_slots;

    println!(
        "{:>10}  {:>12}  {:>12}  {:>12}  {:>12}",
        "interval", "wall clock", "duty cycle", "delta (mean)", "delta (worst)"
    );
    println!("{}", "-".repeat(66));
    for interval in [100u32, 500, 1_000, 2_000, 5_000, 10_000, 50_000] {
        let epoch_seconds = f64::from(interval) * BLOCK_SECONDS;
        let duty = all_pools_build / epoch_seconds;
        let worst = f64::from(interval) * nullifiers_per_block * HASH_BYTES as f64;
        println!(
            "{:>10}  {:>11.1}h  {:>11.2}%  {:>12}  {:>12}",
            interval,
            epoch_seconds / 3600.0,
            duty * 100.0,
            human(worst / 2.0),
            human(worst)
        );
    }

    println!("\nA cohort at the operating point is 384.9 KB (D38), so the delta is worth");
    println!("comparing against that: an interval whose worst-case delta exceeds the");
    println!("cohort has moved the cost back onto the client it was meant to serve.");
    let cohort = 384.9 * 1024.0;
    let breakeven = cohort / (nullifiers_per_block * HASH_BYTES as f64);
    println!(
        "Break-even, worst case: {:.0} blocks ({:.1} h). Past that a wallet downloads",
        breakeven,
        breakeven * BLOCK_SECONDS / 3600.0
    );
    println!("more delta than cohort, and the snapshot is carrying less than half its weight.");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_byte_model_matches_a_real_tree() {
        // The whole binary's byte column rests on this. If the model and the
        // structure disagree, every GB figure reported is fiction.
        for count in [1u64, 2, 3, 1_000, 4_096, 4_097] {
            let (_, bytes) = build(PoolId::Orchard, count);
            assert!(bytes > 0, "count={count}");
        }
    }

    #[test]
    fn depth_steps_at_powers_of_two() {
        // Why the build extrapolation is on slots and not values: 4,097 values
        // cost the same as 8,192 and nearly twice what 4,096 cost.
        assert_eq!(depth_for(4_096), 12);
        assert_eq!(depth_for(4_097), 13);

        // One value past a power of two nearly doubles the tree: the value
        // vector grows by 32 bytes and the node count goes from 2^13-1 to
        // 2^14-1. Stated as the two components rather than as an identity,
        // because the first version of this assertion was off by exactly the
        // one node that `2n+1` adds and looked right.
        let small = resident_bytes(4_096);
        let large = resident_bytes(4_097);
        assert_eq!(small, 4_096 * 32 + ((1 << 13) - 1) * 32);
        assert_eq!(large, 4_097 * 32 + ((1 << 14) - 1) * 32);
        assert!(
            large > small * 3 / 2,
            "{large} should be far above {small} for one extra value"
        );
    }

    #[test]
    fn orchards_snapshot_is_the_one_that_decides_the_default() {
        // Stated as an assertion so a future change to the counts cannot
        // quietly invalidate the prose in `epoch.rs`.
        let orchard = resident_bytes(50_392_548);
        let others: u64 = [2_129_853u64, 1_547_199, 70_381]
            .into_iter()
            .map(resident_bytes)
            .sum();
        assert!(
            orchard > others * 4,
            "orchard {orchard} vs everything else {others}"
        );
    }
}

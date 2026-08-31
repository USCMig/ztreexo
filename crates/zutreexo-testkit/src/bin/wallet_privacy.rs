//! Per-query anonymity is not wallet anonymity. This measures the gap.
//!
//! `docs/design.md` D39 settled the per-query number: a spend-status query hides
//! one note among **12,278** others, at every pool, for a few hundred kilobytes.
//! It also recorded what that number does not cover, and this is it.
//!
//! A wallet holding `n` notes must query `n` buckets. The bridge therefore sees
//! a *set* of `n` bucket indices, and that set is a property of the wallet, not
//! of any one note. Two things follow that the per-query figure says nothing
//! about:
//!
//! * **Linkage.** A wallet's bucket set is stable — nullifiers do not move
//!   between buckets — so a bridge can recognise the same wallet returning, even
//!   across a fresh circuit, a fresh connection, a fresh identity.
//! * **Cardinality.** The number of queries is the number of notes.
//!
//! # What is measured
//!
//! 1. **Fingerprint uniqueness.** Over a simulated population of wallets, how
//!    many share a bucket set with anyone else? The wallet-level anonymity set
//!    is the size of that equivalence class, and it is the honest counterpart to
//!    the 12,278.
//!
//! 2. **Whether decoy buckets fix it.** [D35](../../../docs/design.md) killed
//!    decoy *nullifiers* by retrospective correlation: the real one appears
//!    on-chain when spent and the decoys never do. Decoy *buckets* look
//!    different — a bucket holds 12,278 genuine nullifiers belonging to other
//!    people, so no single bucket is ever exposed as fake. The attack that
//!    applies instead is **intersection over sessions**: re-randomise the decoys
//!    each session and the real buckets are the ones that appear every time.
//!    This measures how many sessions that takes.
//!
//! Both are combinatorics over bucket indices rather than over trees, so they
//! run in seconds. Bandwidth is projected from D39's measured 32 bytes a member.
//!
//! # Usage
//!
//! ```text
//! cargo run --release --bin wallet_privacy
//! ZUTREEXO_WALLETS=200000 ZUTREEXO_NOTES=25 cargo run --release --bin wallet_privacy
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::env;

/// Orchard's nullifier count, `docs/benchmarks.md` Phase 0.
const POOL_SIZE: u64 = 50_392_547;

/// Measured wire cost per cohort member, D39: 31.3–32.0 bytes across pools.
const BYTES_PER_MEMBER: f64 = 32.0;

/// Fixed cost of a cohort regardless of size: header plus the fringe siblings,
/// ~26 of them at 33 bytes each (D38's `siblings` column).
const COHORT_OVERHEAD: f64 = 1_000.0;

/// Prefix widths worth reporting. 12 is the operating point chosen in D38.
const WIDTHS: &[u8] = &[2, 4, 6, 8, 10, 12];

/// xorshift64*. Seeded, so a run is reproducible — CLAUDE.md §5 rule 5.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A bucket index, uniform over `2^bits`. Nullifiers are hash outputs, so
    /// their prefixes are uniform and this is the real distribution.
    fn bucket(&mut self, bits: u8) -> u32 {
        if bits == 0 {
            return 0;
        }
        (self.next_u64() >> (64 - u32::from(bits))) as u32
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}

fn human(bytes: f64) -> String {
    if bytes >= 1_073_741_824.0 {
        format!("{:.2} GB", bytes / 1_073_741_824.0)
    } else if bytes >= 1_048_576.0 {
        format!("{:.1} MB", bytes / 1_048_576.0)
    } else if bytes >= 1024.0 {
        format!("{:.0} KB", bytes / 1024.0)
    } else {
        format!("{bytes:.0} B")
    }
}

/// Wire cost of one cohort at `bits` over the pool.
fn cohort_bytes(bits: u8) -> f64 {
    let members = POOL_SIZE as f64 / (1u64 << bits) as f64;
    members * BYTES_PER_MEMBER + COHORT_OVERHEAD
}

/// A wallet's query fingerprint: which buckets it asks about, deduplicated.
///
/// A set rather than a multiset, because two notes in one bucket are answered
/// by one query — the wallet has no reason to ask twice, and a bridge counting
/// queries sees the deduplicated number.
fn fingerprint(rng: &mut Rng, notes: usize, bits: u8) -> BTreeSet<u32> {
    (0..notes).map(|_| rng.bucket(bits)).collect()
}

/// How many wallets share each fingerprint.
fn uniqueness(wallets: usize, notes: usize, bits: u8, seed: u64) -> (f64, usize, f64) {
    let mut rng = Rng(seed | 1);
    let mut classes: BTreeMap<BTreeSet<u32>, usize> = BTreeMap::new();
    for _ in 0..wallets {
        *classes
            .entry(fingerprint(&mut rng, notes, bits))
            .or_insert(0) += 1;
    }

    let unique = classes.values().filter(|count| **count == 1).count();
    let largest = classes.values().copied().max().unwrap_or(0);
    // The anonymity set a wallet actually gets is the size of its own class,
    // averaged over wallets rather than over classes — a single huge class
    // must not make a population of singletons look private.
    let total: usize = classes.values().map(|c| c * c).sum();
    let mean_class = total as f64 / wallets.max(1) as f64;
    (
        unique as f64 / wallets.max(1) as f64 * 100.0,
        largest,
        mean_class,
    )
}

/// Sessions needed before intersecting the queried bucket sets isolates the
/// real ones.
///
/// Each session the wallet asks about its `notes` real buckets plus `decoys`
/// freshly chosen ones. The bridge intersects across sessions. Returns the
/// session count at which the intersection first equals the real set, or
/// `None` if it had not converged within `limit`.
fn sessions_to_isolate(
    notes: usize,
    decoys: usize,
    bits: u8,
    limit: usize,
    rng: &mut Rng,
) -> Option<usize> {
    let real: BTreeSet<u32> = (0..notes).map(|_| rng.bucket(bits)).collect();
    let mut intersection: Option<BTreeSet<u32>> = None;

    for session in 1..=limit {
        let mut asked = real.clone();
        for _ in 0..decoys {
            asked.insert(rng.bucket(bits));
        }
        intersection = Some(match intersection {
            None => asked,
            Some(previous) => previous.intersection(&asked).copied().collect(),
        });
        if intersection.as_ref() == Some(&real) {
            return Some(session);
        }
    }
    None
}

fn main() {
    let wallets = env_usize("ZUTREEXO_WALLETS", 100_000);
    let notes = env_usize("ZUTREEXO_NOTES", 10);
    let seed = env_usize("ZUTREEXO_SEED", 0x5eed_9999) as u64;

    println!("wallet_privacy — {wallets} simulated wallets, {notes} notes each");
    println!("pool: Orchard, {POOL_SIZE} nullifiers\n");

    println!("=== 1. Is a wallet's bucket set a fingerprint? ===\n");
    println!(
        "{:>5}  {:>8}  {:>10}  {:>9}  {:>12}  {:>11}  {:>11}",
        "bits", "buckets", "per-query k", "unique", "mean class", "1 query", "session"
    );
    println!("{}", "-".repeat(82));

    for bits in WIDTHS {
        let buckets = 1u64 << bits;
        let per_query = POOL_SIZE / buckets;
        let (unique_pct, _largest, mean_class) = uniqueness(wallets, notes, *bits, seed);
        let one = cohort_bytes(*bits);
        // Distinct buckets, so a session is cheaper than notes x cohort when
        // the wallet's notes collide -- which is the only saving on offer.
        let mut rng = Rng(seed ^ 0x1234);
        let distinct: f64 = (0..64)
            .map(|_| fingerprint(&mut rng, notes, *bits).len() as f64)
            .sum::<f64>()
            / 64.0;
        let session = one * distinct;

        println!(
            "{:>5}  {:>8}  {:>10}  {:>8.1}%  {:>12.1}  {:>11}  {:>11}",
            bits,
            buckets,
            per_query,
            unique_pct,
            mean_class,
            human(one),
            human(session)
        );
    }

    println!("\n\"per-query k\" is the anonymity D38 and D39 measured: one note among that many.");
    println!("\"mean class\" is the wallet-level anonymity set — how many of the simulated");
    println!("wallets share your exact bucket set. 1.0 means every wallet is distinguishable.");
    println!("\"session\" is one round of queries for all {notes} notes.");

    println!("\n=== 2. Do decoy buckets help, or does intersection strip them? ===\n");
    println!("D35 killed decoy *nullifiers*: the real one appears on-chain when spent and the");
    println!("decoys never do. A decoy *bucket* is not exposed that way — it holds thousands of");
    println!("genuine nullifiers belonging to other people. The attack that applies is");
    println!("intersection across sessions, since only the real buckets recur every time.\n");

    println!(
        "{:>6}  {:>8}  {:>22}  {:>14}",
        "decoys", "asked", "sessions to isolate", "cost per session"
    );
    println!("{}", "-".repeat(60));

    let bits = 12u8;
    for decoys in [0usize, 5, 10, 25, 50, 100] {
        let mut rng = Rng(seed ^ 0xabcd ^ (decoys as u64) << 8 | 1);
        let trials = 200;
        let mut converged = Vec::new();
        let mut never = 0usize;
        for _ in 0..trials {
            match sessions_to_isolate(notes, decoys, bits, 64, &mut rng) {
                Some(sessions) => converged.push(sessions),
                None => never += 1,
            }
        }
        let median = if converged.is_empty() {
            None
        } else {
            let mut sorted = converged.clone();
            sorted.sort_unstable();
            sorted.get(sorted.len() / 2).copied()
        };
        let verdict = match median {
            Some(m) if never == 0 => format!("{m}"),
            Some(m) => format!("{m} ({never}/{trials} held out)"),
            None => format!("none in 64 ({never}/{trials} held out)"),
        };
        println!(
            "{:>6}  {:>8}  {:>22}  {:>14}",
            decoys,
            notes + decoys,
            verdict,
            human(cohort_bytes(bits) * (notes + decoys) as f64)
        );
    }

    println!("\nsessions are counted until the intersection of the queried bucket sets equals");
    println!("the real one exactly. A wallet checking spend status daily reaches that many");
    println!("sessions in that many days.");

    println!("\n=== 3. Splitting queries across non-colluding bridges ===\n");
    println!("Neither a wider prefix nor decoys survive. What remains is to give no single");
    println!("bridge the whole set: ask bridge A about some notes, bridge B about others.");
    println!("Each then sees a fraction of the fingerprint. Below, how identifying that");
    println!("fraction is at the {bits}-bit operating point.\n");

    println!(
        "{:>16}  {:>9}  {:>12}  {:>28}",
        "buckets per bridge", "unique", "mean class", "bridges needed for 10 notes"
    );
    println!("{}", "-".repeat(74));

    for per_bridge in [1usize, 2, 3, 5, 10] {
        let (unique_pct, _, mean_class) = uniqueness(wallets, per_bridge, bits, seed ^ 0x777);
        let bridges = notes.div_ceil(per_bridge.max(1));
        println!(
            "{:>16}  {:>8.1}%  {:>12.1}  {:>28}",
            per_bridge, unique_pct, mean_class, bridges
        );
    }

    println!("\nmean class is over {wallets} simulated wallets, so it is bounded by that");
    println!("population — a real one is far larger and the figures for one or two buckets");
    println!("would rise with it. What does not change is the shape: the fingerprint becomes");
    println!("identifying almost immediately as buckets accumulate.");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]

    use super::*;

    #[test]
    fn a_zero_bit_prefix_is_one_bucket() {
        // Every wallet asks the same single question, which is the whole-set
        // download. It must not divide by zero or shift by 64.
        let mut rng = Rng(1);
        for _ in 0..100 {
            assert_eq!(rng.bucket(0), 0);
        }
        let (unique, _, mean) = uniqueness(1_000, 10, 0, 7);
        assert_eq!(unique, 0.0, "no wallet can be unique with one bucket");
        assert_eq!(mean, 1_000.0, "every wallet shares the one fingerprint");
    }

    #[test]
    fn buckets_stay_inside_their_range() {
        let mut rng = Rng(42);
        for bits in [1u8, 2, 8, 12, 20, 32] {
            for _ in 0..1_000 {
                let bucket = rng.bucket(bits);
                assert!(
                    u64::from(bucket) < (1u64 << bits),
                    "bits={bits} produced {bucket}"
                );
            }
        }
    }

    #[test]
    fn a_wide_prefix_makes_wallets_unique_and_a_narrow_one_does_not() {
        // The property the whole measurement turns on, asserted rather than
        // only printed: uniqueness rises with bucket count.
        let (wide_unique, _, wide_class) = uniqueness(5_000, 10, 12, 11);
        let (narrow_unique, _, narrow_class) = uniqueness(5_000, 10, 2, 11);
        assert!(
            wide_unique > narrow_unique,
            "12 bits should distinguish more wallets than 2: {wide_unique} vs {narrow_unique}"
        );
        assert!(
            wide_class < narrow_class,
            "a wider prefix must shrink the wallet anonymity set"
        );
    }

    #[test]
    fn intersection_isolates_the_real_buckets_eventually() {
        // With no decoys the first session already reveals them.
        let mut rng = Rng(3);
        assert_eq!(sessions_to_isolate(10, 0, 12, 64, &mut rng), Some(1));

        // With decoys it takes longer but still converges, which is the
        // finding: fresh decoys each session are stripped by intersection.
        let mut rng = Rng(5);
        let sessions = sessions_to_isolate(10, 25, 12, 64, &mut rng);
        assert!(
            sessions.is_some_and(|s| s > 1),
            "decoys must delay isolation without preventing it, got {sessions:?}"
        );
    }

    #[test]
    fn cohort_cost_falls_as_the_prefix_widens() {
        assert!(cohort_bytes(12) < cohort_bytes(6));
        assert!(cohort_bytes(6) < cohort_bytes(2));
        // And the operating point matches D38's measurement to within a few
        // percent, which is what makes the projection usable.
        let measured = 384.9 * 1024.0;
        let projected = cohort_bytes(12);
        assert!(
            (projected - measured).abs() / measured < 0.10,
            "projection {projected} should track the measured {measured}"
        );
    }
}

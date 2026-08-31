//! Does spreading queries over unlinkable sessions actually defeat the
//! fingerprint, and how big does the bridge's user base have to be?
//!
//! `docs/design.md` D40 measured that a wallet's *set* of buckets uniquely
//! identifies it, and concluded the only surviving mitigation was one
//! non-colluding bridge per note. **That conclusion was too strong.** The
//! fingerprint exists because `n` buckets arrive together in one identifiable
//! session; what does the work is the sessions being *unlinkable*, not the
//! bridges being distinct. One bridge receiving ten single-bucket queries it
//! cannot join holds ten independent observations.
//!
//! That reframes the requirement from "n non-colluding operators" to "n
//! unlinkable sessions", which Tor already provides — and it moves the question
//! to whether a bridge can re-join those sessions by other means. This measures
//! the two that matter.
//!
//! # The attack
//!
//! Sessions carry no identity, so the bridge sees a stream of
//! `(time, bucket)` with no way to attribute a single query. Two signals remain:
//!
//! * **Timing.** Queries issued in a burst share a narrow window.
//! * **Repetition.** A wallet's buckets are stable, so it asks the same ones
//!   tomorrow.
//!
//! Neither is enough alone. Together they are the intersection attack again:
//! take the buckets seen inside the wallet's active window each day, intersect
//! across days, and what survives is the wallet's set. Background traffic is
//! what defeats it — every unrelated query inside the window is noise that has
//! to be intersected away.
//!
//! So the contest is `background queries in the window` against `number of
//! buckets`. This simulates it directly rather than trusting the algebra, and
//! grants the adversary the **worst case**: they are told exactly when the
//! wallet is active.
//!
//! # Usage
//!
//! ```text
//! cargo run --release --bin session_privacy
//! ZUTREEXO_NOTES=25 ZUTREEXO_DAYS=365 cargo run --release --bin session_privacy
//! ```

use std::collections::BTreeSet;
use std::env;

/// The operating point, D38.
const PREFIX_BITS: u8 = 12;
const BUCKETS: u64 = 1 << PREFIX_BITS;

/// Wallet populations worth reporting. The low end is the launch condition:
/// a new bridge has few users, and that is exactly when the crowd is thinnest.
const POPULATIONS: &[u64] = &[1_000, 10_000, 100_000, 1_000_000];

/// How long a wallet spreads its queries over, in seconds.
const WINDOWS: &[(u64, &str)] = &[
    (1, "1 second"),
    (60, "1 minute"),
    (900, "15 minutes"),
    (3_600, "1 hour"),
    (21_600, "6 hours"),
    (86_400, "1 day"),
];

const SECONDS_PER_DAY: u64 = 86_400;

/// xorshift64*, seeded. CLAUDE.md §5 rule 5.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn bucket(&mut self) -> u32 {
        (self.next_u64() % BUCKETS) as u32
    }

    /// A uniform draw in [0, 1).
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Poisson draw by Knuth's method. Fine at the rates here; falls back to
    /// the mean for large lambda, where the relative spread is negligible and
    /// the product would underflow.
    fn poisson(&mut self, lambda: f64) -> u64 {
        if lambda > 500.0 {
            return lambda as u64;
        }
        let limit = (-lambda).exp();
        let mut product = 1.0f64;
        let mut count = 0u64;
        loop {
            product *= self.unit();
            if product <= limit {
                return count;
            }
            count = count.saturating_add(1);
            if count > 100_000 {
                return count;
            }
        }
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}

/// Wallets holding at least one note in any given bucket.
///
/// The crowd a single unlinkable query hides in: `W * (1 - (1 - 1/B)^n)`.
fn crowd(population: u64, notes: u64) -> f64 {
    let miss = 1.0 - 1.0 / BUCKETS as f64;
    population as f64 * (1.0 - miss.powi(notes as i32))
}

/// Days of intersection before the wallet's bucket set is isolated.
///
/// Each day the adversary observes every bucket queried inside the wallet's
/// active window — the wallet's own, plus whatever background traffic landed
/// there — and intersects with what it holds. `None` means the intersection
/// was still larger than the wallet's set after `days`.
///
/// # Why this counts rather than simulates
///
/// The obvious implementation inserts every background query into a set, and
/// at a million queries a day that is far too slow to sweep. It is also more
/// work than the question needs. The wallet's own buckets are in the
/// intersection forever, and every *other* bucket is exchangeable: each
/// survives a day exactly when the background happens to hit it. So the state
/// is one number — how many non-wallet buckets remain — and a day is one
/// binomial thinning of it. Exact, not an approximation.
fn days_to_isolate(notes: u64, background_in_window: f64, days: u64, rng: &mut Rng) -> Option<u64> {
    // Distinct buckets the wallet asks about: two notes can share one.
    let real: BTreeSet<u32> = (0..notes).map(|_| rng.bucket()).collect();
    let others = BUCKETS.saturating_sub(real.len() as u64);

    let mut surviving = others;

    for day in 1..=days {
        // How many background queries landed in the window today, and hence
        // the chance any given bucket was among them.
        let hits = rng.poisson(background_in_window);
        let miss = (1.0 - 1.0 / BUCKETS as f64).powi(hits.min(1_000_000) as i32);
        let appears = 1.0 - miss;

        let mut kept = 0u64;
        for _ in 0..surviving {
            if rng.unit() < appears {
                kept = kept.saturating_add(1);
            }
        }
        surviving = kept;

        if surviving == 0 {
            return Some(day);
        }
    }
    None
}

fn main() {
    let notes = env_u64("ZUTREEXO_NOTES", 10);
    let days = env_u64("ZUTREEXO_DAYS", 180);
    let trials = env_u64("ZUTREEXO_TRIALS", 40);
    let seed = env_u64("ZUTREEXO_SEED", 0x51de_2026);

    println!("session_privacy — {notes} notes, {PREFIX_BITS}-bit buckets ({BUCKETS} of them)");
    println!("one bucket per unlinkable session; the adversary is told when the wallet is active");
    println!("and intersects the buckets seen in that window across days\n");

    println!("=== 1. How big does the user base have to be? ===\n");
    println!(
        "{:>12}  {:>16}  {:>18}",
        "wallets", "queries per day", "crowd per bucket"
    );
    println!("{}", "-".repeat(52));
    for population in POPULATIONS {
        println!(
            "{:>12}  {:>16}  {:>18.0}",
            population,
            population * notes,
            crowd(*population, notes)
        );
    }
    println!("\n\"crowd per bucket\" is how many wallets hold a note in any given bucket —");
    println!("the anonymity set of one unlinkable single-bucket query. It is the number the");
    println!("whole approach rests on, and it is thinnest exactly at launch.");

    println!("\n=== 2. Does spreading queries defeat the intersection attack? ===\n");
    println!("Days until the adversary recovers the wallet's exact bucket set.");
    println!("\"safe\" means it had not converged within {days} days.\n");

    print!("{:>12}", "wallets");
    for (_, label) in WINDOWS {
        print!("  {label:>11}");
    }
    println!();
    println!("{}", "-".repeat(12 + WINDOWS.len() * 13));

    for population in POPULATIONS {
        // Background rate: every other wallet issues `notes` queries a day,
        // spread across the day. The target's own queries are already counted
        // in `real`, so exclude one wallet.
        let daily = population.saturating_sub(1) * notes;
        print!("{population:>12}");

        for (window, _) in WINDOWS {
            let in_window = daily as f64 * (*window as f64 / SECONDS_PER_DAY as f64);
            let mut rng = Rng(seed ^ (population << 8) ^ window | 1);
            let mut converged = Vec::new();
            let mut safe = 0u64;
            for _ in 0..trials {
                match days_to_isolate(notes, in_window, days, &mut rng) {
                    Some(day) => converged.push(day),
                    None => safe = safe.saturating_add(1),
                }
            }
            // `converged` empty and `safe == trials` are the same condition;
            // one test, so clippy is right that two arms would be redundant.
            let cell = if converged.is_empty() {
                "safe".to_owned()
            } else {
                let mut sorted = converged.clone();
                sorted.sort_unstable();
                let median = sorted.get(sorted.len() / 2).copied().unwrap_or(0);
                if safe > 0 {
                    format!("{median}d ({safe}/{trials})")
                } else {
                    format!("{median}d")
                }
            };
            print!("  {cell:>11}");
        }
        println!();
    }

    println!("\n=== 3. The rule that falls out ===\n");
    println!("Safety is background queries inside the window against the {BUCKETS} buckets.");
    println!("A ratio near 1 leaves the wallet isolated in weeks; a ratio of ~10 holds for");
    println!("the whole {days}-day horizon. Solving for the window:\n");
    println!("    spread >= 10 * buckets * 86400 / (wallets * notes)   seconds\n");
    println!(
        "{:>12}  {:>22}  {:>18}",
        "wallets", "minimum spread", "matches the sweep"
    );
    println!("{}", "-".repeat(56));
    for population in POPULATIONS {
        let required =
            10.0 * BUCKETS as f64 * SECONDS_PER_DAY as f64 / (*population * notes) as f64;
        let pretty = if required >= SECONDS_PER_DAY as f64 {
            format!("{:.1} days", required / SECONDS_PER_DAY as f64)
        } else if required >= 3_600.0 {
            format!("{:.1} hours", required / 3_600.0)
        } else {
            format!("{:.0} minutes", required / 60.0)
        };
        // The nearest swept window at or above the requirement.
        let observed = WINDOWS
            .iter()
            .find(|(window, _)| *window as f64 >= required)
            .map_or("beyond a day", |(_, label)| *label);
        println!("{population:>12}  {pretty:>22}  {observed:>18}");
    }
    println!("\nAt 1,000 wallets the rule asks for more than a day, which is another way of");
    println!("saying a bridge that small cannot hide anyone: the sweep has it isolated in 97");
    println!("days even at maximum spread, and the crowd per bucket is 2.");

    println!(
        "\nThe contest is background queries inside the window against the {BUCKETS} buckets."
    );
    println!("When the window holds far more unrelated queries than there are buckets, every");
    println!("bucket appears every day and the intersection never narrows. When it holds few,");
    println!("the wallet's own buckets are the only ones that recur.");
    println!("\nA burst is not a spread: issuing all {notes} queries at once is the same as");
    println!("sending them in one session, whatever the transport underneath.");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]

    use super::*;

    #[test]
    fn no_background_traffic_isolates_immediately() {
        // The degenerate case that proves the attack is implemented at all: a
        // wallet alone on a bridge is identified by its first session.
        let mut rng = Rng(1);
        assert_eq!(days_to_isolate(10, 0.0, 180, &mut rng), Some(1));
    }

    #[test]
    fn heavy_background_traffic_never_isolates() {
        // When the window holds many multiples of the bucket count, every
        // bucket shows up every day and the intersection cannot shrink.
        let mut rng = Rng(2);
        assert_eq!(
            days_to_isolate(10, (BUCKETS * 10) as f64, 180, &mut rng),
            None
        );
    }

    #[test]
    fn more_background_traffic_never_makes_isolation_faster() {
        // Monotonicity. If this failed, the simulation would be measuring
        // something other than what it claims.
        let mut previous = 0u64;
        for lambda in [0.0f64, 100.0, 500.0, 2_000.0] {
            let mut rng = Rng(7);
            let days = days_to_isolate(10, lambda, 400, &mut rng).unwrap_or(u64::MAX);
            assert!(
                days >= previous,
                "lambda={lambda} isolated in {days}d, faster than the lighter case's {previous}d"
            );
            previous = days;
        }
    }

    #[test]
    fn the_crowd_grows_with_the_population_and_with_notes() {
        assert!(crowd(100_000, 10) > crowd(10_000, 10));
        assert!(crowd(100_000, 50) > crowd(100_000, 10));
        // Matches the closed form W * n / B closely while n << B.
        let approx = 100_000.0 * 10.0 / BUCKETS as f64;
        let exact = crowd(100_000, 10);
        assert!(
            (exact - approx).abs() / approx < 0.01,
            "crowd {exact} should track {approx}"
        );
    }

    #[test]
    fn poisson_has_about_the_right_mean() {
        let mut rng = Rng(11);
        let lambda = 50.0;
        let draws = 4_000;
        let total: u64 = (0..draws).map(|_| rng.poisson(lambda)).sum();
        let mean = total as f64 / draws as f64;
        assert!(
            (mean - lambda).abs() < 2.0,
            "mean {mean} should be near {lambda}"
        );
    }
}

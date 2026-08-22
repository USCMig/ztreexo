//! Measurement helpers shared by the replay binaries.
//!
//! Nothing here affects a root, so none of it is consensus-relevant. It lives
//! in the library rather than in one binary because Phase 5b compares figures
//! across three runs — a genesis replay, a windowed compact-node replay, and a
//! tip-following shadow run — and a peak-RSS number is only comparable to
//! another if both were read the same way.

use std::time::Duration;

/// Resident set size in MiB, read from `/proc`. Zero where unavailable.
///
/// This is the basis for every RSS figure in `docs/benchmarks.md`, including
/// the 32.7 GiB genesis-to-tip peak that Phase 5b's compact-node number is
/// weighed against. Reading it any other way would make that comparison
/// meaningless, which is why it is here and not copied per binary.
pub fn rss_mib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmRSS:"))
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|value| value.parse::<u64>().ok())
                })
        })
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

/// Peak resident set size in MiB, read from `/proc`. Zero where unavailable.
///
/// `VmHWM` is the kernel's high-water mark, so it survives the allocator
/// handing memory back. Sampling [`rss_mib`] in the reporting loop — which is
/// what the genesis replay did — misses a peak that happens between samples,
/// and during the sandblasting window the interesting spike is exactly the sort
/// of thing that fits between two reports.
pub fn peak_rss_mib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmHWM:"))
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|value| value.parse::<u64>().ok())
                })
        })
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

/// Per-block timings, kept as a full sample rather than a running mean.
///
/// # Why not a mean
///
/// Stage 2d measured throughput spanning **9 to 1,568 blocks/s over mainnet
/// history — a 165× range** — with the slow end concentrated in the
/// sandblasting window, and drew the explicit conclusion that *"a p50 taken
/// over quiet history understates the p99 a node must survive by more than two
/// orders of magnitude"*. CLAUDE.md Phase 5 asks for p50 and p99 for that
/// reason. A mean over 3.45M blocks would hide the case the node actually has
/// to survive, so every sample is retained and the quantiles are exact.
///
/// At 8 bytes per block and 3.45M blocks that is 27 MB, which is affordable
/// against a replay that already holds tens of gigabytes.
#[derive(Clone, Debug, Default)]
pub struct Latencies {
    /// Every sample, in microseconds, in arrival order.
    micros: Vec<u64>,
}

impl Latencies {
    /// An empty sample set.
    pub fn new() -> Latencies {
        Latencies { micros: Vec::new() }
    }

    /// Records one observation, saturating rather than wrapping.
    pub fn record(&mut self, elapsed: Duration) {
        self.micros
            .push(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX));
    }

    /// How many samples were taken.
    pub fn count(&self) -> usize {
        self.micros.len()
    }

    /// Sum of every sample, in microseconds.
    pub fn total_micros(&self) -> u64 {
        self.micros.iter().copied().fold(0u64, u64::saturating_add)
    }

    /// The `q`th quantile in microseconds, with `q` in `0.0..=1.0`.
    ///
    /// Nearest-rank on a sorted copy: exact, deterministic, and no
    /// interpolation to argue about. `None` when nothing was recorded, because
    /// reporting `0` for an empty sample set is how a run that measured nothing
    /// gets published as a fast one.
    pub fn quantile(&self, q: f64) -> Option<u64> {
        if self.micros.is_empty() {
            return None;
        }
        let mut sorted = self.micros.clone();
        sorted.sort_unstable();
        let last = sorted.len().saturating_sub(1);
        // `q` is clamped rather than trusted so a caller cannot index out of
        // range; the alternative is a panic in a measurement path.
        let rank = (q.clamp(0.0, 1.0) * last as f64).round() as usize;
        sorted.get(rank.min(last)).copied()
    }

    /// Convenience: p50, p99, and the maximum, all in microseconds.
    pub fn summary(&self) -> Option<LatencySummary> {
        Some(LatencySummary {
            count: self.count(),
            p50_micros: self.quantile(0.50)?,
            p99_micros: self.quantile(0.99)?,
            max_micros: self.quantile(1.0)?,
            mean_micros: self.total_micros() / (self.count().max(1) as u64),
        })
    }
}

/// A rendered quantile summary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LatencySummary {
    /// Samples behind the figures.
    pub count: usize,
    /// Median.
    pub p50_micros: u64,
    /// 99th percentile — the number stage 2d says to report.
    pub p99_micros: u64,
    /// Worst single block.
    pub max_micros: u64,
    /// Reported alongside the quantiles so the skew is visible, never alone.
    pub mean_micros: u64,
}

impl std::fmt::Display for LatencySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "n={} p50={:.3}ms p99={:.3}ms max={:.3}ms mean={:.3}ms",
            self.count,
            self.p50_micros as f64 / 1000.0,
            self.p99_micros as f64 / 1000.0,
            self.max_micros as f64 / 1000.0,
            self.mean_micros as f64 / 1000.0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_are_exact_on_a_known_sample() {
        let mut l = Latencies::new();
        for micros in 1..=100u64 {
            l.record(Duration::from_micros(micros));
        }
        // Nearest-rank over 100 samples indexed 0..=99: rank = round(q * 99).
        assert_eq!(l.quantile(0.0), Some(1));
        assert_eq!(l.quantile(0.50), Some(51));
        assert_eq!(l.quantile(0.99), Some(99));
        assert_eq!(l.quantile(1.0), Some(100));
        assert_eq!(l.count(), 100);
    }

    #[test]
    fn an_empty_set_reports_nothing_rather_than_zero() {
        // A run that measured nothing must not publish as a fast one.
        let l = Latencies::new();
        assert_eq!(l.quantile(0.5), None);
        assert!(l.summary().is_none());
    }

    #[test]
    fn insertion_order_does_not_change_the_quantiles() {
        let mut ascending = Latencies::new();
        let mut descending = Latencies::new();
        for micros in 1..=50u64 {
            ascending.record(Duration::from_micros(micros));
            descending.record(Duration::from_micros(51 - micros));
        }
        assert_eq!(ascending.summary(), descending.summary());
    }

    #[test]
    fn a_tail_spike_moves_p99_and_max_but_not_p50() {
        // The property stage 2d's 165x range makes load-bearing: one
        // pathological block must be visible in the tail and invisible in the
        // median, which is the whole reason quantiles are reported.
        let mut l = Latencies::new();
        for _ in 0..99 {
            l.record(Duration::from_micros(10));
        }
        l.record(Duration::from_secs(1));
        let s = l.summary().unwrap();
        assert_eq!(s.p50_micros, 10);
        assert_eq!(s.max_micros, 1_000_000);
        assert!(s.mean_micros > 10, "a spike should move the mean too");
    }

    #[test]
    fn out_of_range_quantiles_clamp_rather_than_panic() {
        let mut l = Latencies::new();
        l.record(Duration::from_micros(7));
        assert_eq!(l.quantile(-5.0), Some(7));
        assert_eq!(l.quantile(42.0), Some(7));
    }
}

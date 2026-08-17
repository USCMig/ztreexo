//! Stage 2c: randomised reorgs against a cold replay.
//!
//! CLAUDE.md Phase 2's definition of done is 10⁶ reorgs with zero divergence.
//! That is far too slow for a per-push job, so the count is environment-driven:
//! this runs a few thousand by default and the nightly sweep runs the full 10⁶.
//! A check slow enough to be skipped protects nothing.
//!
//! ```text
//! ZUTREEXO_REORG_ITERATIONS=1000000 cargo test --release -p zutreexo-testkit --test reorg_fuzz
//! ```

#![allow(clippy::panic, clippy::unwrap_used)]

use zutreexo_testkit::reorg::{self, ReorgConfig, ReorgFault};

fn iterations(default: u64) -> u64 {
    std::env::var("ZUTREEXO_REORG_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// **The Phase 2 definition of done**, at whatever scale this run is configured
/// for. Every iteration compares the incrementally-maintained state against a
/// cold replay of the chain that now exists, byte for byte.
#[test]
fn randomised_reorgs_never_diverge_from_a_cold_replay() {
    let total = iterations(2_000);
    let config = ReorgConfig::default();

    // A handful of seeds rather than one: a single seed explores one path
    // through the generator, and a fixed set keeps failures reproducible while
    // covering more shapes than any one of them would.
    let seeds: [u64; 4] = [1, 0xDEAD_BEEF, 0x5EED, u64::MAX];
    let per_seed = (total / seeds.len() as u64).max(1);

    let mut reorgs = 0u64;
    let mut blocks = 0u64;
    let mut deepest = 0u32;
    let mut unreachable = 0u64;

    for seed in seeds {
        let report =
            reorg::run(seed, per_seed, &config).unwrap_or_else(|divergence| panic!("{divergence}"));
        reorgs += report.reorgs;
        blocks += report.blocks_applied;
        deepest = deepest.max(report.deepest);
        unreachable += report.out_of_reach;

        assert!(
            report.cold_checks > 0,
            "seed {seed}: no cold replay was ever performed — the invariant was \
             not actually checked"
        );

        // The chain must stay pinned. An earlier version let the tip
        // random-walk upward; it reached height 15,722 by iteration 24,523 and
        // died on a tree-capacity error that read like a rollback bug, having
        // meanwhile made every cold replay progressively slower. Asserting the
        // bound here makes a regression obvious at any scale instead of only
        // at the one where it finally overflows.
        assert_eq!(
            report.highest_tip, config.chain_len,
            "seed {seed}: tip reached {} but the chain is pinned at {} — the \
             chain is growing, which will exhaust the tree and slow every cold \
             replay",
            report.highest_tip, config.chain_len
        );
    }

    eprintln!(
        "{reorgs} reorgs across {} seeds, {blocks} blocks applied, \
         deepest unwind {deepest}, {unreachable} beyond journal reach",
        seeds.len()
    );

    assert!(reorgs > 0, "no reorg was performed");
    assert!(
        deepest >= 2,
        "deepest reorg was only {deepest} blocks; the fuzzer is not exercising \
         multi-block unwinds"
    );
}

/// Snapshot cadence changes which code path a rollback takes — restoring at the
/// target versus restoring earlier and replaying forward — so both are covered.
#[test]
fn every_snapshot_interval_holds_the_invariant() {
    for snapshot_interval in [1u32, 2, 5, 16] {
        let config = ReorgConfig {
            snapshot_interval,
            ..ReorgConfig::default()
        };
        let report = reorg::run(0xABCD, 300, &config)
            .unwrap_or_else(|d| panic!("interval {snapshot_interval}: {d}"));
        assert!(report.reorgs > 0);
        eprintln!(
            "interval {snapshot_interval}: {} reorgs, {} cold checks",
            report.reorgs, report.cold_checks
        );
    }
}

/// The same seed must produce the same run. Without this a divergence cannot be
/// turned into a corpus seed, which is the whole point of the seeding scheme.
#[test]
fn runs_are_reproducible_from_the_seed() {
    let config = ReorgConfig::default();
    let first = reorg::run(42, 200, &config).unwrap();
    let second = reorg::run(42, 200, &config).unwrap();
    assert_eq!(first, second, "the same seed produced different runs");

    let different = reorg::run(43, 200, &config).unwrap();
    assert_ne!(
        first, different,
        "different seeds produced identical runs; the seed is not being used"
    );
}

// ---------------------------------------------------------------------------
// Proving the fuzzer detects a broken rollback.
//
// 10^6 green iterations look exactly the same whether the invariant is being
// checked or silently passing. These inject rollback bugs and require the
// fuzzer to notice.
// ---------------------------------------------------------------------------

/// Asserts the fault was caught *by the invariant*, not by something incidental.
///
/// This matters more than it looks. The first version of these faults
/// desynchronised the block height, and both tests passed — because the next
/// block failed a contiguity check before any cold replay ran. Green, for a
/// reason with nothing to do with the claim. Requiring `NotColdReplay`
/// specifically is what makes these tests evidence rather than decoration.
fn expect_count_tier(seed: u64, fault: ReorgFault, what: &str) {
    let config = ReorgConfig {
        fault: Some(fault),
        ..ReorgConfig::default()
    };
    match reorg::run(seed, 500, &config) {
        Err(reorg::ReorgDivergence::CountMismatch {
            iteration, field, ..
        }) => {
            eprintln!("{what}: caught by the count tier at iteration {iteration} ({field})");
        }
        Err(other) => panic!("{what}: expected a count mismatch, got: {other}"),
        Ok(report) => panic!("{what} went undetected across {} reorgs", report.reorgs),
    }
}

/// A nullifier left behind by an incomplete unwind. Changes a count, so the
/// cheap tier sees it on the very next iteration.
#[test]
fn a_leftover_nullifier_is_caught_by_the_count_tier() {
    expect_count_tier(7, ReorgFault::LeftoverNullifier, "leftover nullifier");
}

/// A transparent output left behind. Nullifier roots are correct here, so
/// anything checking only the shielded side would pass.
#[test]
fn a_leftover_output_is_caught_by_the_count_tier() {
    expect_count_tier(11, ReorgFault::LeftoverOutput, "leftover output");
}

/// **The test that justifies the cold replay.**
///
/// A count-preserving corruption: one surviving block's nullifier takes a
/// different value. Nothing is added or removed, so every count still agrees
/// and the cheap tier cannot see it. Only the byte-for-byte comparison does.
#[test]
fn a_count_preserving_corruption_is_caught_only_by_the_cold_replay() {
    let config = ReorgConfig {
        fault: Some(ReorgFault::AlteredHistory),
        ..ReorgConfig::default()
    };
    match reorg::run(3, 500, &config) {
        Err(reorg::ReorgDivergence::NotColdReplay { iteration, .. }) => {
            eprintln!("altered history: caught by the cold replay at iteration {iteration}");
        }
        Err(reorg::ReorgDivergence::CountMismatch { field, .. }) => panic!(
            "the altered-history fault changed a count ({field}); it is not \
             count-preserving, so it proves nothing about the cold-replay tier"
        ),
        Err(other) => panic!("expected a cold-replay divergence, got: {other}"),
        Ok(report) => panic!(
            "a count-preserving corruption survived {} reorgs and {} cold \
             checks — the expensive tier is not working",
            report.reorgs, report.cold_checks
        ),
    }
}

/// And the counts must be provably blind to it, or the test above does not
/// isolate the cold-replay tier.
#[test]
fn the_count_tier_is_provably_blind_to_that_corruption() {
    let config = ReorgConfig {
        fault: Some(ReorgFault::AlteredHistory),
        // Disable the expensive tier entirely, leaving counts as the only
        // active check. A large interval would not do: the final iteration is
        // always checked, which is correct behaviour and would mask this.
        cold_check_every: 0,
        ..ReorgConfig::default()
    };
    match reorg::run(3, 100, &config) {
        Ok(report) => {
            assert_eq!(report.cold_checks, 0, "the cold replay ran after all");
            eprintln!(
                "counts alone accepted {} corrupted reorgs — which is exactly \
                 why the cold replay exists",
                report.reorgs
            );
        }
        Err(other) => panic!("the count tier saw a corruption it cannot see: {other}"),
    }
}

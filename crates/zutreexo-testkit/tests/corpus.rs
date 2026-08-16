//! Replays the regression corpus. See `corpus/README.md` for the rule.
//!
//! Every seed here reproduced a real divergence once. Each must now replay
//! clean, and must keep replaying clean forever. A seed that starts failing
//! means a fix regressed.

#![allow(clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use zutreexo_testkit::harness::{load_repro, replay, Fault, HarnessConfig};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus")
}

/// Replays one seed against a fresh, empty state.
///
/// `Ok(())` means the seed no longer diverges, which for a committed seed is
/// the required outcome.
fn run_seed(path: &Path) -> Result<(), String> {
    let repro = load_repro(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let blocks = [repro.block];
    match replay(&blocks, &repro.config) {
        Ok(_) => Ok(()),
        Err(divergence) => Err(format!(
            "{}: still diverges: {divergence}\n  originally: {}",
            path.display(),
            repro.divergence
        )),
    }
}

fn seeds() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(corpus_dir()) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    // Deterministic order: directory iteration order is not stable across
    // filesystems, and CLAUDE.md §5 rule 5 applies to tests too.
    paths.sort();
    paths
}

#[test]
fn every_seed_replays_clean() {
    let paths = seeds();
    if paths.is_empty() {
        eprintln!(
            "corpus is empty — no divergence has been found yet. \
             This test guards nothing until one is."
        );
        return;
    }

    let mut failures = Vec::new();
    for path in &paths {
        if let Err(reason) = run_seed(path) {
            failures.push(reason);
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} corpus seeds diverge:\n{}",
        failures.len(),
        paths.len(),
        failures.join("\n")
    );
    eprintln!("{} corpus seeds replayed clean", paths.len());
}

/// Proves the runner can actually fail.
///
/// An empty corpus plus a runner that cannot detect a bad seed is two layers of
/// nothing. This builds a seed that *should* diverge — by recording a fault in
/// its config — and asserts the runner reports it.
#[test]
fn the_runner_detects_a_divergent_seed() {
    // Any real block with at least two nullifiers in one pool. Reversing them
    // moves leaf indices without changing counts, so only a root check sees it.
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/ironwood-activation.jsonl");
    let Ok(text) = std::fs::read_to_string(&fixture) else {
        eprintln!(
            "SKIPPED: {} not present; regenerate with scripts/measure_baseline.sh",
            fixture.display()
        );
        return;
    };

    let mut chosen: Option<(u32, String)> = None;
    for line in text.lines() {
        let hex_str = line.trim().trim_matches('"');
        if hex_str.is_empty() {
            continue;
        }
        let Ok(bytes) = hex::decode(hex_str) else {
            continue;
        };
        use zebra_chain::serialization::ZcashDeserialize;
        let Ok(block) = zebra_chain::block::Block::zcash_deserialize(&bytes[..]) else {
            continue;
        };
        let Ok(summary) = zutreexo_chain::summarize_block(&block) else {
            continue;
        };
        let reorderable = zutreexo_chain::PoolId::ALL
            .into_iter()
            .any(|pool| summary.nullifiers_for(pool).len() >= 2);
        if reorderable {
            chosen = Some((summary.height, hex_str.to_owned()));
            break;
        }
    }

    let Some((height, block_hex)) = chosen else {
        eprintln!("SKIPPED: no suitable block in the fixture");
        return;
    };

    let dir = std::env::temp_dir().join("zutreexo-corpus-selftest");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("synthetic-divergence.json");

    let seed = serde_json::json!({
        "divergence": "synthetic: injected reordering",
        "kind": "root",
        "height": height,
        "slice": "selftest",
        "config": {
            "depth": 14,
            "root_check_every": 1,
            "allow_unknown_spends": true,
            "enforce_contiguous": false,
            "fault": Fault::ReorderNullifiers { height }.to_json(),
        },
        "block_hex": block_hex,
    });
    std::fs::write(&path, format!("{seed:#}\n")).unwrap();

    let outcome = run_seed(&path);
    assert!(
        outcome.is_err(),
        "the corpus runner accepted a seed that should diverge — \
         it cannot be trusted to catch a regression"
    );
    eprintln!("runner correctly rejected a divergent seed: {outcome:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The config stored in a repro must survive the round trip, or a committed
/// seed would replay under different settings than the ones that caught it and
/// silently pass.
#[test]
fn repro_config_round_trips() {
    let dir = std::env::temp_dir().join("zutreexo-corpus-roundtrip");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("seed.json");

    // A minimal but valid block: the genesis-shaped fixture is unnecessary,
    // because only the config half is under test here. Reuse a real one.
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/ironwood-activation.jsonl");
    let Ok(text) = std::fs::read_to_string(&fixture) else {
        eprintln!("SKIPPED: fixture not present");
        return;
    };
    let first = text
        .lines()
        .next()
        .unwrap()
        .trim()
        .trim_matches('"')
        .to_owned();

    let seed = serde_json::json!({
        "divergence": "test",
        "height": 0,
        "slice": "selftest",
        "config": {
            "depth": 12,
            "root_check_every": 7,
            "allow_unknown_spends": false,
            "enforce_contiguous": true,
            "fault": Fault::DropCreate { height: 42 }.to_json(),
        },
        "block_hex": first,
    });
    std::fs::write(&path, format!("{seed:#}\n")).unwrap();

    let repro = load_repro(&path).unwrap();
    assert_eq!(repro.config.depth, 12);
    assert_eq!(repro.config.root_check_every, 7);
    assert!(!repro.config.allow_unknown_spends);
    assert_eq!(repro.config.fault, Some(Fault::DropCreate { height: 42 }));
    // Always relaxed regardless of what was stored: a seed is one block out of
    // its chain, so requiring contiguity would fail every seed.
    assert!(!repro.config.enforce_contiguous);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A default config must not accidentally disable a tier.
#[test]
fn default_config_runs_both_local_tiers() {
    let config = HarnessConfig::default();
    assert!(
        config.root_check_every > 0,
        "the default config disables tier 2, the load-bearing check"
    );
    assert!(config.depth <= zutreexo_testkit::naive::MAX_NAIVE_DEPTH);
    assert!(config.fault.is_none(), "the default config injects a fault");
}

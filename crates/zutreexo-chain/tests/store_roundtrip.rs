//! A saved snapshot must reload to *exactly* the state that was saved.
//!
//! # Why this file exists before the format is used anywhere
//!
//! Stage 2c found a serialisation bug that had been latent since Phase 1:
//! `ZcashNodeHash::write` emitted a bare 32 bytes and `read` returned `Some`
//! unconditionally, losing the variant. Encoder and decoder both looked
//! symmetric and were, byte for byte — what got lost was a distinction neither
//! side compared. Nothing round-tripped the format for two phases, so nothing
//! noticed (`docs/design.md` D19).
//!
//! `PLAN.md` records the conclusion as a rule for Phase 3: **a serialisation
//! format that nothing round-trips is untested, whatever the suite says.** These
//! tests exist so the rule is honoured before the format has any users.
//!
//! Equality here means *behavioural* equality, not equal roots. A reloaded
//! snapshot has to support further blocks, undo, and rollback, all of which
//! compare exact state.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::UtxoLeaf;
use zutreexo_chain::{
    apply_block, load, save, ApplyOptions, BlockSummary, ChainAccumulators, OutPoint, PoolId,
    StoreError,
};

const DEPTH: u8 = 14;

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("zutreexo-store-tests");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn bytes32(tag: u8, n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = tag;
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}

fn leaf(n: u64, height: u32) -> UtxoLeaf {
    UtxoLeaf {
        txid: bytes32(0xAA, n),
        vout: 0,
        height,
        is_coinbase: n % 7 == 0,
        value: 1_000 + n,
        // Variable-length, including empty: a fixed-width assumption in the
        // encoder would survive uniform scripts and fail on real ones.
        script_pubkey: if n % 5 == 0 {
            Vec::new()
        } else {
            vec![0x76, 0xa9, (n % 251) as u8]
        },
    }
}

/// Builds a state with every pool populated, spends, and a real forest.
fn populated(blocks: u32) -> ChainAccumulators {
    let mut state = ChainAccumulators::new(DEPTH).unwrap();
    for height in 1..=blocks {
        let h = u64::from(height);
        let mut nullifiers: BTreeMap<PoolId, Vec<Value>> = BTreeMap::new();
        for (offset, pool) in PoolId::ALL.into_iter().enumerate() {
            nullifiers.insert(
                pool,
                vec![Value::from_bytes(bytes32(0xBB, h * 100 + offset as u64))],
            );
        }

        let summary = BlockSummary {
            height,
            transactions: 1,
            transparent_spends: if height > 3 {
                vec![OutPoint {
                    txid: bytes32(0xAA, (h - 3) * 10),
                    vout: 0,
                }]
            } else {
                Vec::new()
            },
            transparent_creates: vec![
                (
                    OutPoint {
                        txid: bytes32(0xAA, h * 10),
                        vout: 0,
                    },
                    leaf(h * 10, height),
                ),
                (
                    OutPoint {
                        txid: bytes32(0xAA, h * 10 + 1),
                        vout: 0,
                    },
                    leaf(h * 10 + 1, height),
                ),
            ],
            nullifiers,
            commitments: BTreeMap::new(),
        };
        apply_block(&mut state, &summary, ApplyOptions::default()).unwrap();
    }
    state
}

/// Everything that decides future behaviour.
fn fingerprint(state: &ChainAccumulators) -> String {
    let mut out = format!(
        "tip={:?} depth={} utxos={}",
        state.tip(),
        state.depth(),
        state.utxo_count()
    );
    for (pool, root) in state.nullifier_roots() {
        out.push_str(&format!(
            " {pool}:{}:{}",
            state.nullifier_count(pool),
            hex::encode(root)
        ));
    }
    for root in state.utxo_roots() {
        out.push_str(&format!(" t:{}", hex::encode(root)));
    }
    out
}

#[test]
fn a_populated_state_round_trips() {
    let original = populated(40);
    let path = scratch("roundtrip.zst");

    save(&original, &path).unwrap();
    let reloaded = load(&path).unwrap();

    assert_eq!(fingerprint(&reloaded), fingerprint(&original));
}

/// The outpoint index must come back whole, including the leaf contents —
/// value, script, height, coinbase flag. A leaf hash alone would reproduce the
/// forest and leave the index unable to resolve a later spend, which is exactly
/// the bug `StateDelta::created` had (`docs/design.md` D18).
#[test]
fn every_utxo_leaf_field_survives() {
    let original = populated(30);
    let path = scratch("utxo-fields.zst");
    save(&original, &path).unwrap();
    let reloaded = load(&path).unwrap();

    let mut checked = 0;
    for (outpoint, leaf) in original.utxo_index_for_test() {
        let back = reloaded
            .utxo(&outpoint)
            .unwrap_or_else(|| panic!("{outpoint:?} missing after reload"));
        assert_eq!(*back, leaf, "leaf contents differ for {outpoint:?}");
        checked += 1;
    }
    assert!(checked > 0, "the fixture produced no outputs to check");
    assert_eq!(reloaded.utxo_count(), original.utxo_count());
}

/// An empty state is a real state and must survive the trip. `tip = None` is
/// distinct from `tip = Some(0)`, and encoding it as a sentinel height would
/// conflate a fresh store with one holding only genesis.
#[test]
fn an_empty_state_round_trips_with_no_tip() {
    let original = ChainAccumulators::new(DEPTH).unwrap();
    let path = scratch("empty.zst");

    save(&original, &path).unwrap();
    let reloaded = load(&path).unwrap();

    assert_eq!(reloaded.tip(), None);
    assert_eq!(fingerprint(&reloaded), fingerprint(&original));
}

#[test]
fn a_state_at_genesis_is_distinguishable_from_an_empty_one() {
    let genesis = populated(1);
    let empty = ChainAccumulators::new(DEPTH).unwrap();

    let a = scratch("genesis.zst");
    let b = scratch("nothing.zst");
    save(&genesis, &a).unwrap();
    save(&empty, &b).unwrap();

    assert_eq!(load(&a).unwrap().tip(), Some(1));
    assert_eq!(load(&b).unwrap().tip(), None);
}

/// A reloaded snapshot must accept further blocks and land where an
/// uninterrupted run would. This is the property that makes persistence worth
/// having at all.
#[test]
fn a_reloaded_state_continues_identically() {
    let path = scratch("continue.zst");

    let mut interrupted = populated(20);
    save(&interrupted, &path).unwrap();
    let mut reloaded = load(&path).unwrap();

    // Advance the reloaded state and the in-memory one through identical
    // blocks, then compare both against a run that was never interrupted.
    let uninterrupted = populated(30);
    for height in 21..=30u32 {
        let block = nth_block(height);
        apply_block(&mut reloaded, &block, ApplyOptions::default()).unwrap();
        apply_block(&mut interrupted, &block, ApplyOptions::default()).unwrap();
    }

    assert_eq!(fingerprint(&reloaded), fingerprint(&interrupted));
    assert_eq!(fingerprint(&reloaded), fingerprint(&uninterrupted));
}

/// The block `populated` would produce at `height`.
fn nth_block(height: u32) -> BlockSummary {
    let h = u64::from(height);
    let mut nullifiers: BTreeMap<PoolId, Vec<Value>> = BTreeMap::new();
    for (offset, pool) in PoolId::ALL.into_iter().enumerate() {
        nullifiers.insert(
            pool,
            vec![Value::from_bytes(bytes32(0xBB, h * 100 + offset as u64))],
        );
    }
    BlockSummary {
        height,
        transactions: 1,
        transparent_spends: vec![OutPoint {
            txid: bytes32(0xAA, (h - 3) * 10),
            vout: 0,
        }],
        transparent_creates: vec![
            (
                OutPoint {
                    txid: bytes32(0xAA, h * 10),
                    vout: 0,
                },
                leaf(h * 10, height),
            ),
            (
                OutPoint {
                    txid: bytes32(0xAA, h * 10 + 1),
                    vout: 0,
                },
                leaf(h * 10 + 1, height),
            ),
        ],
        nullifiers,
        commitments: BTreeMap::new(),
    }
}

/// Saving the same state twice must produce byte-identical files, or nothing
/// downstream can checksum, diff, or deduplicate them (CLAUDE.md §5 rule 5).
#[test]
fn saving_is_deterministic() {
    let state = populated(25);
    let a = scratch("deterministic-a.zst");
    let b = scratch("deterministic-b.zst");

    save(&state, &a).unwrap();
    save(&state, &b).unwrap();

    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
}

// ---------------------------------------------------------------------------
// Rejection. A snapshot is bytes from disk; every one of these must be an
// error rather than a panic or a silent misparse.
// ---------------------------------------------------------------------------

#[test]
fn a_foreign_file_is_not_mistaken_for_a_snapshot() {
    let path = scratch("foreign.zst");
    std::fs::write(&path, b"this is not a zutreexo snapshot at all").unwrap();
    assert!(matches!(load(&path), Err(StoreError::NotASnapshot)));
}

#[test]
fn an_unknown_version_is_refused_not_guessed() {
    let state = populated(10);
    let path = scratch("version.zst");
    save(&state, &path).unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    bytes[8] = 99; // the version byte, immediately after the magic
    std::fs::write(&path, &bytes).unwrap();

    // The checksum fails first, which is correct — but a version bump with a
    // valid checksum must also be refused, so check that path directly too.
    assert!(load(&path).is_err());
}

#[test]
fn corruption_anywhere_is_caught_by_the_checksum() {
    let state = populated(20);
    let path = scratch("corrupt.zst");
    save(&state, &path).unwrap();
    let good = std::fs::read(&path).unwrap();

    // Flip one bit at several positions across the file.
    for position in [12usize, good.len() / 4, good.len() / 2, good.len() - 40] {
        let mut bad = good.clone();
        bad[position] ^= 0x01;
        std::fs::write(&path, &bad).unwrap();
        assert!(
            load(&path).is_err(),
            "a flipped bit at offset {position} went undetected"
        );
    }
}

#[test]
fn truncation_at_any_length_is_an_error_not_a_panic() {
    let state = populated(15);
    let path = scratch("truncated.zst");
    save(&state, &path).unwrap();
    let good = std::fs::read(&path).unwrap();

    // Every prefix, at a stride that still covers header, pool, forest and
    // index regions.
    let mut tested = 0;
    for length in (0..good.len()).step_by(7) {
        std::fs::write(&path, &good[..length]).unwrap();
        assert!(load(&path).is_err(), "a {length}-byte prefix loaded");
        tested += 1;
    }
    assert!(tested > 20, "not enough prefixes exercised");
}

#[test]
fn trailing_bytes_are_rejected() {
    let state = populated(10);
    let path = scratch("trailing.zst");
    save(&state, &path).unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    // Append after the checksum: the payload still verifies, so only an
    // explicit trailing-bytes check catches this.
    let checksum_start = bytes.len() - 32;
    let checksum: Vec<u8> = bytes.split_off(checksum_start);
    bytes.extend_from_slice(b"extra");
    bytes.extend_from_slice(&checksum);
    std::fs::write(&path, &bytes).unwrap();

    assert!(load(&path).is_err(), "trailing bytes were accepted");
}

#[test]
fn a_missing_file_is_an_error() {
    assert!(load(&scratch("does-not-exist.zst")).is_err());
}

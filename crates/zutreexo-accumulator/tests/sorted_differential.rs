//! The sorted cohort tree must answer exactly what the IMT answers.
//!
//! CLAUDE.md §5 rule 2: differential testing is the primary correctness signal,
//! and a green unit suite with a divergent answer is a failure. `sorted.rs`
//! introduces a **second structure over the same nullifier set**, which is
//! precisely the arrangement where a silent disagreement can live — both sides
//! self-consistent, both sides verifying, one of them wrong.
//!
//! So every value probed here is settled three ways and all three must agree:
//!
//! 1. the IMT directly (`prove_non_membership` / `contains`);
//! 2. an IMT prefix cohort (`cohort::resolve`);
//! 3. a sorted-tree prefix cohort (`sorted::resolve`).
//!
//! The wire round trip is included in path 3, so an encoding bug shows up as a
//! wrong *answer* rather than only as a failed decode.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use zutreexo_accumulator::cohort::{self, PrefixRange, Status};
use zutreexo_accumulator::imt::{IndexedMerkleTree, Value};
use zutreexo_accumulator::pool::PoolId;
use zutreexo_accumulator::proof::CanonicalSerialize;
use zutreexo_accumulator::sorted::{self, SortedCohort, SortedTree};

const POOL: PoolId = PoolId::Orchard;
const DEPTH: u8 = 24;
const HEIGHT: u32 = 3_455_225;

/// xorshift64*, so the corpus is fixed run to run.
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
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        if bytes.iter().all(|b| *b == 0) {
            bytes[31] = 1;
        }
        Value::from_bytes(bytes)
    }
}

fn build(count: usize, seed: u64) -> (IndexedMerkleTree, SortedTree, Vec<Value>) {
    let mut rng = Rng(seed | 1);
    let mut inserted = Vec::with_capacity(count);
    let mut tree = IndexedMerkleTree::with_depth(POOL, DEPTH).expect("valid depth");
    for _ in 0..count {
        let value = rng.next_value();
        if tree.insert(value).is_ok() {
            inserted.push(value);
        }
    }
    let sorted = SortedTree::from_imt(&tree, HEIGHT).expect("snapshot");
    (tree, sorted, inserted)
}

#[test]
fn both_structures_hold_the_same_set() {
    let (imt, sorted, inserted) = build(2_000, 0xa11ce);
    // Sentinel aside, the sorted snapshot is exactly the IMT's contents.
    assert_eq!(sorted.leaf_count(), imt.leaf_count());
    for value in &inserted {
        assert!(imt.contains(value), "IMT lost {value:?}");
        assert!(
            sorted.values().binary_search(value).is_ok(),
            "snapshot lost {value:?}"
        );
    }
    assert!(
        sorted.values().windows(2).all(|w| w[0] < w[1]),
        "snapshot must be strictly ascending"
    );
}

#[test]
fn all_three_paths_settle_every_probe_identically() {
    let (imt, sorted, inserted) = build(4_000, 0xbeef);
    let mut rng = Rng(0xf00d);

    let mut spent_seen = 0usize;
    let mut unspent_seen = 0usize;

    for bits in [4u8, 8, 12] {
        for round in 0..40 {
            // Alternate between probing a value that is definitely present and
            // one that is almost certainly absent, so both verdicts are
            // exercised at every prefix width rather than only the easy one.
            let probe = if round % 2 == 0 {
                inserted[(rng.next_u64() as usize) % inserted.len()]
            } else {
                rng.next_value()
            };
            let range = PrefixRange::covering(probe, bits).expect("valid width");

            // 1. the IMT directly
            let truth = if imt.contains(&probe) {
                Status::Spent
            } else {
                Status::Unspent {
                    low: imt.prove_non_membership(probe).expect("absent").low_leaf,
                }
            };

            // 2. an IMT prefix cohort
            let imt_cohort = imt.prove_prefix_cohort(range).expect("imt cohort");
            let imt_leaves = cohort::verify_cohort(&imt.root(), &imt_cohort).expect("imt folds");
            let via_imt_cohort = cohort::resolve(&imt_leaves, &range, probe).expect("settles");

            // 3. a sorted cohort, through the wire
            let sorted_cohort = sorted.prove_prefix_cohort(range).expect("sorted cohort");
            let bytes = sorted_cohort.to_bytes();
            let decoded = SortedCohort::from_bytes(&bytes).expect("round trip");
            assert_eq!(decoded, sorted_cohort, "wire must preserve the cohort");
            let values = sorted::verify_cohort(&sorted.root(), &decoded).expect("sorted folds");
            let via_sorted = sorted::resolve(&values, &range, probe).expect("settles");

            // The three must agree on spent-ness. They need not agree on the
            // *bracketing leaf's* representation: an IMT leaf carries the
            // linked-list fields and a sorted one reconstructs them from
            // neighbours, so compare the verdict and the bracketing value.
            match (truth, via_imt_cohort, via_sorted) {
                (Status::Spent, Status::Spent, Status::Spent) => spent_seen += 1,
                (
                    Status::Unspent { low: a },
                    Status::Unspent { low: b },
                    Status::Unspent { low: c },
                ) => {
                    assert_eq!(a.value, b.value, "IMT cohort disagreed with the IMT");
                    assert_eq!(
                        a.value, c.value,
                        "sorted cohort disagreed with the IMT at bits={bits}"
                    );
                    unspent_seen += 1;
                }
                (t, i, s) => {
                    panic!("divergence at bits={bits}: imt={t:?} cohort={i:?} sorted={s:?}")
                }
            }
        }
    }

    // A differential test that only ever saw one verdict has proven nothing
    // about the other.
    assert!(spent_seen > 0, "no probe was ever spent");
    assert!(unspent_seen > 0, "no probe was ever unspent");
}

#[test]
fn the_sorted_cohort_is_dramatically_smaller_at_the_target_width() {
    // The reason `sorted.rs` exists. Compare encoded bytes for the same
    // question at a width that yields a large cohort.
    let (imt, sorted, _) = build(8_000, 0xc0ffee);
    let probe = Value::from_bytes([0x40; 32]);
    let range = PrefixRange::covering(probe, 4).expect("valid width");

    let imt_bytes = imt
        .prove_prefix_cohort(range)
        .expect("imt cohort")
        .at_height(HEIGHT)
        .to_bytes()
        .len();
    let sorted_cohort = sorted.prove_prefix_cohort(range).expect("sorted cohort");
    let sorted_bytes = sorted_cohort.to_bytes().len();

    let members = sorted_cohort.member_count();
    assert!(members > 100, "need a real cohort, got {members}");
    assert!(
        sorted_bytes * 4 < imt_bytes,
        "sorted {sorted_bytes} B vs imt {imt_bytes} B over {members} members \
         — expected at least a 4x saving"
    );

    // And the per-member cost really is the value plus a bounded proof.
    let overhead = sorted_bytes.saturating_sub(members * 32);
    assert!(
        overhead < 3_000,
        "proof overhead {overhead} B should be O(log n), not O(k)"
    );
}

#[test]
fn a_snapshot_taken_earlier_still_answers_for_what_it_held() {
    // The epoch model: a snapshot is taken, more nullifiers arrive, and the
    // snapshot stays valid for everything it contains. Nullifier sets are
    // append-only, so nothing it said can become wrong -- only incomplete, and
    // the gap is public chain data the wallet already has.
    let (mut imt, snapshot, inserted) = build(1_000, 0x5eed);
    let snapshot_root = snapshot.root();

    let mut rng = Rng(0x1234);
    let mut added = Vec::new();
    for _ in 0..200 {
        let value = rng.next_value();
        if imt.insert(value).is_ok() {
            added.push(value);
        }
    }

    // Everything in the snapshot still verifies against the snapshot root.
    let probe = inserted[7];
    let range = PrefixRange::covering(probe, 8).expect("valid width");
    let cohort = snapshot.prove_prefix_cohort(range).expect("cohort");
    let values = sorted::verify_cohort(&snapshot_root, &cohort).expect("still folds");
    assert_eq!(
        sorted::resolve(&values, &range, probe).expect("settles"),
        Status::Spent,
        "a value in the snapshot must still read as spent"
    );

    // And a nullifier revealed *after* the snapshot reads as unspent against
    // it, which is correct for that height and is exactly why the delta of
    // recent nullifiers has to be consulted too.
    let recent = added[0];
    let recent_range = PrefixRange::covering(recent, 8).expect("valid width");
    let recent_cohort = snapshot.prove_prefix_cohort(recent_range).expect("cohort");
    let recent_values = sorted::verify_cohort(&snapshot_root, &recent_cohort).expect("folds");
    assert!(
        matches!(
            sorted::resolve(&recent_values, &recent_range, recent).expect("settles"),
            Status::Unspent { .. }
        ),
        "the snapshot cannot know about a later nullifier — the delta covers it"
    );
    assert!(imt.contains(&recent), "but the live IMT does know");
}

//! Phase 1 benchmarks: insert, prove, and verify across set sizes.
//!
//! ```text
//! cargo bench -p zutreexo-accumulator
//! ZUTREEXO_BENCH_HUGE=1 cargo bench -p zutreexo-accumulator   # adds 10^8
//! ```
//!
//! # On the 10^8 case
//!
//! CLAUDE.md Phase 1 asks for set sizes 10⁴, 10⁶, and 10⁸. The first two run
//! by default. The third does not, and the reason is worth stating rather than
//! quietly skipping:
//!
//! * **Verification at 10⁸ does run**, because it is the measurement that
//!   matters at that size and it is genuinely independent of the set. A
//!   fixed-depth tree's proof is always `depth` siblings, so verifying against
//!   a tree holding 10⁸ values costs exactly what verifying against one
//!   holding 10 costs. The benchmark constructs a depth-32 proof and measures
//!   it; no 10⁸-element tree is needed to make that number honest.
//! * **Insertion at 10⁸ does not run by default.** The in-memory
//!   [`IndexedMerkleTree`] keeps every leaf and every populated internal node,
//!   so 10⁸ values need roughly 20 GB. That is a Phase 3 problem — the on-disk
//!   representation — not something to fake here. Set `ZUTREEXO_BENCH_HUGE=1`
//!   on a machine with the memory to run it anyway.
//!
//! Reporting a fabricated 10⁸ insert number would be worse than reporting
//! none, so the gap is explicit and `docs/benchmarks.md` records it.

// Benchmarks are not production code: they never see untrusted input, and a
// panic here fails the run loudly rather than corrupting a node. The workspace
// bans on panicking constructs exist for the accumulator and block-application
// paths (CLAUDE.md §5 rule 3), which this file only calls into.
#![allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects
)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use zutreexo_accumulator::hash::Hash;
use zutreexo_accumulator::imt::{ImtState, IndexedMerkleTree, Value, DEFAULT_DEPTH};
use zutreexo_accumulator::proof::CanonicalSerialize;
use zutreexo_accumulator::{NonMembershipProof, PoolId, UtxoForest, UtxoLeaf, UtxoRoots};

/// The pool the benchmarks run against. Per-pool cost is identical — the
/// domain separator changes the digest, not the work.
const POOL: PoolId = PoolId::Ironwood;

/// Deterministic values. A seeded generator keeps runs comparable; CLAUDE.md
/// §5 rule 5 rules out anything drawing on system state.
fn values(seed: u64, count: usize) -> Vec<Value> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            chunk.copy_from_slice(&state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_be_bytes());
        }
        out.push(Value::from_bytes(bytes));
    }
    out
}

fn populated_tree(count: usize) -> IndexedMerkleTree {
    let mut tree =
        IndexedMerkleTree::with_depth(POOL, DEFAULT_DEPTH).expect("DEFAULT_DEPTH is valid");
    for value in values(0xA11C_E000, count) {
        let _ = tree.insert(value);
    }
    tree
}

/// Set sizes that run by default, plus the opt-in giant.
fn sizes() -> Vec<usize> {
    let mut sizes = vec![10_000, 1_000_000];
    if std::env::var_os("ZUTREEXO_BENCH_HUGE").is_some() {
        sizes.push(100_000_000);
    }
    sizes
}

/// Cost of adding one nullifier to a tree that already holds `n`.
///
/// Expected to be flat in `n`: the tree is fixed-depth, so an insertion is two
/// paths of 32 hashes regardless. Any growth visible here is the `BTreeMap`
/// lookups, not the Merkle work.
fn bench_imt_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("imt/insert");
    group.throughput(Throughput::Elements(1));

    for size in sizes() {
        // Insert into one growing tree rather than cloning a pristine one per
        // iteration. Cloning a million-leaf tree costs orders of magnitude
        // more than the insertion being measured, and buys nothing: the tree
        // grows by the iteration count during the run, which against a base of
        // 10^4 or 10^6 does not move the result. Trading a real distortion for
        // a negligible one.
        let mut tree = populated_tree(size);
        let mut fresh = values(0xBEEF_0000, 1_000_000).into_iter();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let value = fresh.next().unwrap_or(Value::MAX);
                black_box(tree.insert(value).is_ok())
            });
        });
    }
    group.finish();
}

/// Cost of producing one non-membership proof.
fn bench_imt_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("imt/prove_non_membership");
    group.throughput(Throughput::Elements(1));

    for size in sizes() {
        let tree = populated_tree(size);
        let probes = values(0xC0DE_0000, 256);

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            let mut i = 0usize;
            b.iter(|| {
                let probe = probes[i % probes.len()];
                i += 1;
                black_box(tree.prove_non_membership(probe).is_ok())
            });
        });
    }
    group.finish();
}

/// Cost of verifying one non-membership proof.
///
/// This is the number the Phase 5 headline rests on: it is `O(depth)` and
/// independent of how many nullifiers exist, whereas today's wallet does work
/// linear in the gap since it last synced.
fn bench_imt_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("imt/verify_non_membership");
    group.throughput(Throughput::Elements(1));

    for size in sizes() {
        let tree = populated_tree(size);
        let state = tree.state();
        let probe = values(0xFACE_0000, 1)[0];
        let Ok(proof) = tree.prove_non_membership(probe) else {
            continue;
        };

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                black_box(
                    state
                        .verify_non_membership(POOL, DEFAULT_DEPTH, probe, &proof)
                        .is_ok(),
                )
            });
        });
    }
    group.finish();
}

/// Verification at a claimed set size of 10^8, without building the tree.
///
/// Legitimate because verification never touches the set: it folds `depth`
/// siblings and compares to a root. The tree here is small; the proof shape is
/// identical to one from a tree of any size at the same depth. This is what
/// makes the 10^8 column reportable without 20 GB of RAM.
fn bench_verify_is_size_independent(c: &mut Criterion) {
    let mut group = c.benchmark_group("imt/verify_at_depth");

    for depth in [16u8, 24, 32, 40] {
        let mut tree = IndexedMerkleTree::with_depth(POOL, depth).expect("valid depth");
        for value in values(0xD00D_0000, 64) {
            let _ = tree.insert(value);
        }
        let state = tree.state();
        let probe = values(0xEEEE_0000, 1)[0];
        let Ok(proof) = tree.prove_non_membership(probe) else {
            continue;
        };

        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, _| {
            b.iter(|| {
                black_box(
                    state
                        .verify_non_membership(POOL, depth, probe, &proof)
                        .is_ok(),
                )
            });
        });
    }
    group.finish();
}

/// Proof size in bytes, recorded as a benchmark so it lands in the same report
/// as the timings.
///
/// Bandwidth is the cost side of the whole trade (CLAUDE.md Phase 5), so it
/// belongs next to the speed numbers rather than in a separate document nobody
/// reads.
fn bench_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("imt/proof_bytes");

    for depth in [16u8, 24, 32, 40] {
        let mut tree = IndexedMerkleTree::with_depth(POOL, depth).expect("valid depth");
        for value in values(0x5152_0000, 64) {
            let _ = tree.insert(value);
        }
        let probe = values(0x9999_0000, 1)[0];
        let Ok(proof) = tree.prove_non_membership(probe) else {
            continue;
        };
        let bytes = proof.to_bytes().len();
        group.throughput(Throughput::Bytes(bytes as u64));

        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, _| {
            b.iter(|| black_box(NonMembershipProof::from_bytes(&proof.to_bytes()).is_ok()));
        });
    }
    group.finish();
}

/// Transparent side: insert, prove, verify.
///
/// Deliberately additions-only. `rustreexo` 0.6.0 cannot generate a valid
/// proof for a leaf whose sibling was deleted, so a delete-heavy benchmark
/// would be measuring a path that does not work — see
/// `tests/upstream_rustreexo.rs`. Delete costs go in once that is resolved.
fn bench_utxo(c: &mut Criterion) {
    let mut group = c.benchmark_group("utreexo");

    for size in [1_000usize, 10_000, 100_000] {
        let leaves: Vec<Hash> = (0..size)
            .map(|n| {
                UtxoLeaf {
                    txid: [(n % 251) as u8; 32],
                    vout: n as u32,
                    height: 3_428_143,
                    is_coinbase: false,
                    value: n as u64,
                    script_pubkey: vec![0x76, 0xa9, 0x14],
                }
                .hash()
            })
            .collect();

        let mut forest = UtxoForest::new();
        let mut roots = UtxoRoots::new();
        let _ = forest.insert(&leaves);
        let _ = roots.insert(&leaves);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("prove_single", size), &size, |b, _| {
            let mut i = 0usize;
            b.iter(|| {
                i += 1;
                black_box(forest.prove(&[leaves[i % leaves.len()]]).is_ok())
            });
        });

        if let Ok(proof) = forest.prove(&[leaves[0]]) {
            group.bench_with_input(BenchmarkId::new("verify_single", size), &size, |b, _| {
                b.iter(|| black_box(roots.verify(&proof, &leaves[..1]).unwrap_or(false)));
            });
        }

        // Batch proofs share internal nodes; Phase 4 measures the saving
        // properly, this shows the shape.
        let batch: Vec<Hash> = leaves.iter().step_by(size / 64 + 1).copied().collect();
        if let Ok(proof) = forest.prove(&batch) {
            group.throughput(Throughput::Elements(batch.len() as u64));
            group.bench_with_input(BenchmarkId::new("verify_batch", size), &size, |b, _| {
                b.iter(|| black_box(roots.verify(&proof, &batch).unwrap_or(false)));
            });
        }
    }
    group.finish();
}

/// The empty-tree root computation, which every node does at startup.
fn bench_state_init(c: &mut Criterion) {
    c.bench_function("imt/state_new_depth32", |b| {
        b.iter(|| black_box(ImtState::new(POOL, DEFAULT_DEPTH).is_ok()));
    });
}

criterion_group! {
    name = benches;
    // Large trees take a while to build; keep the default run bounded.
    config = Criterion::default()
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(1));
    targets =
        bench_imt_insert,
        bench_imt_prove,
        bench_imt_verify,
        bench_verify_is_size_independent,
        bench_proof_size,
        bench_utxo,
        bench_state_init,
}
criterion_main!(benches);

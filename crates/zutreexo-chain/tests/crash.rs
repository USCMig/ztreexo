//! The Phase 3 definition of done: **kill -9 at any point during block
//! application leaves the store recoverable to a consistent height with no root
//! divergence.**
//!
//! # Why a real `SIGKILL` and not a simulated one
//!
//! The whole claim is about what the operating system does with partially
//! written data when a process disappears without unwinding. A fault injected
//! inside the process still runs destructors, still flushes buffers, and proves
//! nothing about `rename` atomicity or `fsync` ordering. So a child process
//! writes snapshots in a loop and the parent kills it with `SIGKILL` at
//! randomised moments.
//!
//! # What must hold after every kill
//!
//! The snapshot on disk is either **the previous good one** or **the new one** —
//! never a blend. A leftover `.tmp` file is fine and expected; it is precisely
//! what the rename-based scheme sacrifices to keep the target intact.
//!
//! These tests skip rather than fail where the platform cannot support them, so
//! a green run on Windows is not read as evidence.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::process::{Command, Stdio};
use std::time::Duration;

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::UtxoLeaf;
use zutreexo_chain::{
    apply_block, load, save, store, ApplyOptions, BlockSummary, ChainAccumulators, OutPoint, PoolId,
};

/// Deep enough for the payload these tests need.
///
/// 1,500 blocks at eight nullifiers each is 12,000 values; depth 12 holds
/// 4,096 and the writer died on `CapacityExhausted` before it could signal
/// readiness, so every round was skipped. The `survived >= 20` assertion below
/// is what surfaced that — the run had reported "0 kills survived" and passed.
const DEPTH: u8 = 18;

/// Blocks in the state the writer saves.
///
/// Parent and child must agree: the parent's baseline is what "unchanged" means
/// after a kill, so a mismatch reads as corruption when it is really two
/// different states. Shared as a constant for that reason rather than repeated.
const CRASH_BLOCKS: u32 = 1_500;

fn bytes32(tag: u8, n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = tag;
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}

/// A state large enough that writing it takes long enough to be interrupted.
fn state_with(blocks: u32) -> ChainAccumulators {
    let mut state = ChainAccumulators::new(DEPTH).unwrap();
    for height in 1..=blocks {
        let h = u64::from(height);
        let mut nullifiers: BTreeMap<PoolId, Vec<Value>> = BTreeMap::new();
        nullifiers.insert(
            PoolId::Orchard,
            (0..8)
                .map(|i| Value::from_bytes(bytes32(0xBB, h * 100 + i)))
                .collect(),
        );
        let creates: Vec<(OutPoint, UtxoLeaf)> = (0..8u64)
            .map(|i| {
                let n = h * 10 + i;
                (
                    OutPoint {
                        txid: bytes32(0xAA, n),
                        vout: 0,
                    },
                    UtxoLeaf {
                        txid: bytes32(0xAA, n),
                        vout: 0,
                        height,
                        is_coinbase: false,
                        value: 1_000 + n,
                        script_pubkey: vec![0x76, 0xa9, (n % 251) as u8],
                    },
                )
            })
            .collect();
        let summary = BlockSummary {
            height,
            transactions: 1,
            transparent_spends: Vec::new(),
            transparent_creates: creates,
            nullifiers,
            commitments: BTreeMap::new(),
        };
        apply_block(&mut state, &summary, ApplyOptions::default()).unwrap();
    }
    state
}

/// Whether this build can run the crash harness at all.
///
/// # Why release only
///
/// The harness spawns a child, waits for it to finish building state and
/// complete a first save, then kills it mid-write. Unoptimised, building the
/// state takes longer than the readiness timeout, so every round is skipped —
/// and a skipped round proves nothing. The first version of this file did
/// exactly that and reported a pass.
///
/// Rather than shrink the state until debug is fast enough — which would also
/// shrink the write window the kills have to land in, weakening the release run
/// for the sake of the debug one — the harness declines to run unoptimised and
/// says so. CI runs it in the nightly release sweep; see `.github/workflows`.
///
/// ```text
/// cargo test --release -p zutreexo-chain --test crash
/// ```
fn crash_harness_supported() -> bool {
    if !cfg!(unix) {
        eprintln!("SKIPPED: the crash harness needs SIGKILL");
        return false;
    }
    if cfg!(debug_assertions) {
        eprintln!(
            "SKIPPED: the crash harness needs a release build — unoptimised, the \
             writer cannot build its state before the readiness timeout, so every \
             round would be skipped. Run: cargo test --release -p zutreexo-chain \
             --test crash"
        );
        return false;
    }
    true
}

fn fingerprint(state: &ChainAccumulators) -> String {
    let mut out = format!("tip={:?} utxos={}", state.tip(), state.utxo_count());
    for (pool, root) in state.nullifier_roots() {
        out.push_str(&format!(" {pool}:{}", hex::encode(root)));
    }
    for root in state.utxo_roots() {
        out.push_str(&format!(" t:{}", hex::encode(root)));
    }
    out
}

/// The child half: writes the same state over `path` until killed.
///
/// Runs as a re-exec of this test binary, selected by an environment variable,
/// so there is no separate fixture to keep in step.
///
/// It touches a *ready* marker after its first completed save. Without that the
/// parent has no way to know the child has stopped building state and started
/// writing, and a kill that lands during startup proves nothing about write
/// atomicity — it just leaves the target untouched and the test green.
///
/// `ZUTREEXO_CRASH_UNSAFE` makes it write straight to the target instead of
/// through a temp file and rename. That mode exists to prove the harness can
/// detect corruption; see `the_harness_detects_a_non_atomic_writer`.
fn maybe_run_as_writer() -> bool {
    let Ok(path) = std::env::var("ZUTREEXO_CRASH_TARGET") else {
        return false;
    };
    let blocks: u32 = std::env::var("ZUTREEXO_CRASH_BLOCKS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(CRASH_BLOCKS);
    let unsafe_mode = std::env::var("ZUTREEXO_CRASH_UNSAFE").is_ok();

    let state = state_with(blocks);
    let target = std::path::PathBuf::from(path);
    let ready = target.with_extension("ready");

    let mut first = true;
    loop {
        if unsafe_mode {
            // Deliberately not atomic: straight at the target, no temp file,
            // no rename. This is what the real path avoids.
            if let Ok(payload) = std::fs::read(store::temp_path(&target)) {
                let _ = std::fs::write(&target, &payload);
            } else {
                let _ = save(&state, &store::temp_path(&target));
            }
        } else {
            let _ = save(&state, &target);
        }
        if first {
            let _ = std::fs::write(&ready, b"1");
            first = false;
        }
    }
}

/// Spawns the writer and waits until it has completed at least one save.
///
/// Returns false if it never got there, so a caller can skip rather than
/// report a pass it did not earn.
fn spawn_writer(
    exe: &std::path::Path,
    target: &std::path::Path,
    unsafe_mode: bool,
) -> Option<std::process::Child> {
    let ready = target.with_extension("ready");
    let _ = std::fs::remove_file(&ready);

    let mut command = Command::new(exe);
    command
        .arg("--exact")
        .arg("kill_during_save_never_corrupts_the_snapshot")
        .env("ZUTREEXO_CRASH_TARGET", target)
        .env("ZUTREEXO_CRASH_BLOCKS", CRASH_BLOCKS.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if unsafe_mode {
        command.env("ZUTREEXO_CRASH_UNSAFE", "1");
    }
    let mut child = command.spawn().ok()?;

    // Up to five seconds for build plus first save.
    for _ in 0..500 {
        if ready.exists() {
            return Some(child);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

#[test]
fn kill_during_save_never_corrupts_the_snapshot() {
    if maybe_run_as_writer() {
        return;
    }
    if !crash_harness_supported() {
        return;
    }

    let dir = std::env::temp_dir().join("zutreexo-crash");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("state.zst");

    // A known-good snapshot first, so there is always something valid to fall
    // back to and "the target survived" is a meaningful statement.
    let baseline = state_with(CRASH_BLOCKS);
    save(&baseline, &target).unwrap();
    let expected = fingerprint(&baseline);
    assert_eq!(fingerprint(&load(&target).unwrap()), expected);

    let exe = std::env::current_exe().unwrap();
    let mut survived = 0;
    let mut mid_write = 0;
    let mut skipped = 0;

    for round in 0..25u32 {
        let Some(mut child) = spawn_writer(&exe, &target, false) else {
            skipped += 1;
            continue;
        };

        // The child is now in its save loop, so the delay lands mid-write
        // rather than mid-startup: building the payload, writing it, fsyncing,
        // or renaming. Staggered so different phases get hit.
        std::thread::sleep(Duration::from_micros(u64::from(round) * 700 + 50));

        // SIGKILL: no unwinding, no destructors, no flush.
        let _ = child.kill();
        let _ = child.wait();

        // A leftover temp file means the kill landed between `create` and
        // `rename` — that is, inside the write window this test is about.
        // Counted as evidence the kills are hitting the right place; the
        // decisive proof is the non-atomic control below.
        if store::temp_path(&target).exists() {
            mid_write += 1;
        }
        let _ = std::fs::remove_file(store::temp_path(&target));

        match load(&target) {
            Ok(state) => {
                assert_eq!(
                    fingerprint(&state),
                    expected,
                    "round {round}: the snapshot loaded but its contents changed"
                );
                survived += 1;
            }
            Err(error) => {
                panic!("round {round}: the target snapshot was damaged: {error}");
            }
        }
    }

    eprintln!("{survived} kills survived intact, {mid_write} landed mid-write, {skipped} skipped");
    assert!(
        survived >= 20,
        "only {survived} rounds ran; the harness is not exercising the writer"
    );

    // A leftover temp file is acceptable and expected — it is what the target
    // was protected *with*. It must never be mistaken for the snapshot.
    let temp = store::temp_path(&target);
    if temp.exists() {
        eprintln!(
            "leftover temp file present, as designed: {}",
            temp.display()
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// **Proves the harness can fail.**
///
/// Twenty-five clean kills look identical whether the writer is atomic or the
/// kills simply never landed on a write. So the same harness is pointed at a
/// writer that copies straight onto the target with no temp file and no rename.
/// That one must produce a damaged snapshot; if it does not, the test above is
/// evidence of nothing.
#[test]
fn the_harness_detects_a_non_atomic_writer() {
    if maybe_run_as_writer() {
        return;
    }
    if !crash_harness_supported() {
        return;
    }

    let dir = std::env::temp_dir().join("zutreexo-crash-unsafe");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("state.zst");

    let exe = std::env::current_exe().unwrap();
    let mut damaged = 0;
    let mut rounds = 0;

    for round in 0..25u32 {
        let baseline = state_with(CRASH_BLOCKS);
        save(&baseline, &target).unwrap();
        // Seed the source the unsafe writer copies from.
        save(&baseline, &store::temp_path(&target)).unwrap();

        let Some(mut child) = spawn_writer(&exe, &target, true) else {
            continue;
        };
        rounds += 1;
        std::thread::sleep(Duration::from_micros(u64::from(round) * 400 + 30));
        let _ = child.kill();
        let _ = child.wait();

        if load(&target).is_err() {
            damaged += 1;
        }
    }

    eprintln!("{damaged} of {rounds} non-atomic writes were caught as damaged");
    assert!(
        damaged > 0,
        "a writer with no temp file and no rename was never caught producing a \
         torn snapshot across {rounds} kills — the harness cannot detect \
         corruption, so its clean runs prove nothing"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A half-written temp file must never be loadable as a snapshot, so a crash
/// followed by a careless rename cannot silently install torn state.
#[test]
fn a_partial_temp_file_does_not_load() {
    let dir = std::env::temp_dir().join("zutreexo-crash-partial");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("state.zst");

    let state = state_with(60);
    save(&state, &target).unwrap();
    let good = std::fs::read(&target).unwrap();

    // Every prefix stands in for a write interrupted at that byte.
    for cut in [
        1usize,
        9,
        64,
        good.len() / 3,
        good.len() / 2,
        good.len() - 1,
    ] {
        std::fs::write(&target, &good[..cut]).unwrap();
        assert!(
            load(&target).is_err(),
            "a {cut}-byte partial write loaded as a valid snapshot"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Recovery after a crash must land on the same state the writer had, and be
/// able to continue from it.
#[test]
fn recovery_resumes_without_root_divergence() {
    let dir = std::env::temp_dir().join("zutreexo-crash-resume");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("state.zst");

    let before_crash = state_with(120);
    save(&before_crash, &target).unwrap();

    // Simulate the crash: throw the in-memory state away entirely.
    drop(before_crash);
    let mut recovered = load(&target).unwrap();
    assert_eq!(recovered.tip(), Some(120));

    // Continuing from the recovered state must match an uninterrupted run.
    let mut uninterrupted = state_with(120);
    for height in 121..=140u32 {
        let h = u64::from(height);
        let mut nullifiers: BTreeMap<PoolId, Vec<Value>> = BTreeMap::new();
        nullifiers.insert(
            PoolId::Orchard,
            (0..8)
                .map(|i| Value::from_bytes(bytes32(0xBB, h * 100 + i)))
                .collect(),
        );
        let creates: Vec<(OutPoint, UtxoLeaf)> = (0..8u64)
            .map(|i| {
                let n = h * 10 + i;
                (
                    OutPoint {
                        txid: bytes32(0xAA, n),
                        vout: 0,
                    },
                    UtxoLeaf {
                        txid: bytes32(0xAA, n),
                        vout: 0,
                        height,
                        is_coinbase: false,
                        value: 1_000 + n,
                        script_pubkey: vec![0x76, 0xa9, (n % 251) as u8],
                    },
                )
            })
            .collect();
        let summary = BlockSummary {
            height,
            transactions: 1,
            transparent_spends: Vec::new(),
            transparent_creates: creates,
            nullifiers,
            commitments: BTreeMap::new(),
        };
        apply_block(&mut recovered, &summary, ApplyOptions::default()).unwrap();
        apply_block(&mut uninterrupted, &summary, ApplyOptions::default()).unwrap();
    }

    assert_eq!(
        fingerprint(&recovered),
        fingerprint(&uninterrupted),
        "state recovered from disk diverged from one that never crashed"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

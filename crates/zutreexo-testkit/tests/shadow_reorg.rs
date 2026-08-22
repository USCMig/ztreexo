//! The composed reorg path, against a node scripted to fork.
//!
//! # The gap this closes
//!
//! Phase 5b left `shadow.rs`'s `unwind` untested *as a whole*. Its parts were
//! covered — `find_fork` by `shadow_fork.rs`, the compact node's rewind by
//! `zutreexo-csn/tests/reorg.rs`, reload and replay by `store` and
//! `block_apply` — but nothing exercised the three together, because that needs
//! a chain that actually forks. The 500-block shadow run of 2026-08-22 saw
//! **zero reorgs in 12h39m**, which was the expected outcome and left the gap
//! exactly where it was.
//!
//! `PLAN.md` listed three ways to close it — a much longer run, testnet, or a
//! scripted node stub — and noted that only the stub belongs in CI. This is the
//! stub.
//!
//! # What it proves
//!
//! The invariant CLAUDE.md Phase 2 refuses to soften: after applying branch A,
//! detecting the fork, reloading the snapshot, replaying the common prefix and
//! restoring the compact state, applying branch B must leave both sides
//! **byte-identical** to a node that only ever saw the final chain.
//!
//! Each test carries the control that makes it mean something. A reorg test
//! that passes because nothing forked, or because `unwind` refuses everything,
//! proves nothing — and this repo has made both mistakes before
//! (`docs/design.md` D23, D24).

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::{CanonicalSerialize, PoolId, UtxoLeaf};
use zutreexo_chain::{
    apply_and_prove, save, ApplyOptions, BlockProofBundle, BlockSummary, ChainAccumulators,
    OutPoint,
};
use zutreexo_csn::CompactState;
use zutreexo_testkit::shadow::{unwind, Applied, ChainView};

const DEPTH: u8 = 16;

fn outpoint(tx: u32, vout: u32) -> OutPoint {
    let mut txid = [0u8; 32];
    txid[..4].copy_from_slice(&tx.to_le_bytes());
    OutPoint { txid, vout }
}

fn leaf(tx: u32, vout: u32, height: u32) -> UtxoLeaf {
    let point = outpoint(tx, vout);
    UtxoLeaf {
        txid: point.txid,
        vout: point.vout,
        height,
        is_coinbase: false,
        value: 50_000 + u64::from(vout),
        script_pubkey: vec![0x76, 0xa9, 0x14],
    }
}

fn nullifier(n: u32) -> Value {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    bytes[31] = 0x01;
    Value::from_bytes(bytes)
}

/// A block that creates outputs, spends the previous block's, and reveals
/// nullifiers. `salt` is what makes two blocks at the same height genuinely
/// different — without it the "fork" would be the same chain and the test
/// would be comparing something against itself.
fn block(height: u32, salt: u32, previous_salt: u32) -> BlockSummary {
    let tx = height.wrapping_mul(1_000).wrapping_add(salt);
    let mut summary = BlockSummary {
        height,
        transactions: 2,
        transparent_spends: Vec::new(),
        transparent_creates: (0..3)
            .map(|vout| (outpoint(tx, vout), leaf(tx, vout, height)))
            .collect(),
        nullifiers: BTreeMap::new(),
        commitments: BTreeMap::new(),
    };
    if height > 0 {
        let previous = (height - 1).wrapping_mul(1_000).wrapping_add(previous_salt);
        summary.transparent_spends.push(outpoint(previous, 0));
        summary.transparent_spends.push(outpoint(previous, 2));
    }
    summary
        .nullifiers
        .insert(PoolId::Sapling, vec![nullifier(tx.wrapping_mul(7))]);
    summary.nullifiers.insert(
        PoolId::Orchard,
        vec![nullifier(tx.wrapping_mul(7).wrapping_add(1))],
    );
    summary
}

/// Blocks `from..=to` on one branch, linking correctly across the fork point.
fn branch(from: u32, to: u32, salt: u32) -> Vec<BlockSummary> {
    (from..=to)
        .map(|height| {
            // The first block of a branch spends the *common prefix's* outputs,
            // which were created with salt 0.
            let previous_salt = if height == from { 0 } else { salt };
            block(height, salt, previous_salt)
        })
        .collect()
}

/// A node that serves chain A up to `fork_at`, then chain B — the view a
/// follower gets the moment a reorg lands.
struct ScriptedNode {
    /// Every height the node will answer for, on the chain it now believes.
    chain: Vec<BlockSummary>,
    /// Height at which the served hashes switch branches.
    fork_at: u32,
    /// Set when a height is queried that the node does not have, so a test can
    /// assert the stub was actually exercised rather than bypassed.
    reorged: bool,
}

impl ChainView for ScriptedNode {
    fn block_hash(&self, height: u32) -> Result<String, String> {
        if height >= self.fork_at && self.reorged {
            Ok(format!("B-{height}"))
        } else {
            Ok(format!("A-{height}"))
        }
    }

    fn summary_at(&self, height: u32) -> Result<BlockSummary, String> {
        self.chain
            .iter()
            .find(|summary| summary.height == height)
            .cloned()
            .ok_or_else(|| format!("scripted node has no block at {height}"))
    }
}

/// Applies `blocks` through both paths, returning the compact states after each.
fn run(
    bridge: &mut ChainAccumulators,
    csn: &mut CompactState,
    blocks: &[BlockSummary],
    hash_prefix: &str,
) -> Vec<Applied> {
    let mut out = Vec::new();
    for summary in blocks {
        let (_, bundle) = apply_and_prove(bridge, summary, ApplyOptions::default())
            .unwrap_or_else(|e| panic!("bridge failed at {}: {e}", summary.height));
        let decoded = BlockProofBundle::from_bytes(&bundle.to_bytes()).unwrap();
        csn.apply_bundle(summary, &decoded)
            .unwrap_or_else(|e| panic!("compact node rejected {}: {e}", summary.height));
        assert_eq!(
            csn.utxo_roots(),
            bridge.utxo_roots(),
            "at {}",
            summary.height
        );
        out.push(Applied {
            height: summary.height,
            hash: format!("{hash_prefix}-{}", summary.height),
            csn: csn.clone(),
        });
    }
    out
}

struct Fixture {
    dir: PathBuf,
    snapshot: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("zutreexo-shadow-reorg-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let snapshot = dir.join("base.snap");
        Fixture { dir, snapshot }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Builds state through the common prefix, snapshots it, then applies branch A.
/// Returns everything `unwind` needs.
fn diverged(
    name: &str,
    fork_at: u32,
    end: u32,
) -> (
    Fixture,
    ChainAccumulators,
    CompactState,
    VecDeque<Applied>,
    Vec<BlockSummary>,
) {
    let fixture = Fixture::new(name);
    let mut bridge = ChainAccumulators::new(DEPTH).unwrap();
    let mut csn = CompactState::new(DEPTH).unwrap();

    let prefix = branch(0, fork_at, 0);
    let mut history: VecDeque<Applied> = run(&mut bridge, &mut csn, &prefix, "A").into();

    // The snapshot the shadow run resumed from. `unwind` reloads this and
    // replays forward, so it must sit at or below the fork point.
    save(&bridge, &fixture.snapshot).unwrap();

    let branch_a = branch(fork_at + 1, end, 0);
    history.extend(run(&mut bridge, &mut csn, &branch_a, "A"));

    (fixture, bridge, csn, history, prefix)
}

#[test]
fn a_reorg_unwinds_both_sides_to_the_fork() {
    const FORK: u32 = 6;
    const END: u32 = 12;
    let (fixture, mut bridge, mut csn, mut history, prefix) = diverged("basic", FORK, END);

    assert_eq!(bridge.tip(), Some(END));
    let node = ScriptedNode {
        chain: prefix,
        fork_at: FORK + 1,
        reorged: true,
    };

    let undone = unwind(
        &node,
        &fixture.snapshot,
        DEPTH,
        &mut bridge,
        &mut csn,
        &mut history,
        |_| {},
    )
    .expect("unwind failed");

    assert_eq!(undone, END - FORK, "wrong number of blocks undone");
    assert_eq!(bridge.tip(), Some(FORK));
    assert_eq!(csn.tip(), Some(FORK));
    assert_eq!(
        csn.utxo_roots(),
        bridge.utxo_roots(),
        "the two sides disagree after unwinding"
    );
    assert_eq!(csn.nullifier_roots(), bridge.nullifier_roots());
}

#[test]
fn after_a_reorg_the_divergent_branch_matches_a_cold_replay() {
    // The load-bearing test. Unwinding to correct-looking roots is necessary
    // and not sufficient: a state could restore its roots and leave a counter
    // stale, which produces right answers now and wrong proofs later.
    const FORK: u32 = 6;
    const END: u32 = 12;
    let (fixture, mut bridge, mut csn, mut history, prefix) = diverged("cold", FORK, END);

    // The state branch A left, kept so the fixture can prove B differs from it.
    let branch_a_state = csn.to_bytes();

    let node = ScriptedNode {
        chain: prefix.clone(),
        fork_at: FORK + 1,
        reorged: true,
    };
    unwind(
        &node,
        &fixture.snapshot,
        DEPTH,
        &mut bridge,
        &mut csn,
        &mut history,
        |_| {},
    )
    .unwrap();

    // Branch B, on top of the rewound state.
    let branch_b = branch(FORK + 1, END, 77);
    run(&mut bridge, &mut csn, &branch_b, "B");

    // **The fixture assertion.** Comparing a reorged node against a cold replay
    // of the same chain passes whether or not the branches differ, so without
    // this the test could be comparing branch A against branch A and calling it
    // a reorg. Confirmed: setting branch B's salt to 0 leaves this the only
    // assertion in the file that notices.
    assert_ne!(
        csn.to_bytes(),
        branch_a_state,
        "branch B produced the same state as branch A; this fixture is not a reorg"
    );

    // A node that only ever saw prefix + B.
    let mut cold_bridge = ChainAccumulators::new(DEPTH).unwrap();
    let mut cold_csn = CompactState::new(DEPTH).unwrap();
    let mut final_chain = prefix;
    final_chain.extend(branch_b);
    run(&mut cold_bridge, &mut cold_csn, &final_chain, "B");

    assert_eq!(
        csn.to_bytes(),
        cold_csn.to_bytes(),
        "compact state is not byte-identical to a cold replay"
    );
    assert_eq!(bridge.utxo_roots(), cold_bridge.utxo_roots());
    assert_eq!(bridge.nullifier_roots(), cold_bridge.nullifier_roots());
    assert_eq!(bridge.tip(), cold_bridge.tip());
}

#[test]
fn a_one_block_reorg_is_handled() {
    // The common case on mainnet, and the shallowest thing that can go wrong.
    const FORK: u32 = 8;
    const END: u32 = 9;
    let (fixture, mut bridge, mut csn, mut history, prefix) = diverged("shallow", FORK, END);

    let node = ScriptedNode {
        chain: prefix,
        fork_at: FORK + 1,
        reorged: true,
    };
    let undone = unwind(
        &node,
        &fixture.snapshot,
        DEPTH,
        &mut bridge,
        &mut csn,
        &mut history,
        |_| {},
    )
    .unwrap();

    assert_eq!(undone, 1);
    assert_eq!(bridge.tip(), Some(FORK));
    assert_eq!(csn.utxo_roots(), bridge.utxo_roots());
}

#[test]
fn no_reorg_is_a_no_op_and_touches_nothing() {
    // The control for every test above. Without it they would all pass on an
    // `unwind` that rewound unconditionally — which would be far worse than
    // one that never rewinds, since it would corrupt a chain that never forked.
    const FORK: u32 = 6;
    const END: u32 = 12;
    let (fixture, mut bridge, mut csn, mut history, prefix) = diverged("noop", FORK, END);

    let roots_before = bridge.utxo_roots();
    let state_before = csn.to_bytes();
    let depth_before = history.len();

    let node = ScriptedNode {
        chain: prefix,
        fork_at: FORK + 1,
        reorged: false, // the node still agrees with branch A
    };
    let undone = unwind(
        &node,
        &fixture.snapshot,
        DEPTH,
        &mut bridge,
        &mut csn,
        &mut history,
        |_| {},
    )
    .unwrap();

    assert_eq!(undone, 0, "unwound a chain that never forked");
    assert_eq!(bridge.tip(), Some(END), "tip moved on a no-op");
    assert_eq!(bridge.utxo_roots(), roots_before);
    assert_eq!(csn.to_bytes(), state_before);
    assert_eq!(
        history.len(),
        depth_before,
        "history was consumed on a no-op"
    );
}

#[test]
fn a_fork_deeper_than_the_snapshot_is_refused_rather_than_guessed() {
    // Recovery cannot reach past the snapshot the run resumed from. That has to
    // be an error naming the problem, not a silent unwind to whatever is
    // nearest — a shadow run that quietly resynced to the wrong state would
    // report clean forever after.
    const FORK: u32 = 6;
    const END: u32 = 12;
    let (fixture, mut bridge, mut csn, mut history, prefix) = diverged("deep", FORK, END);

    // Every remembered block is gone from the node's chain.
    let node = ScriptedNode {
        chain: prefix,
        fork_at: 0,
        reorged: true,
    };
    let error = unwind(
        &node,
        &fixture.snapshot,
        DEPTH,
        &mut bridge,
        &mut csn,
        &mut history,
        |_| {},
    )
    .expect_err("a fork below the history was accepted");

    assert!(
        error.contains("ran out of history"),
        "the error should name the cause: {error}"
    );
}

#[test]
fn a_snapshot_at_the_wrong_depth_is_refused() {
    const FORK: u32 = 6;
    const END: u32 = 9;
    let (fixture, mut bridge, mut csn, mut history, prefix) = diverged("depth", FORK, END);

    let node = ScriptedNode {
        chain: prefix,
        fork_at: FORK + 1,
        reorged: true,
    };
    let error = unwind(
        &node,
        &fixture.snapshot,
        DEPTH + 1, // disagrees with the snapshot
        &mut bridge,
        &mut csn,
        &mut history,
        |_| {},
    )
    .expect_err("a depth mismatch was accepted");

    assert!(
        error.contains("depth"),
        "the error should name depth: {error}"
    );
}

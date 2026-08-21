//! **The D31 claim:** a compact node undoes a reorg by keeping old states.
//!
//! A full node cannot do this. Utreexo deletion is not invertible
//! (`docs/design.md` D18), so unwinding a transparent spend needs the deleted
//! leaves *and their positions* carried in a `StateDelta`, and the shadow
//! runner found that maintaining that at tip costs ~15 GiB because
//! `RollbackJournal::record` clones the whole outpoint index.
//!
//! A node holding only roots does not need to invert anything. Its entire state
//! is a few hundred bytes, so it can keep every state it has ever had and step
//! back to one. That is a real advantage of the design and it is asserted in
//! `docs/design.md`, so it is tested here rather than left as an argument.
//!
//! # What has to hold, and the second one is the load-bearing one
//!
//! 1. Restoring a kept state reproduces the roots that state had.
//! 2. **A restored node applying a divergent chain ends byte-identical to one
//!    that only ever saw that chain.** CLAUDE.md Phase 2 refuses to soften this
//!    to "equivalent" — `apply(A..N)`, undo to `K`, apply a divergent `K..M`
//!    must equal a cold replay of the final chain. Property 1 alone would pass
//!    on a state that restored its roots but left an internal counter stale,
//!    and the transparent leaf counter is exactly such a counter: Utreexo
//!    assigns positions from it and never decrements it.
//!
//! This does **not** test the shadow runner's fork detection, which needs a
//! node that actually reorgs. See `PLAN.md`.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::{CanonicalSerialize, PoolId, UtxoLeaf};
use zutreexo_chain::{
    apply_and_prove, ApplyOptions, BlockProofBundle, BlockSummary, ChainAccumulators, OutPoint,
};
use zutreexo_csn::CompactState;

const DEPTH: u8 = 20;

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
        script_pubkey: vec![0x76, 0xa9, 0x14, u8::try_from(vout & 0xFF).unwrap_or(0)],
    }
}

fn nullifier(n: u32) -> Value {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    bytes[31] = 0x01;
    Value::from_bytes(bytes)
}

/// A block that creates three outputs, spends two of the previous block's, and
/// reveals nullifiers into two pools.
///
/// `salt` makes two blocks at the same height genuinely different, which is
/// what a reorg is — without it the "divergent" branch would be the same chain
/// and the test would prove nothing.
fn block(height: u32, salt: u32) -> BlockSummary {
    let tx = height.wrapping_mul(1_000).wrapping_add(salt);
    let mut summary = BlockSummary {
        height,
        transactions: 2,
        transparent_spends: Vec::new(),
        transparent_creates: Vec::new(),
        nullifiers: BTreeMap::new(),
        commitments: BTreeMap::new(),
    };
    for vout in 0..3u32 {
        summary
            .transparent_creates
            .push((outpoint(tx, vout), leaf(tx, vout, height)));
    }
    summary.nullifiers.insert(
        PoolId::Sapling,
        vec![nullifier(tx.wrapping_mul(7).wrapping_add(1))],
    );
    summary.nullifiers.insert(
        PoolId::Orchard,
        vec![
            nullifier(tx.wrapping_mul(7).wrapping_add(2)),
            nullifier(tx.wrapping_mul(7).wrapping_add(3)),
        ],
    );
    summary
}

/// Chains `block`s so each spends outputs the previous one created.
fn chain(from: u32, to: u32, salt: u32) -> Vec<BlockSummary> {
    let mut out = Vec::new();
    for height in from..=to {
        let mut summary = block(height, salt);
        if height > 0 {
            // Spend two outputs of the block before it — using the same salt
            // the previous block was built with, so the outpoints resolve.
            let previous_salt = if height == from { 0 } else { salt };
            let previous = (height - 1).wrapping_mul(1_000).wrapping_add(previous_salt);
            summary.transparent_spends.push(outpoint(previous, 0));
            summary.transparent_spends.push(outpoint(previous, 2));
        }
        out.push(summary);
    }
    out
}

/// Applies a chain through both paths, checking they agree after every block,
/// and returns the compact state after each — the "kept states" D31 describes.
fn run(
    bridge: &mut ChainAccumulators,
    csn: &mut CompactState,
    blocks: &[BlockSummary],
) -> Vec<CompactState> {
    let mut history = Vec::new();
    for summary in blocks {
        let (_, bundle) = apply_and_prove(bridge, summary, ApplyOptions::default())
            .unwrap_or_else(|e| panic!("bridge failed at {}: {e}", summary.height));
        let decoded = BlockProofBundle::from_bytes(&bundle.to_bytes())
            .unwrap_or_else(|e| panic!("bundle at {} would not decode: {e}", summary.height));
        csn.apply_bundle(summary, &decoded)
            .unwrap_or_else(|e| panic!("compact node rejected {}: {e}", summary.height));
        assert_eq!(
            csn.utxo_roots(),
            bridge.utxo_roots(),
            "at {}",
            summary.height
        );
        assert_eq!(
            csn.nullifier_roots(),
            bridge.nullifier_roots(),
            "at {}",
            summary.height
        );
        history.push(csn.clone());
    }
    history
}

#[test]
fn a_kept_state_restores_the_roots_it_had() {
    let mut bridge = ChainAccumulators::new(DEPTH).unwrap();
    let mut csn = CompactState::new(DEPTH).unwrap();
    let history = run(&mut bridge, &mut csn, &chain(0, 19, 0));

    let at_ten = &history[10];
    assert_eq!(at_ten.tip(), Some(10));

    // Restoration is a clone, which is the entire mechanism.
    let restored = at_ten.clone();
    assert_eq!(restored.utxo_roots(), at_ten.utxo_roots());
    assert_eq!(restored.nullifier_roots(), at_ten.nullifier_roots());
    assert_eq!(restored.to_bytes(), at_ten.to_bytes());
}

#[test]
fn a_restored_node_on_a_divergent_chain_matches_a_cold_replay() {
    // The invariant CLAUDE.md Phase 2 refuses to soften: byte-identical to a
    // cold replay of the final chain, not merely "equivalent".
    const FORK: u32 = 10;
    const END: u32 = 19;

    // Branch A, then unwind to the fork, then branch B.
    let mut bridge = ChainAccumulators::new(DEPTH).unwrap();
    let mut csn = CompactState::new(DEPTH).unwrap();
    let history = run(&mut bridge, &mut csn, &chain(0, END, 0));
    assert_eq!(csn.tip(), Some(END));

    let mut reorged = history[FORK as usize].clone();
    assert_eq!(reorged.tip(), Some(FORK));

    // The bridge is rebuilt the way the shadow runner rebuilds it — from the
    // common prefix — because the compact side is what is under test here and
    // the bridge only has to be a correct counterparty.
    let mut rebuilt_bridge = ChainAccumulators::new(DEPTH).unwrap();
    let mut throwaway = CompactState::new(DEPTH).unwrap();
    run(&mut rebuilt_bridge, &mut throwaway, &chain(0, FORK, 0));

    let divergent = chain(FORK + 1, END, 77);
    run(&mut rebuilt_bridge, &mut reorged, &divergent);

    // Cold: a node that only ever saw the final chain.
    let mut cold_bridge = ChainAccumulators::new(DEPTH).unwrap();
    let mut cold_csn = CompactState::new(DEPTH).unwrap();
    let mut final_chain = chain(0, FORK, 0);
    final_chain.extend(divergent);
    run(&mut cold_bridge, &mut cold_csn, &final_chain);

    assert_eq!(
        reorged.utxo_roots(),
        cold_csn.utxo_roots(),
        "transparent roots differ from a cold replay after the reorg"
    );
    assert_eq!(
        reorged.nullifier_roots(),
        cold_csn.nullifier_roots(),
        "nullifier roots differ from a cold replay after the reorg"
    );
    // Byte-identical, which also catches the leaf counter that roots alone
    // would not: Utreexo assigns positions from it and never decrements it, so
    // a stale one produces correct roots now and wrong proofs later.
    assert_eq!(
        reorged.to_bytes(),
        cold_csn.to_bytes(),
        "state is not byte-identical to a cold replay"
    );
    assert_eq!(reorged.utxo_leaves(), cold_csn.utxo_leaves());
}

#[test]
fn keeping_every_state_is_affordable() {
    // The quantitative half of D31: a full node's undo data scales with the
    // state, a compact node's with the reorg depth. Zcash's reorg limit is 100
    // blocks, so that is the depth priced here.
    let mut bridge = ChainAccumulators::new(DEPTH).unwrap();
    let mut csn = CompactState::new(DEPTH).unwrap();
    let history = run(&mut bridge, &mut csn, &chain(0, 99, 0));

    let total: usize = history.iter().map(|s| s.to_bytes().len()).sum();
    assert_eq!(history.len(), 100);
    assert!(
        total < 100 * 1024,
        "100 blocks of rollback history is {total} B, no longer trivially affordable"
    );

    // And it does not grow with chain length: the state is roots, not contents.
    let first = history[0].to_bytes().len();
    let last = history[99].to_bytes().len();
    assert!(
        last < first * 2,
        "state grew from {first} B to {last} B over 100 blocks; it should not scale with the chain"
    );
}

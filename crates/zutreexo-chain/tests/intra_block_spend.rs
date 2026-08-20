//! A block may spend an output it creates. Mainnet block 572 does.
//!
//! `tx[10]` of block 572 spends an output of `tx[8]`. Both Bitcoin and Zcash
//! permit this; only spending an output created *later* in the block is
//! forbidden.
//!
//! `apply_block` originally ordered every deletion before every insertion and
//! documented that ordering as preventing intra-block spends, "which Zcash
//! consensus forbids". That was wrong — a Bitcoin analogy applied backwards
//! (CLAUDE.md §5 rule 7).
//!
//! It survived stages 2a, 2b and 2c because every fixture replay ran with
//! `allow_unknown_spends`: those windows do not start at genesis, so an
//! unresolvable spend is expected and was counted rather than investigated. The
//! genesis-forward replay in 2d, which cannot use that option, hit it after 572
//! blocks.
//!
//! These tests run in milliseconds. The six-hour replay found the bug; this is
//! what keeps it found.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use zutreexo_accumulator::UtxoLeaf;
use zutreexo_chain::{
    apply_block, ApplyOptions, BlockSummary, ChainAccumulators, OutPoint, PoolId,
};

const DEPTH: u8 = 12;

fn outpoint(tag: u8, vout: u32) -> OutPoint {
    OutPoint {
        txid: [tag; 32],
        vout,
    }
}

fn leaf(tag: u8, vout: u32, height: u32) -> UtxoLeaf {
    UtxoLeaf {
        txid: [tag; 32],
        vout,
        height,
        is_coinbase: false,
        value: 1_000 + u64::from(vout),
        script_pubkey: vec![0x76, 0xa9, tag],
    }
}

fn block(height: u32, spends: &[OutPoint], creates: &[(OutPoint, UtxoLeaf)]) -> BlockSummary {
    BlockSummary {
        height,
        transactions: 1,
        transparent_spends: spends.to_vec(),
        transparent_creates: creates.to_vec(),
        nullifiers: BTreeMap::new(),
        commitments: BTreeMap::new(),
    }
}

/// The shape of block 572, in miniature: create an output and spend it in the
/// same block, with no `allow_unknown_spends` to paper over it.
#[test]
fn a_block_may_spend_an_output_it_creates() {
    let mut state = ChainAccumulators::new(DEPTH).unwrap();

    let created_and_spent = outpoint(1, 0);
    let survivor = outpoint(2, 0);

    let summary = block(
        1,
        &[created_and_spent],
        &[
            (created_and_spent, leaf(1, 0, 1)),
            (survivor, leaf(2, 0, 1)),
        ],
    );

    apply_block(&mut state, &summary, ApplyOptions::default())
        .expect("a block spending an output it creates is valid; mainnet 572 does it");

    // The cancelled output never enters the index...
    assert!(
        state.utxo(&created_and_spent).is_none(),
        "an output created and spent in one block must not remain unspent"
    );
    // ...and the other one does.
    assert!(state.utxo(&survivor).is_some());
    assert_eq!(state.utxo_count(), 1);
}

/// Cancellation, not insert-then-delete: the accumulator must look exactly as
/// though the cancelled output never existed.
///
/// This is the property that makes the choice a specification rather than an
/// optimisation — there is no ordering rule to get wrong, because neither
/// operation happens.
#[test]
fn a_cancelled_output_leaves_no_trace_in_the_roots() {
    let survivor = outpoint(2, 0);

    // One block that creates two outputs and spends one of them.
    let mut with_cancel = ChainAccumulators::new(DEPTH).unwrap();
    let cancelled = outpoint(1, 0);
    apply_block(
        &mut with_cancel,
        &block(
            1,
            &[cancelled],
            &[(cancelled, leaf(1, 0, 1)), (survivor, leaf(2, 0, 1))],
        ),
        ApplyOptions::default(),
    )
    .unwrap();

    // The same block with the cancelled pair simply absent.
    let mut without = ChainAccumulators::new(DEPTH).unwrap();
    apply_block(
        &mut without,
        &block(1, &[], &[(survivor, leaf(2, 0, 1))]),
        ApplyOptions::default(),
    )
    .unwrap();

    assert_eq!(
        with_cancel.utxo_roots(),
        without.utxo_roots(),
        "a cancelled output changed the transparent roots; it should be as if \
         it never existed"
    );
    assert_eq!(with_cancel.utxo_count(), without.utxo_count());
}

/// A spend of an output that neither exists nor is created here is still an
/// error. Cancellation must not become a blanket excuse for unresolvable
/// spends — that would silently restore the hole `allow_unknown_spends` left.
#[test]
fn a_genuinely_unknown_outpoint_is_still_rejected() {
    let mut state = ChainAccumulators::new(DEPTH).unwrap();
    let phantom = outpoint(9, 0);

    let error = apply_block(
        &mut state,
        &block(1, &[phantom], &[(outpoint(2, 0), leaf(2, 0, 1))]),
        ApplyOptions::default(),
    )
    .expect_err("an outpoint that is neither known nor created here must fail");

    assert!(
        matches!(error, zutreexo_chain::ApplyError::UnknownOutpoint { .. }),
        "expected UnknownOutpoint, got {error}"
    );
    // And nothing was applied.
    assert_eq!(state.utxo_count(), 0);
}

/// A pre-existing output takes precedence over a same-block creation of the
/// same outpoint. Outpoints are not unique across all history in principle, and
/// resolving to the wrong one would delete the wrong leaf.
#[test]
fn an_existing_output_is_preferred_over_a_same_block_creation() {
    let mut state = ChainAccumulators::new(DEPTH).unwrap();
    let shared = outpoint(1, 0);

    // Block 1 creates it.
    apply_block(
        &mut state,
        &block(1, &[], &[(shared, leaf(1, 0, 1))]),
        ApplyOptions::default(),
    )
    .unwrap();
    assert_eq!(state.utxo_count(), 1);

    // Block 2 spends it and creates something else.
    apply_block(
        &mut state,
        &block(2, &[shared], &[(outpoint(3, 0), leaf(3, 0, 2))]),
        ApplyOptions::default(),
    )
    .unwrap();

    assert!(
        state.utxo(&shared).is_none(),
        "the existing output was not spent"
    );
    assert_eq!(state.utxo_count(), 1);
}

/// Spending the same outpoint twice in one block is still a double spend, even
/// when the block also creates it.
#[test]
fn a_cancelled_outpoint_cannot_be_spent_twice() {
    let mut state = ChainAccumulators::new(DEPTH).unwrap();
    let target = outpoint(1, 0);

    let error = apply_block(
        &mut state,
        &block(1, &[target, target], &[(target, leaf(1, 0, 1))]),
        ApplyOptions::default(),
    )
    .expect_err("spending the same outpoint twice must be rejected");

    assert!(
        matches!(error, zutreexo_chain::ApplyError::DuplicateSpend { .. }),
        "expected DuplicateSpend, got {error}"
    );
}

/// Nullifiers are unaffected by any of this — cancellation is a transparent-side
/// concept only.
#[test]
fn cancellation_does_not_touch_the_shielded_side() {
    use zutreexo_accumulator::imt::Value;

    let mut state = ChainAccumulators::new(DEPTH).unwrap();
    let cancelled = outpoint(1, 0);

    let mut nullifiers = BTreeMap::new();
    nullifiers.insert(PoolId::Orchard, vec![Value::from_bytes([7u8; 32])]);

    let mut summary = block(1, &[cancelled], &[(cancelled, leaf(1, 0, 1))]);
    summary.nullifiers = nullifiers;

    apply_block(&mut state, &summary, ApplyOptions::default()).unwrap();

    assert_eq!(state.nullifier_count(PoolId::Orchard), 1);
    assert_eq!(state.utxo_count(), 0);
}

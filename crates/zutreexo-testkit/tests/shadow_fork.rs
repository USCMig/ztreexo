//! Fork detection, which is the half of a shadow run's reorg handling that can
//! be tested without a chain that reorgs.
//!
//! `PLAN.md` records that `shadow.rs`'s `unwind` is untested in anger. This
//! narrows that: the reload-and-replay half is `load` plus `apply_block`, both
//! covered elsewhere, so what was genuinely untested was deciding *where* to
//! unwind to — and that is a pure walk backwards through a history, comparing
//! against what the node says now.
//!
//! The cases below are the ones an off-by-one lives in: the fork at the very
//! tip, the fork at the very base, no fork at all, and the node being
//! unreachable, which must never be mistaken for a reorg.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::VecDeque;

use zutreexo_testkit::shadow::{find_fork, AppliedBlock, Fork};

/// A history of `count` blocks starting at `start`, each hash naming its
/// height so a mismatch is readable in a failure message.
fn history(start: u32, count: u32) -> VecDeque<AppliedBlock> {
    (0..count)
        .map(|i| AppliedBlock {
            height: start + i,
            hash: format!("chainA-{}", start + i),
        })
        .collect()
}

/// The node agrees with branch A below `fork_at` and reports branch B at or
/// above it — which is what a reorg looks like from outside.
fn node_after_reorg(fork_at: u32) -> impl Fn(u32) -> Result<String, String> {
    move |height| {
        Ok(if height < fork_at {
            format!("chainA-{height}")
        } else {
            format!("chainB-{height}")
        })
    }
}

#[test]
fn no_reorg_leaves_the_history_untouched() {
    let mut h = history(100, 10);
    let before = h.clone();
    let fork = find_fork(&mut h, |height| Ok::<_, String>(format!("chainA-{height}"))).unwrap();

    assert_eq!(fork, Fork::None);
    assert_eq!(h, before, "an agreeing node must not consume history");
}

#[test]
fn a_one_block_reorg_unwinds_exactly_one() {
    // The common case on mainnet, and the one most likely to be off by one.
    let mut h = history(100, 10); // 100..=109
    let fork = find_fork(&mut h, node_after_reorg(109)).unwrap();

    assert_eq!(
        fork,
        Fork::UnwindTo {
            target: 108,
            undone: 1
        }
    );
    // The target must still be *in* the history, because it is the state the
    // compact node rewinds to. Popping it would leave nothing to restore.
    assert_eq!(h.back().map(|a| a.height), Some(108));
    assert_eq!(h.len(), 9);
}

#[test]
fn a_deep_reorg_unwinds_to_the_last_agreeing_block() {
    let mut h = history(100, 10);
    let fork = find_fork(&mut h, node_after_reorg(103)).unwrap();

    assert_eq!(
        fork,
        Fork::UnwindTo {
            target: 102,
            undone: 7
        }
    );
    assert_eq!(h.back().map(|a| a.height), Some(102));
}

#[test]
fn a_fork_below_the_history_is_reported_not_guessed() {
    // Every remembered block is gone. Recovery cannot reach past the run's own
    // history, so this must be distinguishable from a deep-but-recoverable
    // reorg rather than silently unwinding to nothing.
    let mut h = history(100, 10);
    let fork = find_fork(&mut h, node_after_reorg(100)).unwrap();

    assert_eq!(fork, Fork::BeyondHistory { undone: 10 });
    assert!(h.is_empty());
}

#[test]
fn an_empty_history_is_not_a_fork() {
    let mut h: VecDeque<AppliedBlock> = VecDeque::new();
    let fork = find_fork(&mut h, |_| Ok::<_, String>("anything".to_owned())).unwrap();
    assert_eq!(fork, Fork::None, "nothing applied cannot have forked");
}

#[test]
fn an_unreachable_node_is_an_error_not_a_reorg() {
    // The dangerous confusion. A node that cannot be queried must not be read
    // as a node that disagrees — that would unwind a chain that never forked,
    // on nothing more than a restarted container.
    let mut h = history(100, 10);
    let before = h.clone();
    let result = find_fork(&mut h, |_| {
        Err::<String, _>("connection refused".to_owned())
    });

    assert_eq!(result, Err("connection refused".to_owned()));
    assert_eq!(h, before, "a failed query consumed history");
}

#[test]
fn a_query_failing_partway_leaves_the_rest_intact() {
    // The node answers for the tip (disagreeing) and then becomes unreachable.
    // One block comes off, and the rest must survive for a retry.
    let mut h = history(100, 10);
    let mut calls = 0;
    let result = find_fork(&mut h, |height| {
        calls += 1;
        if calls == 1 {
            Ok(format!("chainB-{height}"))
        } else {
            Err("connection refused".to_owned())
        }
    });

    assert!(result.is_err());
    assert_eq!(h.len(), 9, "only the disagreeing block should be gone");
    assert_eq!(h.back().map(|a| a.height), Some(108));
}

#[test]
fn the_search_stops_at_the_first_agreement_rather_than_walking_the_whole_history() {
    // Cost matters: each step is an RPC round trip, and a shadow run holds
    // hundreds of states. A one-block reorg must cost two queries, not 512.
    let mut h = history(0, 512);
    let mut queries = 0;
    let fork = find_fork(&mut h, |height| {
        queries += 1;
        Ok::<_, String>(if height >= 511 {
            format!("chainB-{height}")
        } else {
            format!("chainA-{height}")
        })
    })
    .unwrap();

    assert_eq!(
        fork,
        Fork::UnwindTo {
            target: 510,
            undone: 1
        }
    );
    assert_eq!(queries, 2, "walked further than the fork required");
}

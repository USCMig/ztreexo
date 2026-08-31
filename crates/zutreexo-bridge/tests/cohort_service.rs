//! A wallet settles spend-status over a socket **without naming the note**.
//!
//! This is the end-to-end claim the cohort service exists to make, and it has
//! two halves that must both hold:
//!
//! 1. **The answer is right.** What the wallet concludes from the served cohort
//!    must equal what the bridge's own tree says. A private query that returns
//!    the wrong verdict is worse than a non-private one.
//! 2. **The question is vague.** The bytes crossing the socket must not contain
//!    the nullifier. That is asserted here directly, on the encoded request,
//!    rather than argued from the type — a future field that leaked it would
//!    typecheck fine and this test is what catches it.
//!
//! The privacy limit is `docs/design.md` D40: this buys per-*note* anonymity,
//! not per-*wallet*. Nothing in this file claims otherwise.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::net::TcpListener;

use zutreexo_accumulator::cohort::{PrefixRange, Status};
use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::sorted;
use zutreexo_accumulator::PoolId;
use zutreexo_bridge::epoch::{max_bits_for, EpochPolicy};
use zutreexo_bridge::limits::Limits;
use zutreexo_bridge::server::{serve_with, BridgeClient, ClientError};
use zutreexo_bridge::wire::status;
use zutreexo_bridge::{Bridge, Request};
use zutreexo_chain::{BlockSummary, ChainAccumulators};

const DEPTH: u8 = 20;
const POOL: PoolId = PoolId::Orchard;
/// Enough nullifiers that a 1-bit prefix clears a floor of 200 with room to
/// spare, and few enough that the test stays quick.
const NULLIFIERS: u32 = 2_000;
const EPOCH: u32 = 10;
/// Small enough for a 2,000-value pool to admit a 3-bit prefix. The production
/// figure is 12,298 (`epoch::DEFAULT_MIN_ANONYMITY`) and is exercised by the
/// unit tests in `epoch.rs` against the real per-pool counts.
const FLOOR: u64 = 200;

/// Spread across the value space rather than clustered, so prefix buckets are
/// populated roughly evenly and a narrow range is not accidentally empty.
fn nullifier(n: u32) -> Value {
    let mut bytes = [0u8; 32];
    // xorshift-ish mixing of the index into the leading bytes: the prefix is
    // the *top* of the value, so incrementing counters in the low bytes would
    // put every nullifier in one bucket and prove nothing.
    let mut x = u64::from(n).wrapping_add(0x9e37_79b9_7f4a_7c15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    bytes[..8].copy_from_slice(&x.to_le_bytes());
    bytes[31] = 0x01;
    Value::from_bytes(bytes)
}

fn policy() -> EpochPolicy {
    EpochPolicy {
        interval: EPOCH,
        keep: 2,
        min_anonymity: FLOOR,
    }
}

/// A bridge holding `NULLIFIERS` Orchard nullifiers, snapshotted at [`EPOCH`].
fn bridge() -> (Bridge, Vec<Value>) {
    let mut bridge = Bridge::with_epoch_policy(ChainAccumulators::new(DEPTH).unwrap(), 4, policy());
    let mut inserted = Vec::new();
    // Blocks 1..=EPOCH, so the snapshot at EPOCH sees everything.
    for height in 1..=EPOCH {
        let per_block = NULLIFIERS / EPOCH;
        let values: Vec<Value> = (0..per_block)
            .map(|i| nullifier((height - 1) * per_block + i))
            .collect();
        inserted.extend(values.iter().copied());
        let mut nullifiers = BTreeMap::new();
        nullifiers.insert(POOL, values);
        bridge
            .apply(&BlockSummary {
                height,
                transactions: 1,
                transparent_spends: Vec::new(),
                transparent_creates: Vec::new(),
                nullifiers,
                commitments: BTreeMap::new(),
            })
            .unwrap_or_else(|e| panic!("apply {height}: {e}"));
    }
    (bridge, inserted)
}

/// Drains the server's remaining `accept`s when the client stops early.
///
/// # Why this exists
///
/// `serve`/`serve_with` block in `accept()` for exactly `calls` connections. If
/// the client thread makes fewer — because an assertion failed and it
/// panicked — the server thread waits forever and the *whole test binary
/// hangs* instead of reporting the failure.
///
/// A mutation run found this the hard way: with the byte-budget charge removed,
/// `the_byte_budget_cuts_a_peer_off...` failed its second assertion, skipped its
/// third call, and `cargo test` sat at the deadline for twenty minutes rather
/// than going red in a second. **A test that hangs on failure is worse than no
/// test** — CI reports a timeout with no failing name, and the next person
/// reaches for the wrong thread entirely.
///
/// So the drop glue — which runs on the panic path too — opens and immediately
/// closes one throwaway connection per possible remaining call. The server sees
/// EOF before the headers end, answers `BAD_REQUEST`, and moves on.
struct Drain {
    address: String,
    calls: usize,
}

impl Drop for Drain {
    fn drop(&mut self) {
        for _ in 0..self.calls {
            // Errors are expected and ignored: once the server has stopped
            // accepting, the connect fails and there is nothing left to drain.
            let _ = std::net::TcpStream::connect(&self.address);
        }
    }
}

/// Server on this thread, client on another: `ChainAccumulators` is not `Send`.
/// See `served_ibd.rs` and `docs/design.md` D27.
fn serving<T: Send>(
    bridge: Bridge,
    calls: usize,
    body: impl FnOnce(BridgeClient) -> T + Send,
) -> T {
    serving_with(bridge, calls, Limits::permissive(), body)
}

/// The same, under explicit limits, so the byte budget can be driven.
fn serving_with<T: Send>(
    bridge: Bridge,
    calls: usize,
    limits: Limits,
    body: impl FnOnce(BridgeClient) -> T + Send,
) -> T {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    std::thread::scope(|scope| {
        let handle = scope.spawn({
            let address = address.clone();
            move || {
                let _drain = Drain {
                    address: address.clone(),
                    calls,
                };
                body(BridgeClient::new(&address))
            }
        });
        let _ = serve_with(&bridge, &listener, calls, &limits);
        handle.join().unwrap()
    })
}

#[test]
fn the_request_bytes_never_contain_the_nullifier() {
    // The whole privacy claim, asserted on the wire rather than on the type.
    //
    // A 32-byte value has a vanishing chance of appearing in an 39-byte request
    // by accident, so this is a real check and not a tautology. It fails the
    // moment anyone adds a field carrying the value "just for logging".
    let (_, inserted) = bridge();
    let secret = inserted[123];
    let range = PrefixRange::covering(secret, 3).unwrap();
    let bytes = Request::PrefixCohort {
        pool: POOL,
        epoch: EPOCH,
        bits: range.bits(),
        lo: range.lo(),
    }
    .to_bytes();

    assert!(
        !bytes.windows(32).any(|window| window == secret.as_bytes()),
        "the request carries the nullifier the wallet is asking about"
    );

    // And for contrast, the method it replaces does carry it — so the check
    // above is testing something the old path would have failed.
    let named = Request::NullifierNonMembership {
        pool: POOL,
        nullifier: secret,
    }
    .to_bytes();
    assert!(
        named.windows(32).any(|window| window == secret.as_bytes()),
        "the non-membership request should name the nullifier; if it no longer \
         does, the contrast this test draws is stale"
    );
}

#[test]
fn a_wallet_settles_a_spent_and_an_unspent_note_over_the_socket() {
    let (bridge, inserted) = bridge();
    let spent = inserted[500];
    // Derived the same way but past the end of what was inserted, so it is
    // absent from the pool without being structurally different from a value
    // that is present.
    let unspent = nullifier(NULLIFIERS + 7);
    let truth_spent = bridge.state().tree(POOL).unwrap().contains(&spent);
    let truth_unspent = bridge.state().tree(POOL).unwrap().contains(&unspent);
    assert!(truth_spent && !truth_unspent, "fixture is not set up right");

    // manifest, then one cohort per probe.
    serving(bridge, 3, |client| {
        let manifest = client.epoch_manifest().unwrap();
        assert_eq!(manifest.min_anonymity, FLOOR);
        let entry = manifest
            .epochs
            .iter()
            .find(|e| e.pool == POOL && e.height == EPOCH)
            .expect("the snapshot the bridge took must be advertised");
        assert!(entry.max_bits >= 1, "no width is usable for this pool");

        for (probe, want_spent) in [(spent, true), (unspent, false)] {
            let range = PrefixRange::covering(probe, entry.max_bits).unwrap();
            let cohort = client.prefix_cohort(POOL, EPOCH, range).unwrap();

            // The wallet verifies against the *manifest's* root, which it got
            // independently of the cohort. Folding a cohort against a root the
            // same response supplied would prove nothing.
            let values = sorted::verify_cohort(&entry.root, &cohort)
                .expect("served cohort must fold to the advertised root");
            assert!(
                values.len() as u64 >= FLOOR,
                "cohort of {} is under the advertised floor of {FLOOR}",
                values.len()
            );

            let settled = sorted::resolve(&values, &range, probe).unwrap();
            match (settled, want_spent) {
                (Status::Spent, true) => {}
                (Status::Unspent { .. }, false) => {}
                (other, _) => panic!("wrong verdict for spent={want_spent}: {other:?}"),
            }
        }
    });
}

#[test]
fn a_prefix_narrower_than_the_floor_is_refused_rather_than_widened() {
    let (bridge, inserted) = bridge();
    let leaves = bridge.epochs().get(POOL, EPOCH).unwrap().leaf_count();
    let max_bits = max_bits_for(leaves, FLOOR);
    let probe = inserted[9];

    serving(bridge, 1, move |client| {
        // One bit past the floor names half as many notes as the policy
        // promises. Widening it silently would be worse than refusing: the
        // wallet would receive a proof for a range it did not ask about and
        // has no reason to re-check.
        let range = PrefixRange::covering(probe, max_bits + 1).unwrap();
        let error = client
            .prefix_cohort(POOL, EPOCH, range)
            .expect_err("a too-narrow prefix must be refused");
        assert_eq!(
            error,
            ClientError::Status {
                status: status::PREFIX_TOO_NARROW
            },
            "wrong refusal: {error:?}"
        );
    });
}

#[test]
fn an_epoch_that_was_never_taken_or_has_been_evicted_is_reported_as_such() {
    let (bridge, inserted) = bridge();
    let probe = inserted[3];
    // `keep: 2` and an interval of 10 over heights 1..=10 means exactly one
    // snapshot exists. Height 5 is not an epoch boundary and never was.
    assert!(bridge.epochs().get(POOL, 5).is_none());

    serving(bridge, 1, move |client| {
        let range = PrefixRange::covering(probe, 1).unwrap();
        let error = client
            .prefix_cohort(POOL, 5, range)
            .expect_err("an unknown epoch must be refused");
        assert_eq!(
            error,
            ClientError::Status {
                status: status::NO_SUCH_EPOCH
            },
            "wrong refusal: {error:?}"
        );
    });
}

#[test]
fn retention_evicts_the_oldest_epoch_and_keeps_the_newest() {
    // Three boundaries against `keep: 2`. The store must end holding the two
    // newest, and `latest` must be the newest — a client following the guidance
    // in `epoch`'s module docs picks that one, and if `latest` returned the
    // oldest every client would silently anchor on stale state.
    let mut bridge = Bridge::with_epoch_policy(ChainAccumulators::new(DEPTH).unwrap(), 4, policy());
    for height in 1..=(EPOCH * 3) {
        let mut nullifiers = BTreeMap::new();
        nullifiers.insert(POOL, vec![nullifier(height)]);
        bridge
            .apply(&BlockSummary {
                height,
                transactions: 1,
                transparent_spends: Vec::new(),
                transparent_creates: Vec::new(),
                nullifiers,
                commitments: BTreeMap::new(),
            })
            .unwrap();
    }

    assert!(bridge.epochs().get(POOL, EPOCH).is_none(), "oldest kept");
    assert!(bridge.epochs().get(POOL, EPOCH * 2).is_some());
    assert!(bridge.epochs().get(POOL, EPOCH * 3).is_some());
    assert_eq!(
        bridge.epochs().latest(POOL).map(|tree| tree.height()),
        Some(EPOCH * 3)
    );

    // Every pool is snapshotted, not only the one with traffic: a client asking
    // about an empty pool must get an answer rather than NO_SUCH_EPOCH, or the
    // absence of a snapshot would itself say something about the pool.
    for pool in PoolId::ALL {
        assert!(
            bridge.epochs().get(pool, EPOCH * 3).is_some(),
            "{pool:?} has no snapshot at the newest epoch"
        );
    }
}

#[test]
fn a_bridge_with_epochs_disabled_serves_no_cohorts_and_builds_none() {
    // The opt-out has to actually opt out. A bridge that only serves bundles
    // should not be paying 16.8 s per Orchard rebuild for a method it never
    // answers (`docs/design.md` D38).
    let mut bridge = Bridge::with_epoch_policy(
        ChainAccumulators::new(DEPTH).unwrap(),
        4,
        EpochPolicy::disabled(),
    );
    for height in 1..=(EPOCH * 2) {
        let mut nullifiers = BTreeMap::new();
        nullifiers.insert(POOL, vec![nullifier(height)]);
        bridge
            .apply(&BlockSummary {
                height,
                transactions: 1,
                transparent_spends: Vec::new(),
                transparent_creates: Vec::new(),
                nullifiers,
                commitments: BTreeMap::new(),
            })
            .unwrap();
    }
    assert!(bridge.epochs().is_empty());
    assert!(bridge.manifest().epochs.is_empty());

    let probe = nullifier(1);
    serving(bridge, 1, move |client| {
        let range = PrefixRange::covering(probe, 1).unwrap();
        assert_eq!(
            client.prefix_cohort(POOL, EPOCH, range),
            Err(ClientError::Status {
                status: status::NO_SUCH_EPOCH
            })
        );
    });
}

#[test]
fn the_byte_budget_cuts_a_peer_off_while_the_request_counter_still_allows_it() {
    // The DoS lever cohorts introduce, driven end to end. Every call here is
    // well inside `requests_per_minute`; what stops the peer is bandwidth.
    let (bridge, inserted) = bridge();
    let probe = inserted[42];
    let leaves = bridge.epochs().get(POOL, EPOCH).unwrap().leaf_count();
    let max_bits = max_bits_for(leaves, FLOOR);
    let one = bridge
        .prove_cohort(POOL, EPOCH, PrefixRange::covering(probe, max_bits).unwrap())
        .unwrap();
    let size = {
        use zutreexo_accumulator::CanonicalSerialize;
        one.to_bytes().len() as u64
    };

    let limits = Limits {
        // Room for one cohort and change, not two.
        cohort_bytes_per_minute: size + size / 2,
        requests_per_minute: 600,
        ..Limits::permissive()
    };

    serving_with(bridge, 3, limits, move |client| {
        let range = PrefixRange::covering(probe, max_bits).unwrap();
        assert!(
            client.prefix_cohort(POOL, EPOCH, range).is_ok(),
            "the first cohort is inside the budget"
        );
        assert_eq!(
            client.prefix_cohort(POOL, EPOCH, range),
            Err(ClientError::Status {
                status: status::BUDGET_EXHAUSTED
            }),
            "the second must exhaust the byte budget"
        );
        // And the cheap methods still work: the byte budget is a bandwidth
        // control, not a ban. A peer cut off from cohorts can still fetch the
        // manifest and learn when to come back.
        assert!(
            client.epoch_manifest().is_ok(),
            "exhausting the cohort budget must not deny the cheap methods"
        );
    });
}

#[test]
fn the_manifest_round_trips_and_is_canonically_ordered() {
    let (bridge, _) = bridge();
    let manifest = bridge.manifest();
    assert!(!manifest.epochs.is_empty());

    use zutreexo_accumulator::CanonicalSerialize;
    let bytes = manifest.to_bytes();
    let decoded = zutreexo_bridge::EpochManifest::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, manifest);
    assert_eq!(decoded.to_bytes(), bytes, "re-encode must be identical");

    // Strict pool-then-height order, which is what makes two bridges holding
    // the same snapshots byte-identical — the property a wallet comparing
    // bridges depends on.
    assert!(
        manifest
            .epochs
            .windows(2)
            .all(|w| (w[0].pool, w[0].height) < (w[1].pool, w[1].height)),
        "manifest is not in strict order"
    );

    // And a shuffled encoding must be refused rather than accepted as an
    // equivalent spelling.
    let mut shuffled = manifest.clone();
    shuffled.epochs.reverse();
    assert!(
        zutreexo_bridge::EpochManifest::from_bytes(&shuffled.to_bytes()).is_err(),
        "an out-of-order manifest decoded"
    );
}

#[test]
fn snapshot_now_on_a_disabled_bridge_builds_nothing() {
    // The retention guard inside `EpochStore::snapshot`, which `Bridge::apply`
    // never reaches: a disabled policy is never `due`, so the only way in is
    // the manual entry point. A mutation run found this uncovered — removing
    // the guard left every test green while a bridge that had opted out of
    // cohort service silently paid for four snapshots and served them.
    let mut bridge = Bridge::with_epoch_policy(
        ChainAccumulators::new(DEPTH).unwrap(),
        4,
        EpochPolicy::disabled(),
    );
    let mut nullifiers = BTreeMap::new();
    nullifiers.insert(POOL, vec![nullifier(1)]);
    bridge
        .apply(&BlockSummary {
            height: 1,
            transactions: 1,
            transparent_spends: Vec::new(),
            transparent_creates: Vec::new(),
            nullifiers,
            commitments: BTreeMap::new(),
        })
        .unwrap();

    assert_eq!(
        bridge.snapshot_now().unwrap(),
        0,
        "a disabled bridge must build nothing even when asked directly"
    );
    assert!(bridge.epochs().is_empty());
}

#[test]
fn snapshot_now_lets_a_restored_bridge_serve_before_the_next_boundary() {
    // A bridge brought up from persisted state at an arbitrary height would
    // otherwise answer nothing until it happened to reach a multiple of the
    // interval — up to a full epoch of no service after every restart.
    let mut bridge = Bridge::with_epoch_policy(ChainAccumulators::new(DEPTH).unwrap(), 4, policy());
    for height in 1..EPOCH {
        let mut nullifiers = BTreeMap::new();
        nullifiers.insert(POOL, vec![nullifier(height)]);
        bridge
            .apply(&BlockSummary {
                height,
                transactions: 1,
                transparent_spends: Vec::new(),
                transparent_creates: Vec::new(),
                nullifiers,
                commitments: BTreeMap::new(),
            })
            .unwrap();
    }
    assert!(bridge.epochs().is_empty(), "no boundary reached yet");

    let built = bridge.snapshot_now().unwrap();
    assert_eq!(built, PoolId::ALL.len());
    assert_eq!(
        bridge.epochs().latest(POOL).map(|tree| tree.height()),
        Some(EPOCH - 1)
    );
}

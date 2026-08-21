//! **CLAUDE.md Phase 4 definition of done**, minus the network Zebra is on:
//! *"a CSN can complete IBD to tip using only headers + blocks + bridge-served
//! proofs, ending with roots identical to the bridge's."*
//!
//! A bridge and a compact node run in separate objects, talking over a real
//! `TcpListener` on loopback. Nothing is passed in memory: every bundle is
//! encoded by the bridge, written to a socket, read back and decoded by the
//! client. That is the point — Phase 4a already proved the two agree when the
//! bundle is handed over directly, so testing that again would only re-test the
//! codec against itself.
//!
//! A real socket rather than a mock for the same reason `source.rs`'s tests use
//! one: the framing bugs worth catching here — a short read, a body that
//! arrives in two packets, a length header that disagrees with the payload —
//! only exist on a socket.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::net::TcpListener;

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::{PoolId, UtxoLeaf};
use zutreexo_bridge::server::{serve, BridgeClient, ClientError};
use zutreexo_bridge::{Bridge, Request};
use zutreexo_chain::{BlockSummary, ChainAccumulators, OutPoint};
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
        is_coinbase: vout == 0,
        value: u64::from(tx) * 1000 + u64::from(vout),
        script_pubkey: vec![0xac; (tx % 19) as usize],
    }
}

fn nullifier(n: u32) -> Value {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    bytes[31] = 0x01;
    Value::from_bytes(bytes)
}

/// A chain from genesis with spends, intra-block cancellation, and two pools.
fn chain(blocks: u32) -> Vec<BlockSummary> {
    let mut out = Vec::new();
    let mut next = 1u32;
    for height in 0..blocks {
        let mut summary = BlockSummary {
            height,
            transactions: 3,
            transparent_spends: Vec::new(),
            transparent_creates: Vec::new(),
            nullifiers: BTreeMap::new(),
            commitments: BTreeMap::new(),
        };
        for vout in 0..3u32 {
            summary
                .transparent_creates
                .push((outpoint(height, vout), leaf(height, vout, height)));
        }
        if height > 0 {
            summary.transparent_spends.push(outpoint(height - 1, 0));
            summary.transparent_spends.push(outpoint(height - 1, 2));
        }
        if height % 5 == 4 {
            let point = outpoint(height, 90);
            summary
                .transparent_creates
                .push((point, leaf(height, 90, height)));
            summary.transparent_spends.push(point);
        }
        if height % 3 != 0 {
            for pool in [PoolId::Sapling, PoolId::Orchard] {
                let values: Vec<Value> = (0..=(height % 3))
                    .map(|_| {
                        let v = nullifier(next);
                        next += 1;
                        v
                    })
                    .collect();
                summary.nullifiers.insert(pool, values);
            }
        }
        out.push(summary);
    }
    out
}

fn bridge_with(blocks: u32) -> (Bridge, Vec<BlockSummary>) {
    let summaries = chain(blocks);
    let mut bridge = Bridge::new(ChainAccumulators::new(DEPTH).unwrap(), blocks as usize + 1);
    for summary in &summaries {
        bridge
            .apply(summary)
            .unwrap_or_else(|e| panic!("bridge failed at {}: {e}", summary.height));
    }
    (bridge, summaries)
}

/// Runs the client on a background thread and the server on this one, for
/// exactly `calls` connections.
///
/// **The server has to stay on the calling thread**: `ChainAccumulators` is not
/// `Send`, because `rustreexo`'s `MemForest` is built from `Rc` and `Weak` with
/// interior mutability. That is the same root cause as the clone-aliasing
/// defect in `docs/design.md` D11, and it is a real constraint on how a bridge
/// can be built rather than an inconvenience of this test — see D27.
///
/// `calls` must match exactly what `body` performs. Fewer and the server blocks
/// on `accept` forever; the count is spelled out at each call site for that
/// reason.
fn serving<T: Send>(
    bridge: Bridge,
    calls: usize,
    body: impl FnOnce(BridgeClient) -> T + Send,
) -> T {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    std::thread::scope(|scope| {
        let handle = scope.spawn(move || body(BridgeClient::new(&address)));
        let _ = serve(&bridge, &listener, calls);
        handle.join().unwrap()
    })
}

#[test]
fn a_compact_node_syncs_to_tip_over_a_socket() {
    const BLOCKS: u32 = 60;
    let (bridge, summaries) = bridge_with(BLOCKS);
    let expected_utxo = bridge.state().utxo_roots();
    let expected_nullifiers = bridge.state().nullifier_roots();

    // One call per block, plus one for the roots at the end.
    let csn = serving(bridge, BLOCKS as usize + 1, |client| {
        let mut csn = CompactState::new(DEPTH).unwrap();
        for summary in &summaries {
            let bundle = client
                .block_proof_bundle(summary.height)
                .unwrap_or_else(|e| panic!("fetch {} failed: {e}", summary.height));
            csn.apply_bundle(summary, &bundle)
                .unwrap_or_else(|e| panic!("apply {} failed: {e}", summary.height));
        }

        // The roots the bridge publishes must match what the node computed
        // for itself. If a wallet is going to anchor on a served root, the
        // served root has to be the one the proofs are against.
        let served = client.roots().unwrap();
        assert_eq!(served.height, BLOCKS - 1);
        assert_eq!(served.depth, DEPTH);
        assert_eq!(served.utxo, csn.utxo_roots(), "served utxo roots disagree");
        assert_eq!(
            served.nullifiers,
            csn.nullifier_roots().into_iter().collect::<Vec<_>>(),
            "served nullifier roots disagree"
        );
        csn
    });

    assert_eq!(csn.tip(), Some(BLOCKS - 1));
    assert_eq!(
        csn.utxo_roots(),
        expected_utxo,
        "transparent roots diverged"
    );
    assert_eq!(
        csn.nullifier_roots(),
        expected_nullifiers,
        "nullifier roots diverged"
    );
}

#[test]
fn a_wallet_learns_whether_its_note_is_spent() {
    let (bridge, _) = bridge_with(20);
    let root = bridge.nullifier_roots()[&PoolId::Sapling];

    serving(bridge, 2, |client| {
        // A nullifier the chain revealed: already spent.
        let spent = client.prove_unspent(PoolId::Sapling, nullifier(1)).unwrap();
        assert!(spent.is_none(), "a revealed nullifier reported as unspent");

        // One it never revealed: unspent, with a proof.
        let unspent = client
            .prove_unspent(PoolId::Sapling, nullifier(0x00AB_CDEF))
            .unwrap()
            .expect("an absent nullifier must come with a proof");

        assert_eq!(unspent.pool, PoolId::Sapling);
        assert_eq!(unspent.depth, DEPTH);

        // The proof has to verify against the root — a served proof the wallet
        // cannot check is worth nothing.
        zutreexo_accumulator::imt::verify_non_membership(
            PoolId::Sapling,
            DEPTH,
            &root,
            nullifier(0x00AB_CDEF),
            &unspent.proof,
        )
        .expect("a served non-membership proof must verify against the served root");
    });
}

#[test]
fn a_height_the_bridge_no_longer_keeps_is_refused() {
    // Retention of 5 over a 20-block chain: the early bundles are gone.
    let summaries = chain(20);
    let mut bridge = Bridge::new(ChainAccumulators::new(DEPTH).unwrap(), 5);
    for summary in &summaries {
        bridge.apply(summary).unwrap();
    }
    assert!(bridge.bundle(0).is_none(), "retention did not evict");
    assert!(bridge.bundle(19).is_some(), "retention evicted the tip");

    serving(bridge, 1, |client| {
        // Refused, and told why — not a hang and not a corrupt bundle.
        match client.block_proof_bundle(0) {
            Err(ClientError::Status { status }) => {
                assert_eq!(status, zutreexo_bridge::wire::status::NO_SUCH_HEIGHT);
            }
            other => panic!("expected NO_SUCH_HEIGHT, got {other:?}"),
        }
    });
}

#[test]
fn a_malformed_request_gets_an_answer_rather_than_silence() {
    use std::io::{Read, Write};

    let (bridge, _) = bridge_with(5);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();

    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            let body = b"\xffnot a request";
            let header = format!(
                "POST /zutreexo HTTP/1.1\r\nHost: {address}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let mut stream = std::net::TcpStream::connect(&address).unwrap();
            stream.write_all(header.as_bytes()).unwrap();
            stream.write_all(body).unwrap();

            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).unwrap();
            let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();

            // A client that gets no reply cannot distinguish a bad request from a
            // hung bridge, so the status byte is the whole point of this test.
            assert_eq!(
                raw[split + 4],
                zutreexo_bridge::wire::status::BAD_REQUEST,
                "a malformed request was not answered with BAD_REQUEST"
            );
        });
        let _ = serve(&bridge, &listener, 1);
        handle.join().unwrap();
    });
}

#[test]
fn requests_round_trip_and_reject_junk() {
    for request in [
        Request::AccumulatorRoots,
        Request::BlockProofBundle { height: 12345 },
        Request::NullifierNonMembership {
            pool: PoolId::Ironwood,
            nullifier: nullifier(9),
        },
    ] {
        let bytes = request.to_bytes();
        assert_eq!(Request::from_bytes(&bytes).unwrap(), request);

        // Every truncation is an error, never a panic and never a different
        // valid request.
        for length in 0..bytes.len() {
            assert!(Request::from_bytes(&bytes[..length]).is_err());
        }
        // Trailing bytes would make the encoding non-canonical.
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(Request::from_bytes(&extended).is_err());
    }

    // Unknown method tag and unknown version.
    assert!(Request::from_bytes(&[zutreexo_bridge::WIRE_VERSION, 0xEE]).is_err());
    assert!(Request::from_bytes(&[0xEE, 3]).is_err());
}

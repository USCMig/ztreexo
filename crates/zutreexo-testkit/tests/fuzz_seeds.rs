//! Writes valid encodings into the fuzz corpora.
//!
//! A libFuzzer run starting from nothing spends its early budget rediscovering
//! the format's gates — the version byte, the pool codes, the length prefixes —
//! before it can reach anything interesting. Over a 72-hour run that is
//! affordable but wasteful; over a short one it is the difference between
//! testing the parser and testing the version check.
//!
//! So this dumps one valid encoding of each fuzzed type, plus a couple of edge
//! shapes (empty, multi-pool). It is a test rather than a binary so it stays
//! compiled and cannot rot silently: if an encoding changes, this fails to
//! build alongside everything else.
//!
//! Gated on an environment variable because it writes outside its own
//! directory, which a test has no business doing unasked:
//!
//! ```text
//! ZUTREEXO_DUMP_SEEDS=1 cargo test -p zutreexo-testkit --test fuzz_seeds
//! ```

#![allow(clippy::unwrap_used, clippy::print_stdout)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use zutreexo_accumulator::imt::{ImtState, Value};
use zutreexo_accumulator::proof::{encode_utxo_proof, NonMembershipResponse};
use zutreexo_accumulator::{CanonicalSerialize, IndexedMerkleTree, PoolId, UtxoLeaf};
use zutreexo_bridge::wire::{Request, Roots};
use zutreexo_chain::{
    apply_and_prove, save, ApplyOptions, BlockSummary, ChainAccumulators, OutPoint,
};
use zutreexo_csn::CompactState;

const DEPTH: u8 = 40;

fn corpus(target: &str) -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target);
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn write(target: &str, name: &str, bytes: &[u8]) {
    if let Some(dir) = corpus(target) {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        println!("{} <- {} bytes", path.display(), bytes.len());
    }
}

fn outpoint(tx: u32, vout: u32) -> OutPoint {
    let mut txid = [0u8; 32];
    txid[..4].copy_from_slice(&tx.to_le_bytes());
    OutPoint { txid, vout }
}

fn leaf(tx: u32, vout: u32) -> UtxoLeaf {
    let point = outpoint(tx, vout);
    UtxoLeaf {
        txid: point.txid,
        vout: point.vout,
        height: 42,
        is_coinbase: false,
        value: 50_000,
        script_pubkey: vec![0x76, 0xa9, 0x14],
    }
}

fn nullifier(n: u32) -> Value {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    bytes[31] = 0x01;
    Value::from_bytes(bytes)
}

#[test]
fn dump_fuzz_seeds() {
    if std::env::var_os("ZUTREEXO_DUMP_SEEDS").is_none() {
        println!("set ZUTREEXO_DUMP_SEEDS=1 to write the fuzz corpora");
        return;
    }

    // ---- a bundle with a spend, a create, and two pools ----
    let mut state = ChainAccumulators::new(DEPTH).unwrap();
    let mut first = BlockSummary {
        height: 0,
        transactions: 1,
        transparent_spends: Vec::new(),
        transparent_creates: vec![(outpoint(0, 0), leaf(0, 0)), (outpoint(0, 1), leaf(0, 1))],
        nullifiers: BTreeMap::new(),
        commitments: BTreeMap::new(),
    };
    first.nullifiers.insert(PoolId::Sapling, vec![nullifier(1)]);
    let (_, empty_bundle) = apply_and_prove(&mut state, &first, ApplyOptions::default()).unwrap();
    write("bundle_decode", "insert-only", &empty_bundle.to_bytes());

    let mut second = BlockSummary {
        height: 1,
        transactions: 2,
        transparent_spends: vec![outpoint(0, 0)],
        transparent_creates: vec![(outpoint(1, 0), leaf(1, 0))],
        nullifiers: BTreeMap::new(),
        commitments: BTreeMap::new(),
    };
    second
        .nullifiers
        .insert(PoolId::Sapling, vec![nullifier(2), nullifier(3)]);
    second
        .nullifiers
        .insert(PoolId::Orchard, vec![nullifier(4)]);
    let (_, bundle) = apply_and_prove(&mut state, &second, ApplyOptions::default()).unwrap();
    write("bundle_decode", "spend-two-pools", &bundle.to_bytes());
    write(
        "utxo_proof_decode",
        "batched",
        &encode_utxo_proof(&bundle.utxo_proof),
    );
    write(
        "utxo_proof_decode",
        "empty",
        &encode_utxo_proof(&zutreexo_accumulator::UtxoProof::default()),
    );

    // ---- compact state, empty and populated ----
    write(
        "compact_state_decode",
        "fresh",
        &CompactState::new(DEPTH).unwrap().to_bytes(),
    );
    let mut nullifiers = BTreeMap::new();
    for (i, pool) in PoolId::ALL.into_iter().enumerate() {
        let mut root = [0u8; 32];
        root[0] = 0xF0 | (i as u8);
        nullifiers.insert(
            pool,
            ImtState {
                root,
                leaf_count: 1 + i as u64 * 97,
            },
        );
    }
    let seeded = CompactState::from_roots(
        DEPTH,
        &state.utxo_roots(),
        state.utxos().leaves(),
        &nullifiers,
        Some(1),
    )
    .unwrap();
    write("compact_state_decode", "populated", &seeded.to_bytes());

    // ---- wire requests, one per method tag ----
    write(
        "wire_request_decode",
        "bundle",
        &Request::BlockProofBundle { height: 1_700_000 }.to_bytes(),
    );
    write(
        "wire_request_decode",
        "nonmembership",
        &Request::NullifierNonMembership {
            pool: PoolId::Orchard,
            nullifier: nullifier(9),
        }
        .to_bytes(),
    );
    write(
        "wire_request_decode",
        "roots",
        &Request::AccumulatorRoots.to_bytes(),
    );
    write(
        "wire_request_decode",
        "roots-response",
        &Roots {
            height: 1,
            depth: DEPTH,
            utxo: state.utxo_roots(),
            nullifiers: state.nullifier_roots().into_iter().collect(),
        }
        .to_bytes(),
    );

    // ---- sparse non-membership proof ----
    let tree =
        IndexedMerkleTree::from_values_bulk(PoolId::Orchard, DEPTH, &[nullifier(5), nullifier(7)])
            .unwrap();
    let response = NonMembershipResponse {
        pool: PoolId::Orchard,
        depth: DEPTH,
        height: 1,
        proof: tree.prove_non_membership(nullifier(6)).unwrap(),
    };
    write("nonmembership_decode", "sparse", &response.to_bytes());

    // ---- a real snapshot, minus its trailing checksum ----
    //
    // The target prefixes the magic and reseals, so the seed is the payload
    // body: everything between the magic and the checksum.
    let dir = std::env::temp_dir().join("zutreexo-fuzz-seed");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("seed.snap");
    save(&state, &path).unwrap();
    let full = std::fs::read(&path).unwrap();
    let body = &full[zutreexo_chain::MAGIC.len()..full.len() - 32];
    write("snapshot_decode", "real", body);
    let _ = std::fs::remove_file(&path);

    // ---- a serialised forest ----
    write("forest_decode", "real", &state.utxos().to_bytes().unwrap());
}

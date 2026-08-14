//! Checks the accumulator against the pinned vectors in
//! [`zutreexo_testkit::vectors`].
//!
//! A failure here means a consensus-visible value moved. See that module's
//! docs before changing anything: the fix is almost never to update the
//! constant.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use zutreexo_accumulator::hash;
use zutreexo_accumulator::imt::{IndexedMerkleTree, Value};
use zutreexo_accumulator::{PoolId, UtxoForest, UtxoLeaf};
use zutreexo_testkit::vectors;

fn pool_by_name(name: &str) -> PoolId {
    PoolId::ALL
        .into_iter()
        .find(|pool| pool.to_string() == name)
        .unwrap_or_else(|| panic!("unknown pool in vectors: {name}"))
}

fn value(n: u64) -> Value {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    Value::from_bytes(bytes)
}

#[test]
fn empty_tree_roots_match() {
    for vector in vectors::EMPTY_TREE_ROOTS {
        let pool = pool_by_name(vector.pool);
        let tree = IndexedMerkleTree::with_depth(pool, vector.depth).unwrap();
        assert_eq!(
            hex::encode(tree.root()),
            vector.root,
            "empty root drifted for {} at depth {}",
            vector.pool,
            vector.depth
        );
    }
}

#[test]
fn sequence_roots_match() {
    let values: Vec<Value> = vectors::SEQUENCE.iter().copied().map(value).collect();
    for vector in vectors::SEQUENCE_ROOTS {
        let pool = pool_by_name(vector.pool);
        let tree = IndexedMerkleTree::from_values(pool, vector.depth, &values).unwrap();
        assert_eq!(
            hex::encode(tree.root()),
            vector.root,
            "sequence root drifted for {} at depth {}",
            vector.pool,
            vector.depth
        );
    }
}

#[test]
fn max_value_edge_roots_match() {
    for vector in vectors::MAX_EDGE_ROOTS {
        let pool = pool_by_name(vector.pool);
        let tree =
            IndexedMerkleTree::from_values(pool, vector.depth, &[Value::MAX, value(1)]).unwrap();
        assert_eq!(
            hex::encode(tree.root()),
            vector.root,
            "max-value edge root drifted for {}",
            vector.pool
        );
    }
}

#[test]
fn hash_vectors_match() {
    let mut expected = vectors::HASH_VECTORS.iter();
    let mut check = |label: &str, digest: [u8; 32]| {
        let vector = expected
            .next()
            .unwrap_or_else(|| panic!("missing vector for {label}"));
        assert_eq!(vector.label, label, "vector order changed");
        assert_eq!(
            hex::encode(digest),
            vector.digest,
            "digest drifted: {label}"
        );
    };

    for pool in PoolId::ALL {
        check(
            &format!("imt_empty_leaf/{pool}"),
            hash::imt_empty_leaf(pool),
        );
        check(
            &format!("imt_leaf/{pool}"),
            hash::imt_leaf(pool, &[1u8; 32], &[2u8; 32], 3),
        );
        check(
            &format!("imt_node/{pool}"),
            hash::imt_node(pool, &[1u8; 32], &[2u8; 32]),
        );
    }
    check("utxo_node", hash::utxo_node(&[1u8; 32], &[2u8; 32]));

    assert!(expected.next().is_none(), "unused vectors remain");
}

#[test]
fn utxo_leaf_digest_matches() {
    let leaf = UtxoLeaf {
        txid: [0xab; 32],
        vout: 1,
        height: 3_428_143,
        is_coinbase: false,
        value: 100_000_000,
        script_pubkey: vec![0x76, 0xa9, 0x14],
    };
    assert_eq!(
        hex::encode(leaf.hash()),
        vectors::UTXO_LEAF_DIGEST,
        "transparent leaf preimage layout drifted"
    );
}

#[test]
fn utxo_forest_roots_match() {
    let mut forest = UtxoForest::new();
    let leaves: Vec<[u8; 32]> = (1..=5u32)
        .map(|n| {
            UtxoLeaf {
                txid: [n as u8; 32],
                vout: n,
                height: 1_000_000 + n,
                is_coinbase: n == 1,
                value: u64::from(n) * 50_000,
                script_pubkey: vec![0x51, n as u8],
            }
            .hash()
        })
        .collect();
    forest.insert(&leaves).unwrap();

    let roots: Vec<String> = forest.roots().iter().map(hex::encode).collect();
    assert_eq!(roots, vectors::UTXO_FOREST_ROOTS, "forest roots drifted");
}

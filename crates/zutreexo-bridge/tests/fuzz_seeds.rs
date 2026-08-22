//! Seeds for the wire-format fuzz targets.
//!
//! The bridge owns `Request` and `Roots`, so their seeds are generated here
//! rather than from `zutreexo-testkit`. That split is not tidiness: a
//! dev-dependency on this crate from testkit makes `cargo llvm-cov` compile a
//! second instrumented copy of it, and every function in that copy reports zero
//! — halving `server.rs`'s function coverage for no reason but the measurement.
//!
//! Gated, like its counterpart, because a test has no business writing outside
//! its own directory unasked:
//!
//! ```text
//! ZUTREEXO_DUMP_SEEDS=1 cargo test -p zutreexo-bridge --test fuzz_seeds
//! ```

#![allow(clippy::unwrap_used, clippy::print_stdout)]

use std::path::PathBuf;

use zutreexo_accumulator::imt::{Value, DEFAULT_DEPTH};
use zutreexo_accumulator::{CanonicalSerialize, PoolId};
use zutreexo_bridge::wire::{Request, Roots};

fn write(target: &str, name: &str, bytes: &[u8]) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target);
    if std::fs::create_dir_all(&dir).is_ok() {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        println!("{} <- {} bytes", path.display(), bytes.len());
    }
}

#[test]
fn dump_wire_seeds() {
    if std::env::var_os("ZUTREEXO_DUMP_SEEDS").is_none() {
        println!("set ZUTREEXO_DUMP_SEEDS=1 to write the fuzz corpora");
        return;
    }

    let mut nullifier = [0u8; 32];
    nullifier[31] = 0x01;

    // One per method tag, so the fuzzer starts past the tag dispatch rather
    // than rediscovering three magic bytes.
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
            nullifier: Value::from_bytes(nullifier),
        }
        .to_bytes(),
    );
    write(
        "wire_request_decode",
        "roots",
        &Request::AccumulatorRoots.to_bytes(),
    );

    // `Roots` shares the request target's decoder surface, and it is the only
    // response type with a multi-pool ordering constraint.
    write(
        "wire_request_decode",
        "roots-response",
        &Roots {
            height: 1,
            depth: DEFAULT_DEPTH,
            utxo: vec![[7u8; 32], [9u8; 32]],
            nullifiers: PoolId::ALL
                .into_iter()
                .map(|pool| (pool, [pool.code(); 32]))
                .collect(),
        }
        .to_bytes(),
    );
}

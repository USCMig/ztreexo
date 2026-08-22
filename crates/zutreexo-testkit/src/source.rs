//! Where blocks come from.
//!
//! Stage 2d replays mainnet from genesis, which needs 3.45M blocks streamed in
//! order. The fixture loader that served 2a–2c lives in a test helper and reads
//! whole 200-block slices into memory; neither property survives contact with
//! the full chain.
//!
//! # No HTTP dependency
//!
//! `zebrad` answers JSON-RPC over plain HTTP/1.1 with a `content-length` header
//! and no chunked encoding, and it is reachable on loopback, so there is no TLS
//! to speak of. That makes a correct client about sixty lines over
//! `TcpStream` — cheaper than adding an HTTP crate, its transitive tree, and a
//! licence review to a project whose `deny.toml` exists to keep that surface
//! small.
//!
//! It is deliberately not a general HTTP client. It handles exactly what
//! `zebrad` sends, and fails loudly on anything else rather than guessing.
//!
//! # Ordering is part of the contract
//!
//! Block application is order-dependent — leaf indices, and therefore roots,
//! come out of it. So [`BlockStream`] fetches concurrently for throughput but
//! yields strictly in height order. Measured against a synced node: ~950
//! blocks/s single-threaded, ~2000 with eight workers, which puts a full
//! genesis-to-tip fetch near half an hour rather than the many hours the fixture
//! path would have implied.

use std::io::{Read, Write};
use std::net::TcpStream;

use zebra_chain::block::Block;
use zebra_chain::serialization::ZcashDeserialize;

/// One fetched block: its height, and either its bytes or why they are missing.
///
/// Named rather than written inline because a stream yields these one at a time
/// and the tuple appears in several signatures.
pub type Fetched = (u32, Result<Vec<u8>, SourceError>);

/// Why a block could not be obtained.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SourceError {
    /// The transport failed.
    #[error("rpc transport: {0}")]
    Transport(String),
    /// The node returned an error, or a response this client does not handle.
    #[error("rpc response at height {height}: {reason}")]
    Response {
        /// Height requested.
        height: u32,
        /// What went wrong.
        reason: String,
    },
    /// The bytes did not deserialize as a block.
    #[error("block {height} did not parse: {reason}")]
    Parse {
        /// Height requested.
        height: u32,
        /// What went wrong.
        reason: String,
    },
    /// The source has no block at that height.
    #[error("no block at height {height}")]
    Missing {
        /// Height requested.
        height: u32,
    },
}

/// Anything that can hand back a block by height.
pub trait BlockSource: Send + Sync {
    /// The raw consensus bytes of one block.
    fn raw_block(&self, height: u32) -> Result<Vec<u8>, SourceError>;

    /// The highest height available.
    fn tip(&self) -> Result<u32, SourceError>;

    /// Deserialized, with the height attached to any parse failure.
    fn block(&self, height: u32) -> Result<Block, SourceError> {
        let bytes = self.raw_block(height)?;
        Block::zcash_deserialize(&bytes[..]).map_err(|error| SourceError::Parse {
            height,
            reason: error.to_string(),
        })
    }
}

/// A minimal JSON-RPC client for a local `zebrad`.
#[derive(Clone, Debug)]
pub struct RpcSource {
    address: String,
}

impl Default for RpcSource {
    fn default() -> Self {
        RpcSource::new("127.0.0.1:8232")
    }
}

impl RpcSource {
    /// Points at a `host:port`.
    pub fn new(address: &str) -> RpcSource {
        RpcSource {
            address: address.to_owned(),
        }
    }

    /// The hash of the block the node currently has at `height`.
    ///
    /// # Why a shadow run needs this
    ///
    /// Height alone does not identify a block. Following the tip means the
    /// block at height *h* can be *replaced* — that is what a reorg is — and a
    /// follower that only tracked heights would apply the replacement on top of
    /// the block it superseded and diverge silently from then on.
    ///
    /// So the shadow runner remembers the hash of every block it applied and
    /// re-checks it before extending. A mismatch is the signal to unwind. This
    /// is the first time the rollback path meets a reorg it did not generate
    /// itself: `tests/reorg_fuzz.rs` ran 10⁶ synthetic ones, all of our own
    /// construction.
    pub fn block_hash(&self, height: u32) -> Result<String, SourceError> {
        let value = self.call("getblockhash", &format!("[{height}]"))?;
        if let Some(error) = value.get("error").filter(|e| !e.is_null()) {
            return Err(SourceError::Response {
                height,
                reason: error.to_string(),
            });
        }
        value
            .get("result")
            .and_then(|r| r.as_str())
            .map(str::to_owned)
            .ok_or(SourceError::Missing { height })
    }

    /// One block as `zebrad`'s own JSON, at the given verbosity.
    ///
    /// # The second oracle, live
    ///
    /// `scripts/capture_checkpoints.py` uses this route offline to produce the
    /// committed checkpoints: our parser goes raw bytes → `zebra_chain`
    /// deserializer → counts, and this goes the same raw bytes → zebrad's RPC
    /// serializer → JSON → counts. Agreement means the parse is right rather
    /// than merely self-consistent, which no amount of comparing our two models
    /// against each other can establish.
    ///
    /// A shadow run does it per block instead of per slice, because at tip
    /// there is no committed checkpoint to compare against and the blocks
    /// arriving are ones nobody chose.
    pub fn block_json(&self, height: u32, verbosity: u8) -> Result<serde_json::Value, SourceError> {
        let value = self.call("getblock", &format!(r#"["{height}", {verbosity}]"#))?;
        if let Some(error) = value.get("error").filter(|e| !e.is_null()) {
            return Err(SourceError::Response {
                height,
                reason: error.to_string(),
            });
        }
        value
            .get("result")
            .cloned()
            .ok_or(SourceError::Missing { height })
    }

    /// One request/response cycle on a fresh connection.
    ///
    /// A connection per call rather than a pool: `zebrad` closes idle
    /// connections and the measured throughput is already bounded by the node,
    /// not by socket setup. Keeping it stateless removes a whole class of
    /// half-open-connection bug from a job that runs for half an hour.
    fn call(&self, method: &str, params: &str) -> Result<serde_json::Value, SourceError> {
        let body = format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{method}","params":{params}}}"#);
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.address,
            body.len(),
            body
        );

        let mut stream = TcpStream::connect(&self.address)
            .map_err(|e| SourceError::Transport(format!("connect {}: {e}", self.address)))?;
        stream
            .write_all(request.as_bytes())
            .map_err(|e| SourceError::Transport(format!("write: {e}")))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|e| SourceError::Transport(format!("read: {e}")))?;

        // `Connection: close` means the body ends at EOF, so the content-length
        // header does not need parsing — the split below is the whole protocol
        // handling this client needs.
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| SourceError::Transport("no header terminator".to_owned()))?;
        let body = raw.get(split.saturating_add(4)..).unwrap_or(&[]);

        serde_json::from_slice(body)
            .map_err(|e| SourceError::Transport(format!("malformed json: {e}")))
    }
}

impl BlockSource for RpcSource {
    fn raw_block(&self, height: u32) -> Result<Vec<u8>, SourceError> {
        let value = self.call("getblock", &format!(r#"["{height}", 0]"#))?;
        if let Some(error) = value.get("error").filter(|e| !e.is_null()) {
            return Err(SourceError::Response {
                height,
                reason: error.to_string(),
            });
        }
        let hex_str = value
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or(SourceError::Missing { height })?;
        hex::decode(hex_str).map_err(|e| SourceError::Parse {
            height,
            reason: format!("bad hex: {e}"),
        })
    }

    fn tip(&self) -> Result<u32, SourceError> {
        let value = self.call("getblockchaininfo", "[]")?;
        value
            .get("result")
            .and_then(|r| r.get("blocks"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| SourceError::Transport("no tip in getblockchaininfo".to_owned()))
    }
}

/// Blocks read from a committed `.jsonl` fixture slice.
///
/// Kept so a replay can run with no node at all, and so the fixture path and
/// the RPC path go through the same trait rather than diverging.
#[derive(Clone, Debug)]
pub struct FixtureSource {
    start: u32,
    blocks: Vec<Vec<u8>>,
}

impl FixtureSource {
    /// Loads one slice, whose first block is at `start`.
    pub fn load(path: &std::path::Path, start: u32) -> Result<FixtureSource, SourceError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| SourceError::Transport(format!("{}: {e}", path.display())))?;
        let mut blocks = Vec::new();
        for line in text.lines() {
            let hex_str = line.trim().trim_matches('"');
            if hex_str.is_empty() {
                continue;
            }
            blocks.push(hex::decode(hex_str).map_err(|e| SourceError::Parse {
                height: start.saturating_add(blocks.len() as u32),
                reason: format!("bad hex: {e}"),
            })?);
        }
        Ok(FixtureSource { start, blocks })
    }
}

impl BlockSource for FixtureSource {
    fn raw_block(&self, height: u32) -> Result<Vec<u8>, SourceError> {
        let index = height
            .checked_sub(self.start)
            .and_then(|i| usize::try_from(i).ok())
            .ok_or(SourceError::Missing { height })?;
        self.blocks
            .get(index)
            .cloned()
            .ok_or(SourceError::Missing { height })
    }

    fn tip(&self) -> Result<u32, SourceError> {
        Ok(self
            .start
            .saturating_add(self.blocks.len() as u32)
            .saturating_sub(1))
    }
}

/// Streams a height range in order, fetching ahead concurrently.
///
/// Bounded memory: one window of blocks is in flight at a time, never the whole
/// range. At 3.45M blocks and ~10 KB each, holding them all would be 35 GB.
pub struct BlockStream<'a, S: BlockSource> {
    source: &'a S,
    next: u32,
    end: u32,
    window: usize,
    workers: usize,
    buffered: std::collections::VecDeque<Fetched>,
}

impl<'a, S: BlockSource> BlockStream<'a, S> {
    /// Streams `start..=end`.
    pub fn new(source: &'a S, start: u32, end: u32, window: usize, workers: usize) -> Self {
        BlockStream {
            source,
            next: start,
            end,
            window: window.max(1),
            workers: workers.max(1),
            buffered: std::collections::VecDeque::new(),
        }
    }

    fn refill(&mut self) {
        if self.next > self.end {
            return;
        }
        let count = self.window.min(
            usize::try_from(self.end.saturating_sub(self.next))
                .unwrap_or(usize::MAX)
                .saturating_add(1),
        );
        let heights: Vec<u32> = (0..count)
            .filter_map(|i| u32::try_from(i).ok())
            .map(|i| self.next.saturating_add(i))
            .collect();

        let source = self.source;
        let workers = self.workers.min(heights.len().max(1));
        let mut results: Vec<Option<Fetched>> = (0..heights.len()).map(|_| None).collect();

        std::thread::scope(|scope| {
            let chunk = heights.len().div_ceil(workers);
            let mut handles = Vec::new();
            for slice in heights.chunks(chunk) {
                handles.push(scope.spawn(move || {
                    slice
                        .iter()
                        .map(|h| (*h, source.raw_block(*h)))
                        .collect::<Vec<_>>()
                }));
            }
            let mut out = Vec::new();
            for handle in handles {
                if let Ok(part) = handle.join() {
                    out.extend(part);
                }
            }
            // Restore height order: threads finish out of sequence, and block
            // application is order-dependent.
            out.sort_by_key(|(h, _)| *h);
            for (index, item) in out.into_iter().enumerate() {
                if let Some(slot) = results.get_mut(index) {
                    *slot = Some(item);
                }
            }
        });

        for item in results.into_iter().flatten() {
            self.buffered.push_back(item);
        }
        self.next = self.next.saturating_add(count as u32);
    }
}

impl<S: BlockSource> Iterator for BlockStream<'_, S> {
    type Item = Fetched;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffered.is_empty() {
            self.refill();
        }
        self.buffered.pop_front()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use std::net::{Shutdown, TcpListener};

    fn write_fixture(name: &str, text: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("zutreexo-source-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.jsonl"));
        std::fs::write(&path, text).unwrap();
        path
    }

    // ---------- FixtureSource ----------

    #[test]
    fn fixture_source_loads_hex_lines_in_order() {
        let path = write_fixture("basic", "aabb\nccdd\n");
        let source = FixtureSource::load(&path, 100).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(source.tip().unwrap(), 101);
        assert_eq!(source.raw_block(100).unwrap(), vec![0xaa, 0xbb]);
        assert_eq!(source.raw_block(101).unwrap(), vec![0xcc, 0xdd]);
    }

    #[test]
    fn fixture_source_skips_blank_lines_and_strips_quotes() {
        let path = write_fixture("quoted", "\"aabb\"\n\n\"ccdd\"\n");
        let source = FixtureSource::load(&path, 0).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(source.tip().unwrap(), 1);
        assert_eq!(source.raw_block(0).unwrap(), vec![0xaa, 0xbb]);
        assert_eq!(source.raw_block(1).unwrap(), vec![0xcc, 0xdd]);
    }

    #[test]
    fn fixture_source_rejects_bad_hex_at_load_time() {
        let path = write_fixture("bad-hex", "nothex\n");
        let error = FixtureSource::load(&path, 0).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(matches!(error, SourceError::Parse { height: 0, .. }));
    }

    #[test]
    fn fixture_source_reports_missing_outside_its_range() {
        let path = write_fixture("range", "aabb\n");
        let source = FixtureSource::load(&path, 50).unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(matches!(
            source.raw_block(49),
            Err(SourceError::Missing { height: 49 })
        ));
        assert!(matches!(
            source.raw_block(51),
            Err(SourceError::Missing { height: 51 })
        ));
    }

    // ---------- BlockStream ----------

    #[test]
    fn block_stream_yields_every_height_once_in_order() {
        let path = write_fixture("stream", "00\n01\n02\n03\n04\n");
        let source = FixtureSource::load(&path, 10).unwrap();
        let _ = std::fs::remove_file(&path);

        // A window (2) smaller than the range (5) forces multiple refills.
        let stream = BlockStream::new(&source, 10, 14, 2, 3);
        let heights: Vec<u32> = stream.map(|(h, _)| h).collect();
        assert_eq!(heights, vec![10, 11, 12, 13, 14]);
    }

    #[test]
    fn block_stream_carries_a_missing_height_through_in_place() {
        // The fixture only covers 10..=11; asking through 12 leaves a gap.
        let path = write_fixture("stream-gap", "00\n01\n");
        let source = FixtureSource::load(&path, 10).unwrap();
        let _ = std::fs::remove_file(&path);

        let stream = BlockStream::new(&source, 10, 12, 4, 2);
        let results: Vec<Fetched> = stream.collect();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, 10);
        assert!(results[0].1.is_ok());
        assert_eq!(results[2].0, 12);
        assert!(matches!(
            results[2].1,
            Err(SourceError::Missing { height: 12 })
        ));
    }

    #[test]
    fn block_stream_on_an_empty_range_yields_nothing() {
        let path = write_fixture("stream-empty", "00\n");
        let source = FixtureSource::load(&path, 0).unwrap();
        let _ = std::fs::remove_file(&path);

        // end < start: nothing should be produced.
        let stream = BlockStream::new(&source, 5, 4, 8, 4);
        assert_eq!(stream.count(), 0);
    }

    // ---------- RpcSource, against a fake zebrad ----------

    /// Accepts exactly one connection, drains the request, writes back a
    /// canned HTTP/1.1 response, then closes — enough to drive
    /// `RpcSource::call`'s framing without a real `zebrad`.
    fn fake_zebrad(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let response = format!("HTTP/1.1 200 OK\r\n\r\n{body}");
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.shutdown(Shutdown::Write);
            }
        });
        addr
    }

    #[test]
    fn rpc_source_decodes_a_successful_getblock() {
        let addr = fake_zebrad(r#"{"result":"deadbeef","error":null}"#);
        let source = RpcSource::new(&addr);
        assert_eq!(source.raw_block(1).unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn rpc_source_reads_a_block_hash() {
        // Phase 5b: this is what makes reorg detection possible. Height alone
        // does not identify a block, so a follower that tracked only heights
        // would stack a replacement on the block it replaced.
        let hash = "0000000000074f33c8f9ac98043854c02a64afaf99dacc2f8245b8ada694ba2e";
        let addr = fake_zebrad(
            r#"{"result":"0000000000074f33c8f9ac98043854c02a64afaf99dacc2f8245b8ada694ba2e","error":null}"#,
        );
        let source = RpcSource::new(&addr);
        assert_eq!(source.block_hash(3_455_190).unwrap(), hash);
    }

    #[test]
    fn a_block_hash_error_names_the_height() {
        let addr = fake_zebrad(r#"{"result":null,"error":{"code":-8,"message":"out of range"}}"#);
        let source = RpcSource::new(&addr);
        assert!(matches!(
            RpcSource::block_hash(&source, 9_999_999),
            Err(SourceError::Response {
                height: 9_999_999,
                ..
            })
        ));
    }

    #[test]
    fn a_block_hash_with_no_result_is_missing_not_a_panic() {
        let addr = fake_zebrad(r#"{"error":null}"#);
        let source = RpcSource::new(&addr);
        assert!(matches!(
            source.block_hash(5),
            Err(SourceError::Missing { height: 5 })
        ));
    }

    #[test]
    fn rpc_source_returns_block_json_verbatim() {
        // The live parse oracle. Returned as-is rather than parsed here,
        // because the counting belongs with the comparison in shadow.rs where
        // it can be kept field-for-field identical to
        // scripts/capture_checkpoints.py.
        let addr =
            fake_zebrad(r#"{"result":{"height":42,"tx":[{"vin":[],"vout":[]}]},"error":null}"#);
        let source = RpcSource::new(&addr);
        let json = source.block_json(42, 2).unwrap();
        assert_eq!(json.get("height").and_then(|h| h.as_u64()), Some(42));
        assert_eq!(
            json.get("tx").and_then(|t| t.as_array()).map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn a_block_json_error_field_becomes_a_response_error() {
        let addr = fake_zebrad(r#"{"result":null,"error":{"code":-5,"message":"no such block"}}"#);
        let source = RpcSource::new(&addr);
        assert!(matches!(
            source.block_json(11, 2),
            Err(SourceError::Response { height: 11, .. })
        ));
    }

    #[test]
    fn rpc_source_turns_an_rpc_error_field_into_response_error() {
        let addr = fake_zebrad(r#"{"result":null,"error":{"code":-5,"message":"not found"}}"#);
        let source = RpcSource::new(&addr);
        assert!(matches!(
            source.raw_block(7),
            Err(SourceError::Response { height: 7, .. })
        ));
    }

    #[test]
    fn rpc_source_treats_a_missing_result_as_missing_block() {
        let addr = fake_zebrad(r#"{"result":null,"error":null}"#);
        let source = RpcSource::new(&addr);
        assert!(matches!(
            source.raw_block(9),
            Err(SourceError::Missing { height: 9 })
        ));
    }

    #[test]
    fn rpc_source_rejects_a_result_that_is_not_valid_hex() {
        let addr = fake_zebrad(r#"{"result":"not-hex!","error":null}"#);
        let source = RpcSource::new(&addr);
        assert!(matches!(
            source.raw_block(3),
            Err(SourceError::Parse { height: 3, .. })
        ));
    }

    #[test]
    fn rpc_source_reads_the_tip_out_of_getblockchaininfo() {
        let addr = fake_zebrad(r#"{"result":{"blocks":424242}}"#);
        let source = RpcSource::new(&addr);
        assert_eq!(source.tip().unwrap(), 424_242);
    }

    #[test]
    fn rpc_source_fails_loudly_when_the_response_has_no_tip() {
        let addr = fake_zebrad(r#"{"result":{}}"#);
        let source = RpcSource::new(&addr);
        assert!(matches!(source.tip(), Err(SourceError::Transport(_))));
    }

    #[test]
    fn rpc_source_fails_loudly_on_malformed_json() {
        let addr = fake_zebrad("not json");
        let source = RpcSource::new(&addr);
        assert!(matches!(source.tip(), Err(SourceError::Transport(_))));
    }

    #[test]
    fn rpc_source_fails_loudly_with_no_header_terminator() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"not even an http response");
                let _ = stream.shutdown(Shutdown::Write);
            }
        });

        let source = RpcSource::new(&addr);
        assert!(matches!(source.tip(), Err(SourceError::Transport(_))));
    }

    #[test]
    fn rpc_source_reports_a_refused_connection_as_transport_error() {
        // Bind then drop: guarantees a port nothing is listening on.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);

        let source = RpcSource::new(&addr);
        assert!(matches!(source.tip(), Err(SourceError::Transport(_))));
    }

    #[test]
    fn rpc_source_default_points_at_the_conventional_local_port() {
        assert_eq!(RpcSource::default().address, "127.0.0.1:8232");
    }
}

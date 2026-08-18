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

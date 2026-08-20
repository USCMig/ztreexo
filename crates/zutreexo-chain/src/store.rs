//! On-disk snapshots of accumulator state.
//!
//! # Why this exists
//!
//! Stage 2d established that populating the accumulators from genesis costs
//! seven hours and 32.7 GiB. Without persistence that is the *only* way to get
//! a populated state, which makes every restart a full replay.
//!
//! # Only the values are stored
//!
//! A nullifier tree is written as its values in insertion order — nothing else.
//! Leaves, successor links and the internal node map are all derived on load by
//! [`IndexedMerkleTree::from_values_bulk`], which produces a tree *identical*
//! to a replayed one rather than merely equal-rooted.
//!
//! That is 32 bytes per nullifier against roughly 600 in memory, so the 54.1M
//! nullifiers at tip occupy about 1.7 GB rather than 32 GiB. The more important
//! property is that **there is no redundant state on disk to disagree with
//! itself**: a file that decodes at all yields exactly one tree, so the format
//! cannot encode a subtly inconsistent accumulator.
//!
//! The transparent forest cannot work this way — a Utreexo root depends on the
//! whole history of insertions and deletions, not on current membership — so it
//! is written through `rustreexo`'s own serialization.
//!
//! # Crash consistency
//!
//! Writes go to a temporary file, are `fsync`ed, then `rename`d over the target,
//! and the directory is `fsync`ed. `rename` is atomic on POSIX, so an
//! interrupted save leaves either the previous snapshot or the new one intact —
//! never a half-written file. `tests/crash.rs` kills a writer at randomised
//! points and checks exactly that.
//!
//! # Versioning
//!
//! Every file opens with a magic string and a format version byte. An unknown
//! version is refused rather than guessed at, which is the whole reason the byte
//! exists this early — CLAUDE.md Phase 3 asks for a migration path, and a format
//! with no version to detect is one that can never acquire one.
//!
//! On NU7: the coinholder vote could triple block times and so triple the rate
//! at which nullifier sets grow. That changes capacity planning, not this
//! format — tree depth is a header field rather than a constant, and the payload
//! is a length-prefixed list either way. Recorded here because CLAUDE.md §7 asks
//! for the vote to be checked before the format freezes; the conclusion is that
//! this format does not depend on the outcome.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use zutreexo_accumulator::hash::{store_checksum, Hash, HASH_LEN};
use zutreexo_accumulator::imt::{IndexedMerkleTree, Value};
use zutreexo_accumulator::{PoolId, UtxoForest, UtxoLeaf};

use crate::extract::OutPoint;
use crate::pool::ChainAccumulators;

/// Identifies a zutreexo snapshot. Eight bytes, checked before anything else.
pub const MAGIC: &[u8; 8] = b"ZUTREEXO";

/// On-disk format version.
///
/// Bumped whenever the layout changes in a way an older reader would
/// misinterpret. Readers refuse versions they do not know.
pub const STORE_VERSION: u8 = 1;

/// Why a snapshot could not be written or read.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum StoreError {
    /// Filesystem trouble.
    #[error("snapshot i/o at {path}: {reason}")]
    Io {
        /// The file involved.
        path: String,
        /// What the OS said.
        reason: String,
    },

    /// The file does not begin with [`MAGIC`].
    #[error("not a zutreexo snapshot")]
    NotASnapshot,

    /// The file uses a format this build does not understand.
    #[error("snapshot format version {found}, this build reads {STORE_VERSION}")]
    UnsupportedVersion {
        /// Version byte from the file.
        found: u8,
    },

    /// The payload does not match its recorded checksum.
    #[error("snapshot checksum mismatch: truncated or corrupt")]
    ChecksumMismatch,

    /// The file ended mid-field.
    #[error("snapshot ended early while reading {field}")]
    Truncated {
        /// What was being read.
        field: &'static str,
    },

    /// A field held a value the format does not allow.
    #[error("snapshot is malformed: {reason}")]
    Malformed {
        /// What was wrong.
        reason: String,
    },
}

fn io_error(path: &Path, error: &std::io::Error) -> StoreError {
    StoreError::Io {
        path: path.display().to_string(),
        reason: error.to_string(),
    }
}

/// Append-only byte sink with little-endian primitives.
#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }
    fn bytes_with_len(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.raw(value);
    }
}

/// Bounds-checked cursor. Every read either returns its bytes or an error;
/// there is no way to index past the end.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize, field: &'static str) -> Result<&'a [u8], StoreError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(StoreError::Truncated { field })?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(StoreError::Truncated { field })?;
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, StoreError> {
        self.take(1, field)?
            .first()
            .copied()
            .ok_or(StoreError::Truncated { field })
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, StoreError> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(self.take(4, field)?);
        Ok(u32::from_le_bytes(buf))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, StoreError> {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(self.take(8, field)?);
        Ok(u64::from_le_bytes(buf))
    }

    fn array32(&mut self, field: &'static str) -> Result<[u8; 32], StoreError> {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(self.take(32, field)?);
        Ok(buf)
    }

    /// A length-prefixed blob, with the declared length checked against what
    /// actually remains before anything is allocated.
    fn bytes_with_len(&mut self, field: &'static str) -> Result<&'a [u8], StoreError> {
        let len = usize::try_from(self.u64(field)?).unwrap_or(usize::MAX);
        if len > self.bytes.len().saturating_sub(self.offset) {
            return Err(StoreError::Truncated { field });
        }
        self.take(len, field)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
}

/// Serialises state into the snapshot payload, without the checksum.
fn encode(state: &ChainAccumulators) -> Result<Vec<u8>, StoreError> {
    let mut out = Writer::default();
    out.raw(MAGIC);
    out.u8(STORE_VERSION);
    out.u8(state.depth());

    // Tip as a presence flag plus a height, rather than a sentinel height: a
    // fresh state genuinely has no tip, and encoding that as 0 would make it
    // indistinguishable from a state holding only the genesis block.
    match state.tip() {
        Some(height) => {
            out.u8(1);
            out.u32(height);
        }
        None => {
            out.u8(0);
            out.u32(0);
        }
    }

    let pools: Vec<PoolId> = PoolId::ALL.into_iter().collect();
    out.u8(u8::try_from(pools.len()).unwrap_or(u8::MAX));
    for pool in pools {
        let tree = state.tree(pool).ok_or_else(|| StoreError::Malformed {
            reason: format!("no tree for pool {pool}"),
        })?;
        out.u8(pool.code());
        // Leaf 0 is the sentinel and is implied by the format; only the
        // inserted values are written, in insertion order.
        out.u64(tree.value_count());
        for index in 1..tree.leaf_count() {
            let leaf = tree.leaf(index).ok_or_else(|| StoreError::Malformed {
                reason: format!("{pool} leaf {index} missing while saving"),
            })?;
            out.raw(leaf.value.as_bytes());
        }
    }

    let forest = state
        .utxos()
        .to_bytes()
        .map_err(|error| StoreError::Malformed {
            reason: format!("forest would not serialise: {error}"),
        })?;
    out.bytes_with_len(&forest);

    out.u64(state.utxo_count() as u64);
    for (outpoint, leaf) in state.utxo_index_iter() {
        out.raw(&outpoint.txid);
        out.u32(outpoint.vout);
        out.u32(leaf.height);
        out.u8(u8::from(leaf.is_coinbase));
        out.u64(leaf.value);
        out.bytes_with_len(&leaf.script_pubkey);
    }

    Ok(out.bytes)
}

/// Rebuilds state from a payload that has already passed its checksum.
fn decode(payload: &[u8]) -> Result<ChainAccumulators, StoreError> {
    let mut reader = Reader::new(payload);

    if reader.take(MAGIC.len(), "magic")? != MAGIC.as_slice() {
        return Err(StoreError::NotASnapshot);
    }
    let version = reader.u8("version")?;
    if version != STORE_VERSION {
        return Err(StoreError::UnsupportedVersion { found: version });
    }

    let depth = reader.u8("depth")?;
    let has_tip = reader.u8("tip flag")?;
    let tip_height = reader.u32("tip height")?;

    let mut state = ChainAccumulators::new(depth).map_err(|error| StoreError::Malformed {
        reason: format!("depth {depth} rejected: {error}"),
    })?;

    let pool_count = reader.u8("pool count")?;
    for _ in 0..pool_count {
        let code = reader.u8("pool code")?;
        let pool = PoolId::from_code(code).ok_or(StoreError::Malformed {
            reason: format!("unknown pool code {code}"),
        })?;

        let count = reader.u64("value count")?;
        // Checked against the bytes actually present before allocating: the
        // count is 8 bytes of file that a corrupt snapshot controls.
        let needed = usize::try_from(count)
            .ok()
            .and_then(|n| n.checked_mul(HASH_LEN))
            .ok_or(StoreError::Truncated { field: "values" })?;
        if needed > reader.remaining() {
            return Err(StoreError::Truncated { field: "values" });
        }

        let mut values = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
        for _ in 0..count {
            values.push(Value::from_bytes(reader.array32("value")?));
        }

        let tree = IndexedMerkleTree::from_values_bulk(pool, depth, &values).map_err(|error| {
            StoreError::Malformed {
                reason: format!("{pool} tree would not rebuild: {error}"),
            }
        })?;
        state.replace_tree(pool, tree);
    }

    let forest_bytes = reader.bytes_with_len("forest")?;
    let forest = UtxoForest::from_bytes(forest_bytes).map_err(|error| StoreError::Malformed {
        reason: format!("forest would not deserialise: {error}"),
    })?;

    let utxo_count = reader.u64("utxo count")?;
    // The smallest possible entry: txid, vout, height, coinbase flag, value,
    // and a zero-length script prefix.
    const MIN_UTXO_LEN: usize = 32 + 4 + 4 + 1 + 8 + 8;
    let floor = usize::try_from(utxo_count)
        .ok()
        .and_then(|n| n.checked_mul(MIN_UTXO_LEN))
        .ok_or(StoreError::Truncated {
            field: "utxo index",
        })?;
    if floor > reader.remaining() {
        return Err(StoreError::Truncated {
            field: "utxo index",
        });
    }

    let mut index: BTreeMap<OutPoint, UtxoLeaf> = BTreeMap::new();
    for _ in 0..utxo_count {
        let txid = reader.array32("utxo txid")?;
        let vout = reader.u32("utxo vout")?;
        let height = reader.u32("utxo height")?;
        let is_coinbase = reader.u8("utxo coinbase")? != 0;
        let value = reader.u64("utxo value")?;
        let script_pubkey = reader.bytes_with_len("utxo script")?.to_vec();
        index.insert(
            OutPoint { txid, vout },
            UtxoLeaf {
                txid,
                vout,
                height,
                is_coinbase,
                value,
                script_pubkey,
            },
        );
    }

    if reader.remaining() != 0 {
        return Err(StoreError::Malformed {
            reason: format!("{} trailing bytes", reader.remaining()),
        });
    }

    state.restore_transparent(forest, index);
    state.set_tip_to(if has_tip == 1 { Some(tip_height) } else { None });
    Ok(state)
}

/// Writes a snapshot atomically.
///
/// The payload is built in memory, checksummed, written to `<path>.tmp`,
/// `fsync`ed, then renamed over `path`, and finally the containing directory is
/// `fsync`ed so the rename itself is durable. A crash at any point leaves either
/// the previous snapshot or the new one — never a partial file.
pub fn save(state: &ChainAccumulators, path: &Path) -> Result<(), StoreError> {
    let payload = encode(state)?;
    let checksum = store_checksum(&payload);

    let temp = temp_path(path);
    {
        let mut file = std::fs::File::create(&temp).map_err(|e| io_error(&temp, &e))?;
        file.write_all(&payload).map_err(|e| io_error(&temp, &e))?;
        file.write_all(&checksum).map_err(|e| io_error(&temp, &e))?;
        // Before the rename, not after: a rename that lands ahead of the data
        // is exactly the torn state this is meant to prevent.
        file.sync_all().map_err(|e| io_error(&temp, &e))?;
    }

    std::fs::rename(&temp, path).map_err(|e| io_error(path, &e))?;

    // The rename is only durable once the directory entry is.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Reads a snapshot, verifying magic, version and checksum before use.
pub fn load(path: &Path) -> Result<ChainAccumulators, StoreError> {
    let bytes = std::fs::read(path).map_err(|e| io_error(path, &e))?;
    let split = bytes
        .len()
        .checked_sub(HASH_LEN)
        .ok_or(StoreError::Truncated { field: "checksum" })?;
    let (payload, recorded) = bytes.split_at(split);

    // Magic first: a wrong-format file should say so rather than fail a
    // checksum, which reads like corruption and sends you looking at the disk.
    if payload.len() < MAGIC.len() || payload.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(StoreError::NotASnapshot);
    }

    let computed: Hash = store_checksum(payload);
    if computed.as_slice() != recorded {
        return Err(StoreError::ChecksumMismatch);
    }

    decode(payload)
}

/// The temporary file a save writes through.
///
/// Deliberately beside the target rather than in `/tmp`: `rename` is only
/// atomic within a filesystem, and a temp directory is frequently a different
/// one.
pub fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".tmp");
    PathBuf::from(name)
}

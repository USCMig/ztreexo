//! Canonical serialization for proof types.
//!
//! Every decoder in this module is a remote attack surface: a compact state
//! node decodes proofs supplied by a bridge it does not necessarily trust, and
//! Phase 6 points `cargo-fuzz` at exactly these functions. Three rules follow,
//! and they are why this is hand-rolled rather than derived:
//!
//! 1. **No panics.** Every read is bounds-checked and returns a typed error.
//!    A panic here is a remote crash (CLAUDE.md §5 rule 3).
//! 2. **No unbounded allocation.** Lengths are validated against a hard cap
//!    *before* anything is reserved, so a two-byte header cannot ask for a
//!    gigabyte.
//! 3. **Canonical.** Decoding rejects trailing bytes, and encode-decode-encode
//!    is the identity. Two encodings of one proof would mean two hashes of one
//!    object the moment anything commits to proof bytes.

use std::collections::BTreeMap;

use crate::cohort::{CohortProof, CohortResponse, PrefixRange};
use crate::hash::{Hash, HASH_LEN};
use crate::imt::{
    empty_subtree_hashes, InsertionProof, Leaf, NonMembershipProof, Value, MAX_DEPTH,
};
use crate::pool::PoolId;
use crate::utreexo::UtxoProof;

/// Version byte prefixed to every top-level encoding.
///
/// Phase 3 needs a migration path for the on-disk format; this is the wire-side
/// counterpart and exists from the start so there is never a version-0 format
/// to detect by guessing.
pub const PROOF_FORMAT_VERSION: u8 = 2;

/// Encoded size of a [`Leaf`]: two values and an index.
const LEAF_LEN: usize = 32 + 32 + 8;

/// Decoding failures.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ProofCodecError {
    /// Input ended mid-field.
    #[error("unexpected end of input: needed {needed} more bytes at offset {offset}")]
    UnexpectedEof {
        /// Byte offset where the read failed.
        offset: usize,
        /// How many more bytes were required.
        needed: usize,
    },

    /// Input decoded successfully but was longer than the encoding.
    ///
    /// Rejected rather than ignored: tolerating trailing bytes would make the
    /// encoding non-canonical and give an attacker a free malleability channel.
    #[error("{count} trailing bytes after a complete encoding")]
    TrailingBytes {
        /// Number of bytes left over.
        count: usize,
    },

    /// Version byte this build does not understand.
    #[error("unsupported proof format version {found}, expected {PROOF_FORMAT_VERSION}")]
    UnsupportedVersion {
        /// The version byte read from the input.
        found: u8,
    },

    /// A declared sibling-path length exceeds the largest legal tree depth.
    ///
    /// Checked before allocating, so a hostile length is cheap to reject.
    #[error("declared path length {found} exceeds the maximum depth {MAX_DEPTH}")]
    PathTooLong {
        /// The declared length.
        found: usize,
    },

    /// A pool discriminant with no corresponding [`PoolId`].
    #[error("unknown pool code {code}")]
    UnknownPool {
        /// The unrecognised byte.
        code: u8,
    },

    /// The `rustreexo` proof decoder rejected the input.
    #[error("utreexo proof decode failed: {0}")]
    Utreexo(String),

    /// A length prefix claims more bytes than the input still holds.
    ///
    /// Distinct from [`ProofCodecError::UnexpectedEof`], which is raised *after*
    /// a read runs out. This one is raised *before* allocating, so a hostile
    /// length is rejected without the allocation it was asking for
    /// (`docs/design.md` D13 records exactly this defect in upstream
    /// `rustreexo`'s decoder). A bridge node's clients are untrusted by
    /// definition, so the check has to precede the `with_capacity`.
    #[error("{field} declares {declared} bytes but only {remaining} remain")]
    DeclaredLengthExceedsInput {
        /// Which field carried the length.
        field: &'static str,
        /// The declared length.
        declared: usize,
        /// Bytes actually left.
        remaining: usize,
    },

    /// A field decoded but holds a value the format does not allow.
    #[error("malformed encoding: {reason}")]
    Malformed {
        /// What was wrong.
        reason: &'static str,
    },

    /// A request names a method this build does not implement.
    #[error("unknown method tag {tag}")]
    UnknownMethod {
        /// The unrecognised tag byte.
        tag: u8,
    },
}

/// A bounds-checked cursor over a byte slice.
///
/// Deliberately minimal: every method either returns the bytes asked for or an
/// error, and there is no way to index past the end.
pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// Wraps a slice.
    pub fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, offset: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    /// Consumes exactly `count` bytes.
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], ProofCodecError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ProofCodecError::UnexpectedEof {
                offset: self.offset,
                needed: count,
            })?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProofCodecError::UnexpectedEof {
                offset: self.offset,
                needed: count.saturating_sub(self.remaining()),
            })?;
        self.offset = end;
        Ok(slice)
    }

    /// Consumes one byte.
    pub fn u8(&mut self) -> Result<u8, ProofCodecError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(ProofCodecError::UnexpectedEof {
                offset: self.offset,
                needed: 1,
            })
    }

    /// Consumes a little-endian `u32`.
    ///
    /// Exists because three call sites were doing `take(4)` and then a
    /// `try_into` that cannot fail — `take` already guarantees the length — but
    /// still needed an error arm for it, which was unreachable code in each.
    pub fn u32_le(&mut self) -> Result<u32, ProofCodecError> {
        let bytes = self.take(4)?;
        let mut array = [0u8; 4];
        array.copy_from_slice(bytes);
        Ok(u32::from_le_bytes(array))
    }

    /// Consumes a little-endian `u64`.
    pub fn u64_le(&mut self) -> Result<u64, ProofCodecError> {
        let bytes = self.take(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(buf))
    }

    /// Consumes a 32-byte digest.
    pub fn hash(&mut self) -> Result<Hash, ProofCodecError> {
        let bytes = self.take(32)?;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        Ok(buf)
    }

    /// Consumes a length-prefixed sibling path.
    ///
    /// The cap is checked before `Vec::with_capacity`, which is the whole point
    /// of a one-byte length here.
    pub fn path(&mut self) -> Result<Vec<Hash>, ProofCodecError> {
        let len = usize::from(self.u8()?);
        if len > usize::from(MAX_DEPTH) {
            return Err(ProofCodecError::PathTooLong { found: len });
        }
        let mut path = Vec::with_capacity(len);
        for _ in 0..len {
            path.push(self.hash()?);
        }
        Ok(path)
    }
}

/// Canonical, version-tagged encoding.
pub trait CanonicalSerialize: Sized {
    /// Appends the body — everything after the version byte.
    fn write_body(&self, out: &mut Vec<u8>);

    /// Reads the body from a cursor.
    fn read_body(reader: &mut Reader<'_>) -> Result<Self, ProofCodecError>;

    /// Encodes with the version prefix.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![PROOF_FORMAT_VERSION];
        self.write_body(&mut out);
        out
    }

    /// Decodes, rejecting an unknown version or any trailing bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, ProofCodecError> {
        let mut reader = Reader::new(bytes);
        let version = reader.u8()?;
        if version != PROOF_FORMAT_VERSION {
            return Err(ProofCodecError::UnsupportedVersion { found: version });
        }
        let value = Self::read_body(&mut reader)?;
        if reader.remaining() != 0 {
            return Err(ProofCodecError::TrailingBytes {
                count: reader.remaining(),
            });
        }
        Ok(value)
    }
}

/// Appends a sibling path with the derivable siblings omitted.
///
/// Layout: one length byte, then `ceil(len / 8)` bitmap bytes, then only the
/// siblings whose bit is set. A clear bit means "this sibling is the canonical
/// empty-subtree hash for its level", which the decoder reconstructs from
/// `ladder`.
///
/// # Why this is safe against a lying encoder
///
/// A hostile bridge can clear a bit for a sibling that is *not* empty. The
/// decoder then substitutes the empty hash, the verifier folds the path, and
/// the computed root does not match the one it trusts — so the proof is
/// rejected. The bitmap cannot be used to forge acceptance, only to produce a
/// proof that fails. That is the same guarantee the dense encoding gives
/// against a corrupted sibling, which is why this needs no extra check.
fn write_path_sparse(path: &[Hash], ladder: &[Hash], out: &mut Vec<u8>) {
    let len = u8::try_from(path.len()).unwrap_or(u8::MAX);
    out.push(len);

    let kept = usize::from(len);
    let mut bitmap = vec![0u8; kept.div_ceil(8)];
    for (level, sibling) in path.iter().take(kept).enumerate() {
        if ladder.get(level) != Some(sibling) {
            if let Some(byte) = bitmap.get_mut(level / 8) {
                *byte |= 1 << (level % 8);
            }
        }
    }
    out.extend_from_slice(&bitmap);

    for (level, sibling) in path.iter().take(kept).enumerate() {
        if ladder.get(level) != Some(sibling) {
            out.extend_from_slice(sibling);
        }
    }
}

/// Reads a sparse sibling path, restoring the omitted siblings from `ladder`.
fn read_path_sparse(
    reader: &mut Reader<'_>,
    ladder: &[Hash],
) -> Result<Vec<Hash>, ProofCodecError> {
    let len = usize::from(reader.u8()?);
    if len > usize::from(MAX_DEPTH) {
        return Err(ProofCodecError::PathTooLong { found: len });
    }
    // The ladder is built from the depth the verifier expects. A path longer
    // than it has no empty hash to fall back on, and silently truncating would
    // turn a depth disagreement into a wrong root much later.
    //
    // Sliced once rather than indexed per level: the per-level lookup needed a
    // `None` arm that this check already made unreachable, and unreachable
    // error handling is indistinguishable from the reachable kind when reading
    // the code.
    let empties = ladder.get(..len).ok_or(ProofCodecError::Malformed {
        reason: "sparse path is longer than the tree depth",
    })?;

    let bitmap = reader.take(len.div_ceil(8))?.to_vec();
    let mut path = Vec::with_capacity(len);
    for (level, empty) in empties.iter().enumerate() {
        let present = bitmap
            .get(level / 8)
            .is_some_and(|byte| byte & (1 << (level % 8)) != 0);
        if present {
            path.push(reader.hash()?);
        } else {
            path.push(*empty);
        }
    }
    Ok(path)
}

/// Appends a length-prefixed sibling path.
fn write_path(path: &[Hash], out: &mut Vec<u8>) {
    // Depths above MAX_DEPTH are unrepresentable by construction; saturating
    // keeps this total, and the decoder rejects the result.
    out.push(u8::try_from(path.len()).unwrap_or(u8::MAX));
    for hash in path {
        out.extend_from_slice(hash);
    }
}

/// Appends a leaf.
fn write_leaf(leaf: &Leaf, out: &mut Vec<u8>) {
    out.extend_from_slice(leaf.value.as_bytes());
    out.extend_from_slice(leaf.next_value.as_bytes());
    out.extend_from_slice(&leaf.next_index.to_le_bytes());
}

/// Reads a leaf.
fn read_leaf(reader: &mut Reader<'_>) -> Result<Leaf, ProofCodecError> {
    let value = Value::from_bytes(reader.hash()?);
    let next_value = Value::from_bytes(reader.hash()?);
    let next_index = reader.u64_le()?;
    Ok(Leaf {
        value,
        next_value,
        next_index,
    })
}

impl CanonicalSerialize for NonMembershipProof {
    fn write_body(&self, out: &mut Vec<u8>) {
        write_leaf(&self.low_leaf, out);
        out.extend_from_slice(&self.low_leaf_index.to_le_bytes());
        write_path(&self.siblings, out);
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, ProofCodecError> {
        Ok(NonMembershipProof {
            low_leaf: read_leaf(reader)?,
            low_leaf_index: reader.u64_le()?,
            siblings: reader.path()?,
        })
    }
}

impl CanonicalSerialize for InsertionProof {
    fn write_body(&self, out: &mut Vec<u8>) {
        write_leaf(&self.low_leaf, out);
        out.extend_from_slice(&self.low_leaf_index.to_le_bytes());
        write_path(&self.low_leaf_siblings, out);
        out.extend_from_slice(&self.new_leaf_index.to_le_bytes());
        write_path(&self.new_leaf_siblings, out);
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, ProofCodecError> {
        Ok(InsertionProof {
            low_leaf: read_leaf(reader)?,
            low_leaf_index: reader.u64_le()?,
            low_leaf_siblings: reader.path()?,
            new_leaf_index: reader.u64_le()?,
            new_leaf_siblings: reader.path()?,
        })
    }
}

/// A non-membership proof as a bridge serves it to a wallet.
///
/// # Why this wrapper exists
///
/// Two reasons, and they are the same reason.
///
/// The sparse encoding needs the pool: the omitted siblings are the canonical
/// empty-subtree hashes, and those are domain-separated per pool, so a decoder
/// cannot rebuild them without knowing which tree the proof came from. It needs
/// the depth for the same reason.
///
/// And a proof *should* be pool-tagged regardless. A proof lifted from one
/// pool's tree and applied to another fails on the root check, so nothing
/// unsafe happens either way — but tagging turns that into a decode-time error
/// naming the mistake, rather than a hash mismatch several layers down. This is
/// the reasoning already applied to [`NullifierProofBundle`].
///
/// This is the response type for the bridge's
/// `GetNullifierNonMembershipProof`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NonMembershipResponse {
    /// Which pool's tree the proof is against.
    pub pool: PoolId,
    /// The depth that tree was built at.
    pub depth: u8,
    /// Height whose root the proof is stated against.
    ///
    /// A proof is only meaningful against a root, and a root only exists at a
    /// height. Without this a wallet cannot tell which root to check it with,
    /// and a stale proof would look identical to a fresh one.
    pub height: u32,
    /// The proof itself.
    pub proof: NonMembershipProof,
}

impl CanonicalSerialize for NonMembershipResponse {
    fn write_body(&self, out: &mut Vec<u8>) {
        out.push(self.pool.code());
        out.push(self.depth);
        out.extend_from_slice(&self.height.to_le_bytes());
        write_leaf(&self.proof.low_leaf, out);
        out.extend_from_slice(&self.proof.low_leaf_index.to_le_bytes());
        match empty_subtree_hashes(self.pool, self.depth) {
            Ok(ladder) => write_path_sparse(&self.proof.siblings, &ladder, out),
            // An invalid depth cannot produce a ladder. Fall back to the dense
            // form rather than emitting a truncated path: the decoder rejects
            // the depth anyway, and this keeps the encoder total.
            Err(_) => write_path(&self.proof.siblings, out),
        }
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, ProofCodecError> {
        let code = reader.u8()?;
        let pool = PoolId::from_code(code).ok_or(ProofCodecError::UnknownPool { code })?;
        let depth = reader.u8()?;
        let height = reader.u32_le()?;
        let low_leaf = read_leaf(reader)?;
        let low_leaf_index = reader.u64_le()?;
        let ladder = empty_subtree_hashes(pool, depth).map_err(|_| ProofCodecError::Malformed {
            reason: "invalid tree depth",
        })?;
        let siblings = read_path_sparse(reader, &ladder)?;
        Ok(NonMembershipResponse {
            pool,
            depth,
            height,
            proof: NonMembershipProof {
                low_leaf,
                low_leaf_index,
                siblings,
            },
        })
    }
}

/// Wire form of a prefix cohort ([`crate::cohort`]).
///
/// # Layout, and why the leaf indices are delta-coded
///
/// ```text
/// pool:u8  depth:u8  bits:u8  lo:[u8;32]  height:u32
/// leaf_count:u32   then per leaf: index_delta:varint, leaf(72 B)
/// node_count:u32   then per node: level:u8, index_delta:varint, hash(32 B)
/// ```
///
/// Cohort leaf indices are insertion-order positions scattered across a
/// 40-deep tree, so each is a full `u64` in absolute form: 8 bytes × ~800
/// leaves is 6.4 KB of pure index. Ascending order makes the deltas small, and
/// a varint makes small deltas cheap. The same applies to node indices within
/// a level.
///
/// The range travels as `bits` plus `lo` rather than as a prefix integer,
/// because `lo` is what the verifier needs and deriving it from a prefix means
/// re-implementing the masking in [`crate::cohort::PrefixRange::covering`] on
/// the reading side. `hi` is not sent: it is a function of `lo` and `bits`.
impl CanonicalSerialize for CohortResponse {
    fn write_body(&self, out: &mut Vec<u8>) {
        out.push(self.proof.pool.code());
        out.push(self.proof.depth);
        out.push(self.proof.range.bits());
        out.extend_from_slice(self.proof.range.lo().as_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());

        let leaf_count = u32::try_from(self.proof.leaves.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&leaf_count.to_le_bytes());
        let mut previous = 0u64;
        for (index, leaf) in self.proof.leaves.iter().take(leaf_count as usize) {
            write_varint(index.wrapping_sub(previous), out);
            previous = *index;
            write_leaf(leaf, out);
        }

        let node_count = u32::try_from(self.proof.nodes.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&node_count.to_le_bytes());
        let mut previous_level = 0u8;
        let mut previous_index = 0u64;
        for ((level, index), hash) in self.proof.nodes.iter().take(node_count as usize) {
            // Nodes come out of a BTreeMap keyed by (level, index), so they are
            // already grouped by level and ascending within it. Reset the delta
            // base at each level boundary.
            if *level != previous_level {
                previous_index = 0;
                previous_level = *level;
            }
            out.push(*level);
            write_varint(index.wrapping_sub(previous_index), out);
            previous_index = *index;
            out.extend_from_slice(hash);
        }
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, ProofCodecError> {
        let code = reader.u8()?;
        let pool = PoolId::from_code(code).ok_or(ProofCodecError::UnknownPool { code })?;
        let depth = reader.u8()?;
        let bits = reader.u8()?;
        let lo = Value::from_bytes(reader.hash()?);
        let height = reader.u32_le()?;

        let range = PrefixRange::covering(lo, bits).map_err(|_| ProofCodecError::Malformed {
            reason: "invalid cohort prefix width",
        })?;
        if range.lo() != lo {
            // `lo` must already be aligned to its bucket. An unaligned bound
            // would answer for a range no prefix describes, and two different
            // encodings would then mean the same cohort.
            return Err(ProofCodecError::Malformed {
                reason: "cohort lower bound is not aligned to its prefix",
            });
        }

        let leaf_count = reader.u32_le()?;
        // One leaf is 72 bytes plus at least one index byte, so a declared
        // count the remaining input cannot hold is rejected before allocating.
        // This is D29's lesson: the guard has to check the direction that
        // actually matters.
        if u64::from(leaf_count) > reader.remaining() as u64 / 73 {
            return Err(ProofCodecError::Malformed {
                reason: "cohort declares more leaves than the input can hold",
            });
        }
        let mut leaves = Vec::with_capacity(leaf_count as usize);
        let mut previous = 0u64;
        for _ in 0..leaf_count {
            let delta = read_varint(reader)?;
            let index = previous
                .checked_add(delta)
                .ok_or(ProofCodecError::Malformed {
                    reason: "cohort leaf index overflows",
                })?;
            previous = index;
            leaves.push((index, read_leaf(reader)?));
        }

        let node_count = reader.u32_le()?;
        // A node is 33 bytes plus at least one index byte.
        if u64::from(node_count) > reader.remaining() as u64 / 34 {
            return Err(ProofCodecError::Malformed {
                reason: "cohort declares more nodes than the input can hold",
            });
        }
        let mut nodes = BTreeMap::new();
        let mut previous_level = 0u8;
        let mut previous_index = 0u64;
        for _ in 0..node_count {
            let level = reader.u8()?;
            if level != previous_level {
                previous_index = 0;
                previous_level = level;
            }
            let delta = read_varint(reader)?;
            let index = previous_index
                .checked_add(delta)
                .ok_or(ProofCodecError::Malformed {
                    reason: "cohort node index overflows",
                })?;
            previous_index = index;
            nodes.insert((level, index), reader.hash()?);
        }

        Ok(CohortResponse {
            height,
            proof: CohortProof {
                pool,
                depth,
                range,
                leaves,
                nodes,
            },
        })
    }
}

/// LEB128, unsigned. Small deltas cost one byte.
fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Reads a LEB128 unsigned integer, rejecting over-long encodings.
fn read_varint(reader: &mut Reader<'_>) -> Result<u64, ProofCodecError> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = reader.u8()?;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(ProofCodecError::Malformed {
        reason: "varint is longer than 64 bits",
    })
}

/// Encodes an insertion proof with the derivable siblings omitted.
///
/// Not a [`CanonicalSerialize`] impl because the encoding depends on the pool
/// and depth, which an [`InsertionProof`] does not carry. The callers that use
/// it — [`NullifierProofBundle`] and the block bundle in `zutreexo-chain` — are
/// pool-keyed already.
pub fn write_insertion_sparse(proof: &InsertionProof, ladder: &[Hash], out: &mut Vec<u8>) {
    write_leaf(&proof.low_leaf, out);
    out.extend_from_slice(&proof.low_leaf_index.to_le_bytes());
    write_path_sparse(&proof.low_leaf_siblings, ladder, out);
    out.extend_from_slice(&proof.new_leaf_index.to_le_bytes());
    write_path_sparse(&proof.new_leaf_siblings, ladder, out);
}

/// Decodes an insertion proof written by [`write_insertion_sparse`].
pub fn read_insertion_sparse(
    reader: &mut Reader<'_>,
    ladder: &[Hash],
) -> Result<InsertionProof, ProofCodecError> {
    let low_leaf = read_leaf(reader)?;
    let low_leaf_index = reader.u64_le()?;
    let low_leaf_siblings = read_path_sparse(reader, ladder)?;
    let new_leaf_index = reader.u64_le()?;
    let new_leaf_siblings = read_path_sparse(reader, ladder)?;
    Ok(InsertionProof {
        low_leaf,
        low_leaf_index,
        low_leaf_siblings,
        new_leaf_index,
        new_leaf_siblings,
    })
}

/// One pool's nullifier proofs for one block.
///
/// Pool-tagged because a proof is only meaningful against the tree it was
/// generated from: the domain separators differ per pool, so a proof moved
/// between pools fails on the root check rather than silently verifying — but
/// tagging makes that a decode-time error instead of a hash-time one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NullifierProofBundle {
    /// Which pool these proofs belong to.
    pub pool: PoolId,
    /// The nullifiers revealed, in block order.
    pub nullifiers: Vec<Value>,
    /// Non-membership proof for each nullifier, against the pre-block root.
    pub non_membership: Vec<NonMembershipProof>,
    /// Insertion proof for each nullifier, applied in order.
    pub insertions: Vec<InsertionProof>,
}

impl NullifierProofBundle {
    /// Whether the three parallel vectors have matching lengths.
    ///
    /// A structural check only — it says nothing about whether the proofs
    /// verify. Block application checks that separately.
    pub fn is_well_formed(&self) -> bool {
        self.nullifiers.len() == self.non_membership.len()
            && self.nullifiers.len() == self.insertions.len()
    }
}

impl CanonicalSerialize for NullifierProofBundle {
    fn write_body(&self, out: &mut Vec<u8>) {
        out.push(self.pool.code());

        let count = u32::try_from(self.nullifiers.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for value in self.nullifiers.iter().take(count as usize) {
            out.extend_from_slice(value.as_bytes());
        }
        for proof in self.non_membership.iter().take(count as usize) {
            proof.write_body(out);
        }
        for proof in self.insertions.iter().take(count as usize) {
            proof.write_body(out);
        }
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Self, ProofCodecError> {
        let code = reader.u8()?;
        let pool = PoolId::from_code(code).ok_or(ProofCodecError::UnknownPool { code })?;

        let mut count_bytes = [0u8; 4];
        count_bytes.copy_from_slice(reader.take(4)?);
        let count = usize::try_from(u32::from_le_bytes(count_bytes)).unwrap_or(usize::MAX);

        // Do not size the vectors from `count` before the bytes exist. The
        // smallest possible entry is one value plus two proofs, so a count
        // larger than that bound cannot be satisfied by the remaining input.
        let min_entry = 32usize
            .saturating_add(LEAF_LEN + 8 + 1)
            .saturating_add(LEAF_LEN + 8 + 1 + 8 + 1);
        if count.saturating_mul(min_entry) > reader.remaining() {
            return Err(ProofCodecError::UnexpectedEof {
                offset: 0,
                needed: count.saturating_mul(min_entry),
            });
        }

        let mut nullifiers = Vec::with_capacity(count);
        for _ in 0..count {
            nullifiers.push(Value::from_bytes(reader.hash()?));
        }
        let mut non_membership = Vec::with_capacity(count);
        for _ in 0..count {
            non_membership.push(NonMembershipProof::read_body(reader)?);
        }
        let mut insertions = Vec::with_capacity(count);
        for _ in 0..count {
            insertions.push(InsertionProof::read_body(reader)?);
        }

        Ok(NullifierProofBundle {
            pool,
            nullifiers,
            non_membership,
            insertions,
        })
    }
}

/// Encodes a transparent batch proof.
///
/// Delegates to `rustreexo`'s own format rather than re-specifying it, so the
/// two implementations cannot drift.
pub fn encode_utxo_proof(proof: &UtxoProof) -> Vec<u8> {
    let mut out = vec![PROOF_FORMAT_VERSION];
    // `Vec`'s `io::Write` is infallible; the error branch is unreachable but
    // returning bytes-so-far keeps the function total.
    if proof.inner().serialize(&mut out).is_err() {
        out.truncate(1);
    }
    out
}

/// Decodes a transparent batch proof.
///
/// # Why this validates the header itself
///
/// `rustreexo::proof::Proof::deserialize` reads a `u64` length prefix and
/// passes it straight to `Vec::with_capacity` without checking it against the
/// input. Eight attacker-chosen bytes therefore buy an allocation of any size:
/// the 10,000-case property sweep that found this aborted the process trying
/// to allocate 3.7 exabytes. That is a remote denial of service in any node
/// that decodes a peer-supplied proof, which is precisely what a compact state
/// node does.
///
/// So the header is validated here, before `rustreexo` sees the bytes. The
/// check is structural rather than a magic constant: `targets` are 8 bytes
/// each and `hashes` 32, so the declared counts must be satisfiable by the
/// input that actually arrived. A proof claiming a billion targets in 40 bytes
/// is rejected without allocating anything.
///
/// The upstream defect is tracked in `docs/design.md` D13. Remove this
/// pre-validation only once the dependency bounds its own allocations, and
/// even then, keep the canonical-length check.
pub fn decode_utxo_proof(bytes: &[u8]) -> Result<UtxoProof, ProofCodecError> {
    let mut reader = Reader::new(bytes);
    let version = reader.u8()?;
    if version != PROOF_FORMAT_VERSION {
        return Err(ProofCodecError::UnsupportedVersion { found: version });
    }
    let rest = reader.take(reader.remaining())?;
    validate_utxo_proof_header(rest)?;

    rustreexo::proof::Proof::deserialize(rest)
        .map(UtxoProof::from_inner)
        .map_err(|e| ProofCodecError::Utreexo(format!("{e:?}")))
}

/// Encoded size of one target position in `rustreexo`'s proof format.
const UTXO_TARGET_LEN: usize = 8;

/// Encoded size of one proof hash: a one-byte variant tag plus the digest.
///
/// `rustreexo` writes proof hashes through `AccumulatorHash::write`, so this
/// tracks [`ZcashNodeHash`](crate::utreexo::ZcashNodeHash)'s encoding rather
/// than the bare digest length. It is 33, not 32, and the difference is not
/// cosmetic — an exact-fit check against the wrong width rejects every valid
/// proof.
///
/// `Empty` and `Placeholder` encode to a single byte, so a proof containing
/// either is shorter than `count * UTXO_HASH_LEN`. The check below is therefore
/// an upper bound rather than an equality; see its comment.
const UTXO_HASH_LEN: usize = 1 + HASH_LEN;

/// Checks that a `rustreexo` proof encoding's declared lengths fit its bytes.
///
/// The layout is `targets_len: u64 ‖ targets ‖ hashes_len: u64 ‖ hashes`, all
/// little-endian. Every arithmetic step is checked, because the whole point is
/// that the declared values are hostile.
fn validate_utxo_proof_header(bytes: &[u8]) -> Result<(), ProofCodecError> {
    let mut reader = Reader::new(bytes);

    let targets_len = usize::try_from(reader.u64_le()?).unwrap_or(usize::MAX);
    let targets_bytes =
        targets_len
            .checked_mul(UTXO_TARGET_LEN)
            .ok_or(ProofCodecError::UnexpectedEof {
                offset: 8,
                needed: usize::MAX,
            })?;
    if targets_bytes > reader.remaining() {
        return Err(ProofCodecError::UnexpectedEof {
            offset: 8,
            needed: targets_bytes,
        });
    }
    reader.take(targets_bytes)?;

    let hashes_len = usize::try_from(reader.u64_le()?).unwrap_or(usize::MAX);

    // **Lower bound first, and this is the one that matters.** Every hash entry
    // costs at least one byte under the tagged encoding — a bare tag for
    // `Empty` or `Placeholder` — so a declared count exceeding the bytes that
    // actually arrived is unsatisfiable no matter what those bytes contain.
    //
    // An earlier version of this function omitted this check and claimed in a
    // comment that "a header claiming a billion hashes in forty bytes is
    // rejected before anything is allocated." That was false, and exactly
    // backwards: only *under*-declaration was caught. `bundle_codec.rs`'s
    // bit-flip test found it by aborting the process on a 141,733,920,801-byte
    // allocation — one flipped bit set the count to 2^32+1, which sailed past
    // the upper-bound check below and straight into `rustreexo`'s
    // `with_capacity`. That is `docs/design.md` D13's defect reached through
    // our own decoder, so guarding it here is not redundant with waiting for
    // upstream.
    if hashes_len > reader.remaining() {
        return Err(ProofCodecError::DeclaredLengthExceedsInput {
            field: "utreexo proof hashes",
            declared: hashes_len,
            remaining: reader.remaining(),
        });
    }

    let hashes_bytes =
        hashes_len
            .checked_mul(UTXO_HASH_LEN)
            .ok_or(ProofCodecError::UnexpectedEof {
                offset: 0,
                needed: usize::MAX,
            })?;
    // Upper bound, not an equality. Hash entries are variable width — one byte
    // for `Empty` or `Placeholder`, 33 for `Some` — so a proof carrying either
    // is legitimately shorter than the maximum, and requiring an exact fit
    // would reject valid proofs. This catches the opposite error from the check
    // above: more bytes present than the declared count could ever consume.
    if hashes_bytes < reader.remaining() {
        return Err(ProofCodecError::UnexpectedEof {
            offset: 0,
            needed: hashes_bytes,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

    use super::*;
    use crate::imt::IndexedMerkleTree;

    const POOL: PoolId = PoolId::Ironwood;
    const D: u8 = 8;

    fn v(n: u64) -> Value {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        Value::from_bytes(bytes)
    }

    fn sample_bundle() -> NullifierProofBundle {
        let mut tree = IndexedMerkleTree::with_depth(POOL, D).unwrap();
        let values = vec![v(30), v(10), v(20)];
        let mut non_membership = Vec::new();
        let mut insertions = Vec::new();
        for value in &values {
            non_membership.push(tree.prove_non_membership(*value).unwrap());
            insertions.push(tree.insert(*value).unwrap());
        }
        NullifierProofBundle {
            pool: POOL,
            nullifiers: values,
            non_membership,
            insertions,
        }
    }

    #[test]
    fn non_membership_round_trips() {
        let bundle = sample_bundle();
        for proof in &bundle.non_membership {
            let bytes = proof.to_bytes();
            let decoded = NonMembershipProof::from_bytes(&bytes).unwrap();
            assert_eq!(&decoded, proof);
            assert_eq!(decoded.to_bytes(), bytes, "encoding is not canonical");
        }
    }

    #[test]
    fn insertion_round_trips() {
        let bundle = sample_bundle();
        for proof in &bundle.insertions {
            let bytes = proof.to_bytes();
            let decoded = InsertionProof::from_bytes(&bytes).unwrap();
            assert_eq!(&decoded, proof);
            assert_eq!(decoded.to_bytes(), bytes, "encoding is not canonical");
        }
    }

    #[test]
    fn bundle_round_trips() {
        let bundle = sample_bundle();
        assert!(bundle.is_well_formed());
        let bytes = bundle.to_bytes();
        let decoded = NullifierProofBundle::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, bundle);
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn decoded_proofs_still_verify() {
        let mut tree = IndexedMerkleTree::with_depth(POOL, D).unwrap();
        tree.insert(v(10)).unwrap();
        let proof = tree.prove_non_membership(v(5)).unwrap();
        let decoded = NonMembershipProof::from_bytes(&proof.to_bytes()).unwrap();
        tree.state()
            .verify_non_membership(POOL, D, v(5), &decoded)
            .unwrap();
    }

    #[test]
    fn utxo_proof_round_trips() {
        use crate::utreexo::{UtxoForest, UtxoLeaf};

        let mut forest = UtxoForest::new();
        let leaves: Vec<Hash> = (1..=8u8)
            .map(|n| {
                UtxoLeaf {
                    txid: [n; 32],
                    vout: 0,
                    height: 1,
                    is_coinbase: false,
                    value: 1,
                    script_pubkey: vec![n],
                }
                .hash()
            })
            .collect();
        forest.insert(&leaves).unwrap();

        let targets = vec![leaves[2], leaves[5]];
        let proof = forest.prove(&targets).unwrap();
        let bytes = encode_utxo_proof(&proof);
        let decoded = decode_utxo_proof(&bytes).unwrap();
        assert!(forest.verify(&decoded, &targets).unwrap());
    }

    // --- hostile input --------------------------------------------------

    #[test]
    fn wrong_version_is_rejected() {
        let bundle = sample_bundle();
        let mut bytes = bundle.to_bytes();
        bytes[0] = 99;
        assert_eq!(
            NullifierProofBundle::from_bytes(&bytes).err(),
            Some(ProofCodecError::UnsupportedVersion { found: 99 })
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let bundle = sample_bundle();
        let mut bytes = bundle.to_bytes();
        bytes.push(0);
        assert_eq!(
            NullifierProofBundle::from_bytes(&bytes).err(),
            Some(ProofCodecError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn empty_input_is_rejected() {
        assert!(matches!(
            NonMembershipProof::from_bytes(&[]),
            Err(ProofCodecError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn unknown_pool_is_rejected() {
        let bundle = sample_bundle();
        let mut bytes = bundle.to_bytes();
        bytes[1] = 200;
        assert_eq!(
            NullifierProofBundle::from_bytes(&bytes).err(),
            Some(ProofCodecError::UnknownPool { code: 200 })
        );
    }

    /// A hostile path length must be rejected before it is allocated.
    #[test]
    fn oversized_path_is_rejected() {
        let mut bytes = vec![PROOF_FORMAT_VERSION];
        bytes.extend_from_slice(&[0u8; LEAF_LEN]);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.push(u8::MAX); // claim 255 siblings
        assert_eq!(
            NonMembershipProof::from_bytes(&bytes).err(),
            Some(ProofCodecError::PathTooLong { found: 255 })
        );
    }

    /// A four-byte count claiming four billion entries must not allocate.
    #[test]
    fn oversized_bundle_count_is_rejected() {
        let mut bytes = vec![PROOF_FORMAT_VERSION, POOL.code()];
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            NullifierProofBundle::from_bytes(&bytes),
            Err(ProofCodecError::UnexpectedEof { .. })
        ));
    }

    /// Regression: a hostile length prefix in a transparent proof must be
    /// rejected without allocating.
    ///
    /// Found by the 10,000-case property sweep, which aborted the test process
    /// with `memory allocation of 3728591668636114096 bytes failed`.
    /// `rustreexo` reads this `u64` and hands it to `Vec::with_capacity`
    /// unchecked; `validate_utxo_proof_header` now stops it first. See
    /// `docs/design.md` D13.
    #[test]
    fn hostile_utxo_proof_length_does_not_allocate() {
        // The exact shape that aborted the sweep: a huge declared target count
        // with no targets behind it.
        let mut bytes = vec![PROOF_FORMAT_VERSION];
        bytes.extend_from_slice(&466_073_958_579_514_262u64.to_le_bytes());
        assert!(matches!(
            decode_utxo_proof(&bytes),
            Err(ProofCodecError::UnexpectedEof { .. })
        ));

        // And the maximum, which would overflow the byte-count multiplication.
        let mut bytes = vec![PROOF_FORMAT_VERSION];
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_utxo_proof(&bytes).is_err());

        // A plausible-looking header whose hash count is unsatisfiable.
        let mut bytes = vec![PROOF_FORMAT_VERSION];
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_utxo_proof(&bytes).is_err());
    }

    /// The header validator must not reject anything the encoder produces.
    #[test]
    fn header_validation_accepts_real_proofs() {
        use crate::utreexo::{UtxoForest, UtxoLeaf};

        let mut forest = UtxoForest::new();
        let leaves: Vec<Hash> = (1..=16u8)
            .map(|n| {
                UtxoLeaf {
                    txid: [n; 32],
                    vout: u32::from(n),
                    height: 1,
                    is_coinbase: false,
                    value: 1,
                    script_pubkey: vec![n],
                }
                .hash()
            })
            .collect();
        forest.insert(&leaves).unwrap();

        for targets in [&leaves[..1], &leaves[..4], &leaves[..], &leaves[0..0]] {
            let proof = forest.prove(targets).unwrap();
            let bytes = encode_utxo_proof(&proof);
            assert!(
                decode_utxo_proof(&bytes).is_ok(),
                "rejected a proof we produced, with {} targets",
                targets.len()
            );
        }
    }

    /// Truncation at every offset must produce an error, never a panic.
    #[test]
    fn every_truncation_is_handled() {
        let bundle = sample_bundle();
        let bytes = bundle.to_bytes();
        for cut in 0..bytes.len() {
            let result = NullifierProofBundle::from_bytes(&bytes[..cut]);
            assert!(result.is_err(), "truncation to {cut} bytes decoded");
        }
    }

    /// Every single-byte corruption must be rejected or decode to something
    /// different — never silently produce the original.
    #[test]
    fn single_byte_corruption_never_forges_the_original() {
        let bundle = sample_bundle();
        let bytes = bundle.to_bytes();
        for i in 0..bytes.len() {
            let mut corrupted = bytes.clone();
            corrupted[i] ^= 0x01;
            if let Ok(decoded) = NullifierProofBundle::from_bytes(&corrupted) {
                assert_ne!(decoded, bundle, "bit flip at {i} decoded to the original");
            }
        }
    }
}

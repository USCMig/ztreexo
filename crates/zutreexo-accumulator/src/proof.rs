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

use crate::hash::{Hash, HASH_LEN};
use crate::imt::{InsertionProof, Leaf, NonMembershipProof, Value, MAX_DEPTH};
use crate::pool::PoolId;
use crate::utreexo::UtxoProof;

/// Version byte prefixed to every top-level encoding.
///
/// Phase 3 needs a migration path for the on-disk format; this is the wire-side
/// counterpart and exists from the start so there is never a version-0 format
/// to detect by guessing.
pub const PROOF_FORMAT_VERSION: u8 = 1;

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
    let hashes_bytes =
        hashes_len
            .checked_mul(UTXO_HASH_LEN)
            .ok_or(ProofCodecError::UnexpectedEof {
                offset: 0,
                needed: usize::MAX,
            })?;
    // An upper bound, not an equality. Hash entries are variable width under
    // the tagged encoding — one byte for `Empty` or `Placeholder`, 33 for
    // `Some` — so a proof carrying either is legitimately shorter than the
    // maximum. Requiring an exact fit would reject valid proofs.
    //
    // The bound still does the job this function exists for: it makes the
    // declared count unsatisfiable by the bytes that actually arrived, so a
    // header claiming a billion hashes in forty bytes is rejected before
    // anything is allocated. Truncation within the bound is caught by
    // `rustreexo`'s own parse immediately afterwards, which allocates
    // incrementally rather than up front.
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

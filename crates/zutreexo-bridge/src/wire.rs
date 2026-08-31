//! The bridge's request and response types, and their encoding.
//!
//! # Why not gRPC
//!
//! CLAUDE.md §4 says to expose these through Zaino, "otherwise as a standalone
//! sidecar with the same transport" — and Zaino speaks gRPC, so that reads as
//! protobuf. This is a deliberate departure, recorded in `docs/design.md` D27.
//!
//! Everything served here already has a canonical binary encoding, built in
//! Phase 4a and now sparse (D28). Wrapping those bytes in protobuf would put
//! one length-delimited framing inside another to no benefit, and pull
//! `tonic`/`prost` into a dependency set that has stayed deliberately small.
//! The codec is kept separate from the transport precisely so a Zaino adapter
//! is a shim over these same bytes rather than a reimplementation.
//!
//! # Shape
//!
//! A request is a one-byte method tag and a body. A response is a one-byte
//! status and a body. Both travel as `application/octet-stream` over HTTP/1.1,
//! so ordinary tooling can talk to it and nothing has to base64 anything —
//! which matters, because inflating the payload by a third would corrupt the
//! bandwidth measurements this project exists to produce.

use zutreexo_accumulator::cohort::PrefixRange;
use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::proof::{CanonicalSerialize, ProofCodecError, Reader};
use zutreexo_accumulator::{Hash, PoolId};

use crate::epoch::EpochEntry;

/// Version of the bridge's **request envelope**.
///
/// # Two version bytes, deliberately
///
/// This one governs the request framing: the method tag and its arguments.
/// The *payloads* — proof bundles, non-membership proofs, [`Roots`] — carry
/// [`PROOF_FORMAT_VERSION`](zutreexo_accumulator::PROOF_FORMAT_VERSION)
/// instead, because they are accumulator encodings that exist independently of
/// this transport and are consumed by code that never opens a socket.
///
/// So the two move independently and that is the intent: adding a method bumps
/// `WIRE_VERSION` and leaves every stored proof readable, while changing a
/// proof's layout bumps the format version and leaves the request framing
/// alone. A single number would force one to lie about the other.
///
/// A test asserting the wrong one of these caught the ambiguity when nothing
/// documented it, which is why this comment exists.
///
/// Bumped to 2 by the cohort service: [`Request::PrefixCohort`] and
/// [`Request::EpochManifest`] are new tags, and a version 1 client would read
/// their responses as garbage rather than as an unknown method.
pub const WIRE_VERSION: u8 = 2;

/// What a client is asking for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Request {
    /// Everything needed to apply one block from roots alone.
    BlockProofBundle {
        /// Height wanted.
        height: u32,
    },
    /// Non-membership proof for one nullifier, against the current root.
    NullifierNonMembership {
        /// Which pool's tree.
        pool: PoolId,
        /// The nullifier to prove absent.
        nullifier: Value,
    },
    /// The accumulator roots at the bridge's tip.
    AccumulatorRoots,
    /// Every nullifier in one prefix bucket of one snapshot epoch.
    ///
    /// # What is deliberately not in this request
    ///
    /// **The nullifier.** [`Request::NullifierNonMembership`] names the exact
    /// value a wallet is about to spend, which tells the bridge which note is
    /// being spent before the transaction is public — the metadata leak
    /// CLAUDE.md Phase 6 asks about. This method names only the *bucket*: the
    /// client derives it with
    /// [`PrefixRange::covering`](zutreexo_accumulator::cohort::PrefixRange::covering),
    /// receives every value in it, and settles membership locally with
    /// [`sorted::resolve`](zutreexo_accumulator::sorted::resolve).
    ///
    /// `docs/design.md` D40 is the limit on what that buys: the crowd is
    /// 12,302 per note but 1 per *wallet*, because a wallet's set of buckets
    /// fingerprints it. D41 gives the spreading rule that recovers it.
    PrefixCohort {
        /// Which pool's snapshot.
        pool: PoolId,
        /// Height of the epoch to answer against. A client should use the
        /// newest the manifest advertises; see [`crate::epoch`].
        epoch: u32,
        /// Prefix width in bits. Refused above the epoch's advertised
        /// `max_bits`.
        bits: u8,
        /// Bucket lower bound, which must be aligned to `bits`.
        lo: Value,
    },
    /// Which snapshot epochs the bridge holds, and the prefix floor for each.
    EpochManifest,
}

impl Request {
    const TAG_BUNDLE: u8 = 1;
    const TAG_NON_MEMBERSHIP: u8 = 2;
    const TAG_ROOTS: u8 = 3;
    const TAG_COHORT: u8 = 4;
    const TAG_MANIFEST: u8 = 5;

    /// Encodes with the version prefix.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![WIRE_VERSION];
        match self {
            Request::BlockProofBundle { height } => {
                out.push(Request::TAG_BUNDLE);
                out.extend_from_slice(&height.to_le_bytes());
            }
            Request::NullifierNonMembership { pool, nullifier } => {
                out.push(Request::TAG_NON_MEMBERSHIP);
                out.push(pool.code());
                out.extend_from_slice(nullifier.as_bytes());
            }
            Request::AccumulatorRoots => out.push(Request::TAG_ROOTS),
            Request::PrefixCohort {
                pool,
                epoch,
                bits,
                lo,
            } => {
                out.push(Request::TAG_COHORT);
                out.push(pool.code());
                out.extend_from_slice(&epoch.to_le_bytes());
                out.push(*bits);
                out.extend_from_slice(lo.as_bytes());
            }
            Request::EpochManifest => out.push(Request::TAG_MANIFEST),
        }
        out
    }

    /// The bucket a cohort request names, as a range.
    ///
    /// `Ok(None)` for a request that is not a cohort request. The alignment
    /// check lives here rather than in the decoder so that the range and the
    /// bytes cannot disagree: a `lo` that is not on a `bits` boundary would
    /// describe a window no prefix produces, and two distinct encodings would
    /// then name the same set of values.
    pub fn prefix_range(&self) -> Result<Option<PrefixRange>, ProofCodecError> {
        let Request::PrefixCohort { bits, lo, .. } = self else {
            return Ok(None);
        };
        let range = PrefixRange::covering(*lo, *bits).map_err(|_| ProofCodecError::Malformed {
            reason: "cohort request names an invalid prefix width",
        })?;
        if range.lo() != *lo {
            return Err(ProofCodecError::Malformed {
                reason: "cohort lower bound is not aligned to its prefix",
            });
        }
        Ok(Some(range))
    }

    /// Decodes a request, rejecting unknown versions, tags, and trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Request, ProofCodecError> {
        let mut reader = Reader::new(bytes);
        let version = reader.u8()?;
        if version != WIRE_VERSION {
            return Err(ProofCodecError::UnsupportedVersion { found: version });
        }
        let request = match reader.u8()? {
            Request::TAG_BUNDLE => Request::BlockProofBundle {
                height: reader.u32_le()?,
            },
            Request::TAG_NON_MEMBERSHIP => {
                let code = reader.u8()?;
                let pool = PoolId::from_code(code).ok_or(ProofCodecError::UnknownPool { code })?;
                Request::NullifierNonMembership {
                    pool,
                    nullifier: Value::from_bytes(reader.hash()?),
                }
            }
            Request::TAG_ROOTS => Request::AccumulatorRoots,
            Request::TAG_COHORT => {
                let code = reader.u8()?;
                let pool = PoolId::from_code(code).ok_or(ProofCodecError::UnknownPool { code })?;
                let epoch = reader.u32_le()?;
                let bits = reader.u8()?;
                let lo = Value::from_bytes(reader.hash()?);
                let request = Request::PrefixCohort {
                    pool,
                    epoch,
                    bits,
                    lo,
                };
                // Rejected at the door rather than at the tree: an unaligned or
                // out-of-range bucket is a malformed request, and letting it
                // reach the store would make the refusal look like a policy
                // decision when it is a parse failure.
                request.prefix_range()?;
                request
            }
            Request::TAG_MANIFEST => Request::EpochManifest,
            other => {
                return Err(ProofCodecError::UnknownMethod { tag: other });
            }
        };
        if reader.remaining() != 0 {
            return Err(ProofCodecError::TrailingBytes {
                count: reader.remaining(),
            });
        }
        Ok(request)
    }
}

/// The accumulator state a light client anchors against.
///
/// Small enough — a few hundred bytes — that a wallet can fetch it from several
/// independent bridges and compare. That is the mitigation for the trust
/// problem in `docs/benchmarks.md` Phase 5a: a proof means nothing without a
/// root, nothing commits roots to the chain before Phase 7, and comparing
/// across bridges reduces "this bridge is honest" to "these bridges are not all
/// colluding".
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Roots {
    /// Height these roots describe.
    pub height: u32,
    /// Depth the nullifier trees were built at.
    pub depth: u8,
    /// Transparent accumulator roots.
    pub utxo: Vec<Hash>,
    /// One nullifier root per pool, in pool order.
    pub nullifiers: Vec<(PoolId, Hash)>,
}

impl CanonicalSerialize for Roots {
    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.height.to_le_bytes());
        out.push(self.depth);
        let utxo = u8::try_from(self.utxo.len()).unwrap_or(u8::MAX);
        out.push(utxo);
        for root in self.utxo.iter().take(usize::from(utxo)) {
            out.extend_from_slice(root);
        }
        let pools = u8::try_from(self.nullifiers.len()).unwrap_or(u8::MAX);
        out.push(pools);
        for (pool, root) in self.nullifiers.iter().take(usize::from(pools)) {
            out.push(pool.code());
            out.extend_from_slice(root);
        }
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<Roots, ProofCodecError> {
        let height = reader.u32_le()?;
        let depth = reader.u8()?;

        let count = usize::from(reader.u8()?);
        let mut utxo = Vec::with_capacity(count.min(reader.remaining()));
        for _ in 0..count {
            utxo.push(reader.hash()?);
        }

        let pools = usize::from(reader.u8()?);
        let mut nullifiers = Vec::with_capacity(pools.min(reader.remaining()));
        for _ in 0..pools {
            let code = reader.u8()?;
            let pool = PoolId::from_code(code).ok_or(ProofCodecError::UnknownPool { code })?;
            nullifiers.push((pool, reader.hash()?));
        }
        // Pool order is part of the encoding: two orderings of the same roots
        // must not both decode, or the response is not canonical and two
        // bridges reporting identical state could disagree byte for byte —
        // which is exactly what a wallet comparing bridges is checking.
        if nullifiers
            .windows(2)
            .any(|w| matches!(w, [a, b] if a.0 >= b.0))
        {
            return Err(ProofCodecError::Malformed {
                reason: "nullifier roots are not in strict pool order",
            });
        }
        Ok(Roots {
            height,
            depth,
            utxo,
            nullifiers,
        })
    }
}

/// What snapshot epochs a bridge holds, and the prefix floor for each.
///
/// A client fetches this once per session and uses it for three things: to
/// learn which epoch to anchor against, to size its own fold, and — the one
/// that matters for privacy — to learn `max_bits` *before* asking, so a
/// legitimate query is never refused for naming too narrow a bucket.
///
/// # Why the floor is advertised rather than merely enforced
///
/// A client that discovers the floor by being refused has already told the
/// bridge the narrow bucket it wanted, which is most of what the floor exists
/// to prevent. Publishing it means the first cohort request a wallet ever sends
/// is already wide enough.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EpochManifest {
    /// The anonymity target the bridge enforces. A client should refuse to use
    /// a bridge advertising less than its own policy requires — the number is
    /// what `docs/design.md` D40's crowd size was measured at, and a bridge
    /// quietly serving smaller cohorts would make that analysis untrue without
    /// making anything fail.
    pub min_anonymity: u64,
    /// Retained snapshots, in pool-then-height order.
    pub epochs: Vec<EpochEntry>,
}

impl CanonicalSerialize for EpochManifest {
    fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.min_anonymity.to_le_bytes());
        let count = u16::try_from(self.epochs.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for entry in self.epochs.iter().take(usize::from(count)) {
            out.push(entry.pool.code());
            out.extend_from_slice(&entry.height.to_le_bytes());
            out.push(entry.depth);
            out.extend_from_slice(&entry.leaf_count.to_le_bytes());
            out.push(entry.max_bits);
            out.extend_from_slice(&entry.root);
        }
    }

    fn read_body(reader: &mut Reader<'_>) -> Result<EpochManifest, ProofCodecError> {
        let min_anonymity = reader.u64_le()?;
        let count = usize::from(reader.u16_le()?);
        // One entry is 47 bytes, so a declared count the input cannot hold is
        // refused before allocating. D29's lesson, in the direction that
        // matters.
        if count > reader.remaining() / ENTRY_BYTES {
            return Err(ProofCodecError::Malformed {
                reason: "manifest declares more epochs than the input can hold",
            });
        }
        let mut epochs = Vec::with_capacity(count);
        for _ in 0..count {
            let code = reader.u8()?;
            let pool = PoolId::from_code(code).ok_or(ProofCodecError::UnknownPool { code })?;
            let height = reader.u32_le()?;
            let depth = reader.u8()?;
            let leaf_count = reader.u64_le()?;
            let max_bits = reader.u8()?;
            let root = reader.hash()?;
            epochs.push(EpochEntry {
                pool,
                height,
                depth,
                leaf_count,
                max_bits,
                root,
            });
        }
        // Same canonicality rule as `Roots`: one ordering, or two bridges
        // holding identical state could answer with different bytes and a
        // wallet comparing them would see a disagreement that is not one.
        if epochs
            .windows(2)
            .any(|w| matches!(w, [a, b] if (a.pool, a.height) >= (b.pool, b.height)))
        {
            return Err(ProofCodecError::Malformed {
                reason: "manifest epochs are not in strict pool-then-height order",
            });
        }
        Ok(EpochManifest {
            min_anonymity,
            epochs,
        })
    }
}

/// Encoded size of one [`EpochEntry`]: pool, height, depth, leaf count,
/// max bits, root.
const ENTRY_BYTES: usize = 1 + 4 + 1 + 8 + 1 + 32;

/// Status byte leading every response.
pub mod status {
    /// Body is the requested payload.
    pub const OK: u8 = 0;
    /// The bridge does not have that height.
    pub const NO_SUCH_HEIGHT: u8 = 1;
    /// The request did not decode.
    pub const BAD_REQUEST: u8 = 2;
    /// The nullifier is already in the tree, so no absence proof exists.
    ///
    /// Distinct from an error: it is a truthful and useful answer, and a wallet
    /// asking about its own note wants to know precisely this.
    pub const ALREADY_SPENT: u8 = 3;
    /// The bridge failed to serve a request it should have been able to.
    pub const INTERNAL: u8 = 4;
    /// The bridge holds no snapshot for that pool at that height.
    ///
    /// Distinct from [`NO_SUCH_HEIGHT`], which is about proof bundles. A client
    /// seeing this has a stale manifest and should refetch it rather than
    /// retry.
    pub const NO_SUCH_EPOCH: u8 = 5;
    /// The prefix asked for would yield a cohort below the bridge's anonymity
    /// floor.
    ///
    /// **Refused rather than widened.** Silently answering a wider range than
    /// the client asked for would hand back a proof the client did not request
    /// and might not re-check, and would hide the policy from the only party
    /// whose privacy it protects. The floor is published in
    /// [`EpochManifest`](super::EpochManifest), so a client that read the
    /// manifest never sees this.
    pub const PREFIX_TOO_NARROW: u8 = 6;
    /// The peer has exhausted its byte budget for cohort responses.
    ///
    /// Separate from the request-count limiter: one cohort is ~385 KB at the
    /// operating point, so a peer inside the request limit can still pull
    /// hundreds of megabytes a minute. See [`crate::limits`].
    pub const BUDGET_EXHAUSTED: u8 = 7;
}

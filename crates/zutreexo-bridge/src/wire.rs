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

use zutreexo_accumulator::imt::Value;
use zutreexo_accumulator::proof::{CanonicalSerialize, ProofCodecError, Reader};
use zutreexo_accumulator::{Hash, PoolId};

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
pub const WIRE_VERSION: u8 = 1;

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
}

impl Request {
    const TAG_BUNDLE: u8 = 1;
    const TAG_NON_MEMBERSHIP: u8 = 2;
    const TAG_ROOTS: u8 = 3;

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
        }
        out
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
}

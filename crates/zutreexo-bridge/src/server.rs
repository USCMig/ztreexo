//! A minimal HTTP/1.1 server carrying binary bodies, and the client for it.
//!
//! Deliberately small — roughly the same shape as `zutreexo-testkit`'s zebrad
//! client, and for the same reason. What is being tested is the *codec* and the
//! bridge's answers; an HTTP stack would add dependency surface without adding
//! anything to that. See `docs/design.md` D27 for why this is not gRPC.
//!
//! # What it does not do
//!
//! No TLS, no authentication, no concurrency beyond one connection at a time,
//! no rate limiting. **Bind it to loopback.** A bridge exposed to the network
//! is a denial-of-service target — a peer requesting proofs for every UTXO is
//! the explicit Phase 6 concern — and none of that analysis has been done.
//! [`serve_once`] exists so a test can drive a real socket without a thread
//! pool.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::time::Instant;

use zutreexo_accumulator::proof::{CanonicalSerialize, NonMembershipResponse};
use zutreexo_accumulator::sorted::SortedCohort;
use zutreexo_chain::BlockProofBundle;

use crate::limits::{Limits, RateLimiter};
use crate::wire::{status, EpochManifest, Request, Roots};
use crate::{Bridge, BridgeError};

/// Serves one request on an accepted connection.
///
/// Errors are transport-level only: a request that fails to decode is answered
/// with [`status::BAD_REQUEST`] rather than dropped, because a client that gets
/// no reply cannot tell a malformed request from a hung bridge.
pub fn serve_once(bridge: &Bridge, stream: &mut TcpStream) -> std::io::Result<()> {
    serve_once_with(bridge, stream, &Limits::default())
}

/// Placeholder peer for the un-metered entry points.
///
/// [`serve_once_with`] has no accepted address to charge — it is handed a
/// stream. Rather than silently skip the byte budget it charges this address,
/// so a caller that wants per-peer accounting has to go through
/// [`serve_once_metered`] and cannot get it by accident.
const UNKNOWN_PEER: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Serves one request under explicit limits.
///
/// The timeouts are applied to the socket here rather than by the caller,
/// because a connection that reaches this function unbounded is already the
/// problem: `read_request` will block in `read()` and, on a single-threaded
/// bridge, that is every client's problem at once.
pub fn serve_once_with(
    bridge: &Bridge,
    stream: &mut TcpStream,
    limits: &Limits,
) -> std::io::Result<()> {
    serve_once_metered(bridge, stream, limits, UNKNOWN_PEER, None)
}

/// The same, charging cohort payload against one peer's byte budget.
///
/// The budget is separate from the request counter because a cohort is three
/// orders of magnitude larger than anything else this server sends; see
/// [`Limits::cohort_bytes_per_minute`].
pub fn serve_once_metered(
    bridge: &Bridge,
    stream: &mut TcpStream,
    limits: &Limits,
    peer: IpAddr,
    limiter: Option<&mut RateLimiter>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(limits.read_timeout))?;
    stream.set_write_timeout(Some(limits.write_timeout))?;

    let body = match read_request(stream, limits) {
        Ok(body) => body,
        Err(error) => {
            write_response(stream, status::BAD_REQUEST, &[])?;
            return Err(error);
        }
    };

    let mut metered = false;
    let (code, payload) = match Request::from_bytes(&body) {
        Err(_) => (status::BAD_REQUEST, Vec::new()),
        Ok(Request::AccumulatorRoots) => (status::OK, bridge.roots().to_bytes()),
        Ok(Request::BlockProofBundle { height }) => match bridge.bundle(height) {
            Some(bundle) => (status::OK, bundle.to_bytes()),
            None => (status::NO_SUCH_HEIGHT, Vec::new()),
        },
        Ok(Request::NullifierNonMembership { pool, nullifier }) => {
            match bridge.prove_unspent(pool, nullifier) {
                Ok(Some(proof)) => (status::OK, proof.to_bytes()),
                Ok(None) => (status::ALREADY_SPENT, Vec::new()),
                Err(_) => (status::INTERNAL, Vec::new()),
            }
        }
        Ok(Request::EpochManifest) => (status::OK, bridge.manifest().to_bytes()),
        Ok(request @ Request::PrefixCohort { pool, epoch, .. }) => {
            // The range was validated during decode, so this cannot fail; the
            // guarded form keeps the handler total rather than relying on that
            // (CLAUDE.md §5 rule 3 — no unwrap in a serving path).
            match request.prefix_range() {
                Ok(Some(range)) => match bridge.prove_cohort(pool, epoch, range) {
                    Ok(cohort) => {
                        metered = true;
                        (status::OK, cohort.to_bytes())
                    }
                    Err(BridgeError::NoSuchEpoch { .. }) => (status::NO_SUCH_EPOCH, Vec::new()),
                    Err(BridgeError::PrefixTooNarrow { .. }) => {
                        (status::PREFIX_TOO_NARROW, Vec::new())
                    }
                    Err(_) => (status::INTERNAL, Vec::new()),
                },
                _ => (status::BAD_REQUEST, Vec::new()),
            }
        }
    };

    // A cap on our own output. Refusing to send is better than spending the
    // only serving thread on a response nobody asked to be this large; the
    // client learns the request was refused rather than waiting on a stall.
    if payload.len() > limits.max_response_bytes {
        return write_response(stream, status::INTERNAL, &[]);
    }

    // Charged only on the payload actually being sent, and only for cohorts:
    // billing a client for a refusal would let one over-budget request lock it
    // out of the cheap methods too.
    if metered {
        if let Some(limiter) = limiter {
            if !limiter.allow_bytes(peer, payload.len() as u64) {
                return write_response(stream, status::BUDGET_EXHAUSTED, &[]);
            }
        }
    }

    write_response(stream, code, &payload)
}

/// Accepts and serves connections until `limit` have been handled.
///
/// Single-threaded and sequential. Adequate for a test or a local sidecar;
/// see the module docs before pointing it at anything else.
pub fn serve(bridge: &Bridge, listener: &TcpListener, limit: usize) -> std::io::Result<()> {
    serve_with(bridge, listener, limit, &Limits::default())
}

/// The same, under explicit limits and with per-address rate limiting.
///
/// A refused peer is answered with [`status::BAD_REQUEST`] and the connection
/// closed, rather than dropped silently: a client that gets no reply cannot
/// distinguish being rate-limited from a bridge that has fallen over, and will
/// usually retry harder.
pub fn serve_with(
    bridge: &Bridge,
    listener: &TcpListener,
    limit: usize,
    limits: &Limits,
) -> std::io::Result<()> {
    let mut limiter = RateLimiter::new(limits);
    for _ in 0..limit {
        let (mut stream, peer) = listener.accept()?;
        if !limiter.allow(peer.ip()) {
            // Timeouts first: even the refusal must not be able to block.
            let _ = stream.set_write_timeout(Some(limits.write_timeout));
            let _ = write_response(&mut stream, status::BAD_REQUEST, &[]);
            continue;
        }
        // One bad connection must not take the server down.
        let _ = serve_once_metered(bridge, &mut stream, limits, peer.ip(), Some(&mut limiter));
    }
    Ok(())
}

/// Reads an HTTP request and returns its body.
fn read_request(stream: &mut TcpStream, limits: &Limits) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now();
    // Read until the header terminator, then exactly `Content-Length` more.
    // Reading to EOF would work only if the client half-closed, and a client
    // that expects a reply cannot.
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before the request headers ended",
            ));
        }
        buffer.extend_from_slice(chunk.get(..read).unwrap_or(&[]));
        // A header block this large is not a request this server serves.
        if buffer.len() > limits.max_header_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request headers too long",
            ));
        }
        // A per-read timeout alone is not enough. A client can send one byte
        // just inside every deadline and hold the queue indefinitely at no
        // cost to itself, which on a single-threaded bridge is the whole
        // service. The total deadline is what actually bounds that.
        if deadline.elapsed() > limits.request_deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request deadline exceeded while reading headers",
            ));
        }
    };

    let headers = String::from_utf8_lossy(buffer.get(..header_end).unwrap_or(&[])).to_lowercase();
    let length: usize = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    // Bounded before allocating: a hostile Content-Length is otherwise a free
    // out-of-memory (the same defect `docs/design.md` D13 records upstream).
    if length > limits.max_body_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }

    let mut body = buffer
        .get(header_end.saturating_add(4)..)
        .unwrap_or(&[])
        .to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(chunk.get(..read).unwrap_or(&[]));
        if deadline.elapsed() > limits.request_deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request deadline exceeded while reading the body",
            ));
        }
    }
    body.truncate(length);
    Ok(body)
}

fn write_response(stream: &mut TcpStream, code: u8, payload: &[u8]) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len().saturating_add(1)
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&[code])?;
    stream.write_all(payload)?;
    stream.flush()
}

/// A client for [`serve`].
#[derive(Clone, Debug)]
pub struct BridgeClient {
    address: String,
}

/// Why a bridge call failed.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ClientError {
    /// Could not reach the bridge or the connection failed mid-call.
    #[error("bridge transport: {0}")]
    Transport(String),

    /// The bridge answered, but not with the payload.
    #[error("bridge returned status {status}")]
    Status {
        /// The status byte. See [`crate::wire::status`].
        status: u8,
    },

    /// The payload did not decode.
    #[error("bridge payload: {0}")]
    Decode(String),
}

impl BridgeClient {
    /// Points a client at `host:port`.
    pub fn new(address: &str) -> BridgeClient {
        BridgeClient {
            address: address.to_owned(),
        }
    }

    /// One request/response cycle on a fresh connection.
    fn call(&self, request: &Request) -> Result<(u8, Vec<u8>), ClientError> {
        let body = request.to_bytes();
        let header = format!(
            "POST /zutreexo HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.address,
            body.len()
        );

        let mut stream = TcpStream::connect(&self.address)
            .map_err(|e| ClientError::Transport(format!("connect {}: {e}", self.address)))?;
        stream
            .write_all(header.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .map_err(|e| ClientError::Transport(format!("write: {e}")))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|e| ClientError::Transport(format!("read: {e}")))?;

        // `Connection: close` means the body ends at EOF.
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| ClientError::Transport("no header terminator".to_owned()))?;
        let payload = raw.get(split.saturating_add(4)..).unwrap_or(&[]);
        let (status, rest) = payload
            .split_first()
            .ok_or_else(|| ClientError::Transport("empty response".to_owned()))?;
        Ok((*status, rest.to_vec()))
    }

    /// Fetches the bundle for one height.
    pub fn block_proof_bundle(&self, height: u32) -> Result<BlockProofBundle, ClientError> {
        let (status, body) = self.call(&Request::BlockProofBundle { height })?;
        if status != status::OK {
            return Err(ClientError::Status { status });
        }
        BlockProofBundle::from_bytes(&body).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// Fetches the bridge's roots.
    pub fn roots(&self) -> Result<Roots, ClientError> {
        let (status, body) = self.call(&Request::AccumulatorRoots)?;
        if status != status::OK {
            return Err(ClientError::Status { status });
        }
        Roots::from_bytes(&body).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// Fetches the bridge's epoch manifest.
    ///
    /// A client should call this first: it carries the prefix floor, and a
    /// client that learns the floor by being refused has already told the
    /// bridge the narrow bucket it wanted.
    pub fn epoch_manifest(&self) -> Result<EpochManifest, ClientError> {
        let (status, body) = self.call(&Request::EpochManifest)?;
        if status != status::OK {
            return Err(ClientError::Status { status });
        }
        EpochManifest::from_bytes(&body).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// Fetches every nullifier in one prefix bucket of one snapshot epoch.
    ///
    /// The bucket is what travels; the nullifier the caller cares about never
    /// leaves the caller. Settle it locally with
    /// [`sorted::resolve`](zutreexo_accumulator::sorted::resolve) after
    /// verifying against the epoch's root from the manifest.
    pub fn prefix_cohort(
        &self,
        pool: zutreexo_accumulator::PoolId,
        epoch: u32,
        range: zutreexo_accumulator::cohort::PrefixRange,
    ) -> Result<SortedCohort, ClientError> {
        let (status, body) = self.call(&Request::PrefixCohort {
            pool,
            epoch,
            bits: range.bits(),
            lo: range.lo(),
        })?;
        if status != status::OK {
            return Err(ClientError::Status { status });
        }
        SortedCohort::from_bytes(&body).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// Asks whether a nullifier is unspent.
    ///
    /// `Ok(None)` means the bridge says it is already spent. That is an answer,
    /// not an error, and it is usually the one the caller wanted.
    pub fn prove_unspent(
        &self,
        pool: zutreexo_accumulator::PoolId,
        nullifier: zutreexo_accumulator::imt::Value,
    ) -> Result<Option<NonMembershipResponse>, ClientError> {
        let (status, body) = self.call(&Request::NullifierNonMembership { pool, nullifier })?;
        match status {
            status::OK => NonMembershipResponse::from_bytes(&body)
                .map(Some)
                .map_err(|e| ClientError::Decode(e.to_string())),
            status::ALREADY_SPENT => Ok(None),
            other => Err(ClientError::Status { status: other }),
        }
    }
}

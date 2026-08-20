//! The server's bounds against a client that is not being polite.
//!
//! None of this is a substitute for the Phase 6 denial-of-service analysis, and
//! the server is still loopback-only (`docs/design.md` D27). But the two limits
//! it does have — a cap on header size and a cap on declared body length — are
//! the difference between a bad request and an out-of-memory, so they get
//! tests rather than trust. The body cap in particular is the defect D13
//! records upstream: a length prefix believed ahead of the data it describes.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use zutreexo_bridge::server::serve;
use zutreexo_bridge::wire::status;
use zutreexo_bridge::Bridge;
use zutreexo_chain::{BlockSummary, ChainAccumulators};

const DEPTH: u8 = 12;

fn bridge() -> Bridge {
    let mut bridge = Bridge::new(ChainAccumulators::new(DEPTH).unwrap(), 4);
    bridge
        .apply(&BlockSummary {
            height: 0,
            transactions: 1,
            transparent_spends: Vec::new(),
            transparent_creates: Vec::new(),
            nullifiers: BTreeMap::new(),
            commitments: BTreeMap::new(),
        })
        .unwrap();
    bridge
}

/// Runs one client interaction against a real server, returning the status
/// byte the client saw, or `None` if the server hung up without answering.
fn against_server(client: impl FnOnce(&str) -> Option<u8> + Send) -> Option<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let bridge = bridge();
    std::thread::scope(|scope| {
        let handle = scope.spawn(move || client(&address));
        // Server on this thread: ChainAccumulators is not Send (D27).
        let _ = serve(&bridge, &listener, 1);
        handle.join().unwrap()
    })
}

/// Reads the status byte from a response, if the server sent one.
fn status_of(stream: &mut TcpStream) -> Option<u8> {
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    raw.get(split + 4).copied()
}

#[test]
fn an_oversized_header_block_is_refused_rather_than_buffered() {
    let seen = against_server(|address| {
        let mut stream = TcpStream::connect(address).ok()?;
        // Well past the 16 KiB cap, sent as a single valid-looking header line
        // that never terminates the block.
        let padding = "x".repeat(64 * 1024);
        let _ = stream.write_all(format!("POST / HTTP/1.1\r\nX-Pad: {padding}\r\n").as_bytes());
        let _ = stream.flush();
        status_of(&mut stream)
    });

    // **The rejection may or may not arrive, and that is not fixable here.**
    // The client is still writing 64 KiB when the server gives up and closes.
    // Closing a socket that still has unread data in its receive buffer sends
    // RST, which discards anything the server already wrote — so the status
    // byte is delivered or lost depending on timing, and no amount of care on
    // the server side changes that. Draining the request before answering
    // would fix the delivery and reintroduce the unbounded read this cap
    // exists to prevent.
    //
    // What is being tested is therefore the part that is guaranteed: the
    // server stops reading at the cap, stays alive, and if it does answer, it
    // answers BAD_REQUEST rather than trying to parse the flood. `serve`
    // returning at all is the liveness half — a server that buffered the whole
    // 64 KiB and blocked would hang this scope.
    assert!(
        matches!(seen, None | Some(status::BAD_REQUEST)),
        "an oversized header block got an unexpected answer: {seen:?}"
    );
}

#[test]
fn a_declared_body_larger_than_the_cap_is_refused_before_allocating() {
    let seen = against_server(|address| {
        let mut stream = TcpStream::connect(address).ok()?;
        // Claim 4 GiB and send two bytes. A server that trusted the header
        // would try to reserve the 4 GiB first.
        let request = "POST /zutreexo HTTP/1.1\r\nHost: x\r\n\
                       Content-Length: 4294967296\r\nConnection: close\r\n\r\nhi";
        let _ = stream.write_all(request.as_bytes());
        let _ = stream.flush();
        status_of(&mut stream)
    });

    assert_eq!(
        seen,
        Some(status::BAD_REQUEST),
        "a hostile Content-Length was not refused"
    );
}

#[test]
fn a_client_that_vanishes_mid_header_does_not_take_the_server_down() {
    let seen = against_server(|address| {
        let mut stream = TcpStream::connect(address).ok()?;
        // A partial header block, then close. The server sees EOF before the
        // terminator.
        let _ = stream.write_all(b"POST / HTTP/1.1\r\nHost: x");
        let _ = stream.flush();
        drop(stream);
        None
    });

    // The client is gone, so nothing is asserted about what it saw. What
    // matters is that `serve` returned at all — a panic or a block here would
    // fail the test by hanging the scope, and one dead connection must not end
    // the server.
    assert_eq!(seen, None);
}

#[test]
fn a_body_shorter_than_its_content_length_is_refused() {
    let seen = against_server(|address| {
        let mut stream = TcpStream::connect(address).ok()?;
        // Promises 64 bytes, sends 4, then closes. The server reads to EOF and
        // ends up with a truncated request rather than a hang.
        let request = "POST /zutreexo HTTP/1.1\r\nHost: x\r\n\
                       Content-Length: 64\r\nConnection: close\r\n\r\nabcd";
        let _ = stream.write_all(request.as_bytes());
        let _ = stream.flush();
        let _ = stream.shutdown(std::net::Shutdown::Write);
        status_of(&mut stream)
    });

    assert_eq!(
        seen,
        Some(status::BAD_REQUEST),
        "a truncated body was not refused"
    );
}

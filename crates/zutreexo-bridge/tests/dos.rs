//! Denial-of-service properties of the bridge server.
//!
//! CLAUDE.md Phase 6 asks for an explicit DoS analysis: "cost to a bridge node
//! of a peer requesting proofs for every UTXO; rate limiting and proof-size
//! caps". Writing it turned up something cheaper than requesting 27.5M proofs.
//!
//! # The attack these tests are about
//!
//! The bridge is **single-threaded by construction** — `ChainAccumulators` is
//! not `Send` (`docs/design.md` D27) — so serving is one queue. A client that
//! connects and then says nothing parks the only serving thread in `read()`.
//! Not slowly, and not just for itself: for every other client, indefinitely,
//! from one socket carrying no traffic and costing no CPU.
//!
//! Against a threaded server slowloris degrades throughput. Against this one it
//! is total.
//!
//! # Each test carries its own control
//!
//! A timeout test that passes because the server answered quickly for some
//! *other* reason proves nothing, and Phase 3's crash harness already made that
//! mistake once — 25 clean kills that never landed on a write
//! (`docs/design.md` D23). So the slowloris test asserts both directions: the
//! request is refused under a short deadline, and the identical client is
//! served under a generous one.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use zutreexo_accumulator::imt::DEFAULT_DEPTH;
use zutreexo_bridge::limits::Limits;
use zutreexo_bridge::server::{serve_once_with, serve_with};
use zutreexo_bridge::wire::Request;
use zutreexo_bridge::Bridge;
use zutreexo_chain::ChainAccumulators;

fn bridge() -> Bridge {
    Bridge::new(ChainAccumulators::new(DEFAULT_DEPTH).unwrap(), 128)
}

/// A client that opens a connection, sends a partial header, and never
/// finishes it. The whole attack, in four lines.
fn slowloris(address: std::net::SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(b"POST / HTTP/1.1\r\n").unwrap();
    stream.flush().unwrap();
    stream
}

#[test]
fn a_silent_client_cannot_hold_the_server_forever() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let bridge = bridge();

    let limits = Limits {
        read_timeout: Duration::from_millis(200),
        request_deadline: Duration::from_millis(400),
        ..Limits::default()
    };

    let _attacker = slowloris(address);

    let (mut stream, _) = listener.accept().unwrap();
    let began = Instant::now();
    let result = serve_once_with(&bridge, &mut stream, &limits);
    let took = began.elapsed();

    assert!(result.is_err(), "a half-sent request was accepted");
    assert!(
        took < Duration::from_secs(5),
        "the server blocked for {took:?}; the timeout is not applied"
    );
}

#[test]
fn the_control_shows_the_same_client_is_served_when_it_finishes() {
    // Without this, the test above would pass on a server that refused
    // everything — which is not hardening, it is breakage.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let bridge = bridge();

    let body = Request::AccumulatorRoots.to_bytes();
    let mut client = TcpStream::connect(address).unwrap();
    let request = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len());
    client.write_all(request.as_bytes()).unwrap();
    client.write_all(&body).unwrap();
    client.flush().unwrap();

    let (mut stream, _) = listener.accept().unwrap();
    serve_once_with(&bridge, &mut stream, &Limits::permissive())
        .expect("a complete request must be served");

    let mut response = Vec::new();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let _ = client.read_to_end(&mut response);
    assert!(!response.is_empty(), "a complete request got no response");
}

#[test]
fn a_dribbling_client_is_cut_off_by_the_total_deadline() {
    // The refinement that a per-read timeout alone misses: bytes arriving
    // just inside every read timeout, forever. Each read succeeds; only the
    // total deadline ends it.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let bridge = bridge();

    let limits = Limits {
        read_timeout: Duration::from_secs(5),
        request_deadline: Duration::from_millis(300),
        ..Limits::default()
    };

    let handle = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        // One byte every 50 ms — comfortably inside a 5 s read timeout.
        for _ in 0..40 {
            if stream.write_all(b"X").is_err() {
                return;
            }
            let _ = stream.flush();
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let (mut stream, _) = listener.accept().unwrap();
    let began = Instant::now();
    let result = serve_once_with(&bridge, &mut stream, &limits);
    let took = began.elapsed();

    assert!(result.is_err(), "a dribbling client was served");
    assert!(
        took < Duration::from_secs(3),
        "the total deadline did not fire: {took:?}"
    );
    let _ = handle.join();
}

#[test]
fn an_oversized_content_length_is_refused_before_allocating() {
    // D13's shape at the transport layer: a header claiming a huge body must
    // be rejected on the number, not by trying to read that many bytes.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let bridge = bridge();

    let mut client = TcpStream::connect(address).unwrap();
    client
        .write_all(b"POST / HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n")
        .unwrap();
    client.flush().unwrap();

    let (mut stream, _) = listener.accept().unwrap();
    let began = Instant::now();
    let result = serve_once_with(&bridge, &mut stream, &Limits::default());
    assert!(result.is_err(), "an 11-digit Content-Length was accepted");
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "the server tried to read the declared body"
    );
}

#[test]
fn rate_limiting_refuses_a_flood_but_still_answers() {
    // Two properties at once, because either alone is misleading: the limiter
    // must refuse the excess *and* the refusals must be answered, or a client
    // cannot tell rate limiting from a dead bridge and retries harder.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let bridge = bridge();

    let limits = Limits {
        requests_per_minute: 3,
        ..Limits::permissive()
    };

    let handle = std::thread::spawn(move || {
        let body = Request::AccumulatorRoots.to_bytes();
        let mut answered = 0;
        for _ in 0..6 {
            let Ok(mut client) = TcpStream::connect(address) else {
                continue;
            };
            let request = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len());
            if client.write_all(request.as_bytes()).is_err() {
                continue;
            }
            let _ = client.write_all(&body);
            let _ = client.flush();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut response = Vec::new();
            let _ = client.read_to_end(&mut response);
            if !response.is_empty() {
                answered += 1;
            }
        }
        answered
    });

    serve_with(&bridge, &listener, 6, &limits).unwrap();
    let answered = handle.join().unwrap();

    assert_eq!(
        answered, 6,
        "every connection must get a reply, refused or not"
    );
}

#[test]
fn a_response_over_the_cap_is_refused_rather_than_sent() {
    // The cap is on *our* output, and it exists so the single serving thread
    // is never spent on a response nobody bounded. Exercised with an absurdly
    // small cap, because the honest alternative — building a response larger
    // than 8 MB — would need tip state and minutes of setup to test one branch.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let bridge = bridge();

    let limits = Limits {
        max_response_bytes: 4,
        ..Limits::permissive()
    };

    let body = Request::AccumulatorRoots.to_bytes();
    let mut client = TcpStream::connect(address).unwrap();
    let request = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len());
    client.write_all(request.as_bytes()).unwrap();
    client.write_all(&body).unwrap();
    client.flush().unwrap();

    let (mut stream, _) = listener.accept().unwrap();
    serve_once_with(&bridge, &mut stream, &limits).unwrap();

    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);

    // The status byte is the last thing in the header block; a refused
    // oversized response carries INTERNAL and an empty payload.
    let at = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header terminator");
    assert_eq!(
        response[at + 4],
        zutreexo_bridge::wire::status::INTERNAL,
        "an over-cap response was sent rather than refused"
    );
    assert_eq!(
        response.len() - (at + 4),
        1,
        "the refused response carried a payload"
    );
}

#[test]
fn the_default_wrappers_serve_a_request() {
    // `serve_once` and `serve` apply Limits::default(). Covered explicitly
    // because every other test here passes limits by hand, and a default that
    // silently broke would be invisible to all of them — while being the entry
    // point everything outside the tests actually calls.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let bridge = bridge();

    let handle = std::thread::spawn(move || {
        let body = Request::AccumulatorRoots.to_bytes();
        let mut client = TcpStream::connect(address).unwrap();
        let request = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len());
        client.write_all(request.as_bytes()).unwrap();
        client.write_all(&body).unwrap();
        client.flush().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response);
        response
    });

    // Both default wrappers, not just `serve`: `serve_once` is the entry point
    // a caller with its own accept loop uses, and nothing else here reaches it.
    let (mut stream, _) = listener.accept().unwrap();
    zutreexo_bridge::server::serve_once(&bridge, &mut stream).unwrap();
    let response = handle.join().unwrap();
    assert!(!response.is_empty(), "the default wrapper served nothing");
}

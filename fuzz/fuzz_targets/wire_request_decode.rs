//! `Request::from_bytes` — the bridge's request envelope.
//!
//! Small, but it is the first thing a bridge parses from a socket, so it is
//! the outermost untrusted surface in the system. Unknown method tags, unknown
//! pool codes, and trailing bytes all have to be errors rather than guesses.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zutreexo_bridge::wire::Request;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = Request::from_bytes(data) {
        let re = request.to_bytes();
        let again = Request::from_bytes(&re).expect("a request we just encoded must decode");
        assert_eq!(again, request, "request round trip is not stable");
    }
});

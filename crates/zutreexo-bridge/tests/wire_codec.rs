//! The bridge's wire codec against hostile input.
//!
//! Everything here decodes bytes a client or a bridge sent, which makes it the
//! crate's untrusted-input surface. `docs/design.md` D24 is the standing lesson:
//! a check with no test is a check that may already be unreachable, and the
//! coverage gate is what found this file's first gap — the pool-order rejection
//! in `Roots::read_body` was written and never exercised.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use zutreexo_accumulator::proof::ProofCodecError;
use zutreexo_accumulator::{CanonicalSerialize, Hash, PoolId, PROOF_FORMAT_VERSION};
use zutreexo_bridge::wire::Roots;
use zutreexo_bridge::{EpochManifest, Request, WIRE_VERSION};

fn hash(n: u8) -> Hash {
    [n; 32]
}

fn roots() -> Roots {
    Roots {
        height: 987_654,
        depth: 40,
        utxo: vec![hash(1), hash(2), hash(3)],
        nullifiers: vec![
            (PoolId::Sprout, hash(10)),
            (PoolId::Sapling, hash(11)),
            (PoolId::Orchard, hash(12)),
            (PoolId::Ironwood, hash(13)),
        ],
    }
}

#[test]
fn roots_round_trip() {
    let original = roots();
    assert_eq!(Roots::from_bytes(&original.to_bytes()).unwrap(), original);
}

#[test]
fn roots_with_no_utxo_leaves_round_trip() {
    // An empty accumulator has no roots at all, which is a real state at
    // genesis and an easy one for a length-prefixed decoder to mishandle.
    let mut empty = roots();
    empty.utxo.clear();
    empty.height = 0;
    assert_eq!(Roots::from_bytes(&empty.to_bytes()).unwrap(), empty);
}

#[test]
fn nullifier_roots_out_of_pool_order_are_rejected() {
    // The encoding has to be canonical: a wallet's whole defence against a
    // single dishonest bridge is fetching roots from several and comparing
    // them, and that comparison is worthless if two byte strings can describe
    // the same state.
    let mut swapped = roots();
    swapped.nullifiers.swap(0, 1);

    let bytes = swapped.to_bytes();
    assert!(
        Roots::from_bytes(&bytes).is_err(),
        "out-of-order pool roots decoded; the encoding is not canonical"
    );
}

#[test]
fn a_repeated_pool_is_rejected() {
    // `>=` in the ordering check, not `>`, so a duplicate is caught too — a
    // response naming Orchard twice would otherwise decode with whichever root
    // came last silently winning.
    let mut duplicated = roots();
    duplicated.nullifiers = vec![(PoolId::Orchard, hash(20)), (PoolId::Orchard, hash(21))];
    assert!(Roots::from_bytes(&duplicated.to_bytes()).is_err());
}

#[test]
fn every_truncation_of_roots_is_an_error_not_a_panic() {
    let bytes = roots().to_bytes();
    for length in 0..bytes.len() {
        assert!(
            Roots::from_bytes(&bytes[..length]).is_err(),
            "a {length}-byte prefix decoded as a complete Roots"
        );
    }
}

#[test]
fn trailing_bytes_after_roots_are_rejected() {
    let mut bytes = roots().to_bytes();
    bytes.push(0);
    assert!(Roots::from_bytes(&bytes).is_err());
}

#[test]
fn an_unknown_pool_code_in_roots_is_rejected() {
    let bytes = roots().to_bytes();
    // Walk the encoding to the first pool code rather than hard-coding an
    // offset, so this test does not quietly stop testing anything if a field
    // is added ahead of it.
    let utxo_count = bytes[1 + 4 + 1] as usize;
    let pool_section = 1 + 4 + 1 + 1 + utxo_count * 32 + 1;
    let mut corrupted = bytes.clone();
    corrupted[pool_section] = 0xEE;
    assert!(Roots::from_bytes(&corrupted).is_err());
}

#[test]
fn a_declared_root_count_larger_than_the_input_is_rejected() {
    // The classic length-prefix attack: claim 255 roots and send none. It must
    // fail without first allocating for 255.
    let mut bytes = roots().to_bytes();
    bytes[1 + 4 + 1] = 0xFF; // utxo root count
    assert!(Roots::from_bytes(&bytes).is_err());
}

#[test]
fn an_unknown_payload_version_is_refused() {
    // `Roots` is a *payload*, so its version byte is PROOF_FORMAT_VERSION, not
    // WIRE_VERSION — the request envelope carries that one. This test first
    // used WIRE_VERSION + 1, which was 2 at the time, which was exactly the
    // format version: it wrote the *correct* byte and then asserted the decode
    // would fail. It went red, which is how the ambiguity surfaced. The two
    // versions are now documented at `WIRE_VERSION`.
    let mut bytes = roots().to_bytes();
    assert_eq!(
        bytes[0], PROOF_FORMAT_VERSION,
        "Roots should be tagged with the payload format version"
    );
    bytes[0] = PROOF_FORMAT_VERSION.wrapping_add(1);
    assert!(Roots::from_bytes(&bytes).is_err());
}

#[test]
fn the_envelope_and_payload_versions_are_separate_concerns() {
    // Guards the invariant the comment at `WIRE_VERSION` describes.
    //
    // This assertion used to be `assert_ne!` on the two numbers, with a message
    // saying that if they ever coincided it should be deliberate rather than
    // accidental. **They now coincide, at 2, and this is that deliberate
    // statement.** The cohort service added two request tags and bumped the
    // envelope from 1 to 2; the payload layouts did not change, so the format
    // version stayed at 2. Nothing about the two versions became linked — they
    // arrived at the same integer from opposite directions and will diverge
    // again at the next change to either.
    //
    // So the check is now behavioural, which is what it should have been from
    // the start: comparing integers could never distinguish "independent knobs
    // that happen to agree" from "one knob read twice". Bumping one version
    // must invalidate its own encoding and leave the other's alone.
    let mut request = Request::AccumulatorRoots.to_bytes();
    assert_eq!(
        request[0], WIRE_VERSION,
        "a request envelope carries the wire version"
    );
    let mut payload = roots().to_bytes();
    assert_eq!(
        payload[0], PROOF_FORMAT_VERSION,
        "a payload carries the proof format version"
    );

    request[0] = WIRE_VERSION.wrapping_add(1);
    assert!(
        Request::from_bytes(&request).is_err(),
        "an envelope from the future must be refused"
    );
    payload[0] = PROOF_FORMAT_VERSION.wrapping_add(1);
    assert!(
        Roots::from_bytes(&payload).is_err(),
        "a payload from the future must be refused"
    );

    // And the separation itself: a *correctly* versioned payload still decodes
    // no matter what the envelope version is, because the payload never sees
    // it. If the two were ever collapsed into one constant, bumping it would
    // break both of these at once and this test would say so.
    assert!(
        Roots::from_bytes(&roots().to_bytes()).is_ok(),
        "the payload decoder must not consult the envelope version"
    );
}

// --- the cohort service's request framing (Phase 6c) -----------------------

/// Builds the bytes of a `PrefixCohort` request by hand: version, tag, pool,
/// epoch(4), bits, then 32 bytes of `lo`.
///
/// Hand-built rather than encoded from a `Request`, because these tests need to
/// produce combinations the encoder will not — an unaligned bound, an
/// impossible width — and going through the type would fix them first.
fn cohort_request(bits: u8, lo: [u8; 32]) -> Vec<u8> {
    let mut out = vec![WIRE_VERSION, 4, PoolId::Orchard.code()];
    out.extend_from_slice(&10u32.to_le_bytes());
    out.push(bits);
    out.extend_from_slice(&lo);
    out
}

#[test]
fn a_cohort_request_round_trips() {
    let mut lo = [0u8; 32];
    lo[0] = 0x80;
    let bytes = cohort_request(8, lo);
    let decoded = Request::from_bytes(&bytes).expect("valid request");
    assert_eq!(decoded.to_bytes(), bytes, "re-encode must be identical");
    let range = decoded
        .prefix_range()
        .expect("valid range")
        .expect("a cohort request has one");
    assert_eq!(range.bits(), 8);
}

#[test]
fn a_cohort_request_whose_lower_bound_is_unaligned_is_refused() {
    // `lo` must sit on a `bits` boundary. An unaligned bound describes a window
    // no prefix produces, so two different encodings would name the same set of
    // values and the request would stop being canonical — and the bridge would
    // answer for a range the client cannot re-derive from its own nullifier.
    //
    // Byte 1 of `lo` is inside the region an 8-bit prefix zeroes.
    let mut lo = [0u8; 32];
    lo[0] = 0x80;
    lo[1] = 0x01;
    let error = Request::from_bytes(&cohort_request(8, lo)).expect_err("must be refused");
    assert!(
        matches!(
            error,
            ProofCodecError::Malformed {
                reason: "cohort lower bound is not aligned to its prefix"
            }
        ),
        "wrong error: {error:?}"
    );
}

#[test]
fn a_cohort_request_with_an_impossible_prefix_width_is_refused() {
    // Zero bits is the whole value space and would be a request for every
    // nullifier in the pool; anything past MAX_PREFIX_BITS is not a range this
    // codebase can express. Both must be refused at the door rather than
    // reaching the tree, where the refusal would look like a policy decision.
    for bits in [0u8, 33, 255] {
        let error = Request::from_bytes(&cohort_request(bits, [0u8; 32])).unwrap_err_or_panic(bits);
        assert!(
            matches!(
                error,
                ProofCodecError::Malformed {
                    reason: "cohort request names an invalid prefix width"
                }
            ),
            "bits={bits}: wrong error: {error:?}"
        );
    }
}

/// Tiny helper so the loop above reads as one assertion per width.
trait UnwrapErrOrPanic {
    fn unwrap_err_or_panic(self, bits: u8) -> ProofCodecError;
}

impl UnwrapErrOrPanic for Result<Request, ProofCodecError> {
    fn unwrap_err_or_panic(self, bits: u8) -> ProofCodecError {
        match self {
            Ok(request) => panic!("bits={bits} decoded as {request:?}"),
            Err(error) => error,
        }
    }
}

#[test]
fn every_truncation_of_a_cohort_request_is_an_error_not_a_panic() {
    let mut lo = [0u8; 32];
    lo[0] = 0x80;
    let bytes = cohort_request(8, lo);
    for cut in 0..bytes.len() {
        assert!(
            Request::from_bytes(&bytes[..cut]).is_err(),
            "a {cut}-byte prefix of a {}-byte request decoded",
            bytes.len()
        );
    }
}

#[test]
fn an_over_declared_manifest_entry_count_is_refused_before_allocating() {
    // D29's shape again. One entry is 47 bytes, so a declared u16::MAX asks for
    // 3.1 MB from a response that may be 11 bytes long. The guard has to check
    // the count against what the input can actually hold, not merely read until
    // it runs out — the difference is whether a hostile bridge can make a
    // wallet allocate on its say-so.
    let manifest = EpochManifest {
        min_anonymity: 12_298,
        epochs: Vec::new(),
    };
    let mut bytes = manifest.to_bytes();
    // version(1) + min_anonymity(8) = the count's offset.
    bytes[9..11].copy_from_slice(&u16::MAX.to_le_bytes());
    let error = EpochManifest::from_bytes(&bytes).expect_err("must be refused");
    assert!(
        matches!(
            error,
            ProofCodecError::Malformed {
                reason: "manifest declares more epochs than the input can hold"
            }
        ),
        "wrong error: {error:?}"
    );
}

#[test]
fn an_empty_manifest_round_trips() {
    // A bridge with epochs disabled answers with this, and a client must be
    // able to read it — an empty manifest is "no cohort service here", not a
    // malformed response.
    let manifest = EpochManifest {
        min_anonymity: 12_298,
        epochs: Vec::new(),
    };
    let bytes = manifest.to_bytes();
    assert_eq!(EpochManifest::from_bytes(&bytes).unwrap(), manifest);
}

#[test]
fn trailing_bytes_after_a_manifest_are_refused() {
    let mut bytes = EpochManifest {
        min_anonymity: 12_298,
        epochs: Vec::new(),
    }
    .to_bytes();
    bytes.push(0);
    assert!(matches!(
        EpochManifest::from_bytes(&bytes),
        Err(ProofCodecError::TrailingBytes { count: 1 })
    ));
}

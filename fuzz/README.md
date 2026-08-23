# Fuzz targets

Phase 6. Seven targets over every deserialisation path a hostile party can
reach. Run them with a **nightly** toolchain — `cargo fuzz` needs
`-Zsanitizer=address`.

```bash
rustup run nightly cargo fuzz run bundle_decode
scripts/fuzz_72h.sh          # the definition-of-done run
```

## The targets

| target | surface | note |
|---|---|---|
| `bundle_decode` | `BlockProofBundle::from_bytes` | the only thing a compact node takes from a party it does not control |
| `utxo_proof_decode` | `decode_utxo_proof` | where D29 lived; D13 still open upstream behind it |
| `snapshot_decode` | `store::load_bytes` | **resealed checksum** — see below |
| `compact_state_decode` | `CompactState::from_bytes` | new in Phase 5b |
| `wire_request_decode` | `Request::from_bytes` | outermost surface; first thing off a socket |
| `nonmembership_decode` | `NonMembershipResponse::from_bytes` | the sparse bitmap (D28) |
| `forest_decode` | `UtxoForest::from_bytes` | upstream recursion; **excluded from the 72 h run**, see D33 — fix written, awaiting a push |

## The checksum reseal, and how to prove it works

`store::load` verifies a BLAKE2b checksum before it calls `decode`, so the
checksum stands in front of every structural check in the parser. A fuzzer that
mutates a snapshot and calls `load` bounces off `ChecksumMismatch` on
essentially every iteration, reaches none of the parser, and reports a clean run
having tested nothing.

This is not hypothetical: `docs/design.md` D24 records three Phase 3 tests that
passed exactly that way — they asserted `is_err()`, got `ChecksumMismatch`, and
the arms they were written to exercise never ran once.

So `snapshot_decode` recomputes a valid checksum over each mutated payload. To
show the reseal is doing work rather than being intended to:

```bash
# resealed: reaches the parser, coverage climbs into the hundreds
rustup run nightly cargo fuzz run snapshot_decode -- -max_total_time=20

# control: every input dies at the checksum, coverage flatlines
ZUTREEXO_FUZZ_NO_RESEAL=1 rustup run nightly cargo fuzz run snapshot_decode -- -max_total_time=20
```

The difference in `cov:` between those two runs is the evidence. A target that
cannot show it is the one D24 warns about.

## Seeds

`ZUTREEXO_DUMP_SEEDS=1 cargo test -p zutreexo-testkit --test fuzz_seeds` writes
one valid encoding of every fuzzed type into `fuzz/corpus/<target>/`. It is a
test rather than a script so it cannot rot silently: change an encoding and it
fails to build with everything else.

Without seeds a run spends its early budget rediscovering the version byte and
the length prefixes instead of testing the parser.

## Crashes

Every crash artifact becomes a **named regression seed in the ordinary test
suite**, added and confirmed failing before the fix — CLAUDE.md's rule, and the
reason `utxo_proof_header.rs` exists.

Write the seed against the *public behaviour* ("this returns an error"), never
against the panic. A test that asserts a panic has to be rewritten by whoever
fixes it, and that is how a regression seed gets quietly deleted.

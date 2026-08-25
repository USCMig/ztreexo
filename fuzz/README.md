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

## Budgeting a run

**Do not give every target the same wall clock.** The 2026-08-22 72-hour run
finished clean — 206 billion executions, no crashes — and produced **34 new
edges, 31 of them in one target** (`docs/design.md`
[D36](../docs/design.md#d36--fuzz-budget-four-of-five-targets-saturated-in-under-two-hours)):

| target | edges gained | last new edge | budget after it |
|---|---|---|---|
| `bundle_decode` | +31 | **71.5 h in** | 0.6% |
| `utxo_proof_decode` | +3 | execution **101** | ~100% |
| `compact_state_decode` | 0 | never | 100% |
| `nonmembership_decode` | 0 | never | 100% |
| `wire_request_decode` | 0 | never | 100% |

Four targets were done in minutes; `bundle_decode` was **still finding edges
when the clock cut it off**, with its last one twenty-five minutes before the
end. Do not read a quiet stretch as exhaustion — its gaps between discoveries
ran 3.0 billion executions and then 0.34 billion. Discovery is bursty.

`scripts/fuzz_72h.sh` now encodes this: 7 days and `-fork=8` for
`bundle_decode`, 24 h each for the rest, and it runs the analysis itself when
it finishes. Get the same for any run, including one still going:

```bash
scripts/fuzz_saturation.py                      # a finished run states its own duration
scripts/fuzz_saturation.py --elapsed-hours 38   # mid-run
```

Read it rather than reading the logs by eye: **a `NEW` line is a new *feature*,
not a new edge**, so a saturated target still prints `NEW` and looks busy.
`nonmembership_decode` logged six of them while its coverage sat at `cov: 323`
for 2.1 billion executions. The script tracks the high-water mark of `cov`.

Time to saturation here runs from execution 101 to twenty hours, so one figure
for all targets is wrong in both directions at once. Before the next run:

- **End a target on saturation, not on the clock** — e.g. once it has run 10×
  longer since its last new edge than it took to find that edge.
- **Give the freed cores to the target still finding things**, via `-fork=N`.
  Use fork mode, not `-jobs=N -workers=N`: `-jobs` scatters `fuzz-<n>.log` into
  the current directory and leaves the main log holding one worker's numbers,
  so the analysis under-reports. Two forks took `bundle_decode` from ~18k to
  ~40k exec/s.
- **A target that gains zero edges needs seeds, not hours.** Being stuck at the
  same edge count for tens of billions of executions means mutation cannot get
  further from the corpus it has. Improve the seeds or add a structured
  `Arbitrary` generator — the same failure mode as the checksum above, one level
  out: there the checksum hid the parser, here the input distribution does.

Saturation does not make a run pointless — its product is the *absence* of a
crash, and that accrues either way. It makes the *schedule* wrong.

## Crashes

Every crash artifact becomes a **named regression seed in the ordinary test
suite**, added and confirmed failing before the fix — CLAUDE.md's rule, and the
reason `utxo_proof_header.rs` exists.

Write the seed against the *public behaviour* ("this returns an error"), never
against the panic. A test that asserts a panic has to be rewritten by whoever
fixes it, and that is how a regression seed gets quietly deleted.

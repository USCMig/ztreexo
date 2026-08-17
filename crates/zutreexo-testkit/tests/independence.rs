//! Enforces the rule that makes the naive oracles worth having.
//!
//! CLAUDE.md Phase 2: the naive model "must share **zero code** with
//! `zutreexo-accumulator`, or the two can be wrong in the same way."
//!
//! Nothing in Rust enforces that. The oracle modules sit in the same crate as
//! `harness`, which must reach the implementation to drive it, so the
//! dependency graph permits an import that would quietly destroy the oracle's
//! value — and the resulting test suite would still be green, which is the
//! worst possible failure mode.
//!
//! So this reads the files as text. It is a crude check and it is the right
//! one: the property is textual, and a textual property should be checked
//! textually rather than trusted to review.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

/// Files that must not mention the implementation.
const ORACLE_FILES: [&str; 2] = ["src/naive.rs", "src/state.rs"];

/// Crate names an oracle must not reach for.
const FORBIDDEN: [&str; 3] = [
    "zutreexo_accumulator",
    "zutreexo_chain",
    "zutreexo_testkit::harness",
];

fn crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Strips `//` and `//!` comment bodies so that *discussing* the rule does not
/// violate it. The doc comments in those files necessarily name the crates they
/// are independent of; only code is constrained.
fn strip_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| match line.find("//") {
            Some(index) => line.get(..index).unwrap_or(""),
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn oracles_do_not_reference_the_implementation() {
    for relative in ORACLE_FILES {
        let path = crate_root().join(relative);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let code = strip_comments(&source);

        for forbidden in FORBIDDEN {
            assert!(
                !code.contains(forbidden),
                "{relative} references `{forbidden}` in code.\n\n\
                 This is the one thing that makes it an oracle. A model that \
                 imports the implementation it checks is a second copy of the \
                 same bug, and it will agree with the implementation for \
                 exactly the reasons that matter. Re-derive the behaviour from \
                 the specification instead. See CLAUDE.md Phase 2."
            );
        }
    }
}

#[test]
fn the_guard_can_actually_fail() {
    // A guard that cannot fail is decoration. This proves the matcher works on
    // text shaped like the real thing.
    let offending = "use zutreexo_accumulator::imt::Value;\nfn f() {}\n";
    let code = strip_comments(offending);
    assert!(code.contains("zutreexo_accumulator"));

    // And that a comment mentioning it is tolerated, which is what lets the
    // module docs explain the rule.
    let commented = "// zutreexo_accumulator is deliberately not imported\nfn f() {}\n";
    let code = strip_comments(commented);
    assert!(!code.contains("zutreexo_accumulator"));
}

#[test]
fn the_oracle_files_still_exist() {
    // A rename would make the loop above iterate over nothing and pass.
    for relative in ORACLE_FILES {
        let path = crate_root().join(relative);
        assert!(
            path.is_file(),
            "{relative} is missing — did it move? This guard silently checks \
             nothing if the paths are stale."
        );
    }
}

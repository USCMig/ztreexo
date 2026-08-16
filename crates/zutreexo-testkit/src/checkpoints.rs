//! The validator oracle: counts as `zebrad` itself reports them.
//!
//! # Why a second oracle exists at all
//!
//! [`NaiveState`](crate::state::NaiveState) catches accumulator bugs, and
//! cannot catch parsing bugs — it is fed from the same parse as the code it
//! checks, so a mis-read block yields two models that agree and are both wrong.
//! Closing that hole needs something that reached the same facts by a different
//! route.
//!
//! Our parser goes: raw block bytes → `zebra_chain`'s consensus deserializer →
//! counts. The node goes: the same raw bytes → `zebrad`'s RPC serializer →
//! JSON → counts. Two independent routes out of one byte string. Agreement
//! means the parse is right rather than merely self-consistent.
//!
//! # Why these are files rather than live RPC
//!
//! CI has no synced node. `scripts/capture_checkpoints.py` records the node's
//! answers into `checkpoints/<slice>.json`, committed, and this module reads
//! them back. Re-run the script when the fixtures are re-captured; if the
//! numbers move, find out why before committing them.
//!
//! Note what this tier does *not* cover: it compares totals over a whole slice,
//! so it catches a systematically mis-read field, not a single misplaced
//! nullifier that another block happens to offset. The naive oracle covers the
//! latter, per block.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Counts the node reported for one fixture slice.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Checkpoint {
    /// Fixture slice name, matching the `.jsonl` basename.
    pub slice: String,
    /// First height in the slice.
    pub start_height: u32,
    /// Last height, inclusive.
    pub end_height: u32,
    /// Number of blocks.
    pub blocks: u64,
    /// Every counted field, keyed exactly as the capture script wrote it.
    pub totals: BTreeMap<String, u64>,
}

impl Checkpoint {
    /// One field, or `None` if the capture did not record it.
    pub fn get(&self, field: &str) -> Option<u64> {
        self.totals.get(field).copied()
    }
}

/// Why a checkpoint could not be loaded.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum CheckpointError {
    /// No file for this slice. Run `scripts/capture_checkpoints.py`.
    #[error("no checkpoint for slice {slice} at {}", path.display())]
    Missing {
        /// The slice asked for.
        slice: String,
        /// Where it was looked for.
        path: PathBuf,
    },
    /// The file could not be read or parsed.
    #[error("checkpoint {slice} is unreadable: {reason}")]
    Malformed {
        /// The slice asked for.
        slice: String,
        /// What went wrong.
        reason: String,
    },
}

/// Directory holding the committed checkpoint files.
pub fn checkpoint_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("checkpoints")
}

/// Loads one slice's checkpoint.
///
/// Returns [`CheckpointError::Missing`] rather than an empty record when the
/// file is absent: a silently-empty oracle is one that passes everything.
pub fn load(slice: &str) -> Result<Checkpoint, CheckpointError> {
    load_from(&checkpoint_dir().join(format!("{slice}.json")), slice)
}

/// Loads a checkpoint from an explicit path.
///
/// Exists so the malformed-input paths can be tested without writing files into
/// the committed checkpoint directory. A parser whose error handling is never
/// exercised is one that will panic the first time a file is truncated.
pub fn load_from(path: &Path, slice: &str) -> Result<Checkpoint, CheckpointError> {
    let text = std::fs::read_to_string(path).map_err(|_| CheckpointError::Missing {
        slice: slice.to_owned(),
        path: path.to_path_buf(),
    })?;

    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| CheckpointError::Malformed {
            slice: slice.to_owned(),
            reason: error.to_string(),
        })?;

    let bad = |what: &str| CheckpointError::Malformed {
        slice: slice.to_owned(),
        reason: format!("missing or non-numeric field: {what}"),
    };

    let number = |key: &str| -> Result<u64, CheckpointError> {
        value
            .get(key)
            .and_then(|v| v.as_u64())
            .ok_or_else(|| bad(key))
    };

    let start = u32::try_from(number("start_height")?).map_err(|_| bad("start_height"))?;
    let end = u32::try_from(number("end_height")?).map_err(|_| bad("end_height"))?;

    let mut totals = BTreeMap::new();
    let object = value
        .get("totals")
        .and_then(|v| v.as_object())
        .ok_or_else(|| bad("totals"))?;
    for (key, entry) in object {
        let count = entry.as_u64().ok_or_else(|| bad(key))?;
        totals.insert(key.clone(), count);
    }

    Ok(Checkpoint {
        slice: slice.to_owned(),
        start_height: start,
        end_height: end,
        blocks: number("blocks")?,
        totals,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// The four slices captured in Phase 0, all of which should be committed.
    const SLICES: [&str; 4] = [
        "sapling-activation",
        "nu5-orchard",
        "sandblasting",
        "ironwood-activation",
    ];

    #[test]
    fn every_slice_has_a_checkpoint() {
        for slice in SLICES {
            let checkpoint = load(slice).unwrap_or_else(|error| panic!("{slice}: {error}"));
            assert_eq!(checkpoint.blocks, 200, "{slice}: unexpected slice length");
            assert_eq!(
                u64::from(checkpoint.end_height - checkpoint.start_height) + 1,
                checkpoint.blocks,
                "{slice}: height range disagrees with block count"
            );
        }
    }

    #[test]
    fn checkpoints_record_every_field_the_harness_compares() {
        // A missing field would make the corresponding comparison silently
        // vacuous, which is the failure mode this tier exists to avoid.
        let required = [
            "sprout_nullifiers",
            "sapling_nullifiers",
            "orchard_nullifiers",
            "ironwood_nullifiers",
            "sprout_commitments",
            "sapling_commitments",
            "orchard_commitments",
            "ironwood_commitments",
            "transparent_spends",
            "transparent_creates",
            "transactions",
        ];
        for slice in SLICES {
            let checkpoint = load(slice).unwrap();
            for field in required {
                assert!(
                    checkpoint.get(field).is_some(),
                    "{slice}: checkpoint has no '{field}'"
                );
            }
        }
    }

    #[test]
    fn the_slices_actually_exercise_the_pools_they_are_named_for() {
        // A fixture that does not contain what it claims to would let the whole
        // harness pass while testing nothing. Each assertion below is the
        // reason that slice was captured in the first place.
        let sapling = load("sapling-activation").unwrap();
        assert!(
            sapling.get("sprout_nullifiers").unwrap() > 0,
            "the Sapling-activation slice should still carry Sprout activity"
        );

        let orchard = load("nu5-orchard").unwrap();
        assert!(
            orchard.get("orchard_nullifiers").unwrap() > 0,
            "the NU5 slice should carry Orchard activity"
        );

        let ironwood = load("ironwood-activation").unwrap();
        assert!(
            ironwood.get("ironwood_nullifiers").unwrap() > 0,
            "the Ironwood slice should carry Ironwood activity"
        );
        assert!(
            ironwood.get("orchard_nullifiers").unwrap() > 0,
            "Orchard is withdraw-only but draining, so it must still appear"
        );

        let sandblast = load("sandblasting").unwrap();
        assert!(
            sandblast.get("transparent_creates").unwrap() > 4000,
            "the sandblasting slice should be output-heavy"
        );
    }

    #[test]
    fn missing_slice_is_an_error_not_an_empty_pass() {
        assert!(matches!(
            load("no-such-slice"),
            Err(CheckpointError::Missing { .. })
        ));
    }

    /// Writes `text` to a temp file and loads it back.
    fn round_trip(name: &str, text: &str) -> Result<Checkpoint, CheckpointError> {
        let dir = std::env::temp_dir().join("zutreexo-checkpoint-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.json"));
        std::fs::write(&path, text).unwrap();
        let result = load_from(&path, name);
        let _ = std::fs::remove_file(&path);
        result
    }

    /// A truncated or hand-edited checkpoint must be an error, never a silently
    /// empty one — an oracle with no data passes everything.
    #[test]
    fn malformed_checkpoints_are_rejected() {
        let cases: [(&str, &str); 5] = [
            ("not-json", "{ this is not json"),
            (
                "no-totals",
                r#"{"start_height":1,"end_height":2,"blocks":2}"#,
            ),
            (
                "totals-not-an-object",
                r#"{"start_height":1,"end_height":2,"blocks":2,"totals":[]}"#,
            ),
            (
                "non-numeric-total",
                r#"{"start_height":1,"end_height":2,"blocks":2,"totals":{"a":"x"}}"#,
            ),
            (
                "height-overflows-u32",
                r#"{"start_height":99999999999,"end_height":2,"blocks":2,"totals":{}}"#,
            ),
        ];

        for (name, text) in cases {
            assert!(
                matches!(
                    round_trip(name, text),
                    Err(CheckpointError::Malformed { .. })
                ),
                "{name}: should have been rejected as malformed"
            );
        }
    }

    #[test]
    fn a_well_formed_checkpoint_loads() {
        let text = r#"{
            "start_height": 100,
            "end_height": 101,
            "blocks": 2,
            "totals": { "orchard_nullifiers": 7 }
        }"#;
        let checkpoint = round_trip("good", text).unwrap();
        assert_eq!(checkpoint.start_height, 100);
        assert_eq!(checkpoint.end_height, 101);
        assert_eq!(checkpoint.blocks, 2);
        assert_eq!(checkpoint.get("orchard_nullifiers"), Some(7));
        assert_eq!(checkpoint.get("absent_field"), None);
    }
}

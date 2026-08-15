//! Deterministic test vectors, pinned so later refactors cannot drift.
//!
//! CLAUDE.md Phase 1 requires these to be checked in. Every value below is a
//! root or digest produced by `zutreexo-accumulator` at the commit that
//! introduced it. They are not independently derived from a specification —
//! there is no Zcash specification for these structures yet — so they pin
//! *stability*, not correctness. Correctness comes from the naive oracle in
//! [`crate::naive`], which recomputes the same roots from scratch through
//! unshared code.
//!
//! Between them the two catch different things: the oracle catches a wrong
//! tree, and these catch a tree that quietly became a *different* right tree —
//! a changed domain separator, a reordered preimage field, a flipped
//! endianness. Any of those would invalidate every root a deployed node had
//! ever computed.
//!
//! # If one of these fails
//!
//! Do not update the constant to match. Work out which change moved it and
//! whether that change was intended. A deliberate format change is a version
//! bump plus a migration, not an edited hex string.

/// A pinned indexed-Merkle-tree root.
pub struct RootVector {
    /// Pool name, matching `PoolId`'s `Display`.
    pub pool: &'static str,
    /// Tree depth.
    pub depth: u8,
    /// Hex-encoded root.
    pub root: &'static str,
}

/// A pinned digest from a single hash function.
pub struct HashVector {
    /// What was hashed, for legibility in a failure message.
    pub label: &'static str,
    /// Hex-encoded digest.
    pub digest: &'static str,
}

/// Roots of freshly initialised trees — sentinel leaf only.
///
/// Depth 40 is `zutreexo-accumulator`'s `DEFAULT_DEPTH` (not a link: that crate
/// is a dev-dependency of this one, not a lib dependency, deliberately). Depths
/// 10 and 32 are kept because they were pinned before the depth decision, and a
/// root that moves is worth noticing regardless of which depth it belongs to.
///
/// These are the most sensitive values in the file: they depend on the empty
/// leaf separator, the node separator, the sentinel's encoding, and the depth,
/// and on nothing else.
pub const EMPTY_TREE_ROOTS: &[RootVector] = &[
    RootVector {
        pool: "sprout",
        depth: 10,
        root: "711b28943a3bf36c8c524cf3de28ecbc66e65f882d8d52197aab6163ba7ea2b7",
    },
    RootVector {
        pool: "sprout",
        depth: 32,
        root: "4e5ceeff37e3b8801abe57d9c423a0683c6c5a3b4289489406997edf421e7dfc",
    },
    RootVector {
        pool: "sapling",
        depth: 10,
        root: "2ff4b0ab2e465f7e3f459d62e87bd991476069a0bd9ce317e624fbb949cdaa51",
    },
    RootVector {
        pool: "sapling",
        depth: 32,
        root: "852b22758384864f98aec83b8cf5fd1526c021799ff7e7a3038dca14cf3c300f",
    },
    RootVector {
        pool: "orchard",
        depth: 10,
        root: "692e6c3e16a87b402052d60ec4d294c20450b12cdf06357a68e6eae5070f9d4e",
    },
    RootVector {
        pool: "orchard",
        depth: 32,
        root: "52e01b67164117c8d9ddae334678e13df03f5fceefe1cc2f3e5e808b4d30dfc0",
    },
    RootVector {
        pool: "ironwood",
        depth: 10,
        root: "45fa22927696824c83a140dedcd717ec8a049621729e939fc613acf482b673ed",
    },
    RootVector {
        pool: "ironwood",
        depth: 32,
        root: "392417acfb14a3a5f2711d1ac8a796860eedbc550d803ba7271e74384885702b",
    },
    RootVector {
        pool: "sprout",
        depth: 40,
        root: "10ac3c3d48790b358a4ced15ead5d47b25739c6cb365987f7c3c82eb14364ae3",
    },
    RootVector {
        pool: "sapling",
        depth: 40,
        root: "085b161f07d30bbde6305f40dcd5d200ddee745189f98e28eda2c1b0d25bce30",
    },
    RootVector {
        pool: "orchard",
        depth: 40,
        root: "5d7ab2847197560aae9157838f4c47c33448e7fe109ad5e96d6b1a29647ff8eb",
    },
    RootVector {
        pool: "ironwood",
        depth: 40,
        root: "dc0ec676f6f24a8023585c7554617a384c8127551f2a8a161388aa807be7ac9d",
    },
];

/// The insertion sequence behind [`SEQUENCE_ROOTS`].
///
/// Chosen so each insertion lands in a different position relative to its
/// neighbours: append at the end, splice at the front, splice into the middle,
/// and one value large enough to sit well above the rest.
pub const SEQUENCE: &[u64] = &[7, 3, 91, 1, 42, 12345, 8];

/// Roots after inserting [`SEQUENCE`] in order, as big-endian `u64`s in the
/// low 8 bytes of a 32-byte value.
pub const SEQUENCE_ROOTS: &[RootVector] = &[
    RootVector {
        pool: "sprout",
        depth: 10,
        root: "1c2eb45caa2b9aedf92e7562dc82e560adb2e61f7ae0441116df8209de538997",
    },
    RootVector {
        pool: "sprout",
        depth: 32,
        root: "6854071cd52ca82cbde6151d37f2dcc839f0eaec683773456d6e9e3bf885e126",
    },
    RootVector {
        pool: "sapling",
        depth: 10,
        root: "6faaae6d5a78649106d808996bb2db11f8bcce59d8fac562fa66831aa71bbb36",
    },
    RootVector {
        pool: "sapling",
        depth: 32,
        root: "6f9ccecece440df5282a1cf828db30beb4890a2fdbd8bd5e0bbdd1cb6e68dc48",
    },
    RootVector {
        pool: "orchard",
        depth: 10,
        root: "60bb08403a96904068e181de56a30246ac98a4cec26d2c5b6ba8570ef7272496",
    },
    RootVector {
        pool: "orchard",
        depth: 32,
        root: "0db82d46cc608ae9b0f83d452ed07ec70dde87374d572f9b576d00f09dc0233e",
    },
    RootVector {
        pool: "ironwood",
        depth: 10,
        root: "ea8707bed302105272621fbdb2c527d43401ba1c337598f98adf5d654c89aacc",
    },
    RootVector {
        pool: "ironwood",
        depth: 32,
        root: "6f7feccf733f4bdf3065e1f38e2a52e63b641c1c31e1536fb60a8527f242ddbf",
    },
    RootVector {
        pool: "sprout",
        depth: 40,
        root: "33689000ea31e22ac6b7bc7c2f1815ef8e9be900179cf249dbf5a9cf7d31a3ad",
    },
    RootVector {
        pool: "sapling",
        depth: 40,
        root: "33239264b978bbb429b80cacd185717d66fd261469139ebdc29493eda9515913",
    },
    RootVector {
        pool: "orchard",
        depth: 40,
        root: "dadffd3ca3a01f08cf00b9720ed14f8256c0e20eabbafd13735c7af390bc9bdc",
    },
    RootVector {
        pool: "ironwood",
        depth: 40,
        root: "f4114cfc9d855cb4ccc7eeffd0f6e2e94916bf1b3dfea4633e30b2ffc1cf53c1",
    },
];

/// Roots after inserting `Value::MAX` and then `1`, at depth 32.
///
/// The maximum-value edge case CLAUDE.md Phase 1 calls out: `MAX` becomes the
/// list's maximum with a zero `next_value`, and the subsequent insertion has to
/// splice *below* it rather than after it.
pub const MAX_EDGE_ROOTS: &[RootVector] = &[
    RootVector {
        pool: "sprout",
        depth: 32,
        root: "8c39bff1121e717604d2546a8752a06527ce889905f340d50faddd0e97fa42bc",
    },
    RootVector {
        pool: "sapling",
        depth: 32,
        root: "bc06cb5afba74d81576e64e841b0b52b031ca6cc58d29bc42f552f8bab149305",
    },
    RootVector {
        pool: "orchard",
        depth: 32,
        root: "1754445c28dccbaee0d9efcd3e8104b34889ce885f5ab076d0f077aa55fbd423",
    },
    RootVector {
        pool: "ironwood",
        depth: 32,
        root: "ee8ba4f75c78827110b63055e58a227bfa7f00dc664d87b9c789ce8ed4bfdca7",
    },
    RootVector {
        pool: "sprout",
        depth: 40,
        root: "a6e3f85e48902ed03542dfa0d3961bf02408328baa1d46f71fd05fa63df1ca81",
    },
    RootVector {
        pool: "sapling",
        depth: 40,
        root: "4daf5676e727fd49aabcf9ccaa3e2905df9dab201aeae7f2d0d7d57ad38aaad0",
    },
    RootVector {
        pool: "orchard",
        depth: 40,
        root: "c1f0dad5dffbc1b0348596821c223ef5a04398eaf1069f76377272330c58eece",
    },
    RootVector {
        pool: "ironwood",
        depth: 40,
        root: "a231d3cf1ee8cdbb16537090cccf2962c6c14601dad5da5adcc94753a1d30ff4",
    },
];

/// Individual hash-function outputs.
///
/// `leaf` is `imt_leaf(pool, [1u8; 32], [2u8; 32], 3)`; `node` is
/// `imt_node(pool, [1u8; 32], [2u8; 32])`; `empty` is `imt_empty_leaf(pool)`.
/// These pin the domain separators directly, independently of any tree.
pub const HASH_VECTORS: &[HashVector] = &[
    HashVector {
        label: "imt_empty_leaf/sprout",
        digest: "be14f78b7853a64ca8232121013d1c04d4e6c7b7d8d80b745426f2941f1f0a64",
    },
    HashVector {
        label: "imt_leaf/sprout",
        digest: "40007f4444e3b208e9cc5d3d2c79f49daee692690538b30491bd78476ec282f7",
    },
    HashVector {
        label: "imt_node/sprout",
        digest: "cfd6fca3010e56ede379f98d3a2b5ccbac93db6c046c898632f40bd5fe9d1ce3",
    },
    HashVector {
        label: "imt_empty_leaf/sapling",
        digest: "4e8f53525816f7d2536f78244cac069ce192d5f595e9712597d6df88ccae9a92",
    },
    HashVector {
        label: "imt_leaf/sapling",
        digest: "90b5261cf5a4fe1c12f539eb3f2c4a9ab9defdc047b8e3fc043e7736b2401b90",
    },
    HashVector {
        label: "imt_node/sapling",
        digest: "df054a0d7f53e04b3901b008502e658aa11162872e65d4401ab1b0fcb273d3e4",
    },
    HashVector {
        label: "imt_empty_leaf/orchard",
        digest: "26dad056b214a83fa828005c75d98eabf70674e7e0047bd61c9162397aad2dc0",
    },
    HashVector {
        label: "imt_leaf/orchard",
        digest: "cb9547e56737cbbc04940f721fa11f84a5cd34c5448912a623739c8a620fea80",
    },
    HashVector {
        label: "imt_node/orchard",
        digest: "6464194f1e8fe36d9101cc29a9f0ac8c7f84e76eb1d0a2091d31341ce383ab17",
    },
    HashVector {
        label: "imt_empty_leaf/ironwood",
        digest: "28dfc7b30406457cf6d435d7c532bb5d12a520308cde607da2d80c0746bb10e7",
    },
    HashVector {
        label: "imt_leaf/ironwood",
        digest: "0a35414e01201cf8e98b3c930d72bf387f24096075e5660d84d0f7f238b95d7b",
    },
    HashVector {
        label: "imt_node/ironwood",
        digest: "ef96ea88e97304cb2a8a7e7a83644476fab5e03929f7c606ec1a46dd74453527",
    },
    HashVector {
        label: "utxo_node",
        digest: "2ae9ab02b4801570787cdfa6440efd6b5aaf16a7f10dfb0f05617fa837d3e888",
    },
];

/// Digest of the transparent leaf described in [`UTXO_LEAF_FIELDS`].
///
/// Pinning this pins the preimage layout: field order, endianness, the
/// coinbase byte, and the script length prefix.
pub const UTXO_LEAF_DIGEST: &str =
    "93d1651eca3fbee211af6eae843f720447044a249b0e848eddf1120e1cc79f50";

/// The leaf behind [`UTXO_LEAF_DIGEST`], as `(field, value)` for legibility.
///
/// `txid` is 32 bytes of `0xab`; height is Ironwood's activation height.
pub const UTXO_LEAF_FIELDS: &[(&str, &str)] = &[
    ("txid", "ab repeated 32 times"),
    ("vout", "1"),
    ("height", "3428143"),
    ("is_coinbase", "false"),
    ("value", "100000000"),
    ("script_pubkey", "76a914"),
];

/// Roots of a transparent forest holding five leaves.
///
/// Five is deliberately not a power of two, so the forest has more than one
/// perfect tree and the root ordering is exercised.
pub const UTXO_FOREST_ROOTS: &[&str] = &[
    "8b83eadea93d3b49df868f9a4b6435e359effe2580e9fb54d998dfaca5cf45a3",
    "6c00931c1c04634b6cbf1afebf7364bbc3a742f71fd3a7ed9795968fdfcdb7fd",
];

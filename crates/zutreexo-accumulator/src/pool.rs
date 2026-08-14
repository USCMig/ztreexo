//! Shielded pool identity.
//!
//! Zcash has more than one live shielded pool, and therefore more than one live
//! nullifier set. Ironwood activated at height 3,428,143 as part of NU6.3 and
//! restricted Orchard to withdrawals only; because withdrawal is discretionary,
//! Orchard drains slowly rather than emptying. Both nullifier sets are live
//! indefinitely, so per-pool parameterisation is mandatory rather than
//! defensive (CLAUDE.md §2.3, §7).
//!
//! [`PoolId`] is defined here, in the accumulator crate rather than in
//! `zutreexo-chain`, because the domain separators in [`crate::hash`] are
//! pool-specific and domain separation is a Phase 1 concern. `zutreexo-chain`
//! re-exports it.

/// A Zcash shielded pool, one per nullifier set.
///
/// Sprout is included rather than excluded. It is legacy and small, but its
/// nullifier set is nonzero and permanent, and a replay from genesis has to
/// account for it. Excluding it would make the chain crate unable to represent
/// real history for the sake of saving one enum variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PoolId {
    /// The original shielded pool (JoinSplit-based). Legacy, draining, small.
    Sprout,
    /// The Sapling pool, activated at height 419,200.
    Sapling,
    /// The Orchard pool, activated with NU5. Withdraw-only since Ironwood.
    Orchard,
    /// The Ironwood pool, activated at height 3,428,143 with NU6.3.
    Ironwood,
}

impl PoolId {
    /// Every pool, in a fixed order.
    ///
    /// The order is part of the serialization of multi-pool state, so it is
    /// deterministic and must not be reordered once anything is persisted.
    pub const ALL: [PoolId; 4] = [
        PoolId::Sprout,
        PoolId::Sapling,
        PoolId::Orchard,
        PoolId::Ironwood,
    ];

    /// The four-byte tag embedded in this pool's hash domain separators.
    ///
    /// These bytes are consensus-visible the moment any root derived from them
    /// is compared across nodes. They must never change.
    pub const fn tag(self) -> [u8; 4] {
        match self {
            PoolId::Sprout => *b"Sprt",
            PoolId::Sapling => *b"Sapl",
            PoolId::Orchard => *b"Orch",
            PoolId::Ironwood => *b"Iron",
        }
    }

    /// A stable single-byte discriminant for on-disk and wire encodings.
    ///
    /// Distinct from [`PoolId::tag`] on purpose: the tag is a hash input and
    /// must stay human-legible in personalization strings, while this is a
    /// compact encoding. Neither may change.
    pub const fn code(self) -> u8 {
        match self {
            PoolId::Sprout => 0,
            PoolId::Sapling => 1,
            PoolId::Orchard => 2,
            PoolId::Ironwood => 3,
        }
    }

    /// Inverse of [`PoolId::code`]. Returns `None` for an unknown discriminant.
    pub const fn from_code(code: u8) -> Option<PoolId> {
        match code {
            0 => Some(PoolId::Sprout),
            1 => Some(PoolId::Sapling),
            2 => Some(PoolId::Orchard),
            3 => Some(PoolId::Ironwood),
            _ => None,
        }
    }
}

impl core::fmt::Display for PoolId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            PoolId::Sprout => "sprout",
            PoolId::Sapling => "sapling",
            PoolId::Orchard => "orchard",
            PoolId::Ironwood => "ironwood",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_are_unique() {
        let mut seen = Vec::new();
        for pool in PoolId::ALL {
            assert_eq!(PoolId::from_code(pool.code()), Some(pool));
            assert!(!seen.contains(&pool.code()), "duplicate code for {pool}");
            seen.push(pool.code());
        }
        assert_eq!(PoolId::from_code(4), None);
        assert_eq!(PoolId::from_code(255), None);
    }

    #[test]
    fn tags_are_unique() {
        let mut seen = Vec::new();
        for pool in PoolId::ALL {
            assert!(!seen.contains(&pool.tag()), "duplicate tag for {pool}");
            seen.push(pool.tag());
        }
    }
}

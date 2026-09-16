//! Weights for pallet-launch-treasury.
//!
//! Not yet benchmarked. Every call here is a sum of already-benchmarked
//! calls in other pallets plus this pallet's own O(1) reads and writes, so
//! the figures below are built the same way, from `energy-generation`'s
//! `weights.rs` (`bond_extra`, `cooperate(n)`, `unbond`,
//! `withdraw_unbonded_update`, `chill`) and the DEX / broker swap weights,
//! with a margin. Replace with `frame-benchmarking` output before mainnet;
//! the shape (which call pays for what) is what matters until then.

#![allow(unused_parens)]
#![allow(unused_imports)]

use core::marker::PhantomData;
use frame_support::{traits::Get, weights::Weight};

pub trait WeightInfo {
    fn stake() -> Weight;
    fn retarget() -> Weight;
    fn harvest() -> Weight;
    fn compound() -> Weight;
    fn retire() -> Weight;
    fn finalize_retirement() -> Weight;
    fn set_terms() -> Weight;
    fn set_targets() -> Weight;
}

/// `energy-generation::cooperate(n)` at `n = 16`: 66 µs + 16 × 3.3 µs.
const COOPERATE_16_REF: u64 = 120_000_000;
const COOPERATE_16_READS: u64 = 12 + 16;
const COOPERATE_16_WRITES: u64 = 6;
/// `bond_extra`: 95 µs, 9 reads, 7 writes.
const BOND_EXTRA_REF: u64 = 96_000_000;
/// `unbond`: 99 µs, 13 reads, 8 writes.
const UNBOND_REF: u64 = 99_000_000;
/// Two swaps (broker, DEX) and a burn: ~3 × 200 µs.
const COMPOUND_REF: u64 = 600_000_000;

pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn stake() -> Weight {
        Weight::from_parts(BOND_EXTRA_REF + COOPERATE_16_REF + 30_000_000, 20_000)
            .saturating_add(T::DbWeight::get().reads(9 + COOPERATE_16_READS + 8))
            .saturating_add(T::DbWeight::get().writes(7 + COOPERATE_16_WRITES + 5))
    }
    fn retarget() -> Weight {
        Weight::from_parts(COOPERATE_16_REF + 10_000_000, 12_000)
            .saturating_add(T::DbWeight::get().reads(COOPERATE_16_READS + 3))
            .saturating_add(T::DbWeight::get().writes(COOPERATE_16_WRITES + 1))
    }
    fn harvest() -> Weight {
        Weight::from_parts(20_000_000, 4_000)
            .saturating_add(T::DbWeight::get().reads(4))
            .saturating_add(T::DbWeight::get().writes(2))
    }
    fn compound() -> Weight {
        Weight::from_parts(COMPOUND_REF, 30_000)
            .saturating_add(T::DbWeight::get().reads(30))
            .saturating_add(T::DbWeight::get().writes(16))
    }
    fn retire() -> Weight {
        Weight::from_parts(UNBOND_REF + COOPERATE_16_REF + 40_000_000, 24_000)
            .saturating_add(T::DbWeight::get().reads(13 + COOPERATE_16_READS + 10))
            .saturating_add(T::DbWeight::get().writes(8 + COOPERATE_16_WRITES + 6))
    }
    fn finalize_retirement() -> Weight {
        Weight::from_parts(60_000_000 + 64 * 1_000_000, 12_000)
            .saturating_add(T::DbWeight::get().reads(8 + 64))
            .saturating_add(T::DbWeight::get().writes(4 + 64))
    }
    fn set_terms() -> Weight {
        Weight::from_parts(10_000_000, 2_000).saturating_add(T::DbWeight::get().writes(1))
    }
    fn set_targets() -> Weight {
        Weight::from_parts(COOPERATE_16_REF + 10_000_000, 12_000)
            .saturating_add(T::DbWeight::get().reads(COOPERATE_16_READS + 3))
            .saturating_add(T::DbWeight::get().writes(COOPERATE_16_WRITES + 2))
    }
}

impl WeightInfo for () {
    fn stake() -> Weight {
        Weight::from_parts(300_000_000, 20_000)
    }
    fn retarget() -> Weight {
        Weight::from_parts(150_000_000, 12_000)
    }
    fn harvest() -> Weight {
        Weight::from_parts(30_000_000, 4_000)
    }
    fn compound() -> Weight {
        Weight::from_parts(700_000_000, 30_000)
    }
    fn retire() -> Weight {
        Weight::from_parts(300_000_000, 24_000)
    }
    fn finalize_retirement() -> Weight {
        Weight::from_parts(200_000_000, 12_000)
    }
    fn set_terms() -> Weight {
        Weight::from_parts(20_000_000, 2_000)
    }
    fn set_targets() -> Weight {
        Weight::from_parts(150_000_000, 12_000)
    }
}

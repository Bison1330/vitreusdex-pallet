//! Weights for pallet-launch-treasury.
//!
//! Not yet measured on reference hardware. The ref-time figures are sums
//! of already-benchmarked calls in other pallets plus a margin, from
//! `energy-generation`'s `weights.rs` (`bond_extra`, `cooperate(n)`,
//! `unbond`, `withdraw_unbonded_update`, `chill`) and the DEX / broker swap
//! weights. The read and write counts are what `benchmarking.rs` actually
//! touched when run against the testnet runtime (2026-09-16, `--steps 2
//! --repeat 1` on a development box: counts are hardware-independent, the
//! times from that run are not and were discarded). Replace the whole file
//! with `frame-benchmarking` output per `pallets/BENCHMARKING.md` before
//! mainnet; the shape (which call pays for what) is what matters until then.

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
    /// `n`: retiring launches credited from the queue (≤ `MaxUnlockingChunks`).
    fn finalize_retirement(n: u32) -> Weight;
    fn set_terms() -> Weight;
    fn set_targets() -> Weight;
}

/// `energy-generation::cooperate(n)` at `n = 16`: 66 µs + 16 × 3.3 µs.
const COOPERATE_16_REF: u64 = 120_000_000;
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
            .saturating_add(T::DbWeight::get().reads(66))
            .saturating_add(T::DbWeight::get().writes(26))
    }
    fn retarget() -> Weight {
        Weight::from_parts(COOPERATE_16_REF + 10_000_000, 12_000)
            .saturating_add(T::DbWeight::get().reads(57))
            .saturating_add(T::DbWeight::get().writes(19))
    }
    fn harvest() -> Weight {
        Weight::from_parts(20_000_000, 4_000)
            .saturating_add(T::DbWeight::get().reads(4))
            .saturating_add(T::DbWeight::get().writes(2))
    }
    fn compound() -> Weight {
        Weight::from_parts(COMPOUND_REF, 30_000)
            .saturating_add(T::DbWeight::get().reads(26))
            .saturating_add(T::DbWeight::get().writes(19))
    }
    fn retire() -> Weight {
        Weight::from_parts(UNBOND_REF + COOPERATE_16_REF + 40_000_000, 24_000)
            .saturating_add(T::DbWeight::get().reads(71))
            .saturating_add(T::DbWeight::get().writes(27))
    }
    fn finalize_retirement(n: u32) -> Weight {
        Weight::from_parts(60_000_000, 12_000)
            .saturating_add(Weight::from_parts(1_000_000, 0).saturating_mul(n.into()))
            .saturating_add(T::DbWeight::get().reads(10))
            .saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(n.into())))
            .saturating_add(T::DbWeight::get().writes(6))
            .saturating_add(T::DbWeight::get().writes((1_u64).saturating_mul(n.into())))
    }
    fn set_terms() -> Weight {
        Weight::from_parts(10_000_000, 2_000).saturating_add(T::DbWeight::get().writes(1))
    }
    fn set_targets() -> Weight {
        Weight::from_parts(COOPERATE_16_REF + 10_000_000, 12_000)
            .saturating_add(T::DbWeight::get().reads(56))
            .saturating_add(T::DbWeight::get().writes(20))
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
    fn finalize_retirement(n: u32) -> Weight {
        Weight::from_parts(200_000_000, 12_000).saturating_add(Weight::from_parts(1_000_000, 0).saturating_mul(n.into()))
    }
    fn set_terms() -> Weight {
        Weight::from_parts(20_000_000, 2_000)
    }
    fn set_targets() -> Weight {
        Weight::from_parts(150_000_000, 12_000)
    }
}

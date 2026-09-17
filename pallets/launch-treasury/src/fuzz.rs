//! Property-based fuzzing of the three pallets — vitreus-dex, launchpad,
//! launch-treasury — on this crate's mock runtime, which composes the real
//! DEX and launchpad with `MockStaking` and `MockBroker` (mock.rs). Designed
//! after the 2026-09-17 review (pallets/REVIEW_2026-09-17.md), whose
//! findings were all adversarial ordering and edge arithmetic across a
//! pallet boundary; this is the tool that looks for that class by machine.
//!
//! **Generators.** A `Vec<Op>` of 1..=100 steps. Every `Op` addresses a
//! launch by index modulo the launches that exist, an account by index into
//! the dev keys, a sale by a fraction of the seller's holding, time by a
//! delta — so any subsequence is still a valid program and proptest's
//! shrinking (drop an op, simplify a value) always lands on something that
//! runs. Amounts come from a scale-aware strategy: a weighted union of the
//! edges the review was about (1 wei, ED ± 1, min stake ± 1, the graduation
//! target ± 1, `MAX_TRADE_IN` ± 1, a quarter of u128::MAX) and log-uniform
//! draws across 10^12..10^24.
//!
//! **Judged results.** Every op's dispatch result is `Ok` or an error on
//! that op's allowlist (`NotDormant`, `NothingToDo`, `WrongPhase`, an
//! unaffordable transfer…). Anything else — `ArithmeticOverflow` inside a
//! bound, `Token(Frozen)`, `NotExpendable`, `Unquotable` where a no-op was
//! due — fails the case. That is the class §9.6, Finding 14 and R8 were:
//! the counterpart pallet refusing what this one assumed.
//!
//! **Invariants after every step** (`check_all`): the treasury's own
//! `try_state` (I-T1 floor, both halves of I-T2, I-T7); the launchpad's
//! I1/I2/I5/I6 and I4 — a curve's `k` never decreases across an op — plus
//! the R2 rule that the vault's own buys leave `last_trade_block` alone;
//! every DEX pool's balances ≥ its stored reserves, `k` from balances never
//! decreasing except on a liquidity removal, Σ positions + MINIMUM_LIQUIDITY
//! == TotalLiquidity; and two conservation laws across the boundary — every
//! launch token is in an account we can name, and every VTRS is (Σ over
//! named accounts == total issuance).
//!
//! **Where it runs.** `cargo test` runs `PROPTEST_CASES` (default 32) cases
//! in seconds, so it is in CI; by hand, `PROPTEST_CASES=5000 cargo test
//! --release -p pallet-launch-treasury -- fuzz` for an hour. proptest
//! persists every failing seed in `proptest-regressions/`, which is
//! committed and replayed first, forever.
//!
//! A failure prints the minimal sequence as numbered sentences, the
//! invariant that broke, and a one-screen summary of the state it broke in.

use super::*;
use crate::mock::*;
use core::fmt;
use frame_support::traits::{
    fungibles::Mutate as FungiblesMutate,
    tokens::{Fortitude, Precision, Preservation},
};
use pallet_launchpad::{Curves, Launches, NextLaunchId, Phase};
use pallet_vitreus_dex::{LiquidityPositions, Pools, TotalLiquidity, MINIMUM_LIQUIDITY};
use proptest::prelude::*;
use sp_core::U256;
use sp_runtime::{DispatchError, TokenError};
use std::collections::BTreeMap;

const USERS: [Acc; 4] = [ALICE, BOB, CHARLIE, KEEPER];
const USER_NAMES: [&str; 4] = ["alice", "bob", "charlie", "keeper"];
const VALS: [Acc; 3] = [VAL_A, VAL_B, VAL_C];
const VAL_NAMES: [&str; 3] = ["val-a", "val-b", "val-c"];
const MAX_TRADE_IN: u128 = pallet_launchpad::curve::MAX_TRADE_IN;
const SELLABLE: u128 = 800_000_000 * UNIT;
const RESERVED: u128 = 200_000_000 * UNIT;

// ---- amounts ---------------------------------------------------------------

/// The edges: what the review's arithmetic findings lived at.
fn edges() -> Vec<u128> {
    vec![
        1,
        ED - 1,
        ED,
        ED + 1,
        UNIT - 1,
        UNIT,
        UNIT + 1,
        MIN_COOP_BOND - 1,
        T_DEFAULT / 3,
        T_DEFAULT - 1,
        T_DEFAULT,
        T_DEFAULT + 1,
        3 * T_DEFAULT,
        MAX_TRADE_IN - 1,
        MAX_TRADE_IN,
        MAX_TRADE_IN + 1,
        u128::MAX / 4,
    ]
}

fn amount() -> impl Strategy<Value = u128> {
    prop_oneof![
        3 => any::<prop::sample::Index>().prop_map(|i| { let e = edges(); e[i.index(e.len())] }),
        7 => (12u32..=24, 1u128..=9_999).prop_map(|(e, m)| m.saturating_mul(10u128.pow(e)) / 1_000),
    ]
}

/// Rewards are capped so a hundred of them cannot overflow the asset's supply.
fn reward() -> impl Strategy<Value = u128> {
    prop_oneof![
        2 => Just(1u128),
        2 => Just(UNIT),
        6 => (0u32..=27, 1u128..=999).prop_map(|(e, m)| m.saturating_mul(10u128.pow(e)) / 100 + 1),
    ]
}

// ---- ops -------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Where {
    Vault,
    Escrow,
    Pool,
    Broker,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum What {
    Vtrs,
    Lnrg,
    Token,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Op {
    CreateLaunch { creator: u8, initial_buy: u128 },
    Buy { who: u8, launch: u8, q: u128 },
    Sell { who: u8, launch: u8, frac_bps: u16 },
    ClaimCreatorFees { launch: u8 },
    Graduate { launch: u8 },
    PoolSwap { who: u8, launch: u8, buy: bool, amount: u128 },
    AddLiquidity { who: u8, launch: u8, vtrs: u128 },
    RemoveLiquidity { who: u8, launch: u8, frac_bps: u16 },
    Stake { launch: u8 },
    Retarget,
    Harvest,
    Compound { who: u8, launch: u8 },
    Retire { launch: u8 },
    Finalize { launch: u8 },
    SetTerms { impact: u16, bounty: u16, min_stake: u128, interval: u64, dormancy: u64 },
    SetTargets { mask: u8 },
    PayRewards { lnrg: u128 },
    Slash { bps: u16 },
    SetCooperable { validator: u8, ok: bool },
    SetReputation { ok: bool },
    FundBroker { vtrs: u128 },
    DrainBroker,
    Donate { to: Where, what: What, launch: u8, amount: u128 },
    AdvanceBlocks { n: u32 },
    AdvanceEras { n: u8 },
}

fn op() -> impl Strategy<Value = Op> {
    let who = 0u8..4;
    let launch = 0u8..8;
    prop_oneof![
        4 => (who.clone(), prop_oneof![6 => Just(0u128), 4 => amount()]).prop_map(|(creator, initial_buy)| Op::CreateLaunch { creator, initial_buy }),
        10 => (who.clone(), launch.clone(), amount()).prop_map(|(who, launch, q)| Op::Buy { who, launch, q }),
        6 => (who.clone(), launch.clone(), 1u16..=10_000).prop_map(|(who, launch, frac_bps)| Op::Sell { who, launch, frac_bps }),
        2 => launch.clone().prop_map(|launch| Op::ClaimCreatorFees { launch }),
        2 => launch.clone().prop_map(|launch| Op::Graduate { launch }),
        6 => (who.clone(), launch.clone(), any::<bool>(), amount()).prop_map(|(who, launch, buy, amount)| Op::PoolSwap { who, launch, buy, amount }),
        2 => (who.clone(), launch.clone(), amount()).prop_map(|(who, launch, vtrs)| Op::AddLiquidity { who, launch, vtrs }),
        2 => (who.clone(), launch.clone(), 1u16..=10_000).prop_map(|(who, launch, frac_bps)| Op::RemoveLiquidity { who, launch, frac_bps }),
        6 => launch.clone().prop_map(|launch| Op::Stake { launch }),
        1 => Just(Op::Retarget),
        3 => Just(Op::Harvest),
        8 => (who.clone(), launch.clone()).prop_map(|(who, launch)| Op::Compound { who, launch }),
        3 => launch.clone().prop_map(|launch| Op::Retire { launch }),
        3 => launch.clone().prop_map(|launch| Op::Finalize { launch }),
        1 => (0u16..=600, 0u16..=300, prop_oneof![Just(0u128), Just(ED), Just(UNIT), Just(10 * UNIT)], 0u64..=50, 0u64..=200).prop_map(|(impact, bounty, min_stake, interval, dormancy)| Op::SetTerms { impact, bounty, min_stake, interval, dormancy }),
        1 => (0u8..8).prop_map(|mask| Op::SetTargets { mask }),
        6 => reward().prop_map(|lnrg| Op::PayRewards { lnrg }),
        1 => (0u16..=10_000).prop_map(|bps| Op::Slash { bps }),
        1 => (0u8..3, any::<bool>()).prop_map(|(validator, ok)| Op::SetCooperable { validator, ok }),
        1 => any::<bool>().prop_map(|ok| Op::SetReputation { ok }),
        1 => amount().prop_map(|vtrs| Op::FundBroker { vtrs }),
        1 => Just(Op::DrainBroker),
        2 => (prop_oneof![Just(Where::Vault), Just(Where::Escrow), Just(Where::Pool), Just(Where::Broker)], prop_oneof![Just(What::Vtrs), Just(What::Lnrg), Just(What::Token)], launch.clone(), amount()).prop_map(|(to, what, launch, amount)| Op::Donate { to, what, launch, amount }),
        8 => prop_oneof![5 => 0u32..=20, 3 => Just(BURN_INTERVAL as u32), 2 => Just(DORMANCY as u32 + 1)].prop_map(|n| Op::AdvanceBlocks { n }),
        3 => prop_oneof![4 => 0u8..=3, 2 => Just(BONDING_DURATION as u8 + 1)].prop_map(|n| Op::AdvanceEras { n }),
    ]
}

fn vtrs_str(v: u128) -> String {
    if v >= UNIT / 1000 {
        format!("{} VTRS", v as f64 / UNIT as f64)
    } else {
        format!("{v} wei")
    }
}

impl fmt::Debug for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let u = |i: u8| USER_NAMES[i as usize % USERS.len()];
        match self {
            Op::CreateLaunch { creator, initial_buy } => write!(f, "{} creates a launch (initial buy {})", u(*creator), vtrs_str(*initial_buy)),
            Op::Buy { who, launch, q } => write!(f, "{} buys {} of launch[{launch}]", u(*who), vtrs_str(*q)),
            Op::Sell { who, launch, frac_bps } => write!(f, "{} sells {}% of their launch[{launch}] tokens", u(*who), *frac_bps as f64 / 100.0),
            Op::ClaimCreatorFees { launch } => write!(f, "the creator claims launch[{launch}]'s fees"),
            Op::Graduate { launch } => write!(f, "someone calls graduate(launch[{launch}])"),
            Op::PoolSwap { who, launch, buy, amount } => write!(f, "{} {} {} in launch[{launch}]'s pool", u(*who), if *buy { "buys with" } else { "sells" }, if *buy { vtrs_str(*amount) } else { format!("{amount} token units") }),
            Op::AddLiquidity { who, launch, vtrs } => write!(f, "{} adds {} of liquidity to launch[{launch}]'s pool", u(*who), vtrs_str(*vtrs)),
            Op::RemoveLiquidity { who, launch, frac_bps } => write!(f, "{} removes {}% of their liquidity from launch[{launch}]'s pool", u(*who), *frac_bps as f64 / 100.0),
            Op::Stake { launch } => write!(f, "stake(launch[{launch}])"),
            Op::Retarget => write!(f, "retarget()"),
            Op::Harvest => write!(f, "harvest()"),
            Op::Compound { who, launch } => write!(f, "{} compounds launch[{launch}]", u(*who)),
            Op::Retire { launch } => write!(f, "retire(launch[{launch}])"),
            Op::Finalize { launch } => write!(f, "finalize_retirement(launch[{launch}])"),
            Op::SetTerms { impact, bounty, min_stake, interval, dormancy } => write!(f, "governance sets terms: impact {impact} bps, bounty {bounty} bps, min stake {}, interval {interval}, dormancy {dormancy}", vtrs_str(*min_stake)),
            Op::SetTargets { mask } => write!(f, "governance sets targets to {:?}", (0..3).filter(|i| mask & (1 << i) != 0).map(|i| VAL_NAMES[i]).collect::<Vec<_>>()),
            Op::PayRewards { lnrg } => write!(f, "{lnrg} LNRG-wei of staking rewards arrive"),
            Op::Slash { bps } => write!(f, "the vault is slashed {}%", *bps as f64 / 100.0),
            Op::SetCooperable { validator, ok } => write!(f, "{} becomes {}", VAL_NAMES[*validator as usize % 3], if *ok { "cooperable" } else { "uncooperable" }),
            Op::SetReputation { ok } => write!(f, "the vault's reputation is {}", if *ok { "sufficient" } else { "too low" }),
            Op::FundBroker { vtrs } => write!(f, "the broker gains {}", vtrs_str(*vtrs)),
            Op::DrainBroker => write!(f, "the broker is drained to ED"),
            Op::Donate { to, what, launch, amount } => write!(f, "someone sends {} {} to the {}", amount, match what { What::Vtrs => "VTRS-wei", What::Lnrg => "LNRG-wei", What::Token => "token units" }, match to { Where::Vault => "vault".to_string(), Where::Escrow => format!("escrow of launch[{launch}]"), Where::Pool => format!("pool of launch[{launch}]"), Where::Broker => "broker".to_string() }),
            Op::AdvanceBlocks { n } => write!(f, "{n} blocks pass"),
            Op::AdvanceEras { n } => write!(f, "{n} eras pass"),
        }
    }
}

// ---- world -----------------------------------------------------------------

fn launch_at(i: u8) -> Option<LaunchId> {
    let n = NextLaunchId::<Test>::get();
    if n == 0 {
        None
    } else {
        Some(i as LaunchId % n)
    }
}

fn asset_of(id: LaunchId) -> u128 {
    Launches::<Test>::get(id).map(|l| l.asset_id).unwrap_or(ASSET_BASE + id as u128)
}

fn kind(id: LaunchId) -> NativeOrAssetId {
    NativeOrAssetId::WithId(asset_of(id))
}

fn pool_account(id: LaunchId) -> Acc {
    VitreusDex::pool_account_for(NativeOrAssetId::Native, kind(id))
}

fn escrow_of(id: LaunchId) -> Acc {
    Launches::<Test>::get(id).map(|l| l.escrow).unwrap_or(TREASURY)
}

fn free(who: &Acc) -> u128 {
    Balances::free_balance(who)
}

fn spendable(who: &Acc) -> u128 {
    free(who).saturating_sub(ED)
}

fn origin(who: &Acc) -> RuntimeOrigin {
    RuntimeOrigin::signed(who.clone())
}

fn bv(s: &[u8]) -> frame_support::BoundedVec<u8, frame_support::traits::ConstU32<50>> {
    s.to_vec().try_into().unwrap()
}

/// Run one op. `Ok(None)` is a no-op the world made meaningless (no launch
/// yet, nothing to sell); `Ok(Some(res))` is a dispatch result to judge.
fn run(op: &Op) -> Option<Result<(), DispatchError>> {
    let user = |i: u8| USERS[i as usize % USERS.len()].clone();
    Some(match op {
        Op::CreateLaunch { creator, initial_buy } => Launchpad::create_launch(
            origin(&user(*creator)),
            bv(b"Fuzz"),
            bv(b"FZ"),
            None,
            *initial_buy,
            0,
            None,
            None,
        )
        .map(|_| ())
        .map_err(|e| e.error),
        Op::Buy { who, launch, q } => {
            let id = launch_at(*launch)?;
            Launchpad::buy(origin(&user(*who)), id, *q, 0).map(|_| ()).map_err(|e| e.error)
        },
        Op::Sell { who, launch, frac_bps } => {
            let id = launch_at(*launch)?;
            let w = user(*who);
            let held = Assets::balance(asset_of(id), &w);
            let tokens = held / 10_000 * (*frac_bps as u128)
                + (held % 10_000) * (*frac_bps as u128) / 10_000;
            if tokens == 0 {
                return None;
            }
            Launchpad::sell(origin(&w), id, tokens, 0)
        },
        Op::ClaimCreatorFees { launch } => {
            let id = launch_at(*launch)?;
            let recipient = Launches::<Test>::get(id)?.creator_fee_recipient;
            Launchpad::claim_creator_fees(origin(&recipient), id)
        },
        Op::Graduate { launch } => {
            let id = launch_at(*launch)?;
            Launchpad::graduate(origin(&KEEPER), id)
        },
        Op::PoolSwap { who, launch, buy, amount } => {
            let id = launch_at(*launch)?;
            let w = user(*who);
            let (a_in, a_out, amt) = if *buy {
                (NativeOrAssetId::Native, kind(id), *amount)
            } else {
                let held = Assets::balance(asset_of(id), &w);
                let amt = (*amount).min(held);
                if amt == 0 {
                    return None;
                }
                (kind(id), NativeOrAssetId::Native, amt)
            };
            VitreusDex::swap_exact_tokens_for_tokens(origin(&w), a_in, a_out, amt, 0, w.clone())
        },
        Op::AddLiquidity { who, launch, vtrs } => {
            let id = launch_at(*launch)?;
            let w = user(*who);
            let tokens = Assets::balance(asset_of(id), &w);
            if tokens == 0 {
                return None;
            }
            VitreusDex::add_liquidity(
                origin(&w),
                NativeOrAssetId::Native,
                kind(id),
                *vtrs,
                tokens,
                0,
                0,
            )
        },
        Op::RemoveLiquidity { who, launch, frac_bps } => {
            let id = launch_at(*launch)?;
            let w = user(*who);
            let pair = VitreusDex::canonical_pair(NativeOrAssetId::Native, kind(id));
            let shares = LiquidityPositions::<Test>::get(&w, &pair).map(|p| p.shares).unwrap_or(0);
            let take = shares / 10_000 * (*frac_bps as u128)
                + (shares % 10_000) * (*frac_bps as u128) / 10_000;
            if take == 0 {
                return None;
            }
            VitreusDex::remove_liquidity(origin(&w), NativeOrAssetId::Native, kind(id), take, 0, 0)
        },
        Op::Stake { launch } => LaunchTreasury::stake(origin(&KEEPER), launch_at(*launch)?),
        Op::Retarget => LaunchTreasury::retarget(origin(&KEEPER)),
        Op::Harvest => LaunchTreasury::harvest(origin(&KEEPER)),
        Op::Compound { who, launch } => {
            LaunchTreasury::compound(origin(&user(*who)), launch_at(*launch)?)
        },
        Op::Retire { launch } => LaunchTreasury::retire(origin(&KEEPER), launch_at(*launch)?),
        Op::Finalize { launch } => {
            LaunchTreasury::finalize_retirement(origin(&KEEPER), launch_at(*launch)?)
        },
        Op::SetTerms { impact, bounty, min_stake, interval, dormancy } => {
            LaunchTreasury::set_terms(
                RuntimeOrigin::root(),
                TreasuryTerms {
                    dormancy_blocks: *dormancy,
                    min_stake: *min_stake,
                    max_burn_impact_bps: *impact,
                    min_burn_interval: *interval,
                    keeper_bounty_bps: *bounty,
                },
            )
        },
        Op::SetTargets { mask } => LaunchTreasury::set_targets(
            RuntimeOrigin::root(),
            (0..3).filter(|i| mask & (1 << i) != 0).map(|i| VALS[i].clone()).collect(),
        ),
        Op::PayRewards { lnrg } => Assets::mint_into(LNRG_ID, &vault(), *lnrg).map(|_| ()),
        Op::Slash { bps } => {
            MockStaking::slash(&vault(), *bps as u128);
            Ok(())
        },
        Op::SetCooperable { validator, ok } => {
            MockStaking::set_validator(VALS[*validator as usize % 3].clone(), *ok);
            Ok(())
        },
        Op::SetReputation { ok } => {
            REPUTATION_OK.with(|r| *r.borrow_mut() = *ok);
            Ok(())
        },
        Op::FundBroker { vtrs } => {
            let _ = Balances::transfer_allow_death(
                origin(&ALICE),
                BROKER,
                (*vtrs).min(spendable(&ALICE)),
            );
            return None;
        },
        Op::DrainBroker => {
            let _ = Balances::transfer_allow_death(origin(&BROKER), ALICE, spendable(&BROKER));
            return None;
        },
        Op::Donate { to, what, launch, amount } => {
            let dest = match to {
                Where::Vault => vault(),
                Where::Broker => BROKER,
                Where::Escrow => escrow_of(launch_at(*launch)?),
                Where::Pool => pool_account(launch_at(*launch)?),
            };
            match what {
                What::Vtrs => {
                    let _ = Balances::transfer_allow_death(
                        origin(&ALICE),
                        dest,
                        (*amount).min(spendable(&ALICE)),
                    );
                },
                What::Lnrg => {
                    let _ = Assets::mint_into(LNRG_ID, &dest, (*amount).min(10u128.pow(27)));
                },
                What::Token => {
                    let id = launch_at(*launch)?;
                    let held = Assets::balance(asset_of(id), &ALICE);
                    let _ = <Assets as FungiblesMutate<Acc>>::transfer(
                        asset_of(id),
                        &ALICE,
                        &dest,
                        (*amount).min(held),
                        Preservation::Expendable,
                    );
                },
            }
            return None;
        },
        Op::AdvanceBlocks { n } => {
            System::set_block_number(System::block_number() + *n as u64);
            return None;
        },
        Op::AdvanceEras { n } => {
            MockStaking::advance_eras(*n as u32);
            return None;
        },
    })
}

// ---- expected errors ---------------------------------------------------------

fn is_mod<E: Into<DispatchError>>(e: &DispatchError, m: E) -> bool {
    *e == m.into()
}

/// Whether `e` is an outcome the op was allowed to have. Everything not
/// listed here is a finding.
fn expected(op: &Op, e: &DispatchError) -> bool {
    use pallet_launchpad::Error as L;
    use pallet_vitreus_dex::Error as D;
    use Error as T;
    // SECURITY_AUDIT Finding 14 (open): a routed fee slice below ED cannot
    // create its recipient — the vault (from genesis, before the first fee
    // ≥ ED) or the DEX's fee escrow (never funded here) — and the trade that
    // routes it fails in full. The fuzzer found both legs in its first 200
    // cases; they are allowed here, by name, until F14 is fixed. Delete this
    // when it is.
    let f14 = matches!(e, DispatchError::Token(TokenError::BelowMinimum))
        && (!System::account_exists(&vault())
            || !System::account_exists(&VitreusDex::fee_escrow_account()))
        && matches!(
            op,
            Op::CreateLaunch { .. }
                | Op::Buy { .. }
                | Op::Sell { .. }
                | Op::PoolSwap { .. }
                | Op::Compound { .. }
        );
    if f14 {
        return true;
    }
    // What pallet-balances says when the payer cannot pay: short of funds,
    // or exactly at ED with a Preserve transfer.
    let funds = matches!(
        e,
        DispatchError::Token(
            TokenError::FundsUnavailable
                | TokenError::NotExpendable
                | TokenError::Frozen
                | TokenError::BelowMinimum
        ) | DispatchError::Arithmetic(_)
    );
    // The DEX has no MAX_TRADE_IN: an amount beyond any real magnitude
    // (issuance is ~10^27) overflows its U256-then-u128 arithmetic and is
    // answered with `Overflow`. Informational; a bound would name it.
    let absurd = |a: u128| a >= 10u128.pow(33);
    let user = |i: &u8| USERS[*i as usize % USERS.len()].clone();
    match op {
        Op::CreateLaunch { creator, initial_buy } => {
            // The creation fee plus the first buy, from a caller that may be poor.
            (funds && *initial_buy + CREATION_FEE + ED > free(&user(creator)))
                || is_mod(e, L::<Test>::ArithmeticOverflow) && *initial_buy > MAX_TRADE_IN
                || is_mod(e, L::<Test>::Unquotable)
                || is_mod(e, L::<Test>::CreationPaused)
        },
        Op::Buy { who, q, .. } => {
            is_mod(e, L::<Test>::WrongPhase)
                || is_mod(e, L::<Test>::Unquotable)
                || (is_mod(e, L::<Test>::ArithmeticOverflow) && *q > MAX_TRADE_IN)
                || (funds && *q + ED > free(&user(who)))
        },
        Op::Sell { .. } => {
            is_mod(e, L::<Test>::WrongPhase)
                || is_mod(e, L::<Test>::Unquotable)
                || is_mod(e, L::<Test>::SellExceedsSold)
        },
        Op::ClaimCreatorFees { .. } => is_mod(e, L::<Test>::ZeroAmount),
        Op::Graduate { .. } => is_mod(e, L::<Test>::WrongPhase),
        Op::PoolSwap { who, buy, amount, .. } => {
            (is_mod(e, D::<Test>::Overflow) && absurd(*amount))
                || is_mod(e, D::<Test>::PoolNotFound)
                || is_mod(e, D::<Test>::InsufficientLiquidity)
                || is_mod(e, D::<Test>::ZeroAmount)
                || (*buy && funds && *amount + ED > free(&user(who)))
            // A sell is clamped to what the seller holds and a zero output is
            // `ZeroAmount` (R10): no funds error is expected on a sell. The
            // arm that allowed one hid R11.
        },
        Op::AddLiquidity { who, vtrs, .. } => {
            (is_mod(e, D::<Test>::Overflow) && absurd(*vtrs))
                || is_mod(e, D::<Test>::PoolNotFound)
                || is_mod(e, D::<Test>::ZeroAmount)
                || is_mod(e, D::<Test>::InsufficientInitialLiquidity)
                || is_mod(e, D::<Test>::InsufficientLiquidity)
                || is_mod(e, D::<Test>::SlippageExceeded)
                || (funds && *vtrs + ED > free(&user(who)))
        },
        Op::RemoveLiquidity { .. } => {
            is_mod(e, D::<Test>::PoolNotFound)
                || is_mod(e, D::<Test>::PoolLocked)
                || is_mod(e, D::<Test>::InsufficientShares)
                || is_mod(e, D::<Test>::ZeroAmount)
                // Known (REVIEW_2026-09-17 informational): the last LP cannot
                // take the pool account under its ED. Allowed until fixed.
                || matches!(e, DispatchError::Token(TokenError::FundsUnavailable))
        },
        Op::Stake { .. } => {
            is_mod(e, T::<Test>::NoTreasury)
                || is_mod(e, T::<Test>::NotActive)
                || is_mod(e, T::<Test>::BelowMinStake)
                || is_mod(e, T::<Test>::VaultInsolvent)
                || is_mod(e, T::<Test>::NothingToDo)
        },
        Op::Retarget => {
            is_mod(e, T::<Test>::NothingToDo)
                || is_mod(e, T::<Test>::NoTargets)
                || matches!(e, DispatchError::Other(_))
        },
        Op::Harvest => is_mod(e, T::<Test>::NothingToDo),
        Op::Compound { .. } => {
            is_mod(e, T::<Test>::NoTreasury) || is_mod(e, T::<Test>::NothingToDo)
        },
        Op::Retire { .. } => {
            is_mod(e, T::<Test>::NoTreasury)
                || is_mod(e, T::<Test>::NotActive)
                || is_mod(e, T::<Test>::NotDormant)
                || is_mod(e, T::<Test>::QueueFull)
                || matches!(e, DispatchError::Other(_))
        },
        Op::Finalize { .. } => {
            is_mod(e, T::<Test>::NoTreasury)
                || is_mod(e, T::<Test>::NotRetiring)
                || is_mod(e, T::<Test>::NotMatured)
                || is_mod(e, T::<Test>::NothingToDo)
        },
        Op::SetTerms { impact, bounty, min_stake, interval, dormancy } => {
            is_mod(e, T::<Test>::TermsOutOfBounds)
                && !((10..=200).contains(impact)
                    && *bounty <= 200
                    && *dormancy > 0
                    && *min_stake > 0
                    && *interval < u64::MAX)
        },
        Op::SetTargets { .. } => false,
        // A reward for a vault that does not exist yet (from genesis, before
        // the first fee) has nowhere to land; on chain make_payout drops it.
        Op::PayRewards { .. } => matches!(
            e,
            DispatchError::Arithmetic(_) | DispatchError::Token(TokenError::CannotCreate)
        ),
        _ => false,
    }
}

// ---- invariants ------------------------------------------------------------

#[derive(Default)]
struct Before {
    curve_k: BTreeMap<LaunchId, U256>,
    last_trade: BTreeMap<LaunchId, u64>,
    pool_k: BTreeMap<LaunchId, U256>,
}

fn snapshot() -> Before {
    let mut b = Before::default();
    for id in 0..NextLaunchId::<Test>::get() {
        if let Some(c) = Curves::<Test>::get(id) {
            if c.phase == Phase::Trading {
                if let Some(k) = Launchpad::invariant_k(id) {
                    b.curve_k.insert(id, k);
                }
            }
            b.last_trade.insert(id, c.last_trade_block);
            if c.phase == Phase::Graduated {
                b.pool_k.insert(id, pool_k(id));
            }
        }
    }
    b
}

fn pool_k(id: LaunchId) -> U256 {
    let acct = pool_account(id);
    U256::from(free(&acct)) * U256::from(Assets::balance(asset_of(id), &acct))
}

fn named_accounts() -> Vec<Acc> {
    let mut v: Vec<Acc> = USERS.to_vec();
    v.extend([vault(), BROKER, TREASURY, EXCESS, VitreusDex::fee_escrow_account()]);
    v.extend(VALS.iter().cloned());
    for id in 0..NextLaunchId::<Test>::get() {
        v.push(escrow_of(id));
        v.push(pool_account(id));
    }
    v
}

/// Every invariant, after every op. Returns the first one that fails.
fn check_all(op: &Op, before: &Before) -> Result<(), String> {
    // The treasury's own.
    LaunchTreasury::do_try_state().map_err(|e| format!("treasury try_state: {e:?}"))?;

    // Launchpad, per launch.
    for id in 0..NextLaunchId::<Test>::get() {
        let Some(l) = Launches::<Test>::get(id) else { continue };
        let Some(c) = Curves::<Test>::get(id) else { continue };
        let asset = l.asset_id;
        let esc = &l.escrow;
        match c.phase {
            Phase::Trading | Phase::Complete => {
                // I1: escrow VTRS ≥ ED + real_quote + unclaimed creator fees.
                let need = ED + c.real_quote + c.creator_fees_unclaimed;
                if free(esc) < need {
                    return Err(format!(
                        "I1 launch {id}: escrow holds {} < ED + real_quote + creator fees = {}",
                        free(esc),
                        need
                    ));
                }
                // I2: escrow tokens ≥ remaining + reserved.
                if Assets::balance(asset, esc) < c.tokens_remaining + RESERVED {
                    return Err(format!(
                        "I2 launch {id}: escrow tokens {} < remaining + reserved",
                        Assets::balance(asset, esc)
                    ));
                }
                if c.phase == Phase::Complete && c.tokens_remaining != 0 {
                    return Err(format!("I6 launch {id}: Complete with tokens remaining"));
                }
                if c.phase == Phase::Trading && c.tokens_remaining == 0 {
                    return Err(format!("I6 launch {id}: Trading with nothing left"));
                }
            },
            Phase::Graduated => {
                if c.real_quote != 0 || c.tokens_remaining != 0 || c.lp_shares == 0 {
                    return Err(format!(
                        "I6 launch {id}: graduated with real_quote {} remaining {} lp_shares {}",
                        c.real_quote, c.tokens_remaining, c.lp_shares
                    ));
                }
                let pair = VitreusDex::canonical_pair(
                    NativeOrAssetId::Native,
                    NativeOrAssetId::WithId(asset),
                );
                let Some(pos) = LiquidityPositions::<Test>::get(esc, &pair) else {
                    return Err(format!("launch {id}: graduated without an escrow position"));
                };
                if pos.locked_until != Some(u64::MAX) {
                    return Err(format!(
                        "launch {id}: escrow position not locked forever: {:?}",
                        pos.locked_until
                    ));
                }
            },
        }
        if c.tokens_remaining > SELLABLE {
            return Err(format!("I5 launch {id}: tokens_remaining above sellable"));
        }
        // I4: k never decreases while trading.
        if let (Some(k0), Some(k1)) = (
            before.curve_k.get(&id),
            if c.phase == Phase::Trading { Launchpad::invariant_k(id) } else { None },
        ) {
            if k1 < *k0 {
                return Err(format!("I4 launch {id}: k fell from {k0} to {k1}"));
            }
        }
        // R2: the vault's own buy leaves the clock alone.
        if let (Op::Compound { .. }, Some(t0)) = (op, before.last_trade.get(&id)) {
            if c.last_trade_block != *t0 {
                return Err(format!(
                    "R2 launch {id}: compound moved last_trade_block {t0} → {}",
                    c.last_trade_block
                ));
            }
        }
        // Token conservation: every unit is somewhere we can name.
        let supply = Assets::total_supply(asset);
        let named: u128 = named_accounts().iter().map(|a| Assets::balance(asset, a)).sum();
        if named != supply {
            return Err(format!("launch {id}: {} token units are in an account nobody names (supply {supply}, named {named})", supply.abs_diff(named)));
        }
    }

    // DEX, per pool.
    for (pair, pool) in Pools::<Test>::iter() {
        let (ba, bb) = (
            Assets::balance_of_kind(&pair.0, &pool.pool_account),
            Assets::balance_of_kind(&pair.1, &pool.pool_account),
        );
        if ba < pool.reserve_a || bb < pool.reserve_b {
            return Err(format!(
                "pool {pair:?}: balances ({ba}, {bb}) below stored reserves ({}, {})",
                pool.reserve_a, pool.reserve_b
            ));
        }
        let total = TotalLiquidity::<Test>::get(&pair).unwrap_or(0);
        if total > 0 {
            let positions: u128 = LiquidityPositions::<Test>::iter()
                .filter(|(_, p, _)| *p == pair)
                .map(|(_, _, pos)| pos.shares)
                .sum();
            if positions + MINIMUM_LIQUIDITY as u128 != total {
                return Err(format!("pool {pair:?}: Σ positions {positions} + {MINIMUM_LIQUIDITY} ≠ TotalLiquidity {total}"));
            }
        }
    }
    if !matches!(op, Op::RemoveLiquidity { .. }) {
        for (id, k0) in &before.pool_k {
            let k1 = pool_k(*id);
            if k1 < *k0 {
                return Err(format!("pool of launch {id}: k fell from {k0} to {k1} on {op:?}"));
            }
        }
    }

    // VTRS conservation across the three pallets.
    let issuance = Balances::total_issuance();
    let named: u128 = named_accounts()
        .iter()
        .map(<Balances as frame_support::traits::Currency<Acc>>::total_balance)
        .sum();
    if named != issuance {
        return Err(format!(
            "{} VTRS-wei are in an account nobody names (issuance {issuance}, named {named})",
            issuance.abs_diff(named)
        ));
    }
    Ok(())
}

trait BalanceOfKind {
    fn balance_of_kind(kind: &NativeOrAssetId, who: &Acc) -> u128;
}
impl BalanceOfKind for Assets {
    fn balance_of_kind(kind: &NativeOrAssetId, who: &Acc) -> u128 {
        match kind {
            NativeOrAssetId::Native => free(who),
            NativeOrAssetId::WithId(id) => Assets::balance(*id, who),
        }
    }
}

fn summary() -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "block {} · era {} · vault: free {} ledger.active {} LNRG {} accounted {} shares {}\n",
        System::block_number(),
        MockStaking::current_era(),
        free(&vault()),
        MockStaking::active(&vault()),
        Assets::balance(LNRG_ID, vault()),
        LnrgAccounted::<Test>::get(),
        TotalShares::<Test>::get()
    ));
    for id in 0..NextLaunchId::<Test>::get() {
        if let Some(c) = Curves::<Test>::get(id) {
            s.push_str(&format!(
                "launch {id}: {:?} real_quote {} remaining {} creator_fees {} last_trade {}",
                c.phase,
                c.real_quote,
                c.tokens_remaining,
                c.creator_fees_unclaimed,
                c.last_trade_block
            ));
            if let Some(t) = Treasuries::<Test>::get(id) {
                s.push_str(&format!(
                    " · treasury {:?} pending {} shares {} accrued {} pending_burn {}",
                    t.status, t.pending, t.shares, t.lnrg_accrued, t.pending_burn
                ));
            }
            if c.phase == Phase::Graduated {
                let a = pool_account(id);
                s.push_str(&format!(
                    " · pool VTRS {} tokens {}",
                    free(&a),
                    Assets::balance(asset_of(id), &a)
                ));
            }
            s.push('\n');
        }
    }
    s.push_str(&format!(
        "broker {} · users {:?}\n",
        free(&BROKER),
        USERS.iter().map(free).collect::<Vec<_>>()
    ));
    s
}

/// Run a sequence; on the first violation, describe it with the op index.
fn run_sequence(ops: &[Op]) -> Result<(), String> {
    let _ = <Assets as FungiblesMutate<Acc>>::burn_from(
        LNRG_ID,
        &vault(),
        0,
        Preservation::Expendable,
        Precision::BestEffort,
        Fortitude::Polite,
    );
    for (i, op) in ops.iter().enumerate() {
        let before = snapshot();
        if let Some(Err(e)) = run(op) {
            if !expected(op, &e) {
                return Err(format!("step {}: {op:?} → unexpected {e:?}\n{}", i + 1, summary()));
            }
        }
        check_all(op, &before)
            .map_err(|why| format!("step {}: after {op:?}: {why}\n{}", i + 1, summary()))?;
    }
    Ok(())
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(32)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), max_shrink_iters: 4096, .. ProptestConfig::default() })]

    /// Arbitrary call sequences against every invariant, from the upgrade
    /// path's state (the vault holds its ED, `VaultFunded` is set).
    #[test]
    fn fuzz_upgrade_path(ops in prop::collection::vec(op(), 1..=100)) {
        let r = new_test_ext().execute_with(|| run_sequence(&ops));
        prop_assert!(r.is_ok(), "\n{}\nsequence:\n{}", r.unwrap_err(), ops.iter().enumerate().map(|(i, o)| format!("  {}. {o:?}", i + 1)).collect::<Vec<_>>().join("\n"));
    }

    /// The same, from genesis (§9.6: nothing funds the vault, the first fee does).
    #[test]
    fn fuzz_from_genesis(ops in prop::collection::vec(op(), 1..=100)) {
        let r = new_test_ext_from_genesis().execute_with(|| run_sequence(&ops));
        prop_assert!(r.is_ok(), "\n{}\nsequence:\n{}", r.unwrap_err(), ops.iter().enumerate().map(|(i, o)| format!("  {}. {o:?}", i + 1)).collect::<Vec<_>>().join("\n"));
    }
}

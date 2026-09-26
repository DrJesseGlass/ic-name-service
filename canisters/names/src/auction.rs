//! Sealed-bid auctions for free flat names (DESIGN.md section 5).
//!
//! A flat name nobody holds (never taken, released, or lapsed past its
//! grace period) goes to a Vickrey auction rather than to whoever calls
//! first. The first commitment on a free name opens the auction: bidders
//! commit sha256(domain, bidder, amount, salt) with an escrowed deposit,
//! reveal amount and salt in the reveal phase, and anyone may close the
//! auction once that is over. No timers: an ended auction waits until
//! someone closes it, or until the next bid on the name closes it first.
//!
//! The winner pays the second-highest revealed bid (or the reserve) and
//! holds the name under the Harberger tax, assessed at their own bid. So a
//! reveal must leave room in the deposit for one grace period of tax at
//! the bid, which becomes the name's opening balance; the rest of the
//! winner's deposit is credited back. Losers are credited their deposits.
//! The price and any forfeited deposit (an unrevealed commitment) go to
//! the treasury.
//!
//! The rules are in the ic-auction crate (ic_auction::vickrey); this
//! module holds what is this canister's: the stored config, the running
//! auctions with the target each revealed bid names, and turning an
//! outcome into credits and a record.

use crate::harberger::{self, Config as HarbergerConfig, Status, MAX_PRICE};
use crate::store::{self, Harberger, Memory, Record, Target};
use candid::{CandidType, Decode, Encode, Principal};
use ic_auction::vickrey::{self, Auction, Params, Phase};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{StableBTreeMap, Storable};
use serde::Deserialize;
use std::borrow::Cow;
use std::cell::RefCell;

const CONFIG_KEY: &str = "auction";
const PROCEEDS_KEY: &str = "auction_proceeds";

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Length of the commit phase, from the first commitment.
    pub commit_ns: u64,
    /// Length of the reveal phase after it.
    pub reveal_ns: u64,
    /// The least a winner pays, cycles. The Harberger min_price applies
    /// too: an auction opens with the larger of the two.
    pub reserve: u128,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            commit_ns: 3 * 24 * 60 * 60 * 1_000_000_000,
            reveal_ns: 2 * 24 * 60 * 60 * 1_000_000_000,
            reserve: 0,
        }
    }
}

/// The stored config, or the default when none was ever set.
pub fn config() -> Config {
    match store::meta_get(CONFIG_KEY) {
        None => Config::default(),
        Some(b) => candid::decode_one::<Config>(&b).expect("decode auction config"),
    }
}

/// Applies to auctions opened from here on; a running auction keeps the
/// phases and reserve it opened with.
pub fn set_config(c: Config) -> Result<(), String> {
    if c.commit_ns == 0 || c.reveal_ns == 0 {
        return Err("commit_ns and reveal_ns must be positive".to_string());
    }
    if c.reserve > MAX_PRICE {
        return Err(format!("reserve above the maximum price of {MAX_PRICE}"));
    }
    store::meta_set(
        CONFIG_KEY,
        candid::encode_one(&c).map_err(|e| e.to_string())?,
    );
    Ok(())
}

/// The reserve a new auction opens with.
fn reserve(cfg: &HarbergerConfig, a: &Config) -> u128 {
    a.reserve.max(cfg.min_price)
}

/// One auction, as stored.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Running {
    pub auction: Auction,
    /// The scoped name each revealed bidder wants the flat name to alias,
    /// keyed by the bidder's principal bytes.
    pub targets: Vec<(Vec<u8>, String)>,
}

impl Storable for Running {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).expect("encode Running"))
    }
    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).expect("encode Running")
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Running).expect("decode Running")
    }
    const BOUND: Bound = Bound::Unbounded;
}

thread_local! {
    /// flat name -> its auction, from the first commitment until closed.
    static AUCTIONS: RefCell<StableBTreeMap<String, Running, Memory>> =
        RefCell::new(StableBTreeMap::init(store::memory(store::MEM_AUCTIONS)));
}

fn get(name: &str) -> Option<Running> {
    AUCTIONS.with(|a| a.borrow().get(&name.to_string()))
}

fn put(name: &str, r: Running) {
    AUCTIONS.with(|a| {
        a.borrow_mut().insert(name.to_string(), r);
    });
}

fn remove(name: &str) {
    AUCTIONS.with(|a| {
        a.borrow_mut().remove(&name.to_string());
    });
}

/// Deposits escrowed in auctions not yet closed, cycles. A ledger change
/// would strand them.
pub fn escrowed() -> u128 {
    AUCTIONS.with(|a| {
        a.borrow().iter().fold(0u128, |acc, e| {
            e.value()
                .auction
                .bids
                .iter()
                .fold(acc, |acc, b| acc.saturating_add(b.deposit))
        })
    })
}

/// Auction prices and forfeited deposits so far. Also counted in the
/// treasury's collected total, which fund_self spends against.
pub fn proceeds() -> u128 {
    store::meta_get_u128(PROCEEDS_KEY)
}

fn note_proceeds(amount: u128) {
    if amount > 0 {
        store::meta_set_u128(PROCEEDS_KEY, proceeds().saturating_add(amount));
        harberger::note_tax_collected(amount);
    }
}

/// Who holds `name` at `now`, if anyone. A lapsed record is held by no one.
fn holder(cfg: &HarbergerConfig, name: &str, now: u64) -> Option<Principal> {
    let mut r = store::get_record(name)?;
    let (status, _) = harberger::settle_record(cfg, &mut r, now);
    (status != Status::Free).then_some(r.owner)
}

/// Would a commitment with `deposit` be accepted at `now`? Changes
/// nothing, so the bid endpoint can ask before it pulls the deposit.
pub fn check_bid(cfg: &HarbergerConfig, name: &str, deposit: u128, now: u64) -> Result<(), String> {
    let reserve = match get(name) {
        Some(r) => match r.auction.phase(now) {
            Phase::Commit => r.auction.params.reserve,
            Phase::Reveal => {
                return Err(format!(
                    "bidding on '{name}' is over; its reveal phase runs until {}",
                    r.auction.reveal_until_ns()
                ))
            }
            // Ended: a winner takes the name at close; otherwise the
            // close refunds and a new auction opens with this bid.
            Phase::Closed => {
                if r.auction.outcome(now)?.winner.is_some() {
                    return Err(format!(
                        "the auction for '{name}' has a winner; close_auction hands the name over"
                    ));
                }
                reserve(cfg, &config())
            }
        },
        None => {
            if let Some(owner) = holder(cfg, name, now) {
                return Err(format!("'{name}' is owned by {}", owner.to_text()));
            }
            reserve(cfg, &config())
        }
    };
    if deposit < reserve {
        return Err(format!(
            "deposit must be at least the reserve of {reserve} cycles"
        ));
    }
    Ok(())
}

/// Record a commitment whose deposit has been pulled. Opens an auction
/// when none is running, closing an ended one first. Returns the deposit
/// of the bidder's replaced earlier commitment, for the caller to credit
/// back. On Err nothing about this bid was stored and the caller credits
/// the deposit back.
pub fn place_bid(
    cfg: &HarbergerConfig,
    name: &str,
    bidder: Principal,
    commitment: [u8; 32],
    deposit: u128,
    now: u64,
) -> Result<Option<u128>, String> {
    if get(name).is_some_and(|r| r.auction.phase(now) == Phase::Closed) {
        close(cfg, name, now)?;
    }
    check_bid(cfg, name, deposit, now)?;
    let mut r = get(name).unwrap_or_else(|| {
        let a = config();
        Running {
            auction: Auction::open(
                Params {
                    commit_ns: a.commit_ns,
                    reveal_ns: a.reveal_ns,
                    reserve: reserve(cfg, &a),
                },
                now,
            ),
            targets: Vec::new(),
        }
    });
    let replaced = r
        .auction
        .commit(now, bidder.as_slice().to_vec(), commitment, deposit)?;
    put(name, r);
    Ok(replaced)
}

/// Open the caller's commitment. `alias_to` is where the name points if
/// this bid wins; the caller has checked it is a scoped name.
pub fn reveal(
    cfg: &HarbergerConfig,
    name: &str,
    bidder: Principal,
    amount: u128,
    salt: &[u8],
    alias_to: String,
    now: u64,
) -> Result<(), String> {
    let mut r = get(name).ok_or_else(|| format!("no auction for '{name}'"))?;
    let b = bidder.as_slice();
    let mut auction = r.auction.clone();
    auction.reveal(now, b, amount, salt)?;
    // The bid becomes the assessed price, so it must fit the tax's range
    // and leave one grace period of tax in the deposit.
    if amount > MAX_PRICE {
        return Err(format!("bid above the maximum price of {MAX_PRICE} cycles"));
    }
    let deposit = auction
        .bids
        .iter()
        .find(|x| x.bidder == b)
        .map(|x| x.deposit)
        .unwrap_or(0);
    let need = amount.saturating_add(harberger::min_deposit(cfg, amount));
    if deposit < need {
        return Err(format!(
            "the deposit of {deposit} cycles must cover the bid plus one grace period of tax at it: {need}"
        ));
    }
    r.auction = auction;
    r.targets.retain(|(x, _)| x != b);
    r.targets.push((b.to_vec(), alias_to));
    put(name, r);
    Ok(())
}

/// What closing an auction did.
#[derive(CandidType, Clone, Debug, PartialEq, Eq)]
pub struct Closed {
    /// The new holder, or None when no revealed bid met the reserve.
    pub winner: Option<Principal>,
    /// What the winner paid, cycles; 0 when nobody won.
    pub price: u128,
    /// The winner's assessed price from here on: their own bid.
    pub assessed: u128,
    /// Kept from unrevealed commitments.
    pub forfeited: u128,
}

/// Close an ended auction: credit every refund, hand the name to the
/// winner, and send the price and forfeits to the treasury.
pub fn close(cfg: &HarbergerConfig, name: &str, now: u64) -> Result<Closed, String> {
    let r = get(name).ok_or_else(|| format!("no auction for '{name}'"))?;
    let outcome = r.auction.outcome(now)?;

    // Nothing else gives a free name a holder while its auction runs, but
    // if something did, nobody wins and the would-be winner is refunded
    // in full.
    let mut lapsed: Option<(Record, u128)> = None;
    let mut free = true;
    if let Some(mut rec) = store::get_record(name) {
        let (status, tax) = harberger::settle_record(cfg, &mut rec, now);
        if status == Status::Free {
            lapsed = Some((rec, tax));
        } else {
            free = false;
        }
    }
    let winner = outcome.winner.clone().filter(|_| free);
    let price = if winner.is_some() { outcome.price } else { 0 };

    // Work out the winner's holding before anything is written.
    let holding = match &winner {
        None => None,
        Some(w) => {
            let bid = r
                .auction
                .bids
                .iter()
                .find(|b| &b.bidder == w)
                .and_then(|b| b.revealed)
                .ok_or("winner has no revealed bid")?;
            let alias = r
                .targets
                .iter()
                .find(|(b, _)| b == w)
                .map(|(_, t)| t.clone())
                .ok_or("winner revealed no target")?;
            let assessed = bid.clamp(cfg.min_price, MAX_PRICE);
            Some((Principal::from_slice(w), alias, assessed))
        }
    };

    let mut forfeited = 0u128;
    let mut opening_balance = 0u128;
    for s in &outcome.settlements {
        let who = Principal::from_slice(&s.bidder);
        forfeited = forfeited.saturating_add(s.forfeited);
        let refund = if Some(&s.bidder) == winner.as_ref() {
            // Keep one grace period of tax as the opening balance.
            let assessed = holding.as_ref().map(|h| h.2).unwrap_or(0);
            opening_balance = s.refund.min(harberger::min_deposit(cfg, assessed));
            s.refund - opening_balance
        } else if Some(&s.bidder) == outcome.winner.as_ref() {
            // A voided win: the price was never charged.
            s.refund.saturating_add(outcome.price)
        } else {
            s.refund
        };
        store::add_credit(&who, refund);
    }

    let mut assessed = 0;
    if let Some((owner, alias, a)) = holding {
        assessed = a;
        let target = Target::Alias(alias);
        let (mut rec, tax) = match lapsed {
            Some((old, tax)) => (
                Record {
                    owner,
                    previous_target: Some(old.target.clone()),
                    target,
                    text: Vec::new(),
                    updated_ns: now,
                    changed_hands_ns: now,
                    ..old
                },
                tax,
            ),
            None => (Record::new(name.to_string(), owner, target, now), 0),
        };
        rec.flat = Some(Harberger::new(assessed, opening_balance, now));
        crate::commit_flat(rec, tax);
    }
    note_proceeds(price.saturating_add(forfeited));
    remove(name);
    Ok(Closed {
        winner: winner.map(|b| Principal::from_slice(&b)),
        price,
        assessed,
        forfeited,
    })
}

/// An auction as bidders and tooling see it. Amounts stay sealed until
/// the auction has ended.
#[derive(CandidType, Clone, Debug)]
pub struct View {
    pub name: String,
    pub phase: Phase,
    pub opened_ns: u64,
    pub commit_until_ns: u64,
    pub reveal_until_ns: u64,
    pub reserve: u128,
    /// Every committed bidder, in commitment order.
    pub bidders: Vec<Principal>,
    pub revealed: u32,
    /// Once ended: who close_auction will make the holder, and the price.
    pub winner: Option<Principal>,
    pub price: Option<u128>,
}

fn view(name: &str, r: &Running, now: u64) -> View {
    let a = &r.auction;
    let outcome = a.outcome(now).ok();
    View {
        name: name.to_string(),
        phase: a.phase(now),
        opened_ns: a.opened_ns,
        commit_until_ns: a.commit_until_ns(),
        reveal_until_ns: a.reveal_until_ns(),
        reserve: a.params.reserve,
        bidders: a
            .bids
            .iter()
            .map(|b| Principal::from_slice(&b.bidder))
            .collect(),
        revealed: a.bids.iter().filter(|b| b.revealed.is_some()).count() as u32,
        winner: outcome
            .as_ref()
            .and_then(|o| o.winner.as_ref())
            .map(|b| Principal::from_slice(b)),
        price: outcome.filter(|o| o.winner.is_some()).map(|o| o.price),
    }
}

pub fn status(name: &str, now: u64) -> Option<View> {
    get(name).map(|r| view(name, &r, now))
}

/// Every auction not yet closed, in name order.
pub fn list(now: u64) -> Vec<View> {
    AUCTIONS.with(|a| {
        a.borrow()
            .iter()
            .map(|e| view(e.key(), &e.value(), now))
            .collect()
    })
}

/// The commitment for a bid, as the canister checks it.
pub fn commitment(bidder: Principal, amount: u128, salt: &[u8]) -> [u8; 32] {
    vickrey::commitment(bidder.as_slice(), amount, salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;
    const T: u128 = 1_000_000_000_000;

    fn cfg() -> HarbergerConfig {
        HarbergerConfig {
            rate_bps: 10_000,
            min_price: T,
            grace_ns: 10 * S,
            ..HarbergerConfig::default()
        }
    }

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n; 10])
    }

    fn setup() {
        set_config(Config {
            commit_ns: 100 * S,
            reveal_ns: 100 * S,
            reserve: 0,
        })
        .unwrap();
    }

    fn commit(name: &str, who: Principal, amount: u128, deposit: u128, now: u64) {
        let c = commitment(who, amount, b"salt");
        assert_eq!(place_bid(&cfg(), name, who, c, deposit, now).unwrap(), None);
    }

    #[test]
    fn running_round_trips_through_stable_memory() {
        let mut a = Auction::open(
            Params {
                commit_ns: 1,
                reveal_ns: 2,
                reserve: 3,
            },
            4,
        );
        a.commit(4, vec![1, 2], [7; 32], 5).unwrap();
        let r = Running {
            auction: a,
            targets: vec![(vec![1, 2], "alice/app".into())],
        };
        assert_eq!(
            Running::from_bytes(Cow::Owned(r.to_bytes().into_owned())),
            r
        );
    }

    #[test]
    fn second_price_wins_and_the_rest_is_credited() {
        setup();
        let c = cfg();
        let (a, b, x) = (p(1), p(2), p(3));
        commit("vick", a, 50 * T, 60 * T, 0);
        commit("vick", b, 30 * T, 40 * T, 10 * S);
        commit("vick", x, 90 * T, 90 * T, 20 * S);
        // Too late to commit, too early to close.
        assert!(check_bid(&c, "vick", 90 * T, 150 * S).is_err());
        assert!(close(&c, "vick", 150 * S).is_err());
        reveal(&c, "vick", a, 50 * T, b"salt", "alice/app".into(), 150 * S).unwrap();
        reveal(&c, "vick", b, 30 * T, b"salt", "bob/app".into(), 150 * S).unwrap();
        // x never reveals.
        let collected = harberger::tax_collected();
        let v = status("vick", 200 * S).unwrap();
        assert_eq!((v.winner, v.price), (Some(a), Some(30 * T)));
        let out = close(&c, "vick", 200 * S).unwrap();
        assert_eq!(
            out,
            Closed {
                winner: Some(a),
                price: 30 * T,
                assessed: 50 * T,
                forfeited: 90 * T
            }
        );
        let r = store::get_record("vick").unwrap();
        assert_eq!(r.owner, a);
        assert_eq!(r.target, Target::Alias("alice/app".into()));
        let h = r.flat.unwrap();
        assert_eq!(h.price, 50 * T);
        assert_eq!(h.balance, harberger::min_deposit(&c, 50 * T));
        assert_eq!(store::credit_of(&a), 60 * T - 30 * T - h.balance);
        assert_eq!(store::credit_of(&b), 40 * T);
        assert_eq!(store::credit_of(&x), 0);
        assert_eq!(harberger::tax_collected(), collected + 30 * T + 90 * T);
        assert!(status("vick", 200 * S).is_none());
        assert_eq!(escrowed(), 0);
        // Held now: no new auction.
        assert!(check_bid(&c, "vick", 90 * T, 201 * S)
            .unwrap_err()
            .contains("owned by"));
    }

    #[test]
    fn a_reveal_must_leave_a_grace_period_of_tax() {
        setup();
        let c = cfg();
        let a = p(1);
        commit("tight", a, 50 * T, 50 * T, 0);
        let err = reveal(&c, "tight", a, 50 * T, b"salt", "alice/app".into(), 150 * S).unwrap_err();
        assert!(err.contains("grace period"), "{err}");
        // Still unrevealed, so it forfeits.
        assert_eq!(close(&c, "tight", 200 * S).unwrap().forfeited, 50 * T);
    }

    #[test]
    fn deposit_below_the_reserve_is_refused_before_pulling() {
        setup();
        let c = cfg();
        assert!(check_bid(&c, "cheap", T - 1, 0)
            .unwrap_err()
            .contains("reserve"));
        assert!(check_bid(&c, "cheap", T, 0).is_ok());
    }

    #[test]
    fn an_unwon_auction_is_closed_by_the_next_bid() {
        setup();
        let c = cfg();
        let (a, b) = (p(1), p(2));
        commit("again", a, 5 * T, 20 * T, 0);
        // a never reveals; after the reveal phase b's bid closes the old
        // auction (a forfeits) and opens a new one.
        assert!(check_bid(&c, "again", 20 * T, 150 * S).is_err());
        commit("again", b, 5 * T, 20 * T, 250 * S);
        let v = status("again", 250 * S).unwrap();
        assert_eq!(v.opened_ns, 250 * S);
        assert_eq!(v.bidders, vec![b]);
        assert_eq!(store::credit_of(&a), 0);
        assert_eq!(escrowed(), 20 * T);
    }

    #[test]
    fn a_lapsed_name_goes_to_the_winner_and_remembers_its_target() {
        setup();
        let c = cfg();
        let old = p(9);
        let mut r = Record::new("gone".into(), old, Target::Alias("old/app".into()), 0);
        r.text.push(("description".into(), "old".into()));
        r.flat = Some(Harberger::new(1_000 * T, 0, 0));
        store::put_record(r);
        // Spent at once, free after grace.
        assert!(check_bid(&c, "gone", 2 * T, 5 * S)
            .unwrap_err()
            .contains("owned by"));
        let a = p(1);
        commit("gone", a, 2 * T, 10 * T, 20 * S);
        reveal(&c, "gone", a, 2 * T, b"salt", "alice/app".into(), 150 * S).unwrap();
        let out = close(&c, "gone", 300 * S).unwrap();
        assert_eq!((out.winner, out.price), (Some(a), T));
        let r = store::get_record("gone").unwrap();
        assert_eq!(r.owner, a);
        assert_eq!(r.previous_target, Some(Target::Alias("old/app".into())));
        assert!(r.text.is_empty());
        assert_eq!(r.changed_hands_ns, 300 * S);
        assert_eq!(r.created_ns, 0);
    }

    #[test]
    fn nobody_at_the_reserve_means_nobody_wins() {
        setup();
        let c = cfg();
        let a = p(1);
        commit("low", a, 500, 5 * T, 0);
        reveal(&c, "low", a, 500, b"salt", "alice/app".into(), 150 * S).unwrap();
        let out = close(&c, "low", 200 * S).unwrap();
        assert_eq!(out.winner, None);
        assert!(store::get_record("low").is_none());
        assert_eq!(store::credit_of(&a), 5 * T);
    }

    #[test]
    fn config_checks() {
        assert_eq!(config(), Config::default());
        let mut c = Config {
            commit_ns: 0,
            ..Config::default()
        };
        assert!(set_config(c.clone()).is_err());
        c.commit_ns = 1;
        c.reserve = MAX_PRICE + 1;
        assert!(set_config(c).is_err());
    }
}

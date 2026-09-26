//! Harberger tax on flat names (DESIGN.md section 5).
//!
//! The owner of a flat name self-assesses a price P and prepays a balance.
//! Tax accrues on P at `rate_bps` per year and is settled lazily: on every
//! read or write, the tax due since `settled_ns` comes off the balance.
//! When the balance runs out the name is in a grace period, and after
//! `grace_ns` it is free to claim. Anyone may buy the name at P at any
//! time; the seller gets P plus the unspent balance as a credit.
//!
//! The arithmetic and rules live in the ic-auction crate
//! (ic_auction::harberger); this module holds what is this canister's:
//! the stored config (ledger, fee, market flag, warning window, plus the
//! crate's Params), the tax counters, and the unreconciled ledger
//! amounts. The functions below are thin wrappers so the endpoints read
//! the same as before the extraction.

use crate::store::{self, Harberger, Record};
use candid::{CandidType, Principal};
use ic_auction::harberger::Params;
pub use ic_auction::harberger::{Status, MAX_PRICE};
use serde::Deserialize;

const CONFIG_KEY: &str = "harberger";
const TAX_COLLECTED_KEY: &str = "tax_collected";
const TAX_WITHDRAWN_KEY: &str = "tax_withdrawn";

/// The mainnet cycles ledger.
pub const CYCLES_LEDGER: &str = "um5iw-rqaaa-aaaaq-qaaba-cai";

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The cycles ledger (ICRC-2). Mainnet's by default; a local replica
    /// installs the same id.
    pub ledger: Principal,
    /// Tax per year on the assessed price, in basis points.
    pub rate_bps: u32,
    /// Lowest price anyone may assess, cycles.
    pub min_price: u128,
    /// How long a name with no balance stays with its owner.
    pub grace_ns: u64,
    /// The ledger's transfer fee, cycles, as it answered icrc1_fee when the
    /// config was set. Pinned on every transfer so a changed fee fails the
    /// transfer instead of quietly over-debiting this canister's account.
    pub fee: u128,
    /// Whether new flat names may be claimed. Closed by default, so a
    /// release can ship scoped names alone and open the market later.
    /// Buying a held name is never gated, and holders can always top up,
    /// reassess, withdraw and release.
    pub flat_names_open: bool,
    /// How long after a flat name changes hands the gateway interposes a
    /// warning page instead of redirecting.
    pub handover_warn_ns: u64,
}

impl Config {
    /// The crate's view of this config: the three numbers the tax needs.
    pub fn params(&self) -> Params {
        Params {
            rate_bps: self.rate_bps,
            min_price: self.min_price,
            grace_ns: self.grace_ns,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ledger: Principal::from_text(CYCLES_LEDGER).expect("ledger id"),
            rate_bps: 700,
            min_price: 100_000_000_000,
            grace_ns: 30 * 24 * 60 * 60 * 1_000_000_000,
            fee: 100_000_000,
            flat_names_open: false,
            handover_warn_ns: 30 * 24 * 60 * 60 * 1_000_000_000,
        }
    }
}

/// The stored config, or the default when none was ever set. A stored
/// blob that does not decode is a bug (a schema change without its
/// migration in post_upgrade), not a reason to run on defaults: the
/// ledger, rate and pinned fee would change silently.
pub fn config() -> Config {
    match store::meta_get(CONFIG_KEY) {
        None => Config::default(),
        Some(b) => candid::decode_one::<Config>(&b).expect("decode harberger config"),
    }
}

/// The config as schema 2 (M2) wrote it: no market flag, no handover
/// window. Kept only to migrate it.
#[derive(CandidType, Deserialize)]
struct ConfigV2 {
    ledger: Principal,
    rate_bps: u32,
    min_price: u128,
    grace_ns: u64,
    fee: u128,
}

/// Rewrite a schema 2 config in the current shape. The M2 market had no
/// gate, so it stays open: an upgrade must not change who may buy a name
/// that is already held. Runs from post_upgrade; a no-op when nothing is
/// stored or it already decodes.
pub fn migrate_config_from_v2() {
    let Some(b) = store::meta_get(CONFIG_KEY) else {
        return;
    };
    if candid::decode_one::<Config>(&b).is_ok() {
        return;
    }
    let old: ConfigV2 = candid::decode_one(&b).expect("decode schema 2 harberger config");
    let c = Config {
        ledger: old.ledger,
        rate_bps: old.rate_bps,
        min_price: old.min_price,
        grace_ns: old.grace_ns,
        fee: old.fee,
        // Closed, like a fresh deploy: the flag only stops new claims, so
        // names held at upgrade time stay buyable and taxed as before.
        flat_names_open: false,
        ..Config::default()
    };
    store::meta_set(CONFIG_KEY, candid::encode_one(&c).expect("encode Config"));
}

pub fn set_config(c: Config) -> Result<(), String> {
    c.params().check()?;
    store::meta_set(
        CONFIG_KEY,
        candid::encode_one(&c).map_err(|e| e.to_string())?,
    );
    Ok(())
}

pub fn tax_per_year(cfg: &Config, price: u128) -> u128 {
    cfg.params().tax_per_year(price)
}

pub fn ns_until_spent(cfg: &Config, price: u128, balance: u128) -> Option<u64> {
    cfg.params().ns_until_spent(price, balance)
}

/// The smallest deposit accepted when claiming or buying: the tax for one
/// grace period, so a name is never held on credit.
pub fn min_deposit(cfg: &Config, price: u128) -> u128 {
    cfg.params().min_deposit(price)
}

/// Settle tax up to `now` in place. Returns the status and the tax taken.
pub fn settle(cfg: &Config, h: &mut Harberger, now: u64) -> (Status, u128) {
    h.settle(&cfg.params(), now)
}

/// Add `amount` to the prepaid balance, settling to `now` first. Returns
/// the tax that settle took, for `note_tax_collected` on commit. Refuses a
/// free holding, and one the top-up would leave below a grace period of tax.
pub fn top_up(cfg: &Config, h: &mut Harberger, amount: u128, now: u64) -> Result<u128, String> {
    h.top_up(&cfg.params(), amount, now)
}

/// Settle a flat record in place. Returns the status and the tax taken,
/// which the caller reports with `note_tax_collected` when, and only
/// when, it commits the settled record: the counter must track what the
/// stored balances have actually given up. A record that is not flat is
/// Active and owes nothing.
pub fn settle_record(cfg: &Config, r: &mut Record, now: u64) -> (Status, u128) {
    match r.flat.as_mut() {
        None => (Status::Active, 0),
        Some(h) => settle(cfg, h, now),
    }
}

/// Add tax that a committed settlement took to the treasury counter.
pub fn note_tax_collected(taken: u128) {
    if taken > 0 {
        store::meta_set_u128(TAX_COLLECTED_KEY, tax_collected().saturating_add(taken));
    }
}

pub fn tax_collected() -> u128 {
    store::meta_get_u128(TAX_COLLECTED_KEY)
}

pub fn tax_withdrawn() -> u128 {
    store::meta_get_u128(TAX_WITHDRAWN_KEY)
}

pub fn note_tax_withdrawn(amount: u128) {
    store::meta_set_u128(TAX_WITHDRAWN_KEY, tax_withdrawn().saturating_add(amount));
}

/// A withdrawal that the ledger refused after it was noted.
pub fn undo_tax_withdrawn(amount: u128) {
    store::meta_set_u128(TAX_WITHDRAWN_KEY, tax_withdrawn().saturating_sub(amount));
}

const UNRECONCILED_KEY: &str = "unreconciled";
const UNRECONCILED_LAST_KEY: &str = "unreconciled_last";

/// Cycles whose movement this canister could not confirm (ledger.rs,
/// Failure::Undecodable), for the operator to reconcile against the
/// ledger's blocks. Never spent against.
pub fn unreconciled() -> (u128, String) {
    let last = store::meta_get(UNRECONCILED_LAST_KEY)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    (store::meta_get_u128(UNRECONCILED_KEY), last)
}

pub fn note_unreconciled(amount: u128, what: &str) {
    store::meta_set_u128(UNRECONCILED_KEY, unreconciled().0.saturating_add(amount));
    store::meta_set(UNRECONCILED_LAST_KEY, what.as_bytes().to_vec());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trip() {
        assert_eq!(config(), Config::default());
        let mut c = Config {
            rate_bps: 500,
            ..Config::default()
        };
        set_config(c.clone()).unwrap();
        assert_eq!(config(), c);
        c.rate_bps = 20_000;
        assert!(set_config(c.clone()).is_err());
        c.rate_bps = 500;
        c.grace_ns = 0;
        assert!(set_config(c.clone()).is_err());
        c.grace_ns = 1;
        c.min_price = MAX_PRICE + 1;
        assert!(set_config(c).is_err());
    }

    #[test]
    fn tax_is_counted_only_when_noted() {
        let c = Config {
            grace_ns: 10 * 1_000_000_000,
            ..Config::default()
        };
        let mut r = Record::new(
            "ic-git".into(),
            candid::Principal::anonymous(),
            crate::store::Target::Alias("alice/ic-git".into()),
            0,
        );
        r.flat = Some(Harberger::new(1_000_000_000_000, 1_000_000_000_000, 0));
        let before = tax_collected();
        let (_, taken) = settle_record(&c, &mut r.clone(), ic_auction::harberger::YEAR_NS as u64);
        assert_eq!(taken, tax_per_year(&c, 1_000_000_000_000));
        assert_eq!(tax_collected(), before);
        note_tax_collected(taken);
        assert_eq!(tax_collected(), before + taken);
    }

    #[test]
    fn schema_2_config_migrates_with_its_values_kept() {
        let old = ConfigV2 {
            ledger: candid::Principal::anonymous(),
            rate_bps: 123,
            min_price: 7,
            grace_ns: 9,
            fee: 5,
        };
        store::meta_set(CONFIG_KEY, candid::encode_one(&old).unwrap());
        assert!(candid::decode_one::<Config>(&store::meta_get(CONFIG_KEY).unwrap()).is_err());
        migrate_config_from_v2();
        let c = config();
        assert_eq!(c.ledger, candid::Principal::anonymous());
        assert_eq!(c.rate_bps, 123);
        assert_eq!(c.min_price, 7);
        assert_eq!(c.grace_ns, 9);
        assert_eq!(c.fee, 5);
        assert!(!c.flat_names_open);
        assert_eq!(c.handover_warn_ns, Config::default().handover_warn_ns);
        // Idempotent.
        migrate_config_from_v2();
        assert_eq!(config(), c);
    }
}

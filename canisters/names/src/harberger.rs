//! Harberger tax on flat names (DESIGN.md section 5).
//!
//! The owner of a flat name self-assesses a price P and prepays a balance.
//! Tax accrues on P at `rate_bps` per year and is settled lazily: on every
//! read or write, the tax due since `settled_ns` comes off the balance.
//! When the balance runs out the name is in a grace period, and after
//! `grace_ns` it is free to claim. Anyone may buy the name at P at any
//! time; the seller gets P plus the unspent balance as a credit.
//!
//! No timers, no per-name bookkeeping beyond three numbers. All the money
//! movement is in ledger.rs; this module is arithmetic and rules.

use crate::store::{self, Harberger, Record};
use candid::{CandidType, Principal};
use serde::Deserialize;

const YEAR_NS: u128 = 365 * 24 * 60 * 60 * 1_000_000_000;
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
    if c.rate_bps > 10_000 {
        return Err("rate_bps above 10000 (100% per year)".to_string());
    }
    if c.min_price > MAX_PRICE {
        return Err(format!("min_price above the maximum price of {MAX_PRICE}"));
    }
    if c.grace_ns == 0 {
        return Err("grace_ns is zero: every name would be free at once".to_string());
    }
    store::meta_set(
        CONFIG_KEY,
        candid::encode_one(&c).map_err(|e| e.to_string())?,
    );
    Ok(())
}

/// Prices above this are refused: 10^18 cycles, a million T cycles, far
/// beyond any name and small enough that the tax over any u64 interval
/// fits u128 with room to spare.
pub const MAX_PRICE: u128 = 1_000_000_000_000_000_000;

/// Tax on `price` over `elapsed_ns` at the configured rate. Computed as
/// the yearly tax first so the product stays small; saturates rather than
/// overflowing for inputs outside MAX_PRICE.
pub fn tax(cfg: &Config, price: u128, elapsed_ns: u64) -> u128 {
    tax_per_year(cfg, price)
        .checked_mul(elapsed_ns as u128)
        .map(|x| x / YEAR_NS)
        .unwrap_or(u128::MAX)
}

/// Nanoseconds until `balance` is spent on the tax on `price`, or None
/// when the tax rate is zero (never).
pub fn ns_until_spent(cfg: &Config, price: u128, balance: u128) -> Option<u64> {
    let per_year = tax_per_year(cfg, price);
    if per_year == 0 {
        return None;
    }
    let ns = balance.checked_mul(YEAR_NS)? / per_year;
    Some(ns.min(u64::MAX as u128) as u64)
}

/// Tax per year on `price`.
pub fn tax_per_year(cfg: &Config, price: u128) -> u128 {
    price.saturating_mul(cfg.rate_bps as u128) / 10_000
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Balance covers the tax so far.
    #[serde(rename = "active")]
    Active,
    /// Balance ran out; the owner keeps the name until `until_ns`.
    #[serde(rename = "grace")]
    Grace { until_ns: u64 },
    /// Grace over: anyone may claim the name.
    #[serde(rename = "free")]
    Free,
}

/// Settle tax up to `now` in place. Returns the status and the tax taken.
pub fn settle(cfg: &Config, h: &mut Harberger, now: u64) -> (Status, u128) {
    let mut taken = 0u128;
    if h.lapsed_ns.is_none() && now > h.settled_ns {
        let due = tax(cfg, h.price, now - h.settled_ns);
        if due <= h.balance {
            h.balance -= due;
            taken = due;
        } else {
            // Balance ran out somewhere in the interval; find when.
            let lapsed_at = match ns_until_spent(cfg, h.price, h.balance) {
                Some(ns) => h.settled_ns.saturating_add(ns).min(now),
                None => now,
            };
            taken = h.balance;
            h.balance = 0;
            h.lapsed_ns = Some(lapsed_at);
        }
        h.settled_ns = now;
    }
    let status = match h.lapsed_ns {
        None => Status::Active,
        Some(t) if now < t.saturating_add(cfg.grace_ns) => Status::Grace {
            until_ns: t.saturating_add(cfg.grace_ns),
        },
        Some(_) => Status::Free,
    };
    (status, taken)
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

/// The smallest deposit accepted when claiming or buying: the tax for one
/// grace period, so a name is never held on credit.
pub fn min_deposit(cfg: &Config, price: u128) -> u128 {
    tax(cfg, price, cfg.grace_ns)
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

    fn cfg() -> Config {
        Config {
            grace_ns: 10 * 1_000_000_000,
            ..Config::default()
        }
    }

    #[test]
    fn tax_math() {
        let c = cfg();
        // 7% of 1T over a year.
        assert_eq!(tax(&c, 1_000_000_000_000, YEAR_NS as u64), 70_000_000_000);
        assert_eq!(tax_per_year(&c, 1_000_000_000_000), 70_000_000_000);
        assert_eq!(tax(&c, 1_000_000_000_000, 0), 0);
        // The largest allowed price over the longest interval fits; a
        // silly price saturates instead of overflowing.
        assert!(tax(&c, MAX_PRICE, u64::MAX) < u128::MAX);
        assert_eq!(tax(&c, u128::MAX, u64::MAX), u128::MAX);
    }

    #[test]
    fn settles_lapses_and_frees() {
        let c = cfg();
        let price = 1_000_000_000_000u128;
        let per_year = tax_per_year(&c, price);
        let mut h = Harberger {
            price,
            balance: per_year,
            settled_ns: 0,
            lapsed_ns: None,
        };
        // Half a year: half the balance gone, still active.
        let half = YEAR_NS as u64 / 2;
        let (s, taken) = settle(&c, &mut h, half);
        assert_eq!(s, Status::Active);
        assert_eq!(taken, per_year / 2);
        assert_eq!(h.balance, per_year - per_year / 2);
        assert_eq!(h.settled_ns, half);
        // Five seconds past the year the balance is gone: lapsed at the
        // one year mark (to the nanosecond, up to integer division), and
        // in grace since grace is ten seconds.
        let year = YEAR_NS as u64;
        let (s, taken) = settle(&c, &mut h, year + 5_000_000_000);
        assert_eq!(
            s,
            Status::Grace {
                until_ns: h.lapsed_ns.unwrap() + c.grace_ns
            }
        );
        assert_eq!(taken, per_year - per_year / 2);
        assert_eq!(h.balance, 0);
        let lapsed = h.lapsed_ns.unwrap();
        assert!(
            lapsed >= year - 1_000 && lapsed <= year + 1_000,
            "lapsed {lapsed} vs {year}"
        );
        // Settling again inside grace takes nothing more.
        let (s, taken) = settle(&c, &mut h, lapsed + 5_000_000_000);
        assert!(matches!(s, Status::Grace { .. }));
        assert_eq!(taken, 0);
        // After the grace period the name is free.
        let (s, _) = settle(&c, &mut h, lapsed + c.grace_ns + 1);
        assert_eq!(s, Status::Free);
    }

    #[test]
    fn min_deposit_is_one_grace_period() {
        let c = cfg();
        assert_eq!(
            min_deposit(&c, 1_000_000_000_000),
            tax(&c, 1_000_000_000_000, c.grace_ns)
        );
    }

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
    fn schema_2_config_migrates_with_its_values_kept() {
        let old = ConfigV2 {
            ledger: Principal::from_text("aaaaa-aa").unwrap(),
            rate_bps: 500,
            min_price: 7,
            grace_ns: 9,
            fee: 11,
        };
        store::meta_set(CONFIG_KEY, candid::encode_one(&old).unwrap());
        // The old bytes do not decode as the current shape.
        assert!(candid::decode_one::<Config>(&store::meta_get(CONFIG_KEY).unwrap()).is_err());
        migrate_config_from_v2();
        let c = config();
        assert_eq!(c.ledger, old.ledger);
        assert_eq!(c.rate_bps, 500);
        assert_eq!(c.min_price, 7);
        assert_eq!(c.grace_ns, 9);
        assert_eq!(c.fee, 11);
        assert!(!c.flat_names_open);
        assert_eq!(c.handover_warn_ns, Config::default().handover_warn_ns);
        // Idempotent, and a current config is left alone.
        migrate_config_from_v2();
        assert_eq!(config(), c);
    }

    #[test]
    fn tax_is_counted_only_when_noted() {
        let c = cfg();
        let mut r = Record::new(
            "ic-git".into(),
            candid::Principal::anonymous(),
            crate::store::Target::Alias("alice/ic-git".into()),
            0,
        );
        r.flat = Some(Harberger {
            price: 1_000_000_000_000,
            balance: 1_000_000_000_000,
            settled_ns: 0,
            lapsed_ns: None,
        });
        let before = tax_collected();
        let (_, taken) = settle_record(&c, &mut r.clone(), YEAR_NS as u64);
        assert_eq!(taken, tax_per_year(&c, 1_000_000_000_000));
        assert_eq!(tax_collected(), before);
        note_tax_collected(taken);
        assert_eq!(tax_collected(), before + taken);
    }
}

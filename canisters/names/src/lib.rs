//! ic-name-service: resolver plus registry for canisters (DESIGN.md).
//!
//! State of play: milestones M0 to M2. Scoped names with address and
//! alias targets, text records, certified `resolve`, `announce` gated by
//! caller principal, the stage 1 HTTP gateway (path-based 302), the
//! directory (tags and search), and flat names under a Harberger tax paid
//! in cycles through the cycles ledger.

mod certify;
mod directory;
mod gateway;
mod harberger;
mod ledger;
mod names;
mod store;

use candid::{CandidType, Principal};
use directory::{SearchQuery, SearchResult, TagCount};
use harberger::{Config as HarbergerConfig, Status};
use store::{Handle, Harberger, Record, Target};

// --- lifecycle --------------------------------------------------------------

#[ic_cdk::init]
fn init() {
    store::set_schema_version(store::SCHEMA);
    certify::rebuild();
}

/// The certified tree is heap state and is rebuilt on every upgrade. The
/// tag index is stable memory kept in step on every write, so it is only
/// rebuilt when the schema version says the stored data predates it (an
/// M0 canister had tags text records and no index). A newer schema than
/// this code knows is refused rather than misread.
#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let from = store::schema_version();
    if from > store::SCHEMA {
        ic_cdk::trap(format!(
            "stable memory schema {from} is newer than this code's {}",
            store::SCHEMA
        ));
    }
    certify::rebuild();
    if from < 2 {
        directory::rebuild();
    }
    if from < 3 {
        harberger::migrate_config_from_v2();
    }
    store::set_schema_version(store::SCHEMA);
}

// --- helpers ----------------------------------------------------------------

fn caller() -> Result<Principal, String> {
    let c = ic_cdk::api::msg_caller();
    if c == Principal::anonymous() {
        return Err("anonymous caller".to_string());
    }
    Ok(c)
}

/// The caller must own `handle`. Returns the handle's entry.
fn authorize_handle(handle: &str) -> Result<Handle, String> {
    let caller = caller()?;
    match store::get_handle(handle) {
        None => Err(format!("handle '{handle}' is not registered")),
        Some(h) if h.owner != caller => Err(format!("caller does not own handle '{handle}'")),
        Some(h) => Ok(h),
    }
}

/// The caller must own the handle a scoped name lives under. Returns the
/// caller (the handle's owner).
fn authorize(name: &str) -> Result<Principal, String> {
    let (handle, _) = names::split(name)?;
    Ok(authorize_handle(handle)?.owner)
}

/// The caller must own the flat name and it must not have lapsed. Returns
/// the record settled to `now` (not yet stored) and the tax that
/// settlement took, for `commit_flat`.
fn authorize_flat(cfg: &HarbergerConfig, name: &str, now: u64) -> Result<(Record, u128), String> {
    names::check_flat(name)?;
    let caller = caller()?;
    let mut r = store::get_record(name).ok_or_else(|| format!("no record for '{name}'"))?;
    if r.owner != caller {
        return Err(format!("caller does not own '{name}'"));
    }
    let (status, tax) = harberger::settle_record(cfg, &mut r, now);
    if status == Status::Free {
        return Err(format!("'{name}' has lapsed and is free to claim"));
    }
    Ok((r, tax))
}

/// A flat name must alias a scoped name (DESIGN.md section 4), so a sale
/// never changes what a scoped name means.
fn check_flat_target(target: &Target) -> Result<(), String> {
    match target {
        Target::Alias(to) => names::split(to)
            .map(|_| ())
            .map_err(|e| format!("a flat name must alias a scoped name: {e}")),
        Target::Address(_) => Err("a flat name must alias a scoped name".to_string()),
    }
}

/// Controllers administer the deployer list.
fn admin() -> Result<Principal, String> {
    let c = caller()?;
    if !ic_cdk::api::is_controller(&c) {
        return Err("caller is not a controller".to_string());
    }
    Ok(c)
}

/// Write a record everywhere it lives: the tag index, the certified tree
/// and stable memory.
fn commit(record: Record) {
    if let Some(old) = store::get_record(&record.name) {
        directory::unindex(&old);
    }
    directory::index(&record);
    certify::set(&record.name, record.canonical());
    store::put_record(record);
}

/// Commit a settled flat record and only then count the tax its
/// settlement took: the treasury counter must never run ahead of what the
/// stored balances have given up, since fund_self spends against it.
fn commit_flat(record: Record, tax: u128) {
    harberger::note_tax_collected(tax);
    commit(record);
}

// --- handles ----------------------------------------------------------------

/// Claim a handle for the caller. First come, first served; permanent.
#[ic_cdk::update]
fn register_handle(handle: String) -> Result<(), String> {
    names::check_segment("handle", &handle)?;
    let owner = caller()?;
    store::register_handle(&handle, owner)
}

#[ic_cdk::query]
fn handle_owner(handle: String) -> Option<Principal> {
    store::handle_owner(&handle)
}

#[ic_cdk::query]
fn get_handle(handle: String) -> Option<Handle> {
    store::get_handle(&handle)
}

/// Let one listed deployer announce names under the caller's handle, or
/// revoke that (None).
#[ic_cdk::update]
fn set_handle_deployer(handle: String, deployer: Option<Principal>) -> Result<(), String> {
    names::check_segment("handle", &handle)?;
    let mut h = authorize_handle(&handle)?;
    if let Some(d) = &deployer {
        if !store::is_deployer(d) {
            return Err(format!("{} is not a listed deployer", d.to_text()));
        }
    }
    h.deployer = deployer;
    store::put_handle(&handle, h);
    Ok(())
}

// --- deployers (DESIGN.md section 8) ----------------------------------------

#[ic_cdk::update]
fn add_deployer(p: Principal) -> Result<(), String> {
    admin()?;
    if p == Principal::anonymous() {
        return Err("anonymous cannot be a deployer".to_string());
    }
    store::add_deployer(p);
    Ok(())
}

#[ic_cdk::update]
fn remove_deployer(p: Principal) -> Result<(), String> {
    admin()?;
    if store::remove_deployer(&p) {
        Ok(())
    } else {
        Err(format!("{} is not a listed deployer", p.to_text()))
    }
}

#[ic_cdk::query]
fn list_deployers() -> Vec<Principal> {
    store::list_deployers()
}

/// What a deployer (ic-git) reports after a successful install. Mirrors
/// ic-git's DeployRecord: commit, target, wasm_sha256.
#[derive(CandidType, serde::Deserialize, Clone, Debug)]
struct Announcement {
    /// The scoped name to create or update, `<handle>/<label>`.
    name: String,
    /// The canister the code was installed into.
    canister: Principal,
    /// Repository the code came from, as the deployer names it.
    repo: String,
    /// Git commit that was built, lowercase hex.
    commit: String,
    /// sha256 of the installed module, lowercase hex.
    module_hash: String,
}

/// Trusted by CALLER PRINCIPAL: the caller must be a listed deployer. It
/// may write under a handle it owns, or one whose owner named it via
/// set_handle_deployer. An unregistered handle is registered to the
/// deployer, so anything deployed by git push gets listed with no one
/// registering first (DESIGN.md section 7). The record's target becomes
/// the announced canister and its text records carry the provenance.
#[ic_cdk::update]
fn announce(a: Announcement) -> Result<(), String> {
    let deployer = caller()?;
    if !store::is_deployer(&deployer) {
        return Err(format!("{} is not a listed deployer", deployer.to_text()));
    }
    let (handle, _) = names::split(&a.name)?;
    names::check_hex("commit", &a.commit, &[20, 32])?;
    names::check_hex("module_hash", &a.module_hash, &[32])?;
    names::check_text_value(&a.repo)?;

    let owner = match store::get_handle(handle) {
        None => {
            store::register_handle(handle, deployer)?;
            deployer
        }
        Some(h) if h.owner == deployer || h.deployer == Some(deployer) => h.owner,
        Some(_) => {
            return Err(format!(
                "handle '{handle}' does not allow deployer {}",
                deployer.to_text()
            ))
        }
    };

    let now = ic_cdk::api::time();
    let mut record = store::get_record(&a.name)
        .unwrap_or_else(|| Record::new(a.name.clone(), owner, Target::Address(a.canister), now));
    record.target = Target::Address(a.canister);
    record.updated_ns = now;
    let provenance = [
        ("repo", a.repo),
        ("commit", a.commit),
        ("module_hash", a.module_hash),
        ("deployer", deployer.to_text()),
        ("announced_ns", now.to_string()),
    ];
    for (k, v) in provenance {
        record.text.retain(|(key, _)| key != k);
        record.text.push((k.to_string(), v));
    }
    record.text.sort_by(|x, y| x.0.cmp(&y.0));
    if record.text.len() > names::MAX_TEXT_RECORDS {
        return Err(format!(
            "at most {} text records per name",
            names::MAX_TEXT_RECORDS
        ));
    }
    commit(record);
    Ok(())
}

// --- records ----------------------------------------------------------------

/// Create or repoint a scoped name, or repoint a flat name the caller
/// holds. Text records survive a repoint.
#[ic_cdk::update]
fn set_record(name: String, target: Target) -> Result<(), String> {
    let now = ic_cdk::api::time();
    if !names::is_scoped(&name) {
        let (mut r, tax) = authorize_flat(&harberger::config(), &name, now)?;
        check_flat_target(&target)?;
        r.target = target;
        r.updated_ns = now;
        commit_flat(r, tax);
        return Ok(());
    }
    let caller = authorize(&name)?;
    if let Target::Alias(to) = &target {
        names::split(to)?;
        if *to == name {
            return Err("a name may not alias itself".to_string());
        }
    }
    let record = match store::get_record(&name) {
        Some(mut r) => {
            r.target = target;
            r.updated_ns = now;
            r
        }
        None => Record::new(name.clone(), caller, target, now),
    };
    commit(record);
    Ok(())
}

/// Set (Some) or clear (None) one text record on an existing name.
#[ic_cdk::update]
fn set_text(name: String, key: String, value: Option<String>) -> Result<(), String> {
    let now = ic_cdk::api::time();
    let (mut record, tax) = if names::is_scoped(&name) {
        authorize(&name)?;
        let r = store::get_record(&name).ok_or_else(|| format!("no record for '{name}'"))?;
        (r, 0)
    } else {
        authorize_flat(&harberger::config(), &name, now)?
    };
    names::check_text_key(&key)?;
    record.text.retain(|(k, _)| *k != key);
    if let Some(v) = value {
        names::check_text_value(&v)?;
        if key == "tags" {
            names::check_tags(&v)?;
        }
        if record.text.len() >= names::MAX_TEXT_RECORDS {
            return Err(format!(
                "at most {} text records per name",
                names::MAX_TEXT_RECORDS
            ));
        }
        record.text.push((key, v));
        record.text.sort_by(|a, b| a.0.cmp(&b.0));
    }
    record.updated_ns = now;
    commit_flat(record, tax);
    Ok(())
}

/// Remove a scoped name, or release a flat name: its unspent balance
/// becomes a credit to the owner and the name is free at once.
#[ic_cdk::update]
fn delete_record(name: String) -> Result<(), String> {
    if !names::is_scoped(&name) {
        let (r, tax) = authorize_flat(&harberger::config(), &name, ic_cdk::api::time())?;
        harberger::note_tax_collected(tax);
        if let Some(h) = &r.flat {
            store::add_credit(&r.owner, h.balance);
        }
        store::delete_record(&name);
        directory::unindex(&r);
        certify::remove(&name);
        return Ok(());
    }
    authorize(&name)?;
    match store::delete_record(&name) {
        Some(old) => {
            directory::unindex(&old);
            certify::remove(&name);
            Ok(())
        }
        None => Err(format!("no record for '{name}'")),
    }
}

#[ic_cdk::query]
fn get_record(name: String) -> Option<Record> {
    store::get_record(&name)
}

#[ic_cdk::query]
fn list_names(handle: String) -> Vec<String> {
    store::names_under(&handle)
}

// --- directory (DESIGN.md section 7) ----------------------------------------

#[ic_cdk::query]
fn search(query: SearchQuery) -> SearchResult {
    directory::search(query)
}

#[ic_cdk::query]
fn tags() -> Vec<TagCount> {
    directory::tags()
}

#[ic_cdk::query]
fn schema_version() -> u32 {
    store::schema_version()
}

// --- resolve ----------------------------------------------------------------

#[derive(CandidType)]
struct Resolved {
    /// The name asked for.
    name: String,
    /// Where it ends up after following aliases.
    canister: Principal,
    /// Every record visited, requested name first, address last.
    chain: Vec<Record>,
    /// The subnet certificate over this canister's certified data. None
    /// only when the replica has none to give (never on the IC for a
    /// query).
    certificate: Option<Vec<u8>>,
    /// CBOR hash tree, label "names", revealing the canonical bytes of
    /// every record in `chain` and hashing to the certified root.
    witness: Vec<u8>,
}

#[ic_cdk::query]
fn resolve(name: String) -> Result<Resolved, String> {
    resolve_inner(name)
}

/// Follow aliases from `name` to an address. Returns the canister and every
/// record visited, requested name first. No certification: the gateway's
/// redirect wants only the address.
fn follow(name: &str) -> Result<(Principal, Vec<Record>), String> {
    if names::is_scoped(name) {
        names::split(name)?;
    } else {
        names::check_flat(name)?;
    }
    let now = ic_cdk::api::time();
    let mut cfg: Option<HarbergerConfig> = None;
    let mut chain: Vec<Record> = Vec::new();
    let mut current = name.to_string();
    let canister = loop {
        if chain.len() >= certify::MAX_ALIAS_DEPTH {
            return Err(format!(
                "alias chain deeper than {}",
                certify::MAX_ALIAS_DEPTH
            ));
        }
        if chain.iter().any(|r| r.name == current) {
            return Err(format!("alias loop at '{current}'"));
        }
        let record =
            store::get_record(&current).ok_or_else(|| format!("no record for '{current}'"))?;
        // A lapsed flat name does not resolve. The stored record goes into
        // the chain unsettled, since that is what the witness leaf holds.
        if let Some(h) = &record.flat {
            let cfg = cfg.get_or_insert_with(harberger::config);
            let (status, _) = harberger::settle(cfg, &mut h.clone(), now);
            if status == Status::Free {
                return Err(format!("'{current}' has lapsed and is free to claim"));
            }
        }
        let next = record.target.clone();
        chain.push(record);
        match next {
            Target::Address(p) => break p,
            Target::Alias(n) => current = n,
        }
    };
    Ok((canister, chain))
}

/// Shared by `resolve` and the HTTP gateway. Certification only works in a
/// query context: `data_certificate` is None inside an update call.
fn resolve_inner(name: String) -> Result<Resolved, String> {
    let (canister, chain) = follow(&name)?;
    let hops: Vec<&str> = chain.iter().map(|r| r.name.as_str()).collect();
    let witness = certify::witness(&hops);
    Ok(Resolved {
        name,
        canister,
        chain,
        certificate: ic_cdk::api::data_certificate(),
        witness,
    })
}

// --- flat names under the Harberger tax (DESIGN.md section 5) ---------------
//
// Every payment is an ICRC-2 pull from the caller's cycles ledger account,
// which is an await. State can change while a pull is in flight, so each
// method takes a `Snapshot` of the record, pulls, takes it again at the
// new time, and if the two differ credits the payer back and fails.
// Nothing is written before the pull, and nothing is settled for keeps
// until `commit_flat` after it.

/// What a payment method compares across its pull: the record settled to
/// a given moment, or the reason it cannot be paid for.
#[derive(Clone, PartialEq, Eq)]
struct Snapshot {
    owner: Principal,
    price: u128,
    changed_hands_ns: u64,
    status: Status,
}

/// Pull a payment. A failure that certainly moved nothing is just an
/// error. A reply this code cannot decode may have moved the cycles, so
/// the amount is recorded as unreconciled (treasury) and the method still
/// fails without changing the record: the payer's cycles, if taken, sit
/// in this canister's ledger account until the operator reconciles.
async fn pull(cfg: &HarbergerConfig, payer: Principal, amount: u128) -> Result<(), String> {
    let _guard = InFlight::start();
    match ledger::pull(cfg.ledger, payer, amount, cfg.fee).await {
        Ok(_) => Ok(()),
        Err(f) => {
            if !f.nothing_moved() {
                harberger::note_unreconciled(
                    amount,
                    &format!("pull {amount} from {}: {}", payer.to_text(), f.message()),
                );
            }
            Err(f.message())
        }
    }
}

/// The stored flat record settled to `now`, or None when there is none.
/// The settled copy is not stored: `taken` is what a commit would owe
/// the treasury.
fn snapshot(cfg: &HarbergerConfig, name: &str, now: u64) -> Option<(Record, u128, Snapshot)> {
    let mut r = store::get_record(name)?;
    let (status, taken) = harberger::settle_record(cfg, &mut r, now);
    let price = r.flat.as_ref().map(|h| h.price)?;
    let snap = Snapshot {
        owner: r.owner,
        price,
        changed_hands_ns: r.changed_hands_ns,
        status,
    };
    Some((r, taken, snap))
}

/// Claiming is refused while the market is closed. Buying a held name is
/// never gated: the forced sale is what keeps a holder's price honest
/// (DESIGN.md section 5), so closing the market stops new names, not the
/// pressure on existing ones. Everything a holder needs to keep or leave
/// a name stays open too.
fn market_open(cfg: &HarbergerConfig) -> Result<(), String> {
    if cfg.flat_names_open {
        Ok(())
    } else {
        Err("flat names are not open for claiming yet".to_string())
    }
}

/// A flat name close to running out, for holders and their tooling.
#[derive(CandidType, Clone, Debug)]
pub struct Expiring {
    pub name: String,
    pub owner: Principal,
    pub status: Status,
    /// When the balance runs out (active) or the grace period ends (grace).
    pub deadline_ns: u64,
    /// Settled to now.
    pub balance: u128,
    pub tax_per_year: u128,
}

/// Flat names whose balance runs out, or whose grace period ends, within
/// `within_ns` of now. Free names are not listed: they are gone. Sorted
/// by deadline.
pub fn expiring_inner(within_ns: u64) -> Vec<Expiring> {
    let cfg = harberger::config();
    let now = ic_cdk::api::time();
    let mut out = Vec::new();
    store::for_each_record(|r| {
        let Some(h) = &r.flat else { return };
        let mut h = h.clone();
        let (status, _) = harberger::settle(&cfg, &mut h, now);
        let deadline_ns = match &status {
            Status::Active => match harberger::ns_until_spent(&cfg, h.price, h.balance) {
                Some(ns) => now.saturating_add(ns),
                None => return,
            },
            Status::Grace { until_ns } => *until_ns,
            Status::Free => return,
        };
        if deadline_ns.saturating_sub(now) <= within_ns {
            out.push(Expiring {
                name: r.name.clone(),
                owner: r.owner,
                status,
                deadline_ns,
                balance: h.balance,
                tax_per_year: harberger::tax_per_year(&cfg, h.price),
            });
        }
    });
    out.sort_by_key(|e| e.deadline_ns);
    out
}

#[ic_cdk::query]
fn expiring(within_ns: u64) -> Vec<Expiring> {
    expiring_inner(within_ns)
}

#[derive(CandidType)]
struct FlatStatus {
    name: String,
    owner: Principal,
    target: Target,
    price: u128,
    /// Settled to now.
    balance: u128,
    status: Status,
    tax_per_year: u128,
    /// The least a claim or buy at `price` must deposit.
    min_deposit: u128,
    changed_hands_ns: u64,
}

#[ic_cdk::query]
fn flat_status(name: String) -> Option<FlatStatus> {
    let cfg = harberger::config();
    let (r, _, snap) = snapshot(&cfg, &name, ic_cdk::api::time())?;
    let balance = r.flat.as_ref().map(|h| h.balance).unwrap_or(0);
    Some(FlatStatus {
        name: r.name,
        owner: r.owner,
        target: r.target,
        price: snap.price,
        balance,
        status: snap.status,
        tax_per_year: harberger::tax_per_year(&cfg, snap.price),
        min_deposit: harberger::min_deposit(&cfg, snap.price),
        changed_hands_ns: r.changed_hands_ns,
    })
}

fn check_price(cfg: &HarbergerConfig, price: u128) -> Result<(), String> {
    if price < cfg.min_price {
        return Err(format!(
            "price below the minimum of {} cycles",
            cfg.min_price
        ));
    }
    if price > harberger::MAX_PRICE {
        return Err(format!(
            "price above the maximum of {} cycles",
            harberger::MAX_PRICE
        ));
    }
    Ok(())
}

fn check_deposit(cfg: &HarbergerConfig, price: u128, deposit: u128) -> Result<(), String> {
    let min = harberger::min_deposit(cfg, price);
    if deposit < min {
        return Err(format!(
            "deposit must cover one grace period of tax: at least {min} cycles at this price"
        ));
    }
    Ok(())
}

/// Take a free flat name: unclaimed, or lapsed past its grace period.
/// Pulls `deposit` from the caller. The name aliases `alias_to`.
#[ic_cdk::update]
async fn claim(name: String, alias_to: String, price: u128, deposit: u128) -> Result<(), String> {
    let cfg = harberger::config();
    market_open(&cfg)?;
    let caller = caller()?;
    names::check_flat(&name)?;
    let target = Target::Alias(alias_to);
    check_flat_target(&target)?;
    check_price(&cfg, price)?;
    check_deposit(&cfg, price, deposit)?;
    // Claimable: no record, or one whose grace period is over.
    let claimable = |now: u64| -> Result<Option<(Record, u128, Snapshot)>, String> {
        match snapshot(&cfg, &name, now) {
            None => Ok(None),
            Some(t) if t.2.status == Status::Free => Ok(Some(t)),
            Some((r, _, _)) => Err(format!("'{name}' is owned by {}", r.owner.to_text())),
        }
    };
    let before = claimable(ic_cdk::api::time())?.map(|t| t.2);

    pull(&cfg, caller, deposit).await?;

    let now = ic_cdk::api::time();
    let old = match claimable(now) {
        Ok(old) if old.as_ref().map(|t| &t.2) == before.as_ref() => old,
        _ => {
            store::add_credit(&caller, deposit);
            return Err(format!(
                "'{name}' changed hands while paying; deposit credited back"
            ));
        }
    };
    let (mut r, tax) = match old {
        Some((old, tax, _)) => (
            Record {
                owner: caller,
                previous_target: Some(old.target.clone()),
                target,
                text: Vec::new(),
                updated_ns: now,
                changed_hands_ns: now,
                ..old
            },
            tax,
        ),
        None => (Record::new(name, caller, target, now), 0),
    };
    r.flat = Some(Harberger {
        price,
        balance: deposit,
        settled_ns: now,
        lapsed_ns: None,
    });
    commit_flat(r, tax);
    Ok(())
}

/// Buy a held flat name at its assessed price, if that price is at most
/// `max_price` (what the buyer saw; the seller may have moved it since).
/// Pulls price plus `deposit` from the caller; the seller is credited the
/// price and the unspent balance. The buyer assesses `price` for the name
/// from here on.
#[ic_cdk::update]
async fn buy(
    name: String,
    alias_to: String,
    price: u128,
    deposit: u128,
    max_price: u128,
) -> Result<(), String> {
    let cfg = harberger::config();
    let caller = caller()?;
    names::check_flat(&name)?;
    let target = Target::Alias(alias_to);
    check_flat_target(&target)?;
    check_price(&cfg, price)?;
    check_deposit(&cfg, price, deposit)?;
    // Buyable: held by someone else and not lapsed.
    let buyable = |now: u64| -> Result<(Record, u128, Snapshot), String> {
        let (r, tax, snap) =
            snapshot(&cfg, &name, now).ok_or_else(|| format!("no record for '{name}'"))?;
        if snap.status == Status::Free {
            return Err(format!("'{name}' has lapsed; claim it instead"));
        }
        if snap.owner == caller {
            return Err("you hold this name; use set_price".to_string());
        }
        if snap.price > max_price {
            return Err(format!(
                "price is now {} cycles, above your limit of {max_price}",
                snap.price
            ));
        }
        Ok((r, tax, snap))
    };
    let before = buyable(ic_cdk::api::time())?.2;
    let total = before.price.saturating_add(deposit);

    pull(&cfg, caller, total).await?;

    let now = ic_cdk::api::time();
    let (mut r, tax) = match buyable(now) {
        Ok((r, tax, snap)) if snap == before => (r, tax),
        _ => {
            store::add_credit(&caller, total);
            return Err(format!(
                "'{name}' changed while paying; payment credited back"
            ));
        }
    };
    let unspent = r.flat.as_ref().map(|h| h.balance).unwrap_or(0);
    store::add_credit(&r.owner, before.price.saturating_add(unspent));
    r.owner = caller;
    r.previous_target = Some(std::mem::replace(&mut r.target, target));
    r.text.clear();
    r.updated_ns = now;
    r.changed_hands_ns = now;
    r.flat = Some(Harberger {
        price,
        balance: deposit,
        settled_ns: now,
        lapsed_ns: None,
    });
    commit_flat(r, tax);
    Ok(())
}

/// Add prepaid tax to a held flat name. Anyone may pay. A name in grace
/// comes back to active, but only if the balance after the top-up covers
/// one grace period of tax, as a claim or buy must: otherwise a dust
/// deposit would buy a fresh grace period every time.
#[ic_cdk::update]
async fn deposit(name: String, amount: u128) -> Result<(), String> {
    let cfg = harberger::config();
    let caller = caller()?;
    names::check_flat(&name)?;
    if amount == 0 {
        return Err("amount is zero".to_string());
    }
    // Payable: held and not lapsed, and the top-up is enough.
    let payable = |now: u64| -> Result<(Record, u128, Snapshot), String> {
        let (r, tax, snap) =
            snapshot(&cfg, &name, now).ok_or_else(|| format!("no record for '{name}'"))?;
        if snap.status == Status::Free {
            return Err(format!("'{name}' has lapsed; claim it instead"));
        }
        let balance = r.flat.as_ref().map(|h| h.balance).unwrap_or(0);
        let min = harberger::min_deposit(&cfg, snap.price);
        if balance.saturating_add(amount) < min {
            return Err(format!(
                "balance after the deposit must cover one grace period of tax: at least {min} cycles at this price, {balance} left"
            ));
        }
        Ok((r, tax, snap))
    };
    let before = payable(ic_cdk::api::time())?.2;

    pull(&cfg, caller, amount).await?;

    let now = ic_cdk::api::time();
    let (mut r, tax) = match payable(now) {
        Ok((r, tax, snap)) if snap == before => (r, tax),
        _ => {
            store::add_credit(&caller, amount);
            return Err(format!(
                "'{name}' changed while paying; amount credited back"
            ));
        }
    };
    if let Some(h) = r.flat.as_mut() {
        h.balance = h.balance.saturating_add(amount);
        h.lapsed_ns = None;
        h.settled_ns = now;
    }
    r.updated_ns = now;
    commit_flat(r, tax);
    Ok(())
}

/// Reassess a held flat name. Tax from here on is at the new price.
#[ic_cdk::update]
fn set_price(name: String, price: u128) -> Result<(), String> {
    let cfg = harberger::config();
    check_price(&cfg, price)?;
    let now = ic_cdk::api::time();
    let (mut r, tax) = authorize_flat(&cfg, &name, now)?;
    if let Some(h) = r.flat.as_mut() {
        h.price = price;
    }
    r.updated_ns = now;
    commit_flat(r, tax);
    Ok(())
}

#[ic_cdk::query]
fn credit(p: Principal) -> u128 {
    store::credit_of(&p)
}

// The ledger's transfer fee is charged on top of the amount on every
// transfer or withdraw out of this canister's account, so every payout
// sends amount minus cfg.fee and the account is debited exactly amount.
// cfg.fee is what the ledger answered when the config was set, and it is
// pinned on transfers so a change fails the transfer instead.

thread_local! {
    /// Ledger calls awaiting a reply. A ledger change is refused while
    /// any are outstanding, since their cycles land at the old ledger.
    static IN_FLIGHT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

struct InFlight;

impl InFlight {
    fn start() -> Self {
        IN_FLIGHT.with(|c| c.set(c.get() + 1));
        InFlight
    }
    fn count() -> u32 {
        IN_FLIGHT.with(|c| c.get())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

/// Move `amount` of the caller's credit (sale proceeds, refunds) to the
/// caller's cycles ledger account. The ledger fee comes out of it.
#[ic_cdk::update]
async fn withdraw(amount: u128) -> Result<u128, String> {
    let cfg = harberger::config();
    let caller = caller()?;
    if amount <= cfg.fee {
        return Err(format!(
            "amount must exceed the ledger fee of {} cycles",
            cfg.fee
        ));
    }
    store::take_credit(&caller, amount)?;
    let _guard = InFlight::start();
    match ledger::pay(cfg.ledger, caller, amount - cfg.fee, cfg.fee).await {
        Ok(block) => Ok(block),
        Err(f) => {
            // Only give the credit back when the ledger certainly paid
            // nothing; otherwise a retry would pay twice.
            if f.nothing_moved() {
                store::add_credit(&caller, amount);
            } else {
                harberger::note_unreconciled(
                    amount,
                    &format!("pay {amount} to {}: {}", caller.to_text(), f.message()),
                );
            }
            Err(f.message())
        }
    }
}

#[derive(CandidType)]
struct Treasury {
    /// Tax settled so far, cycles. Sits in this canister's ledger account
    /// alongside prepaid balances and credits, which it must never touch.
    collected: u128,
    withdrawn: u128,
    /// Cycles whose movement could not be confirmed from a ledger reply;
    /// the operator reconciles them against the ledger's blocks.
    unreconciled: u128,
    unreconciled_last: String,
}

#[ic_cdk::query]
fn treasury() -> Treasury {
    let (unreconciled, unreconciled_last) = harberger::unreconciled();
    Treasury {
        collected: harberger::tax_collected(),
        withdrawn: harberger::tax_withdrawn(),
        unreconciled,
        unreconciled_last,
    }
}

/// Turn collected tax into this canister's own cycles (DESIGN.md section
/// 5: the tax funds the canister's operation). Controllers only. The
/// ledger fee comes out of `amount`, so the account is debited exactly
/// what the treasury records as withdrawn.
#[ic_cdk::update]
async fn fund_self(amount: u128) -> Result<u128, String> {
    admin()?;
    let cfg = harberger::config();
    let available = harberger::tax_collected().saturating_sub(harberger::tax_withdrawn());
    if amount <= cfg.fee || amount > available {
        return Err(format!(
            "{available} cycles of tax available to withdraw; amount must exceed the ledger fee of {}",
            cfg.fee
        ));
    }
    // withdraw cannot pin a fee, so check the live one against the pinned
    // one first: a changed fee would come out of prepaid balances.
    let _guard = InFlight::start();
    let live = ledger::fee(cfg.ledger).await.map_err(|f| f.message())?;
    if live != cfg.fee {
        return Err(format!(
            "ledger fee is now {live}, config has {}; run set_harberger_config to refresh it",
            cfg.fee
        ));
    }
    harberger::note_tax_withdrawn(amount);
    match ledger::fund_self(cfg.ledger, amount - cfg.fee).await {
        Ok(block) => Ok(block),
        Err(f) => {
            if f.nothing_moved() {
                harberger::undo_tax_withdrawn(amount);
            } else {
                harberger::note_unreconciled(
                    amount,
                    &format!("fund_self {amount}: {}", f.message()),
                );
            }
            Err(f.message())
        }
    }
}

/// Is any value held that a ledger change would strand? Describes it.
fn funds_held() -> Result<(), String> {
    let mut flat = 0u32;
    store::for_each_record(|r| {
        if r.flat.is_some() {
            flat += 1;
        }
    });
    let credits = store::credits_outstanding();
    let tax = harberger::tax_collected().saturating_sub(harberger::tax_withdrawn());
    let (unreconciled, _) = harberger::unreconciled();
    let in_flight = InFlight::count();
    if flat == 0 && credits == 0 && tax == 0 && unreconciled == 0 && in_flight == 0 {
        return Ok(());
    }
    Err(format!(
        "funds are held at the current ledger: {flat} flat name(s), {credits} cycles of credit, {tax} of tax, {unreconciled} unreconciled, {in_flight} call(s) in flight"
    ))
}

/// Settle every flat name to `now` under `cfg` and store the result, so
/// a rate change from here on applies only to time after it.
fn settle_all(cfg: &HarbergerConfig, now: u64) -> (u32, u128) {
    let mut names = Vec::new();
    store::for_each_record(|r| {
        if r.flat.is_some() {
            names.push(r.name.clone());
        }
    });
    let mut settled = 0u32;
    let mut tax_total = 0u128;
    for name in names {
        if let Some(mut r) = store::get_record(&name) {
            let (_, tax) = harberger::settle_record(cfg, &mut r, now);
            tax_total = tax_total.saturating_add(tax);
            settled += 1;
            commit_flat(r, tax);
        }
    }
    (settled, tax_total)
}

/// Change the tax settings. Controllers only. The ledger may only change
/// while nothing is held or in flight at the current one. The fee is
/// what the ledger answers, not what the caller passes. Existing names
/// are settled under the old rate first, so the new rate never reaches
/// back in time.
#[ic_cdk::update]
async fn set_harberger_config(c: HarbergerConfig) -> Result<(), String> {
    admin()?;
    let mut c = c;
    let current = harberger::config();
    if c.ledger != current.ledger {
        funds_held()?;
    }
    c.fee = ledger::fee(c.ledger).await.map_err(|f| f.message())?;
    // Re-read after the await; another controller may have moved first.
    let current = harberger::config();
    if c.ledger != current.ledger {
        funds_held()?;
    }
    if c.rate_bps != current.rate_bps {
        settle_all(&current, ic_cdk::api::time());
    }
    harberger::set_config(c)
}

#[ic_cdk::query]
fn harberger_config() -> HarbergerConfig {
    harberger::config()
}

// --- HTTP gateway, stage 1 (DESIGN.md section 6) -----------------------------

#[ic_cdk::query]
fn http_request(req: gateway::HttpRequest) -> gateway::HttpResponse {
    gateway::handle(&req)
}

ic_cdk::export_candid!();

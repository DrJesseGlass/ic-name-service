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
/// the record settled to `now` (not yet stored) and its status.
fn authorize_flat(name: &str, now: u64) -> Result<(Record, Status), String> {
    names::check_flat(name)?;
    let caller = caller()?;
    let mut r = store::get_record(name).ok_or_else(|| format!("no record for '{name}'"))?;
    if r.owner != caller {
        return Err(format!("caller does not own '{name}'"));
    }
    let status = harberger::settle_record(&harberger::config(), &mut r, now);
    if status == Status::Free {
        return Err(format!("'{name}' has lapsed and is free to claim"));
    }
    Ok((r, status))
}

/// A flat name must alias a scoped name (DESIGN.md section 4), so a sale
/// never changes what a scoped name means.
fn check_flat_target(target: &Target) -> Result<(), String> {
    match target {
        Target::Alias(to) if names::is_scoped(to) => names::split(to).map(|_| ()),
        _ => Err("a flat name must alias a scoped name".to_string()),
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
        let (mut r, _) = authorize_flat(&name, now)?;
        check_flat_target(&target)?;
        r.target = target;
        r.updated_ns = now;
        commit(r);
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
    let mut record = if names::is_scoped(&name) {
        authorize(&name)?;
        store::get_record(&name).ok_or_else(|| format!("no record for '{name}'"))?
    } else {
        authorize_flat(&name, now)?.0
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
    commit(record);
    Ok(())
}

/// Remove a scoped name, or release a flat name: its unspent balance
/// becomes a credit to the owner and the name is free at once.
#[ic_cdk::update]
fn delete_record(name: String) -> Result<(), String> {
    if !names::is_scoped(&name) {
        let (r, _) = authorize_flat(&name, ic_cdk::api::time())?;
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
    let cfg = harberger::config();
    let now = ic_cdk::api::time();
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
            let (status, _) = harberger::settle(&cfg, &mut h.clone(), now);
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
// method validates, pulls, re-reads, and if the record moved underneath it
// credits the payer back and fails. Nothing is written before the pull.

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
    let mut r = store::get_record(&name)?;
    let h = r.flat.as_mut()?;
    let (status, _) = harberger::settle(&cfg, h, ic_cdk::api::time());
    Some(FlatStatus {
        name: r.name.clone(),
        owner: r.owner,
        target: r.target.clone(),
        price: h.price,
        balance: h.balance,
        status,
        tax_per_year: harberger::tax_per_year(&cfg, h.price),
        min_deposit: harberger::min_deposit(&cfg, h.price),
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
    let caller = caller()?;
    names::check_flat(&name)?;
    let target = Target::Alias(alias_to);
    check_flat_target(&target)?;
    check_price(&cfg, price)?;
    check_deposit(&cfg, price, deposit)?;
    let now = ic_cdk::api::time();
    let snapshot = |r: Option<Record>| -> Result<Option<(Principal, u64)>, String> {
        match r {
            None => Ok(None),
            Some(mut r) => {
                let status = harberger::settle_record(&cfg, &mut r, now);
                if r.flat.is_none() || status != Status::Free {
                    return Err(format!("'{name}' is owned by {}", r.owner.to_text()));
                }
                Ok(Some((r.owner, r.changed_hands_ns)))
            }
        }
    };
    let before = snapshot(store::get_record(&name))?;

    ledger::pull(cfg.ledger, caller, deposit).await?;

    let existing = store::get_record(&name);
    let after = snapshot(existing.clone());
    if after.as_ref().ok() != Some(&before) {
        store::add_credit(&caller, deposit);
        return Err(format!(
            "'{name}' changed hands while paying; deposit credited back"
        ));
    }
    let now = ic_cdk::api::time();
    let mut r = match existing {
        Some(old) => Record {
            owner: caller,
            target,
            text: Vec::new(),
            updated_ns: now,
            changed_hands_ns: now,
            ..old
        },
        None => Record::new(name, caller, target, now),
    };
    r.flat = Some(Harberger {
        price,
        balance: deposit,
        settled_ns: now,
        lapsed_ns: None,
    });
    commit(r);
    Ok(())
}

/// Buy a held flat name at its assessed price. Pulls price plus `deposit`
/// from the caller; the seller is credited the price and the unspent
/// balance. The buyer assesses `price` for the name from here on.
#[ic_cdk::update]
async fn buy(name: String, alias_to: String, price: u128, deposit: u128) -> Result<(), String> {
    let cfg = harberger::config();
    let caller = caller()?;
    names::check_flat(&name)?;
    let target = Target::Alias(alias_to);
    check_flat_target(&target)?;
    check_price(&cfg, price)?;
    check_deposit(&cfg, price, deposit)?;
    let now = ic_cdk::api::time();
    let snapshot = |r: Option<Record>| -> Result<(Principal, u128, u64), String> {
        let mut r = r.ok_or_else(|| format!("no record for '{name}'"))?;
        let status = harberger::settle_record(&cfg, &mut r, now);
        let h = r
            .flat
            .as_ref()
            .ok_or_else(|| format!("'{name}' is not a flat name"))?;
        if status == Status::Free {
            return Err(format!("'{name}' has lapsed; claim it instead"));
        }
        if r.owner == caller {
            return Err("you hold this name; use set_price".to_string());
        }
        Ok((r.owner, h.price, r.changed_hands_ns))
    };
    let before = snapshot(store::get_record(&name))?;
    let total = before.1.saturating_add(deposit);

    ledger::pull(cfg.ledger, caller, total).await?;

    let mut r = store::get_record(&name)
        .unwrap_or_else(|| Record::new(name.clone(), caller, target.clone(), now));
    if snapshot(Some(r.clone())).ok() != Some(before) {
        store::add_credit(&caller, total);
        return Err(format!(
            "'{name}' changed while paying; payment credited back"
        ));
    }
    let now = ic_cdk::api::time();
    harberger::settle_record(&cfg, &mut r, now);
    let unspent = r.flat.as_ref().map(|h| h.balance).unwrap_or(0);
    store::add_credit(&r.owner, before.1.saturating_add(unspent));
    r.owner = caller;
    r.target = target;
    r.text.clear();
    r.updated_ns = now;
    r.changed_hands_ns = now;
    r.flat = Some(Harberger {
        price,
        balance: deposit,
        settled_ns: now,
        lapsed_ns: None,
    });
    commit(r);
    Ok(())
}

/// Add prepaid tax to a held flat name. Anyone may pay; a name in grace
/// comes back to active.
#[ic_cdk::update]
async fn deposit(name: String, amount: u128) -> Result<(), String> {
    let cfg = harberger::config();
    let caller = caller()?;
    names::check_flat(&name)?;
    if amount == 0 {
        return Err("amount is zero".to_string());
    }
    let now = ic_cdk::api::time();
    let check = |r: Option<Record>| -> Result<(Principal, u64), String> {
        let mut r = r.ok_or_else(|| format!("no record for '{name}'"))?;
        let status = harberger::settle_record(&cfg, &mut r, now);
        if r.flat.is_none() {
            return Err(format!("'{name}' is not a flat name"));
        }
        if status == Status::Free {
            return Err(format!("'{name}' has lapsed; claim it instead"));
        }
        Ok((r.owner, r.changed_hands_ns))
    };
    let before = check(store::get_record(&name))?;

    ledger::pull(cfg.ledger, caller, amount).await?;

    let now = ic_cdk::api::time();
    let mut r = store::get_record(&name)
        .unwrap_or_else(|| Record::new(name.clone(), caller, Target::Alias(String::new()), now));
    if check(Some(r.clone())).ok() != Some(before) {
        store::add_credit(&caller, amount);
        return Err(format!(
            "'{name}' changed while paying; amount credited back"
        ));
    }
    harberger::settle_record(&cfg, &mut r, now);
    if let Some(h) = r.flat.as_mut() {
        h.balance = h.balance.saturating_add(amount);
        h.lapsed_ns = None;
        h.settled_ns = now;
    }
    r.updated_ns = now;
    commit(r);
    Ok(())
}

/// Reassess a held flat name. Tax from here on is at the new price.
#[ic_cdk::update]
fn set_price(name: String, price: u128) -> Result<(), String> {
    let cfg = harberger::config();
    check_price(&cfg, price)?;
    let now = ic_cdk::api::time();
    let (mut r, _) = authorize_flat(&name, now)?;
    if let Some(h) = r.flat.as_mut() {
        h.price = price;
    }
    r.updated_ns = now;
    commit(r);
    Ok(())
}

#[ic_cdk::query]
fn credit(p: Principal) -> u128 {
    store::credit_of(&p)
}

/// The cycles ledger's transfer fee, paid by this canister on a withdraw.
const LEDGER_FEE: u128 = 100_000_000;

/// Move `amount` of the caller's credit (sale proceeds, refunds) to the
/// caller's cycles ledger account. The ledger fee comes out of it.
#[ic_cdk::update]
async fn withdraw(amount: u128) -> Result<u128, String> {
    let cfg = harberger::config();
    let caller = caller()?;
    if amount <= LEDGER_FEE {
        return Err(format!(
            "amount must exceed the ledger fee of {LEDGER_FEE} cycles"
        ));
    }
    store::take_credit(&caller, amount)?;
    match ledger::pay(cfg.ledger, caller, amount - LEDGER_FEE).await {
        Ok(block) => Ok(block),
        Err(e) => {
            store::add_credit(&caller, amount);
            Err(e)
        }
    }
}

#[derive(CandidType)]
struct Treasury {
    /// Tax settled so far, cycles. Sits in this canister's ledger account
    /// alongside prepaid balances and credits, which it must never touch.
    collected: u128,
    withdrawn: u128,
}

#[ic_cdk::query]
fn treasury() -> Treasury {
    Treasury {
        collected: harberger::tax_collected(),
        withdrawn: harberger::tax_withdrawn(),
    }
}

/// Turn collected tax into this canister's own cycles (DESIGN.md section
/// 5: the tax funds the canister's operation). Controllers only.
#[ic_cdk::update]
async fn fund_self(amount: u128) -> Result<u128, String> {
    admin()?;
    let cfg = harberger::config();
    let available = harberger::tax_collected().saturating_sub(harberger::tax_withdrawn());
    if amount == 0 || amount > available {
        return Err(format!("{available} cycles of tax available to withdraw"));
    }
    harberger::note_tax_withdrawn(amount);
    match ledger::fund_self(cfg.ledger, amount).await {
        Ok(block) => Ok(block),
        Err(e) => {
            harberger::undo_tax_withdrawn(amount);
            Err(e)
        }
    }
}

#[ic_cdk::update]
fn set_harberger_config(c: HarbergerConfig) -> Result<(), String> {
    admin()?;
    harberger::set_config(c)
}

#[ic_cdk::query]
fn harberger_config() -> HarbergerConfig {
    harberger::config()
}

// --- HTTP gateway, stage 1 (DESIGN.md section 6) -----------------------------

#[ic_cdk::query]
fn http_request(req: gateway::HttpRequest) -> gateway::HttpResponse {
    gateway::handle(&req, false)
}

#[ic_cdk::update]
fn http_request_update(req: gateway::HttpRequest) -> gateway::HttpResponse {
    gateway::handle(&req, true)
}

ic_cdk::export_candid!();

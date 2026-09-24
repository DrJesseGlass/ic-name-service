//! ic-name-service: resolver plus registry for canisters (DESIGN.md).
//!
//! State of play: milestones M0 and M1. Scoped names only, address and
//! alias targets, text records, certified `resolve`, `announce` gated by
//! caller principal, the stage 1 HTTP gateway (path-based 302), and the
//! directory: tags and search.

mod certify;
mod directory;
mod gateway;
mod names;
mod store;

use candid::{CandidType, Principal};
use directory::{SearchQuery, SearchResult, TagCount};
use store::{Handle, Record, Target};

// --- lifecycle --------------------------------------------------------------

#[ic_cdk::init]
fn init() {
    certify::rebuild();
    directory::rebuild();
}

/// The certified tree is heap state and must be rebuilt. The tag index is
/// stable memory kept in step on every write, so it is not: a rebuild here
/// would decode every record a second time for nothing. A future change to
/// what the index contains calls directory::rebuild once, explicitly.
#[ic_cdk::post_upgrade]
fn post_upgrade() {
    certify::rebuild();
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

/// Create or repoint a scoped name. Text records survive a repoint.
#[ic_cdk::update]
fn set_record(name: String, target: Target) -> Result<(), String> {
    let caller = authorize(&name)?;
    if let Target::Alias(to) = &target {
        names::split(to)?;
        if *to == name {
            return Err("a name may not alias itself".to_string());
        }
    }
    let now = ic_cdk::api::time();
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
    authorize(&name)?;
    names::check_text_key(&key)?;
    let mut record = store::get_record(&name).ok_or_else(|| format!("no record for '{name}'"))?;
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
    record.updated_ns = ic_cdk::api::time();
    commit(record);
    Ok(())
}

#[ic_cdk::update]
fn delete_record(name: String) -> Result<(), String> {
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
    names::split(name)?;
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

//! ic-name-service: resolver plus registry for canisters (DESIGN.md).
//!
//! State of play: milestone M0, the resolve half. Scoped names only,
//! address and alias targets, text records, certified `resolve`. Announce,
//! the HTTP gateway and the ic-git hook come next.

mod certify;
mod names;
mod store;

use candid::{CandidType, Principal};
use store::{Record, Target};

// --- lifecycle --------------------------------------------------------------

#[ic_cdk::init]
fn init() {
    certify::rebuild();
}

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

/// The caller must own the handle a scoped name lives under.
fn authorize(name: &str) -> Result<(Principal, String), String> {
    let (handle, _) = names::split(name)?;
    let caller = caller()?;
    match store::handle_owner(handle) {
        None => Err(format!("handle '{handle}' is not registered")),
        Some(owner) if owner != caller => Err(format!("caller does not own handle '{handle}'")),
        Some(_) => Ok((caller, handle.to_string())),
    }
}

fn commit(record: Record) {
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

// --- records ----------------------------------------------------------------

/// Create or repoint a scoped name. Text records survive a repoint.
#[ic_cdk::update]
fn set_record(name: String, target: Target) -> Result<(), String> {
    let (caller, _) = authorize(&name)?;
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
        None => Record {
            name: name.clone(),
            owner: caller,
            target,
            text: Vec::new(),
            created_ns: now,
            updated_ns: now,
            changed_hands_ns: now,
        },
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
        Some(_) => {
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
    names::split(&name)?;
    let mut chain: Vec<Record> = Vec::new();
    let mut current = name.clone();
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
    let hops: Vec<&str> = chain.iter().map(|r| r.name.as_str()).collect();
    Ok(Resolved {
        name,
        canister,
        chain: chain.clone(),
        certificate: ic_cdk::api::data_certificate(),
        witness: certify::witness(&hops),
    })
}

ic_cdk::export_candid!();

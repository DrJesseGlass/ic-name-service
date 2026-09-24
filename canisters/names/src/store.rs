//! Stable-memory registry: handles and records (DESIGN.md section 3).
//!
//! Three maps. HANDLES: handle -> Handle (owner, allowed deployer).
//! RECORDS: scoped name -> Record. DEPLOYERS: principals whose `announce`
//! calls are trusted (DESIGN.md section 8). Values are candid-encoded in
//! stable memory; the certified form is the canonical text in
//! `Record::canonical`, not the candid bytes.

use candid::{CandidType, Decode, Encode, Principal};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, Storable};
use serde::Deserialize;
use std::borrow::Cow;
use std::cell::RefCell;

pub type Memory = VirtualMemory<DefaultMemoryImpl>;

/// What a name points at. Address is the terminal case; alias chains to
/// another scoped name and is followed by `resolve` up to a bounded depth.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Target {
    #[serde(rename = "address")]
    Address(Principal),
    #[serde(rename = "alias")]
    Alias(String),
}

/// A handle and who may write under it. `deployer`, if set, is one listed
/// deployer (see DEPLOYERS) the owner lets announce names here.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Handle {
    pub owner: Principal,
    pub deployer: Option<Principal>,
}

impl Storable for Handle {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).expect("encode Handle"))
    }
    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).expect("encode Handle")
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Handle).expect("decode Handle")
    }
    const BOUND: Bound = Bound::Unbounded;
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub owner: Principal,
    pub target: Target,
    /// Sorted by key, unique keys.
    pub text: Vec<(String, String)>,
    pub created_ns: u64,
    pub updated_ns: u64,
    /// When ownership last changed. Equals created_ns until a transfer.
    pub changed_hands_ns: u64,
}

impl Record {
    /// A fresh record with no text records; every timestamp is `now`.
    pub fn new(name: String, owner: Principal, target: Target, now: u64) -> Self {
        Record {
            name,
            owner,
            target,
            text: Vec::new(),
            created_ns: now,
            updated_ns: now,
            changed_hands_ns: now,
        }
    }

    /// The bytes that get certified. Line oriented, pure ASCII apart from
    /// text values, one field per line, text records sorted by key. A
    /// verifier rebuilds this from the candid record it received and checks
    /// the witness leaf equals it. names.rs rejects control characters in
    /// values, so no value can inject a line.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("name=");
        out.push_str(&self.name);
        out.push('\n');
        out.push_str("owner=");
        out.push_str(&self.owner.to_text());
        out.push('\n');
        out.push_str("target=");
        match &self.target {
            Target::Address(p) => {
                out.push_str("address:");
                out.push_str(&p.to_text());
            }
            Target::Alias(n) => {
                out.push_str("alias:");
                out.push_str(n);
            }
        }
        out.push('\n');
        for (k, v) in &self.text {
            out.push_str("text.");
            out.push_str(k);
            out.push('=');
            out.push_str(v);
            out.push('\n');
        }
        out.push_str(&format!("created_ns={}\n", self.created_ns));
        out.push_str(&format!("updated_ns={}\n", self.updated_ns));
        out.push_str(&format!("changed_hands_ns={}\n", self.changed_hands_ns));
        out.into_bytes()
    }
}

impl Storable for Record {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).expect("encode Record"))
    }
    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).expect("encode Record")
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(&bytes, Record).expect("decode Record")
    }
    const BOUND: Bound = Bound::Unbounded;
}

const MEM_HANDLES: MemoryId = MemoryId::new(0);
const MEM_RECORDS: MemoryId = MemoryId::new(1);
const MEM_DEPLOYERS: MemoryId = MemoryId::new(2);
/// Used by directory.rs for the tag index.
pub const MEM_TAGS: MemoryId = MemoryId::new(3);

/// A virtual memory for a map that lives in another module.
pub fn memory(id: MemoryId) -> Memory {
    MEMORY_MANAGER.with(|m| m.borrow().get(id))
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// handle -> Handle
    static HANDLES: RefCell<StableBTreeMap<String, Handle, Memory>> = RefCell::new(
        StableBTreeMap::init(memory(MEM_HANDLES)),
    );

    /// principal (raw bytes) -> unit. Membership is the value.
    static DEPLOYERS: RefCell<StableBTreeMap<Vec<u8>, (), Memory>> = RefCell::new(
        StableBTreeMap::init(memory(MEM_DEPLOYERS)),
    );

    /// "<handle>/<label>" -> Record
    static RECORDS: RefCell<StableBTreeMap<String, Record, Memory>> = RefCell::new(
        StableBTreeMap::init(memory(MEM_RECORDS)),
    );
}

// --- handles ----------------------------------------------------------------

pub fn get_handle(handle: &str) -> Option<Handle> {
    HANDLES.with(|h| h.borrow().get(&handle.to_string()))
}

pub fn handle_owner(handle: &str) -> Option<Principal> {
    get_handle(handle).map(|h| h.owner)
}

/// First come, first served. Returns Err if taken.
pub fn register_handle(handle: &str, owner: Principal) -> Result<(), String> {
    HANDLES.with(|h| {
        let mut h = h.borrow_mut();
        if h.contains_key(&handle.to_string()) {
            return Err(format!("handle '{handle}' is taken"));
        }
        h.insert(
            handle.to_string(),
            Handle {
                owner,
                deployer: None,
            },
        );
        Ok(())
    })
}

pub fn put_handle(handle: &str, value: Handle) {
    HANDLES.with(|h| {
        h.borrow_mut().insert(handle.to_string(), value);
    });
}

// --- deployers --------------------------------------------------------------

pub fn is_deployer(p: &Principal) -> bool {
    DEPLOYERS.with(|d| d.borrow().contains_key(&p.as_slice().to_vec()))
}

pub fn add_deployer(p: Principal) {
    DEPLOYERS.with(|d| {
        d.borrow_mut().insert(p.as_slice().to_vec(), ());
    });
}

pub fn remove_deployer(p: &Principal) -> bool {
    DEPLOYERS.with(|d| d.borrow_mut().remove(&p.as_slice().to_vec()).is_some())
}

pub fn list_deployers() -> Vec<Principal> {
    DEPLOYERS.with(|d| {
        d.borrow()
            .iter()
            .map(|e| Principal::from_slice(e.key()))
            .collect()
    })
}

// --- records ----------------------------------------------------------------

pub fn get_record(name: &str) -> Option<Record> {
    RECORDS.with(|r| r.borrow().get(&name.to_string()))
}

pub fn put_record(record: Record) {
    RECORDS.with(|r| {
        r.borrow_mut().insert(record.name.clone(), record);
    });
}

pub fn delete_record(name: &str) -> Option<Record> {
    RECORDS.with(|r| r.borrow_mut().remove(&name.to_string()))
}

/// Names under one handle, in key order.
pub fn names_under(handle: &str) -> Vec<String> {
    let prefix = format!("{handle}/");
    RECORDS.with(|r| {
        r.borrow()
            .range(prefix.clone()..)
            .take_while(|e| e.key().starts_with(&prefix))
            .map(|e| e.key().clone())
            .collect()
    })
}

/// Every (name, canonical bytes) pair, for rebuilding the certified tree
/// after an upgrade.
pub fn for_each_canonical(mut f: impl FnMut(&str, Vec<u8>)) {
    RECORDS.with(|r| {
        for e in r.borrow().iter() {
            f(e.key(), e.value().canonical());
        }
    });
}

/// Every record, in name order. Search and index rebuild walk this.
pub fn for_each_record(mut f: impl FnMut(&Record)) {
    RECORDS.with(|r| {
        for e in r.borrow().iter() {
            f(&e.value());
        }
    });
}

impl Record {
    /// One text record's value.
    pub fn text(&self, key: &str) -> Option<&str> {
        self.text
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Record {
        Record {
            name: "alice/ic-git".into(),
            owner: Principal::from_text("2vxsx-fae").unwrap(),
            target: Target::Address(Principal::from_text("umobs-yiaaa-aaaab-agyrq-cai").unwrap()),
            text: vec![
                ("description".into(), "git remote on a canister".into()),
                ("tags".into(), "git,deploy".into()),
            ],
            created_ns: 1,
            updated_ns: 2,
            changed_hands_ns: 1,
        }
    }

    #[test]
    fn canonical_form_is_stable() {
        let want = "name=alice/ic-git\n\
                    owner=2vxsx-fae\n\
                    target=address:umobs-yiaaa-aaaab-agyrq-cai\n\
                    text.description=git remote on a canister\n\
                    text.tags=git,deploy\n\
                    created_ns=1\n\
                    updated_ns=2\n\
                    changed_hands_ns=1\n";
        assert_eq!(String::from_utf8(sample().canonical()).unwrap(), want);
    }

    #[test]
    fn storable_round_trip() {
        let r = sample();
        let bytes = r.to_bytes().into_owned();
        assert_eq!(Record::from_bytes(Cow::Owned(bytes)), r);
    }

    #[test]
    fn registry() {
        let alice = Principal::from_text("2vxsx-fae").unwrap();
        assert!(register_handle("alice", alice).is_ok());
        assert!(register_handle("alice", alice).is_err());
        assert_eq!(handle_owner("alice"), Some(alice));
        assert_eq!(handle_owner("bob"), None);
        let deployer = Principal::from_text("umobs-yiaaa-aaaab-agyrq-cai").unwrap();
        assert!(!is_deployer(&deployer));
        add_deployer(deployer);
        assert!(is_deployer(&deployer));
        assert_eq!(list_deployers(), vec![deployer]);
        put_handle(
            "alice",
            Handle {
                owner: alice,
                deployer: Some(deployer),
            },
        );
        assert_eq!(get_handle("alice").unwrap().deployer, Some(deployer));
        assert!(remove_deployer(&deployer));
        assert!(!is_deployer(&deployer));
        put_record(sample());
        let mut other = sample();
        other.name = "alice/other".into();
        put_record(other);
        let mut foreign = sample();
        foreign.name = "alicia/x".into();
        put_record(foreign);
        assert_eq!(names_under("alice"), vec!["alice/ic-git", "alice/other"]);
        assert!(delete_record("alice/other").is_some());
        assert_eq!(names_under("alice"), vec!["alice/ic-git"]);
    }
}

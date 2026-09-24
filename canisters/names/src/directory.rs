//! Directory and search (DESIGN.md section 7): "what exists".
//!
//! Same canister, same records. A tag index in stable memory keyed
//! "<tag>\0<name>" answers tag lookups by range scan; substring search over
//! names and descriptions is a linear pass over RECORDS, which is right for
//! any size this canister sees before delegation (M3) splits the namespace.
//! Tags come from the "tags" text record (names::check_tags).

use crate::store::{self, Record, Target};
use candid::CandidType;
use ic_stable_structures::StableBTreeMap;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;

thread_local! {
    /// "<tag>\0<name>" -> unit. Membership is the value.
    static TAGS: RefCell<StableBTreeMap<String, (), store::Memory>> =
        RefCell::new(StableBTreeMap::init(store::memory(store::MEM_TAGS)));
}

pub const MAX_LIMIT: u32 = 100;
pub const DEFAULT_LIMIT: u32 = 20;

fn key(tag: &str, name: &str) -> String {
    format!("{tag}\0{name}")
}

/// Tags of a record, from its "tags" text record. Values were validated on
/// the way in, so a plain split is enough.
pub fn tags_of(record: &Record) -> Vec<String> {
    record
        .text("tags")
        .map(|v| v.split(',').map(str::to_string).collect())
        .unwrap_or_default()
}

pub fn index(record: &Record) {
    TAGS.with(|t| {
        let mut t = t.borrow_mut();
        for tag in tags_of(record) {
            t.insert(key(&tag, &record.name), ());
        }
    });
}

pub fn unindex(record: &Record) {
    TAGS.with(|t| {
        let mut t = t.borrow_mut();
        for tag in tags_of(record) {
            t.remove(&key(&tag, &record.name));
        }
    });
}

/// Drop the index and refill it from RECORDS (post_upgrade).
pub fn rebuild() {
    TAGS.with(|t| {
        let mut t = t.borrow_mut();
        let keys: Vec<String> = t.iter().map(|e| e.key().clone()).collect();
        for k in keys {
            t.remove(&k);
        }
    });
    store::for_each_record(index);
}

/// Names carrying `tag`, in name order.
pub fn names_with_tag(tag: &str) -> Vec<String> {
    let prefix = key(tag, "");
    TAGS.with(|t| {
        t.borrow()
            .range(prefix.clone()..)
            .take_while(|e| e.key().starts_with(&prefix))
            .map(|e| e.key()[prefix.len()..].to_string())
            .collect()
    })
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TagCount {
    pub tag: String,
    pub count: u32,
}

/// Every tag in use with how many names carry it, in tag order.
pub fn tags() -> Vec<TagCount> {
    let mut out: Vec<TagCount> = Vec::new();
    TAGS.with(|t| {
        for e in t.borrow().iter() {
            let tag = e.key().split('\0').next().unwrap_or("").to_string();
            match out.last_mut() {
                Some(last) if last.tag == tag => last.count += 1,
                _ => out.push(TagCount { tag, count: 1 }),
            }
        }
    });
    out
}

#[derive(CandidType, Deserialize, Clone, Debug, Default)]
pub struct SearchQuery {
    /// Case-insensitive substring of the name or the description.
    pub q: Option<String>,
    /// Only names carrying this tag.
    pub tag: Option<String>,
    pub offset: Option<u32>,
    /// At most MAX_LIMIT; DEFAULT_LIMIT when absent.
    pub limit: Option<u32>,
}

/// One directory entry: the record fields a listing shows, with the
/// provenance text records lifted out.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub name: String,
    pub target: Target,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub repo: Option<String>,
    pub commit: Option<String>,
    pub module_hash: Option<String>,
    pub updated_ns: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct SearchResult {
    /// Matches before paging.
    pub total: u32,
    pub offset: u32,
    pub hits: Vec<Hit>,
}

fn hit(r: &Record) -> Hit {
    Hit {
        name: r.name.clone(),
        target: r.target.clone(),
        description: r.text("description").map(str::to_string),
        tags: tags_of(r),
        repo: r.text("repo").map(str::to_string),
        commit: r.text("commit").map(str::to_string),
        module_hash: r.text("module_hash").map(str::to_string),
        updated_ns: r.updated_ns,
    }
}

fn matches(r: &Record, q: &str) -> bool {
    if q.is_empty() {
        return true;
    }
    r.name.contains(q)
        || r.text("description")
            .map(|d| d.to_ascii_lowercase().contains(q))
            .unwrap_or(false)
}

pub fn search(query: SearchQuery) -> SearchResult {
    let q = query.q.unwrap_or_default().trim().to_ascii_lowercase();
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let mut total = 0u32;
    let mut hits = Vec::new();
    let mut consider = |r: &Record| {
        if !matches(r, &q) {
            return;
        }
        if total >= offset && hits.len() < limit as usize {
            hits.push(hit(r));
        }
        total += 1;
    };
    match query
        .tag
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        Some(tag) => {
            for name in names_with_tag(tag) {
                if let Some(r) = store::get_record(&name) {
                    consider(&r);
                }
            }
        }
        None => store::for_each_record(&mut consider),
    }
    SearchResult {
        total,
        offset,
        hits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Principal;

    fn rec(name: &str, description: &str, tags: &str) -> Record {
        let mut r = Record::new(
            name.to_string(),
            Principal::from_text("2vxsx-fae").unwrap(),
            Target::Address(Principal::from_text("umobs-yiaaa-aaaab-agyrq-cai").unwrap()),
            7,
        );
        r.text.push(("description".into(), description.into()));
        if !tags.is_empty() {
            r.text.push(("tags".into(), tags.into()));
        }
        r.text.sort();
        r
    }

    #[test]
    fn index_search_and_tags() {
        for r in [
            rec("alice/ic-git", "a git remote on a canister", "git,deploy"),
            rec("alice/ic-vote", "Voting for canisters", "vote"),
            rec("bob/site", "static site", ""),
        ] {
            index(&r);
            store::put_record(r);
        }
        assert_eq!(names_with_tag("git"), vec!["alice/ic-git"]);
        assert_eq!(
            tags(),
            vec![
                TagCount {
                    tag: "deploy".into(),
                    count: 1
                },
                TagCount {
                    tag: "git".into(),
                    count: 1
                },
                TagCount {
                    tag: "vote".into(),
                    count: 1
                },
            ]
        );

        let all = search(SearchQuery::default());
        assert_eq!(all.total, 3);
        assert_eq!(all.hits.len(), 3);

        let q = search(SearchQuery {
            q: Some("CANISTER".into()),
            ..Default::default()
        });
        assert_eq!(q.total, 2);
        assert_eq!(q.hits[0].name, "alice/ic-git");
        assert_eq!(q.hits[0].tags, vec!["git", "deploy"]);

        let by_tag = search(SearchQuery {
            tag: Some("git".into()),
            ..Default::default()
        });
        assert_eq!(by_tag.total, 1);
        assert_eq!(
            by_tag.hits[0].description.as_deref(),
            Some("a git remote on a canister")
        );

        let paged = search(SearchQuery {
            offset: Some(1),
            limit: Some(1),
            ..Default::default()
        });
        assert_eq!(paged.total, 3);
        assert_eq!(paged.hits.len(), 1);
        assert_eq!(paged.hits[0].name, "alice/ic-vote");

        // Retagging moves the name between tags.
        let old = store::get_record("alice/ic-git").unwrap();
        unindex(&old);
        let new = rec("alice/ic-git", "a git remote on a canister", "scm");
        index(&new);
        store::put_record(new);
        assert!(names_with_tag("git").is_empty());
        assert_eq!(names_with_tag("scm"), vec!["alice/ic-git"]);

        // Rebuild from records gives the same index.
        rebuild();
        assert_eq!(names_with_tag("scm"), vec!["alice/ic-git"]);
        assert_eq!(names_with_tag("vote"), vec!["alice/ic-vote"]);
        assert!(names_with_tag("git").is_empty());
    }
}

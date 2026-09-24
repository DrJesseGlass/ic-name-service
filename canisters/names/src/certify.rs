//! Certified resolution (DESIGN.md section 3).
//!
//! An in-heap hash tree mirrors RECORDS: key = scoped name, leaf = the
//! record's canonical bytes (store.rs). Its root, under the label "names",
//! is the canister's certified data, so a `resolve` query can return the
//! subnet's certificate plus a witness that a verifier checks against the
//! root without trusting the replica that answered.
//!
//! The tree is heap state and does not survive an upgrade; `rebuild` walks
//! stable memory in post_upgrade. Cost is one pass over all records, which
//! is fine at any scale this canister will see before delegation (M3)
//! splits the namespace.

use ic_certification::{labeled, labeled_hash, merge_hash_trees, AsHashTree, HashTree, RbTree};
use serde::Serialize;
use std::cell::RefCell;

const LABEL: &[u8] = b"names";

/// Alias chains longer than this fail to resolve. Answers the open question
/// in DESIGN.md section 11 with a default; raise it if a real use needs more.
pub const MAX_ALIAS_DEPTH: usize = 8;

thread_local! {
    static TREE: RefCell<RbTree<Vec<u8>, Vec<u8>>> = RefCell::new(RbTree::new());
}

fn root_hash() -> [u8; 32] {
    TREE.with(|t| labeled_hash(LABEL, &t.borrow().root_hash()))
}

/// Push the current root into certified data. No-op off the IC so unit
/// tests can drive the tree natively.
fn publish() {
    let root = root_hash();
    #[cfg(target_arch = "wasm32")]
    ic_cdk::api::certified_data_set(root);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = root;
}

pub fn set(name: &str, canonical: Vec<u8>) {
    TREE.with(|t| t.borrow_mut().insert(name.as_bytes().to_vec(), canonical));
    publish();
}

pub fn remove(name: &str) {
    TREE.with(|t| t.borrow_mut().delete(name.as_bytes()));
    publish();
}

/// Drop the tree and refill it from stable memory.
pub fn rebuild() {
    TREE.with(|t| {
        let mut t = t.borrow_mut();
        *t = RbTree::new();
        crate::store::for_each_canonical(|name, canonical| {
            t.insert(name.as_bytes().to_vec(), canonical);
        });
    });
    publish();
}

/// A witness covering every name in `names`, wrapped under the label, as
/// self-describing CBOR (what agent libraries expect for a hash tree).
pub fn witness(names: &[&str]) -> Vec<u8> {
    let tree: HashTree = TREE.with(|t| {
        let t = t.borrow();
        let mut merged: Option<HashTree> = None;
        for name in names {
            let w = t.witness(name.as_bytes());
            merged = Some(match merged {
                None => w,
                Some(m) => merge_hash_trees(m, w),
            });
        }
        merged.unwrap_or_else(|| t.as_hash_tree())
    });
    let tree = labeled(LABEL, tree);
    let mut ser = serde_cbor::Serializer::new(Vec::new());
    ser.self_describe().expect("cbor self-describe");
    tree.serialize(&mut ser).expect("cbor hash tree");
    ser.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_certification::{HashTree, LookupResult};

    fn decode(bytes: &[u8]) -> HashTree {
        serde_cbor::from_slice(bytes).unwrap()
    }

    #[test]
    fn witness_reveals_leaf_and_matches_root() {
        set("alice/a", b"A".to_vec());
        set("alice/b", b"B".to_vec());
        set("bob/c", b"C".to_vec());
        let root = root_hash();

        let w = decode(&witness(&["alice/b"]));
        assert_eq!(w.digest(), root);
        match w.lookup_path([b"names".as_slice(), b"alice/b"]) {
            LookupResult::Found(v) => assert_eq!(v, b"B"),
            other => panic!("expected leaf, got {other:?}"),
        }
        // Names not asked for are pruned, not revealed.
        assert!(!matches!(
            w.lookup_path([b"names".as_slice(), b"alice/a"]),
            LookupResult::Found(_)
        ));

        // A multi-name witness reveals every hop under the same root.
        let w = decode(&witness(&["alice/a", "bob/c"]));
        assert_eq!(w.digest(), root);
        assert!(matches!(
            w.lookup_path([b"names".as_slice(), b"alice/a"]),
            LookupResult::Found(_)
        ));
        assert!(matches!(
            w.lookup_path([b"names".as_slice(), b"bob/c"]),
            LookupResult::Found(_)
        ));

        // Removing a name changes the root and the witness proves absence.
        remove("alice/b");
        let root2 = root_hash();
        assert_ne!(root, root2);
        let w = decode(&witness(&["alice/b"]));
        assert_eq!(w.digest(), root2);
        assert!(matches!(
            w.lookup_path([b"names".as_slice(), b"alice/b"]),
            LookupResult::Absent
        ));
    }
}

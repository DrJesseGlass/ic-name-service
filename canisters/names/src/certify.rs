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
//!
//! HTTP responses are certified too, with a skip-certification expression
//! (HTTP gateway protocol v2): the gateway checks that this canister, not
//! a replica or boundary node, chose to serve the path uncertified. That
//! subtree is static, so certified data is the fork of its digest and the
//! names tree:
//!
//!   fork( labeled("http_expr", labeled("<*>", labeled(sha256(cel), leaf("")))),
//!         labeled("names", <name tree>) )
//!
//! A names witness prunes the left side; an HTTP witness prunes the right.
//! The shape matches what the ic-http-certification crate would build
//! (its test vector is checked below), without taking the dependency.

use ic_certification::{
    fork, fork_hash, labeled, labeled_hash, leaf, merge_hash_trees, pruned, AsHashTree, Hash,
    HashTree, RbTree,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::cell::RefCell;

const LABEL: &[u8] = b"names";

/// The CEL expression that tells the gateway to skip response
/// certification for every path. Sent in IC-CertificateExpression.
pub const SKIP_CEL: &str = "default_certification(ValidationArgs{no_certification:Empty{}})";

fn skip_tree() -> HashTree {
    let cel_hash: Hash = Sha256::digest(SKIP_CEL.as_bytes()).into();
    labeled(
        "http_expr",
        labeled("<*>", labeled(cel_hash, leaf(Vec::new()))),
    )
}

thread_local! {
    /// The skip subtree never changes, so its digest is computed once.
    static SKIP_DIGEST: Hash = skip_tree().digest();
}

fn skip_digest() -> Hash {
    SKIP_DIGEST.with(|d| *d)
}

/// Alias chains longer than this fail to resolve. Answers the open question
/// in DESIGN.md section 11 with a default; raise it if a real use needs more.
pub const MAX_ALIAS_DEPTH: usize = 8;

thread_local! {
    static TREE: RefCell<RbTree<Vec<u8>, Vec<u8>>> = const { RefCell::new(RbTree::new()) };
}

fn names_hash() -> Hash {
    TREE.with(|t| labeled_hash(LABEL, &t.borrow().root_hash()))
}

/// The certified data: fork of the static HTTP subtree and the names tree.
fn root_hash() -> Hash {
    fork_hash(&skip_digest(), &names_hash())
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
/// self-describing CBOR (what agent libraries expect for a hash tree). An
/// empty `names` yields a fully pruned tree, never the whole map.
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
        merged.unwrap_or_else(|| pruned(t.root_hash()))
    });
    let tree = fork(pruned(skip_digest()), labeled(LABEL, tree));
    cbor(&tree)
}

fn cbor(value: &impl Serialize) -> Vec<u8> {
    let mut ser = serde_cbor::Serializer::new(Vec::new());
    ser.self_describe().expect("cbor self-describe");
    value.serialize(&mut ser).expect("cbor");
    ser.into_inner()
}

/// The two headers that make a query response acceptable to a verifying
/// HTTP gateway: the certificate over the certified data and a witness
/// whose left side is the whole (static) HTTP subtree and whose right
/// side is the names tree pruned to its hash. None outside a query
/// context, where there is no certificate to give.
pub fn http_headers() -> Option<Vec<(String, String)>> {
    let certificate = ic_cdk::api::data_certificate()?;
    let witness = fork(skip_tree(), pruned(names_hash()));
    let expr_path = ["http_expr", "<*>"];
    let b64 = |b: &[u8]| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(b)
    };
    Some(vec![
        (
            "IC-Certificate".to_string(),
            format!(
                "certificate=:{}:, tree=:{}:, expr_path=:{}:, version=2",
                b64(&certificate),
                b64(&cbor(&witness)),
                b64(&cbor(&expr_path))
            ),
        ),
        ("IC-CertificateExpression".to_string(), SKIP_CEL.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_certification::{HashTree, LookupResult};

    fn decode(bytes: &[u8]) -> HashTree {
        serde_cbor::from_slice(bytes).unwrap()
    }

    #[test]
    fn skip_subtree_matches_the_http_certification_crate() {
        // ic-http-certification 4.0.0, utils/skip_certification.rs test
        // vector for skip_certification_certified_data().
        assert_eq!(
            skip_digest(),
            [
                85, 236, 195, 28, 62, 128, 71, 252, 21, 143, 32, 234, 10, 160, 96, 154, 172, 199,
                181, 126, 6, 234, 64, 220, 65, 134, 2, 114, 167, 214, 66, 145
            ]
        );
        // The HTTP witness and a names witness digest to the same root.
        set("alice/a", b"A".to_vec());
        let http = fork(skip_tree(), pruned(names_hash()));
        assert_eq!(http.digest(), root_hash());
        assert_eq!(decode(&witness(&["alice/a"])).digest(), root_hash());
        // The gateway looks up ["http_expr", "<*>", sha256(cel)] and must
        // find the empty leaf; the names side is pruned, not revealed.
        let cel_hash: Hash = Sha256::digest(SKIP_CEL.as_bytes()).into();
        assert!(matches!(
            http.lookup_path([b"http_expr".as_slice(), b"<*>", &cel_hash]),
            LookupResult::Found(b"")
        ));
        assert!(matches!(
            http.lookup_path([b"names".as_slice(), b"alice/a"]),
            LookupResult::Unknown
        ));
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

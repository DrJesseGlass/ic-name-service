//! Stage 1 HTTP gateway (DESIGN.md section 6): path based, fully on chain.
//!
//!   GET /<handle>/<label>              302 to https://<canister>.icp0.io/
//!   GET /api/resolve/<handle>/<label>  the certified answer as JSON
//!   GET /                              a short usage page
//!
//! Certification at the HTTP layer is not done yet, so responses are only
//! accepted by a verifying gateway when the call is upgraded to an update
//! (`upgrade = true`). The redirect and the index do that. The JSON
//! endpoint cannot: `data_certificate` is only available in a query, and
//! the whole point of the body is the certificate inside it. It is served
//! as a plain query response, which a `raw` gateway domain or a direct
//! replica request accepts, and the body carries its own proof. Certifying
//! the HTTP responses themselves (a skip-certification expression) is the
//! M1 follow-up.

use base64::Engine;
use candid::CandidType;
use serde::{Deserialize, Serialize};

#[derive(CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    pub upgrade: Option<bool>,
}

fn response(status_code: u16, content_type: &str, body: Vec<u8>, upgrade: bool) -> HttpResponse {
    HttpResponse {
        status_code,
        headers: vec![
            ("Content-Type".to_string(), content_type.to_string()),
            ("Cache-Control".to_string(), "no-cache".to_string()),
        ],
        body,
        upgrade: if upgrade { Some(true) } else { None },
    }
}

/// Path without query string or fragment.
fn path_of(url: &str) -> &str {
    let end = url.find(['?', '#']).unwrap_or(url.len());
    &url[..end]
}

/// `in_update` is true inside http_request_update: the response is final.
/// In the query, routes that need a verifying gateway ask for the upgrade.
pub fn handle(req: &HttpRequest, in_update: bool) -> HttpResponse {
    if req.method != "GET" && req.method != "HEAD" {
        return response(405, "text/plain", b"GET only\n".to_vec(), false);
    }
    let path = path_of(&req.url);
    if path == "/" {
        return response(200, "text/plain", index().into_bytes(), !in_update);
    }
    if let Some(name) = path.strip_prefix("/api/resolve/") {
        return api_resolve(name);
    }
    let name = path.trim_start_matches('/').trim_end_matches('/');
    match crate::resolve_inner(name.to_string()) {
        Ok(r) => {
            let location = format!("https://{}.icp0.io/", r.canister.to_text());
            let mut res = response(
                302,
                "text/plain",
                format!("{name} -> {location}\n").into_bytes(),
                !in_update,
            );
            res.headers.push(("Location".to_string(), location));
            res
        }
        Err(e) => response(404, "text/plain", format!("{e}\n").into_bytes(), !in_update),
    }
}

fn index() -> String {
    "ic-name-service\n\n\
     GET /<handle>/<label>              redirect to the canister\n\
     GET /api/resolve/<handle>/<label>  certified answer as JSON\n\n\
     Candid: resolve, get_record, list_names, register_handle, set_record.\n\
     See DESIGN.md in the repository.\n"
        .to_string()
}

#[derive(Serialize)]
struct JsonRecord {
    name: String,
    owner: String,
    target: JsonTarget,
    text: Vec<(String, String)>,
    created_ns: u64,
    updated_ns: u64,
    changed_hands_ns: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum JsonTarget {
    Address(String),
    Alias(String),
}

#[derive(Serialize)]
struct JsonResolved {
    name: String,
    canister: String,
    chain: Vec<JsonRecord>,
    /// base64 CBOR, as in the IC-Certificate header convention.
    certificate: Option<String>,
    /// base64 CBOR hash tree.
    witness: String,
}

fn api_resolve(name: &str) -> HttpResponse {
    let b64 = base64::engine::general_purpose::STANDARD;
    match crate::resolve_inner(name.to_string()) {
        Ok(r) => {
            let out = JsonResolved {
                name: r.name,
                canister: r.canister.to_text(),
                chain: r
                    .chain
                    .into_iter()
                    .map(|rec| JsonRecord {
                        name: rec.name,
                        owner: rec.owner.to_text(),
                        target: match rec.target {
                            crate::store::Target::Address(p) => JsonTarget::Address(p.to_text()),
                            crate::store::Target::Alias(n) => JsonTarget::Alias(n),
                        },
                        text: rec.text,
                        created_ns: rec.created_ns,
                        updated_ns: rec.updated_ns,
                        changed_hands_ns: rec.changed_hands_ns,
                    })
                    .collect(),
                certificate: r.certificate.map(|c| b64.encode(c)),
                witness: b64.encode(r.witness),
            };
            let body = serde_json::to_vec(&out).expect("json");
            response(200, "application/json", body, false)
        }
        Err(e) => {
            let body = serde_json::to_vec(&serde_json::json!({ "error": e })).expect("json");
            response(404, "application/json", body, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(path_of("/alice/ic-git?x=1"), "/alice/ic-git");
        assert_eq!(path_of("/api/resolve/a/b#frag"), "/api/resolve/a/b");
        assert_eq!(path_of("/"), "/");
    }
}

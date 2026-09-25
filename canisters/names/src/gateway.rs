//! Stage 1 HTTP gateway (DESIGN.md section 6): path based, fully on chain.
//!
//!   GET /<handle>/<label>              302 to https://<canister>.icp0.io/
//!   GET /<flat>                        302, or a warning page for a while
//!                                      after the name changed hands
//!   GET /api/resolve/<name>            the certified answer as JSON
//!                                      (timestamps as decimal strings)
//!   GET /api/search?q=&tag=&offset=&limit=   directory search as JSON
//!   GET /api/tags                      tags in use with counts
//!   GET /api/expiring?days=N           flat names running out within N days
//!   GET /.well-known/ic-domains        custom domains, for the boundary nodes
//!   GET /                              a short usage page
//!
//! Every response is a query response carrying the IC-Certificate and
//! IC-CertificateExpression headers (certify::http_headers), with a
//! skip-certification expression: the gateway verifies that this canister
//! chose to serve the path without certifying the body. That works on any
//! gateway domain, raw or not, with no update call. The resolve JSON body
//! carries its own proof (certificate and witness) for clients that want
//! more than the gateway's word.

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

fn response(status_code: u16, content_type: &str, body: Vec<u8>) -> HttpResponse {
    let mut headers = vec![
        ("Content-Type".to_string(), content_type.to_string()),
        ("Cache-Control".to_string(), "no-cache".to_string()),
    ];
    if let Some(cert) = crate::certify::http_headers() {
        headers.extend(cert);
    }
    HttpResponse {
        status_code,
        headers,
        body,
        upgrade: None,
    }
}

/// Minimal HTML escaping for the values that reach the warning page.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Path without query string or fragment.
fn path_of(url: &str) -> &str {
    let end = url.find(['?', '#']).unwrap_or(url.len());
    &url[..end]
}

/// Query string parameters, percent-decoded, first occurrence wins.
fn query_of(url: &str) -> Vec<(String, String)> {
    let Some(start) = url.find('?') else {
        return Vec::new();
    };
    let end = url.find('#').unwrap_or(url.len());
    if end <= start {
        return Vec::new();
    }
    url[start + 1..end]
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                // Two hex digits, checked byte by byte: slicing `s` here
                // would panic when a multibyte character follows the '%',
                // and from_str_radix would accept a leading '+'.
                let digit = |b: u8| (b as char).to_digit(16);
                match (digit(bytes[i + 1]), digit(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi * 16 + lo) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

pub fn handle(req: &HttpRequest) -> HttpResponse {
    if req.method != "GET" && req.method != "HEAD" {
        return response(405, "text/plain", b"GET only\n".to_vec());
    }
    let path = path_of(&req.url);
    if path == "/" {
        return response(200, "text/plain", index().into_bytes());
    }
    if let Some(name) = path.strip_prefix("/api/resolve/") {
        return api_resolve(name.trim_end_matches('/'));
    }
    if path == "/api/search" || path == "/api/search/" {
        return api_search(&query_of(&req.url));
    }
    if path == "/api/tags" || path == "/api/tags/" {
        let body = serde_json::to_vec(&crate::directory::tags()).expect("json");
        return response(200, "application/json", body);
    }
    if path == "/api/expiring" || path == "/api/expiring/" {
        return api_expiring(&query_of(&req.url));
    }
    if path == "/.well-known/ic-domains" {
        // What the boundary nodes read before registering a custom domain
        // for this canister: one hostname per line.
        let mut body = crate::domains_inner().join("\n");
        if !body.is_empty() {
            body.push('\n');
        }
        return response(200, "text/plain", body.into_bytes());
    }
    let name = path.trim_start_matches('/').trim_end_matches('/');
    match crate::follow(name) {
        Ok((canister, chain)) => {
            let location = format!("https://{}.icp0.io/", canister.to_text());
            if let Some(page) = handover_page(&chain, &location) {
                return response(200, "text/html; charset=utf-8", page.into_bytes());
            }
            let mut res = response(
                302,
                "text/plain",
                format!("{name} -> {location}\n").into_bytes(),
            );
            res.headers.push(("Location".to_string(), location));
            res
        }
        Err(e) => response(404, "text/plain", format!("{e}\n").into_bytes()),
    }
}

/// If any record in the chain changed hands within the configured warning
/// window and points somewhere new, a page saying so instead of a silent
/// redirect (DESIGN.md section 5: the forced sale must be visible). A new
/// holder who kept the old target changed nothing a visitor can see, so
/// that case redirects. Plain HTML, no scripts.
fn handover_page(chain: &[crate::store::Record], location: &str) -> Option<String> {
    let now = ic_cdk::api::time();
    let warn_ns = crate::harberger::config().handover_warn_ns;
    let r = chain.iter().find(|r| {
        r.previous_target.as_ref().is_some_and(|p| *p != r.target)
            && now.saturating_sub(r.changed_hands_ns) < warn_ns
    })?;
    let show = |t: &crate::store::Target| match t {
        crate::store::Target::Alias(n) => n.clone(),
        crate::store::Target::Address(p) => p.to_text(),
    };
    let prev = show(r.previous_target.as_ref()?);
    let now_target = show(&r.target);
    let days_ago = now.saturating_sub(r.changed_hands_ns) / 86_400_000_000_000;
    let (name, prev, now_target, location) =
        (esc(&r.name), esc(&prev), esc(&now_target), esc(location));
    Some(format!(
        "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>{name} changed hands</title>\n\
         <style>body{{font-family:sans-serif;max-width:40em;margin:3em auto;padding:0 1em;line-height:1.5}}\
         code{{background:#eee;padding:0 .3em}}</style></head><body>\n\
         <h1>{name} changed hands</h1>\n\
         <p>The name <code>{name}</code> changed hands {days_ago} day(s) ago. Until then it pointed at\n\
         <code>{prev}</code>. It now points at <code>{now_target}</code>.</p>\n\
         <p>A flat name is a vanity handle that anyone may buy at its listed price. The scoped name\n\
         under it is the identity that does not change hands. If you meant the site you visited\n\
         before, use the old scoped name.</p>\n\
         <p><a href=\"{location}\">Continue to {now_target}</a></p>\n\
         <p><a href=\"/{prev}\">Go to {prev} instead</a></p>\n\
         </body></html>\n"
    ))
}

fn index() -> String {
    "ic-name-service\n\n\
     GET /<name>                        redirect to the canister\n\
     GET /api/resolve/<name>            certified answer as JSON\n\
     (a name is <handle>/<label>, or a flat name aliasing one)\n\
     GET /api/search?q=&tag=            directory search as JSON\n\
     GET /api/tags                      tags in use\n\
     GET /api/expiring?days=N           flat names running out soon\n\n\
     Candid: resolve, get_record, list_names, register_handle, set_record.\n\
     See DESIGN.md in the repository.\n"
        .to_string()
}

/// Timestamps are decimal strings: nanoseconds since the epoch exceed
/// 2^53, so a JSON number would be rounded by JavaScript and the client
/// could no longer rebuild the canonical bytes the witness commits to.
#[derive(Serialize)]
struct JsonRecord {
    name: String,
    owner: String,
    target: JsonTarget,
    text: Vec<(String, String)>,
    created_ns: String,
    updated_ns: String,
    changed_hands_ns: String,
    /// Flat names only; the four Harberger lines of the canonical form.
    #[serde(skip_serializing_if = "Option::is_none")]
    flat: Option<JsonHarberger>,
    /// Set once the name has changed hands; see changed_hands_ns.
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_target: Option<JsonTarget>,
}

/// Amounts and times as decimal strings, for the same reason as the
/// timestamps above: cycles exceed 2^53.
#[derive(Serialize)]
struct JsonHarberger {
    price: String,
    balance: String,
    settled_ns: String,
    lapsed_ns: Option<String>,
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
                        created_ns: rec.created_ns.to_string(),
                        updated_ns: rec.updated_ns.to_string(),
                        changed_hands_ns: rec.changed_hands_ns.to_string(),
                        flat: rec.flat.map(|h| JsonHarberger {
                            price: h.price.to_string(),
                            balance: h.balance.to_string(),
                            settled_ns: h.settled_ns.to_string(),
                            lapsed_ns: h.lapsed_ns.map(|t| t.to_string()),
                        }),
                        previous_target: rec.previous_target.map(|t| match t {
                            crate::store::Target::Address(p) => JsonTarget::Address(p.to_text()),
                            crate::store::Target::Alias(n) => JsonTarget::Alias(n),
                        }),
                    })
                    .collect(),
                certificate: r.certificate.map(|c| b64.encode(c)),
                witness: b64.encode(r.witness),
            };
            let body = serde_json::to_vec(&out).expect("json");
            response(200, "application/json", body)
        }
        Err(e) => {
            let body = serde_json::to_vec(&serde_json::json!({ "error": e })).expect("json");
            response(404, "application/json", body)
        }
    }
}

/// Search JSON. Hits mirror directory::Hit with the timestamp as a
/// decimal string (see JsonRecord).
#[derive(Serialize)]
struct JsonHit {
    name: String,
    target: JsonTarget,
    description: Option<String>,
    tags: Vec<String>,
    repo: Option<String>,
    commit: Option<String>,
    module_hash: Option<String>,
    updated_ns: String,
}

#[derive(Serialize)]
struct JsonSearch {
    total: u32,
    offset: u32,
    hits: Vec<JsonHit>,
}

fn api_search(params: &[(String, String)]) -> HttpResponse {
    let num = |k: &str| param(params, k).and_then(|v| v.parse::<u32>().ok());
    let result = crate::directory::search(crate::directory::SearchQuery {
        q: param(params, "q").map(str::to_string),
        tag: param(params, "tag").map(str::to_string),
        offset: num("offset"),
        limit: num("limit"),
    });
    let out = JsonSearch {
        total: result.total,
        offset: result.offset,
        hits: result
            .hits
            .into_iter()
            .map(|h| JsonHit {
                name: h.name,
                target: match h.target {
                    crate::store::Target::Address(p) => JsonTarget::Address(p.to_text()),
                    crate::store::Target::Alias(n) => JsonTarget::Alias(n),
                },
                description: h.description,
                tags: h.tags,
                repo: h.repo,
                commit: h.commit,
                module_hash: h.module_hash,
                updated_ns: h.updated_ns.to_string(),
            })
            .collect(),
    };
    let body = serde_json::to_vec(&out).expect("json");
    response(200, "application/json", body)
}

#[derive(Serialize)]
struct JsonExpiring {
    name: String,
    owner: String,
    status: String,
    /// When the balance runs out (active) or the grace period ends
    /// (grace), nanoseconds, as a decimal string.
    deadline_ns: String,
    balance: String,
    tax_per_year: String,
}

fn api_expiring(params: &[(String, String)]) -> HttpResponse {
    let days = param(params, "days")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30)
        .min(3650);
    let within_ns = days * 86_400_000_000_000;
    let out: Vec<JsonExpiring> = crate::expiring_inner(within_ns)
        .into_iter()
        .map(|e| JsonExpiring {
            name: e.name,
            owner: e.owner.to_text(),
            status: match e.status {
                crate::harberger::Status::Active => "active".to_string(),
                crate::harberger::Status::Grace { .. } => "grace".to_string(),
                crate::harberger::Status::Free => "free".to_string(),
            },
            deadline_ns: e.deadline_ns.to_string(),
            balance: e.balance.to_string(),
            tax_per_year: e.tax_per_year.to_string(),
        })
        .collect();
    let body = serde_json::to_vec(&out).expect("json");
    response(200, "application/json", body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_strings() {
        let q = query_of("/api/search?q=ic%20git&tag=deploy&limit=5#x");
        assert_eq!(param(&q, "q"), Some("ic git"));
        assert_eq!(param(&q, "tag"), Some("deploy"));
        assert_eq!(param(&q, "limit"), Some("5"));
        assert_eq!(param(&q, "offset"), None);
        assert!(query_of("/api/search").is_empty());
        assert_eq!(percent_decode("a+b%2Fc%zz"), "a b/c%zz");
        // A multibyte character right after a '%' must not panic, and a
        // sign is not a hex digit (the '+' then decodes as a space).
        assert_eq!(percent_decode("%a\u{e9}"), "%a\u{e9}");
        assert_eq!(percent_decode("%+1"), "% 1");
        assert_eq!(percent_decode("%41"), "A");
    }

    #[test]
    fn paths() {
        assert_eq!(path_of("/alice/ic-git?x=1"), "/alice/ic-git");
        assert_eq!(path_of("/api/resolve/a/b#frag"), "/api/resolve/a/b");
        assert_eq!(path_of("/"), "/");
    }
}

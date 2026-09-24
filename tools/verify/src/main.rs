//! Independent verifier for ic-name-service certified resolution.
//!
//! Calls `resolve` on the names canister and checks, from the caller's own
//! trust domain, that the answer is what the subnet certified:
//!
//!   A. the certificate's BLS signature (and any subnet delegation) checks
//!      out against the IC root key, and the certificate is fresh;
//!   B. /canister/<names>/certified_data in the certificate equals the
//!      digest of the returned witness tree;
//!   C. for every record in the returned chain, the witness has a leaf at
//!      ["names", <name>] equal to that record's canonical form, rebuilt
//!      here from the candid record (the format is documented in
//!      canisters/names/names.did and reimplemented on purpose, so this
//!      file does not share code with the canister);
//!   D. the chain is well formed: the answer is for the name asked, the
//!      chain starts at it, every alias points at the next record, and the
//!      last record's address is the canister the answer names.
//!
//! Usage:
//!   cargo run --manifest-path tools/verify/Cargo.toml -- \
//!     --canister <names canister id> [--url <boundary node>] \
//!     [--insecure-local-root-key] <name>
//!
//! The IC root key ships with the agent and is what every certificate is
//! checked against, whatever --url points at. A local dfx replica has its
//! own root key, so verifying against one needs --insecure-local-root-key,
//! which fetches the key from the endpoint itself. That trusts the endpoint
//! completely and is never correct for a mainnet check: a proxy that could
//! hand out its own root key could forge everything the tool verifies.
//!
//! --tamper witness|record corrupts the answer after it is received, to
//! show that checks B and C fail on a forged answer. Self-test only.
//!
//! Exit codes: 0 verified, 1 verification failed, 2 usage or transport.

use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use ic_certification::{Certificate, HashTree, LookupResult};
use serde::Deserialize;

#[derive(CandidType, Deserialize, Clone, Debug)]
enum Target {
    #[serde(rename = "address")]
    Address(Principal),
    #[serde(rename = "alias")]
    Alias(String),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct Record {
    name: String,
    owner: Principal,
    target: Target,
    text: Vec<(String, String)>,
    created_ns: u64,
    updated_ns: u64,
    changed_hands_ns: u64,
}

#[derive(CandidType, Deserialize, Debug)]
struct Resolved {
    name: String,
    canister: Principal,
    chain: Vec<Record>,
    certificate: Option<Vec<u8>>,
    witness: Vec<u8>,
}

/// The certified leaf format, from names.did. Independent of the canister.
fn canonical(r: &Record) -> Vec<u8> {
    let mut s = String::new();
    s.push_str(&format!("name={}\n", r.name));
    s.push_str(&format!("owner={}\n", r.owner.to_text()));
    match &r.target {
        Target::Address(p) => s.push_str(&format!("target=address:{}\n", p.to_text())),
        Target::Alias(n) => s.push_str(&format!("target=alias:{n}\n")),
    }
    for (k, v) in &r.text {
        s.push_str(&format!("text.{k}={v}\n"));
    }
    s.push_str(&format!("created_ns={}\n", r.created_ns));
    s.push_str(&format!("updated_ns={}\n", r.updated_ns));
    s.push_str(&format!("changed_hands_ns={}\n", r.changed_hands_ns));
    s.into_bytes()
}

struct Opts {
    url: String,
    canister: Principal,
    name: String,
    tamper: Option<String>,
    insecure_local_root_key: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: names-verify --canister <id> [--url <replica url>] [--insecure-local-root-key] \
         [--tamper witness|record] <handle>/<label>"
    );
    std::process::exit(2);
}

fn parse_args() -> Opts {
    let mut url = "https://icp-api.io".to_string();
    let mut canister = None;
    let mut name = None;
    let mut tamper = None;
    let mut insecure_local_root_key = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--url" => url = args.next().unwrap_or_else(|| usage()),
            "--canister" => {
                let text = args.next().unwrap_or_else(|| usage());
                canister = Some(Principal::from_text(&text).unwrap_or_else(|e| {
                    eprintln!("bad canister id: {e}");
                    usage()
                }));
            }
            "--tamper" => tamper = Some(args.next().unwrap_or_else(|| usage())),
            "--insecure-local-root-key" => insecure_local_root_key = true,
            "-h" | "--help" => usage(),
            _ if a.starts_with('-') => usage(),
            _ => name = Some(a),
        }
    }
    Opts {
        url,
        canister: canister.unwrap_or_else(|| usage()),
        name: name.unwrap_or_else(|| usage()),
        tamper,
        insecure_local_root_key,
    }
}

fn fail(step: &str, why: impl std::fmt::Display) -> ! {
    println!("FAILED at {step}: {why}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let opts = parse_args();

    let agent = Agent::builder()
        .with_url(&opts.url)
        .build()
        .unwrap_or_else(|e| {
            eprintln!("agent: {e}");
            std::process::exit(2)
        });
    if opts.insecure_local_root_key {
        // Trust the endpoint's own root key. Only for a local replica; the
        // flag name says what it costs. Without it the agent's built-in IC
        // root key is used, whatever --url is.
        agent.fetch_root_key().await.unwrap_or_else(|e| {
            eprintln!("fetch_root_key: {e}");
            std::process::exit(2)
        });
        println!(
            "root key            : fetched from {} (INSECURE, local only)",
            opts.url
        );
    }

    let arg = Encode!(&opts.name).expect("encode name");
    let raw = agent
        .query(&opts.canister, "resolve")
        .with_arg(arg)
        .call()
        .await
        .unwrap_or_else(|e| {
            eprintln!("resolve call: {e}");
            std::process::exit(2)
        });
    let mut resolved = match Decode!(&raw, Result<Resolved, String>) {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => fail("resolve", format!("canister returned Err: {e}")),
        Err(e) => fail("decode", e),
    };
    match opts.tamper.as_deref() {
        None => {}
        Some("witness") => {
            // Flip a bit in the last byte, which sits inside a leaf or a
            // pruned hash, so the tree no longer digests to the root.
            let last = resolved.witness.len() - 1;
            resolved.witness[last] ^= 0x01;
            println!("tamper              : witness byte flipped");
        }
        Some("record") => {
            resolved.chain[0].updated_ns += 1;
            println!("tamper              : chain[0].updated_ns changed");
        }
        Some(other) => fail("usage", format!("unknown --tamper {other}")),
    }
    println!("name                : {}", resolved.name);
    println!("canister            : {}", resolved.canister.to_text());
    println!("chain               : {}", resolved.chain.len());

    // A. certificate signature, delegation and freshness.
    let cert_bytes = resolved
        .certificate
        .as_deref()
        .unwrap_or_else(|| fail("A", "no certificate in the answer"));
    let cert: Certificate = serde_cbor::from_slice(cert_bytes)
        .unwrap_or_else(|e| fail("A", format!("certificate cbor: {e}")));
    agent
        .verify(&cert, opts.canister)
        .unwrap_or_else(|e| fail("A", format!("certificate does not verify: {e}")));
    println!("A certificate       : ok (signed by the subnet, fresh)");

    // B. certified_data equals the witness digest.
    let certified_data = ic_agent::lookup_value(
        &cert,
        [
            b"canister".as_slice(),
            opts.canister.as_slice(),
            b"certified_data",
        ],
    )
    .unwrap_or_else(|e| fail("B", format!("certified_data not in certificate: {e}")));
    let witness: HashTree = serde_cbor::from_slice(&resolved.witness)
        .unwrap_or_else(|e| fail("B", format!("witness cbor: {e}")));
    let digest = witness.digest();
    if certified_data != digest.as_slice() {
        fail(
            "B",
            format!(
                "witness root {} != certified_data {}",
                hex(&digest),
                hex(certified_data)
            ),
        );
    }
    println!("B witness root      : ok ({})", hex(&digest));

    // C. every record in the chain is a leaf of the witness.
    for r in &resolved.chain {
        let want = canonical(r);
        match witness.lookup_path([b"names".as_slice(), r.name.as_bytes()]) {
            LookupResult::Found(got) if got == want.as_slice() => {}
            LookupResult::Found(got) => fail(
                "C",
                format!(
                    "leaf for {} differs from the returned record:\n--- leaf\n{}--- record\n{}",
                    r.name,
                    String::from_utf8_lossy(got),
                    String::from_utf8_lossy(&want)
                ),
            ),
            other => fail("C", format!("no leaf for {} in witness: {other:?}", r.name)),
        }
    }
    println!(
        "C leaves            : ok ({} record(s) match)",
        resolved.chain.len()
    );

    // D. the chain is what it claims.
    if resolved.name != opts.name {
        fail(
            "D",
            format!("answer is for {} not {}", resolved.name, opts.name),
        );
    }
    if resolved.chain.is_empty() {
        fail("D", "empty chain");
    }
    if resolved.chain[0].name != resolved.name {
        fail(
            "D",
            format!(
                "chain starts at {} not {}",
                resolved.chain[0].name, resolved.name
            ),
        );
    }
    for w in resolved.chain.windows(2) {
        match &w[0].target {
            Target::Alias(n) if *n == w[1].name => {}
            other => fail(
                "D",
                format!("{} does not alias {}: {other:?}", w[0].name, w[1].name),
            ),
        }
    }
    let last = resolved.chain.last().unwrap();
    match &last.target {
        Target::Address(p) if *p == resolved.canister => {}
        other => fail(
            "D",
            format!(
                "last record {} is not the answer's address: {other:?}",
                last.name
            ),
        ),
    }
    println!("D chain             : ok");
    println!(
        "VERIFIED {} -> {}",
        resolved.name,
        resolved.canister.to_text()
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

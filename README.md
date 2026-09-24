# ic-name-service

A resolver plus registry for canisters on the Internet Computer. A caller
asks for a name and gets a canister id plus a subnet certificate, then talks
to the target directly. Design brief: DESIGN.md.

State: milestones M0 and M1 (DESIGN.md section 10). Scoped names
(`<handle>/<label>`), address and alias targets, text records, certified
`resolve` with an independent verifier, `announce` gated by caller
principal, the stage 1 HTTP gateway, the ic-git hook, and the directory:
tags and search. Not yet deployed; deployment will go through ic-git.

## Layout

    canisters/names/         the canister (Rust, ic-cdk 0.20)
      names.did              public interface, with the certified leaf format
      src/lib.rs             endpoints and lifecycle
      src/names.rs           name grammar, text record and hex limits
      src/store.rs           stable-memory handles, records, deployer list
      src/certify.rs         hash tree over records, certified data, witnesses
      src/directory.rs       tag index and search
      src/gateway.rs         HTTP: /<name> -> 302, /api/* -> JSON
    tools/verify/            independent verifier of a resolve answer (own
                             cargo workspace; uses ic-agent)
    tools/smoke-test.sh      end-to-end run against a local replica
    tools/reproducible-build.sh, Dockerfile.build, tools/build-env.sh
                             the ic-git build recipe, unchanged in substance

## Interface

    register_handle : (text) -> (Result)                    claim <handle>, permanent
    set_record      : (text, Target) -> (Result)            <handle>/<label> -> address | alias
    set_text        : (text, text, opt text) -> (Result)    key/value metadata on a name
    delete_record   : (text) -> (Result)
    get_record      : (text) -> (opt Record) query
    list_names      : (text) -> (vec text) query            names under a handle
    resolve         : (text) -> (ResolveResult) query       follows aliases, certified
    handle_owner    : (text) -> (opt principal) query
    get_handle      : (text) -> (opt Handle) query
    set_handle_deployer : (text, opt principal) -> (Result) let a deployer announce here
    add_deployer / remove_deployer : (principal) -> (Result) controllers only
    list_deployers  : () -> (vec principal) query
    announce        : (Announcement) -> (Result)            listed deployers only
    search          : (SearchQuery) -> (SearchResult) query  substring and tag, paged
    tags            : () -> (vec TagCount) query
    http_request    : (HttpRequest) -> (HttpResponse) query
    http_request_update : (HttpRequest) -> (HttpResponse)

Writes require the caller to own the handle. Resolution visits at most 8
records (the name plus 7 alias hops) and refuses loops.

## Announce

A deployer such as ic-git calls `announce` after a successful install with
the scoped name, the target canister, the repo, the commit and the module
hash. The call is trusted because the caller principal is on the deployer
list, which controllers manage. The deployer may write under a handle it
owns or one whose owner named it with `set_handle_deployer`. An
unregistered handle is registered to the deployer on first announce, so a
git push lists an app with nobody registering first. The record's target
becomes the canister and its text records carry repo, commit, module_hash,
deployer and announced_ns.

The ic-git side is one optional module (canisters/git/src/names.rs there)
behind `names_set_config(canister, handle)`: every repo of that instance is
announced as `<handle>/<repo>`, and a refused or failed announce is noted
in the deploy status without failing the deploy.

## Directory

A registry answers "where is X"; the directory answers "what exists".
Tags come from the `tags` text record: comma separated, no spaces, each
tag in the handle grammar, at most 16. A stable-memory index keyed by tag,
kept in step on every write, answers `search` by tag with a range scan; a
substring query over names and descriptions is a pass over all records, which is right at any size
this canister will see before delegation. Hits carry the description, the
tags and the provenance text records (repo, commit, module_hash) that
announce fills in. `/api/search?q=&tag=&offset=&limit=` and `/api/tags`
serve the same over HTTP.

The verifier's check E closes the loop: when the final record pins a
module_hash, the target canister's live module hash is read from the IC
state tree and must match, so a name whose target was upgraded away from
the announced code fails verification instead of silently routing.

## HTTP gateway, stage 1

    GET /<handle>/<label>              302 to https://<canister>.icp0.io/
    GET /api/resolve/<handle>/<label>  the certified answer as JSON
    GET /api/search?q=&tag=&offset=&limit=   directory search as JSON
    GET /api/tags                      tags in use with counts
    GET /                              usage

HTTP responses are not certified yet. The redirect, the index, search and
tags ask the gateway to upgrade the call to an update, so they work on any
domain. The resolve JSON endpoint cannot, because the certificate inside
the body only exists in a query, so it is served as a plain query: use a
`raw` gateway domain or a direct replica request, and verify the body.
Certifying the HTTP responses themselves is the M1 follow-up.

## Certified resolution

`resolve` is a query, so its answer is not signed by the subnet on its own.
The canister keeps a hash tree over every record, keyed by name, with the
record's canonical text form as the leaf, and publishes the tree's root
(under the label `names`) as certified data. The answer carries the
certificate over that root and a witness revealing the leaf of every record
in the alias chain. The canonical form is documented in names.did; a
verifier rebuilds it from the returned record and checks it equals the
leaf. Nothing in the answer needs to be trusted from the replica.

tools/verify is that verifier, written without sharing code with the
canister. It checks (A) the certificate's signature, delegation and
freshness against the IC root key, (B) that certified_data in the
certificate equals the witness digest, (C) that every record in the chain
is a leaf of the witness with the canonical bytes, (D) that the chain
starts at the requested name, links by alias, and ends at the answered
canister, and (E) that a pinned module_hash matches the target's live
module hash. `--tamper witness|record` forges the answer after receipt to show
B and C fail; the smoke test runs both.

    cargo run --release --manifest-path tools/verify/Cargo.toml -- \
      --canister <id> [--url <boundary node>] <handle>/<label>

Certificates are always checked against the IC root key the agent ships
with, whatever --url is. A local dfx replica has its own key, so a local
check needs --insecure-local-root-key, which trusts the endpoint for the
key and is never correct against mainnet.

## Build and test

    cargo test -p name_canister        unit tests, native
    dfx start --background             a local replica
    tools/smoke-test.sh                deploy, register, resolve, verify,
                                       announce, gateway, upgrade
    tools/reproducible-build.sh        native build, prints the module sha256
    tools/reproducible-build.sh --docker   the portable build that attestations use

Toolchain pins: rust 1.94.1 (rust-toolchain.toml), dfx 0.31.0. Build through
the script, not a bare `dfx build`, so the path remapping applies and the
hash is machine independent.

## Reproducible build

Same recipe as ic-git: a pinned container (Dockerfile.build) runs the same
cargo and ic-wasm pipeline dfx uses, with `--remap-path-prefix` set by
tools/build-env.sh so no host path reaches the wasm. `dfx build --check`
is used in place of a mainnet build because the canister id is not embedded
in the module, which lets the recipe run offline before the first deploy.
Once the canister is deployed, `tools/reproducible-build.sh --check`
compares the built hash against the on-chain module hash, and verified.json
records each attested tag.

Conventions: pure ASCII in source, messages and docs; no unicode.

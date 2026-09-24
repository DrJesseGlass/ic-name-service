# ic-name-service

A resolver plus registry for canisters on the Internet Computer. A caller
asks for a name and gets a canister id plus a subnet certificate, then talks
to the target directly. Design brief: DESIGN.md.

State: milestone M0 (DESIGN.md section 10). Scoped names
(`<handle>/<label>`), address and alias targets, text records, certified
`resolve` with an independent verifier, `announce` gated by caller
principal, the stage 1 HTTP gateway, and the ic-git hook. Not yet deployed
to mainnet.

## Layout

    canisters/names/         the canister (Rust, ic-cdk 0.20)
      names.did              public interface, with the certified leaf format
      src/lib.rs             endpoints and lifecycle
      src/names.rs           name grammar, text record and hex limits
      src/store.rs           stable-memory handles, records, deployer list
      src/certify.rs         hash tree over records, certified data, witnesses
      src/gateway.rs         HTTP: /<name> -> 302, /api/resolve/<name> -> JSON
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
    http_request    : (HttpRequest) -> (HttpResponse) query
    http_request_update : (HttpRequest) -> (HttpResponse)

Writes require the caller to own the handle. Aliases are followed up to 8
hops and loops are refused.

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

## HTTP gateway, stage 1

    GET /<handle>/<label>              302 to https://<canister>.icp0.io/
    GET /api/resolve/<handle>/<label>  the certified answer as JSON
    GET /                              usage

HTTP responses are not certified yet. The redirect and the index ask the
gateway to upgrade the call to an update, so they work on any domain. The
JSON endpoint cannot, because the certificate inside the body only exists
in a query, so it is served as a plain query: use a `raw` gateway domain or
a direct replica request, and verify the body. Certifying the HTTP
responses themselves is the M1 follow-up.

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
is a leaf of the witness with the canonical bytes, and (D) that the chain
starts at the requested name, links by alias, and ends at the answered
canister. `--tamper witness|record` forges the answer after receipt to show
B and C fail; the smoke test runs both.

    cargo run --release --manifest-path tools/verify/Cargo.toml -- \
      --canister <id> [--url http://127.0.0.1:4943] <handle>/<label>

Without --url it talks to mainnet and never fetches a root key.

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

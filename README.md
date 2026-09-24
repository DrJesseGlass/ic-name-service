# ic-name-service

A resolver plus registry for canisters on the Internet Computer. A caller
asks for a name and gets a canister id plus a subnet certificate, then talks
to the target directly. Design brief: DESIGN.md.

State: milestone M0, the resolve half. Scoped names (`<handle>/<label>`),
address and alias targets, text records, certified `resolve`. Announce, the
HTTP gateway and the ic-git hook are next (DESIGN.md section 10).

## Layout

    canisters/names/         the canister (Rust, ic-cdk 0.20)
      names.did              public interface, with the certified leaf format
      src/lib.rs             endpoints and lifecycle
      src/names.rs           name grammar and text record limits
      src/store.rs           stable-memory handles and records
      src/certify.rs         hash tree over records, certified data, witnesses
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

Writes require the caller to own the handle. Aliases are followed up to 8
hops and loops are refused.

## Certified resolution

`resolve` is a query, so its answer is not signed by the subnet on its own.
The canister keeps a hash tree over every record, keyed by name, with the
record's canonical text form as the leaf, and publishes the tree's root
(under the label `names`) as certified data. The answer carries the
certificate over that root and a witness revealing the leaf of every record
in the alias chain. The canonical form is documented in names.did; a
verifier rebuilds it from the returned record and checks it equals the
leaf. Nothing in the answer needs to be trusted from the replica.

## Build and test

    cargo test -p name_canister        unit tests, native
    dfx start --background             a local replica
    tools/smoke-test.sh                deploy, register, resolve, upgrade
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

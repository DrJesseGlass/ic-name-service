# ic-name-service

A resolver plus registry for canisters on the Internet Computer. A caller
asks for a name and gets a canister id plus a subnet certificate, then talks
to the target directly. Design brief: DESIGN.md.

State: milestones M0 to M2 (DESIGN.md section 10). Scoped names
(`<handle>/<label>`), address and alias targets, text records, certified
`resolve` with an independent verifier, `announce` gated by caller
principal, the stage 1 HTTP gateway, the ic-git hook, the directory (tags
and search), and flat names under a Harberger tax paid in cycles. Not yet
deployed; deployment will go through ic-git.

## Layout

    canisters/names/         the canister (Rust, ic-cdk 0.20)
      names.did              public interface, with the certified leaf format
      src/lib.rs             endpoints and lifecycle
      src/names.rs           name grammar, text record and hex limits
      src/store.rs           stable-memory handles, records, deployer list
      src/certify.rs         hash tree over records, certified data, witnesses
      src/directory.rs       tag index and search
      src/harberger.rs       tax arithmetic, lazy settlement, config
      src/ledger.rs          cycles ledger client (ICRC-1, ICRC-2)
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
    claim           : (text, text, nat, nat) -> (Result)     flat name, alias_to, price, deposit
    buy             : (text, text, nat, nat, nat) -> (Result) plus max_price, the buyer's cap
    expiring        : (nat64) -> (vec Expiring) query       names running out within ns
    deposit         : (text, nat) -> (Result)               top up a flat name
    set_price       : (text, nat) -> (Result)               reassess a held flat name
    flat_status     : (text) -> (opt FlatStatus) query      settled to now
    credit / withdraw                                       proceeds owed, paid out on request
    treasury / fund_self                                    tax collected; controllers move it
    search          : (SearchQuery) -> (SearchResult) query  substring and tag, paged
    tags            : () -> (vec TagCount) query
    http_request    : (HttpRequest) -> (HttpResponse) query

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

## Flat names and the Harberger tax

A flat name (`ic-git`, one segment) is scarce and marketable. It always
aliases a scoped name, so a sale never changes what the scoped identity
means. The holder self-assesses a price and prepays a balance in cycles;
tax accrues on the price at the configured rate (7 percent a year by
default) and is settled lazily on every read and write, with no timers.
Anyone may buy the name at the assessed price at any time. The seller is
credited the price plus the unspent balance and withdraws it to the cycles
ledger when they like. When the balance runs out the name enters a grace
period (30 days by default), after which it is free to claim.

The market is closed by default: `flat_names_open` in the config gates
new claims, so a release can ship scoped names alone and open flat names
later. Buying a held name is never gated, because the forced sale is what
keeps a holder's price honest; closing the market stops new names, not
the pressure on existing ones. Holders can always top up, reassess,
withdraw and release. A buy carries a `max_price`, the price the buyer
saw, and is refused if the seller has since moved above it.

Payments are ICRC-2 pulls from the caller's cycles ledger account, so a
caller first approves this canister as a spender for the amount plus the
ledger fee. A claim or buy must deposit at least one grace period of tax
at the assessed price, and a top-up must leave at least that much, so a
name is never held on credit. There is a
minimum price and a maximum, and a reserved name list (`api`). Collected
tax stays in this canister's ledger account until a controller moves it
into the canister's own cycles with `fund_self`; prepaid balances and
credits in the same account are never touched. A ledger reply this code
cannot decode is not treated as "nothing moved": the amount is recorded
as unreconciled in `treasury` for the operator to check against the
ledger's blocks, and no credit is given back or paid twice. Tax is counted when a
settled record is written, never on a read or a refused call, and every
payout (withdraw, fund_self) takes the ledger fee out of the amount, so
the counters match the account to the cycle.

Every payment method validates, pulls, then re-reads the record, and if
the name changed hands during the pull it credits the payer back and
fails, so two buyers racing for one name cannot both pay.

Config changes are guarded. The ledger's transfer fee is read from the
ledger when the config is set and pinned on every transfer, so a fee
change makes a transfer fail instead of quietly debiting more than the
books record. A rate change settles every flat name under the old rate
first, so the new rate never reaches back in time. The ledger itself can
only change while nothing is held there: no flat names, credits,
unwithdrawn tax, unreconciled amounts, or calls in flight.

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
    GET /api/expiring?days=N           flat names running out within N days
    GET /                              usage

Every response is a query response with the IC-Certificate and
IC-CertificateExpression headers carrying a skip-certification expression
(HTTP gateway protocol v2). The gateway verifies that this canister, not a
replica or boundary node, chose to serve the path uncertified, so the
routes work on any gateway domain with no update call. Certified data is
the fork of that static HTTP subtree and the names tree; the resolve JSON
body still carries its own certificate and witness for clients that want
proof of the answer itself.

After a flat name changes hands, `/<flat>` serves a plain HTML page for
the configured window (30 days by default) instead of redirecting: it
names the date, the old target and the new one, and links to both. The
record keeps `previous_target`, which is certified, and the verifier
prints the same warning. `/api/expiring?days=N` lists flat names whose
balance runs out, or whose grace period ends, within N days, for holders
and their tooling to poll.

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
    dfx deps deploy                    the cycles ledger, for the flat name tests
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

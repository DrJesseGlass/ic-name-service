# Security

## Reporting a vulnerability

Report it privately, not in a public issue or pull request:

    https://github.com/DrJesseGlass/ic-name-service/security/advisories/new

That form opens a draft advisory only the maintainer and you can see. Say
what you found, how to reproduce it, and which piece it is in (below).
Expect an acknowledgement within a week.

A bug that is not a security problem is an ordinary issue:
https://github.com/DrJesseGlass/ic-name-service/issues/new/choose

## What counts

ic-name-service's promise is that a name resolves to the target its owner
or a listed deployer set, that the answer can be proved against the IC
root key without trusting a replica, and that the cycles it holds for
flat names are owed to exactly who the books say. Anything that breaks
that promise is in scope, in particular:

- records and ownership (`canisters/names/src/lib.rs`, `store.rs`,
  `names.rs`): a handle, record or text record written or deleted by a
  caller who does not own the handle; an `announce` accepted from a
  principal that is not on the deployer list, or under a registered
  handle that neither belongs to that deployer nor named it with
  `set_handle_deployer`; provenance (repo, commit, module_hash, deployer,
  announced_ns) forged or kept on a name it does not describe; an admin
  method (deployer list, tax and auction config, treasury, domains)
  reached by a caller who is not a controller;
- certified resolution (`certify.rs`, the leaf format in `names.did`): an
  answer whose certificate and witness check out and that is not what the
  canister holds; two different records with the same canonical leaf; an
  alias chain that loops or runs past 8 records;
- the verifier (`tools/verify`): a forged or stale answer it accepts, or
  any of its checks A to E passing when what it names did not hold. That
  is the worst case;
- flat names and the cycles behind them (`harberger.rs`, `auction.rs`,
  the ledger calls): a name held, bought or won without paying for it; a
  deposit, prepaid balance or credit lost, paid twice, or withdrawn by
  someone it is not owed to; `fund_self` moving more than collected tax;
  a bid amount that can be read from the canister before its auction
  has ended, or a commitment that opens to two amounts; an auction
  closed early, or won for less than the second price or the reserve;
  counters that stop matching the ledger account;
- the HTTP gateway (`gateway.rs`): a `/<name>` redirect to a canister
  other than the one the name resolves to; the handover page skipped
  inside its window; markup from a name or a text record executing in a
  page this canister serves; `/.well-known/ic-domains` claiming a domain
  no controller set;
- the reproducible build (README, "Reproducible build"): a way to make a
  module whose hash matches the attested source but whose behaviour
  differs.

The tax arithmetic, the Vickrey rules and the ICRC ledger client come from
the ic-auction crate. A flaw there that reaches this canister is in scope
and is reported here.

## What does not

- Controllers are trusted. They manage the deployer list, the config, the
  treasury and the domains, and they can upgrade the canister. ic-git
  creates it with the repo owner and itself as controllers (README,
  "Deployment through ic-git"). What a controller can do with a method
  meant for controllers is not a report; a way for anyone else to reach
  one is.
- A listed deployer is trusted for what it announces. `announce` is
  believed because of who calls it, not what is in it (DESIGN.md
  section 8), and a handle nobody has registered goes to the first
  deployer that announces under it (README, "Announce"). A deployer
  announcing something false under a handle it may write is that
  deployer's bug.
- The gateway's responses are served with a skip-certification
  expression, on purpose (README, "HTTP gateway, stage 1"). A 302 or an
  `/api/...` body is not itself proof of anything; the proof is the
  certificate and witness in `resolve`, checked by `tools/verify`. A
  client that follows the redirect without checking has chosen to trust
  the gateway.
- `--insecure-local-root-key` on the verifier trusts the endpoint for the
  root key. It says so, and it is never correct against mainnet.
- The Harberger rules working as written: a name bought from under its
  holder at the price they assessed, a name lapsing after its grace
  period, an unrevealed commitment forfeiting its deposit, a buy refused
  because the seller moved above the buyer's `max_price`. Those are the
  mechanism.
- ic-git itself: its canister, its governor and its deploy queue. Those
  go to ic-git
  (https://github.com/DrJesseGlass/ic-git/security/advisories/new). The
  cycles ledger is DFINITY's.
- A dependency advisory with no reachable path in this code. Dependabot
  files those (`.github/dependabot.yml`); if you believe a path exists,
  that is a report.

## Supported versions

Nothing is deployed yet, so today that is `main`. Once the canister is
live it is only what is running: the module the last entry of
`verified.json` records (`tools/check-module-hash.sh` says whether the
canister still runs it) and the `tools/verify` on `main`. Older releases
are not patched.

## How a fix ships

A fix is a release like any other: built in the pinned container, the raw
wasm staged to `deploy/name_canister.wasm` and committed
(`tools/stage-artifact.sh`), pushed to ic-git, which installs it, and its
module hash recorded in `verified.json`. That path takes days, not hours.
The advisory is published, with credit to the reporter if wanted, once
the fixed module is live; until the first deploy, once the fix is on
`main`.

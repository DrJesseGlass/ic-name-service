# ic-name-service: design brief

A name service for canisters on the Internet Computer. It answers "where is
X" (resolution), records who owns which name (registry), lets a browser use
a name (gateway), and answers "what exists" (directory). Sibling to ic-git,
ic-vote and ic-multisig. Written 2026-09-24 as the starting point for the
repo; nothing here is built yet.

## 1. The problem

Canister ids (`umobs-yiaaa-aaaab-agyrq-cai`) are not navigable. There is no
platform-level name for a canister. Custom domains exist at the boundary
nodes, but they are one registration per name and give no discovery. Earlier
name services (ICNS, `.icp` names, 2022) were a registry plus a browser
extension and never got adoption.

Goal: someone can type a short name and reach an app, a canister can look
up another canister by name, and a directory lists what is deployed with
enough metadata to verify it.

## 2. What it is and is not

It IS a resolver plus registry, like DNS or ENS. A caller asks for a name
and gets a canister id plus a certificate. The caller then talks to the
target directly.

It is NOT a router, relay or proxy. Nothing passes through it. Forwarding
does not work on the IC anyway: queries cannot make inter-canister calls,
composite queries only reach the same subnet, and upgrading `http_request`
to an update call costs cycles, adds seconds, and breaks asset certification.

It is NOT a `.icp` top-level domain. No browser resolves that without an
extension. Human-facing names live under a real domain the project owns.

## 3. Record model

One canister, one stable-memory map from name to record. Record types are
modelled on DNS because the semantics transfer:

- address:    name -> canister id
- alias:      name -> another name, resolved recursively (bounded depth)
- delegation: a subtree (`*.<zone>`) is owned by another registry canister,
              so zones can be run by others and the hierarchy scales
- text:       key/value metadata: description, tags, repo, commit,
              expected module hash, deployer

Every record also carries: owner principal, created/updated time,
"changed hands at" time, and (flat names only) the Harberger fields in
section 5.

Resolution is a query call. Because plain queries are not certified, the
map is placed behind certified data (a hash tree over entries, signed by
the subnet) so a resolver can verify an answer without trusting the
boundary node or the replica it hit.

## 4. Two namespaces, two products

Scoped names, `<owner>/<name>`, e.g. `alice/ic-git`:
- free, permanent, never for sale
- owned by an account the service already knows (the principal that
  registered the handle, or the ic-git tenant that pushed the repo)
- what verifiers pin to and what other canisters hard-code

Flat names, `ic-git`:
- scarce, first come, marketable
- held under a Harberger tax (section 5)
- resolve by ALIAS to a scoped name, so a sale of a flat name never changes
  what a scoped name means

The scoped name is the identity; the flat name is the vanity handle.

## 5. Harberger tax on flat names

Squatting prevention without an auction or a committee.

- The owner self-assesses a price P.
- Tax accrues continuously at rate r per year on P.
- Anyone can buy the name at P at any time; the seller receives P and the
  buyer becomes owner at their own new assessed price.
- Settle lazily: store P, prepaid balance, last settlement time. Tax due is
  P * r * elapsed, computed on any read or write of the record. No timers.
- When the balance hits zero: grace period, then the name becomes free.
- A free name (first sale, or lapsed) goes to a sealed-bid second-price
  (Vickrey) auction, not first come: commit a hash with a deposit, reveal,
  highest bid wins at the second-highest. The winner's bid becomes their
  assessed price, so bidding high costs tax from then on. Closing is lazy
  (anyone may close an ended auction), in keeping with no timers. The
  market flag gates new bids only.
- Pay in cycles (ICRC-2 approval against the cycles ledger, service pulls).
  The tax then funds the canister's own operation. ICP later if wanted.
- Zero-price names are fine: no tax, takeable for nothing. Set a small
  minimum P to stop free churn.
- Rate: 5-10%/year. Enough that hoarding a hundred names costs real money,
  low enough that one running project does not notice.

The sharp edge is the forced sale: a buyer takes `ic-git` and points it at
a phishing copy. Mitigations: the alias rule above (scoped identity is
untouched), the "changed hands at" field is public, and the verified module
hash on the record is cleared on transfer so the directory shows the name
unverified until it is re-announced.

## 6. Gateway: from redirect to real domains

Stage 1, path-based, fully on-chain, works today:
- Register ONE custom domain for this canister (call it `<gateway>`).
- `https://<gateway>/ic-git` -> 302 to `https://<canister-id>.icp0.io/`.
- No wildcard DNS, no off-chain code. Cost: the browser bar ends up showing
  the raw canister URL after the redirect.

Stage 2, per-name custom domains, the ideal:
- For each name, write the DNS records (CNAME to `icp1.io`, `_canister-id`
  TXT, `_acme-challenge` CNAME) and register `ic-git.<gateway>` with the
  boundary nodes as a custom domain OF THE TARGET canister.
- The name stays in the browser bar; traffic never touches this canister.
- The target must list the domain in its `/.well-known/ic-domains`, so it
  has to cooperate.
- Driven by HTTPS outcalls to the DNS provider API and the boundary-node
  registration API, on a timer. The registry stays the source of truth.
- Boundary nodes do not take wildcards, which is why stage 1 is path-based
  rather than subdomain-based.

Stage 1 and stage 2 use the same records; nothing in the registry changes.

## 7. Directory and search

A registry answers "where is X"; search answers "what exists". Same
canister, same data, plus text records per entry: description, tags, repo,
commit, module hash, deployer, last verified. Index is a few maps
(tag -> names, substring over names and descriptions). A separate search
canister only earns its keep at a scale far away.

Anything deployed by git push through ic-git can be listed automatically
with all of that filled in, which gives a directory of verifiable apps
without asking anyone to register.

## 8. Integration with ic-git

Direction of dependency: this repo does not depend on ic-git code. ic-git
gets one small optional hook.

- After a successful install, ic-git calls `announce(repo, commit,
  canister_id, module_hash)` on this canister. ic-git's DeployRecord already
  has commit, target, wasm_sha256 and at_ns; announce is that record.
- This canister trusts the announcement because the CALLER PRINCIPAL is a
  listed deployer (ic-git's canister id), not because of anything in the
  payload. Other deployers can be listed the same way.
- The announcement creates or updates the scoped name under the pushing
  tenant's handle and fills the text records.
- Verification pin: the record carries the expected module hash. A resolver
  can read the target's live module hash from the state tree and refuse to
  route a name whose target no longer matches. A name becomes a pinned,
  verifiable alias rather than a mutable pointer.

This repo is itself deployed by git push through ic-git, verified against
its own record, and then lists itself.

## 9. Build and verification conventions

Same as ic-git: pinned rust toolchain (1.94.1 there), dfx 0.31.0,
ic-cdk 0.20, ic-stable-structures 0.7, reproducible build through a pinned
container with path remapping, `verified.json` recording module hashes per
tag, pure ASCII in messages, comments and docs. Copy the recipe rather than
reinventing it.

## 10. First milestone

M0, resolve and announce:
- records: address, alias, text; scoped names only
- `register_handle`, `set_record`, `resolve` (certified), `announce`
  (caller-gated)
- `http_request`: `/<name>` -> 302, `/api/resolve/<name>` -> JSON
- ic-git hook behind a config flag naming this canister
- reproducible build, verified.json, deployed by git push

M1: directory (text records, tags, `/api/search`).
M2: flat names with the Harberger tax, cycles payment, lazy settlement.
M3: delegation records; stage 2 gateway via HTTPS outcalls.

## 11. Open questions

- Handle allocation for scoped names: principal-registered, ic-git tenant,
  or both? Who arbitrates a handle collision?
- Alias depth limit and loop detection.
- Grace period length. (A lapsed name is auctioned, like a first sale.)
- Which DNS provider for stage 2 (needs an API reachable by HTTPS outcalls
  with a stable response for consensus).
- Whether `resolve` for other canisters should be a plain query (cheap,
  uncertified in-canister) or an update (certified but slow); likely both.

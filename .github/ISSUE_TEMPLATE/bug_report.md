---
name: Bug report
about: Something ic-name-service does wrong. Security problems go to the private form instead (SECURITY.md).
title: ''
labels: bug
assignees: ''
---

<!-- If this is a security problem, stop: report it privately at
     https://github.com/DrJesseGlass/ic-name-service/security/advisories/new
     A name that resolves or verifies when it should not, a record changed
     by someone who does not own it, or cycles that go to the wrong place
     is a security problem. -->

## Where

Which piece: the names canister (its id, on mainnet or a local replica),
the HTTP gateway (the URL you requested), the verifier (`tools/verify`),
the build and staging tools (`tools/reproducible-build.sh`,
`tools/stage-artifact.sh`, `tools/check-module-hash.sh`), or
`tools/smoke-test.sh`. The commit you are on, and for a live canister the
module hash from `tools/check-module-hash.sh` if you have it.

## What you did

The exact commands, URL, or calls, with their arguments. For the
verifier, the full command line including `--url` and whether
`--insecure-local-root-key` was set.

## What happened

Output, error text, or a screenshot. Paste text as text. For the
verifier, which of the checks A to E failed.

## What you expected

## Anything else

The name involved, the principal that called (never a private key or a
seed phrase), dfx version for a local replica. For a flat name, the
output of `flat_status` or `auction_status` for it.

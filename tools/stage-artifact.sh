#!/usr/bin/env bash
# Stage the artifact ic-git installs: build in the pinned container and
# copy the RAW wasm to deploy/name_canister.wasm, the path the ic-git
# deploy config names (set_wasm_deploy(repo, "app", "deploy/name_canister.wasm")).
#
#   tools/stage-artifact.sh          build the committed tree, stage, print hashes
#
# ic-git installs a committed .wasm as-is, so the raw module is what goes
# in the repo; the .gz the reproducible build also produces is for a dfx
# install and stays out. Commit deploy/name_canister.wasm on each release
# and record its sha256 (the on-chain module hash) in verified.json.
#
# Refuses a dirty tree, like tools/reproducible-build.sh: the artifact
# must come from a commit anyone can rebuild.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain | grep -v '^?? deploy/' | grep -v '^ M deploy/')" ]; then
  echo "refusing to stage: the working tree has uncommitted changes outside deploy/." >&2
  exit 2
fi
commit=$(git rev-parse HEAD)
out=$(tools/reproducible-build.sh --docker)
echo "$out"
raw=$(echo "$out" | awk '/^artifact/{print $3}' | sed 's/\.gz$//')
[ -f "$raw" ] || { echo "no raw artifact found at $raw" >&2; exit 1; }
mkdir -p deploy
cp "$raw" deploy/name_canister.wasm
sha=$(shasum -a 256 deploy/name_canister.wasm | awk '{print $1}')
echo "staged              : deploy/name_canister.wasm ($(wc -c < deploy/name_canister.wasm | tr -d ' ') bytes)"
echo "raw module sha256   : $sha  (the on-chain module hash after an ic-git install)"
echo "source commit       : $commit"
echo "next: commit deploy/name_canister.wasm, tag, and add a verified.json entry with this hash."

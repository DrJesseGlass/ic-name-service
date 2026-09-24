#!/usr/bin/env bash
# End-to-end check against a running local replica (`dfx start`).
# Deploys the names canister, registers a handle, sets an address and an
# alias, resolves both, and checks the answers carry a certificate.
#
#   tools/smoke-test.sh
#
# Runs as DFX_IDENTITY (default: a plaintext local-only identity named
# smoke-local, created on first run), because an encrypted default identity
# prompts for a password on every call and cannot run unattended.
set -euo pipefail
cd "$(dirname "$0")/.."

id=${DFX_IDENTITY:-smoke-local}
if ! dfx identity list 2>/dev/null | grep -qx "$id"; then
  dfx identity new --storage-mode plaintext "$id" >/dev/null
fi
export DFX_IDENTITY=$id
me=$(dfx identity get-principal --identity "$id")
echo "identity            : $id ($me)"
dfx deploy --identity "$id" names >/dev/null
names=$(dfx canister id names)
echo "names canister      : $names"

# A target to point at. The names canister itself will do.
target=$names
handle="smoke-$RANDOM"

call() { dfx canister call --identity "$id" names "$@"; }

echo "--- register handle $handle"
call register_handle "(\"$handle\")" | grep -q 'Ok' || { echo "register_handle failed" >&2; exit 1; }
echo "--- taken handle is refused"
call register_handle "(\"$handle\")" | grep -q 'Err' || { echo "expected Err on duplicate handle" >&2; exit 1; }

echo "--- set_record $handle/app -> address $target"
call set_record "(\"$handle/app\", variant { address = principal \"$target\" })" | grep -q 'Ok'
echo "--- set_text description"
call set_text "(\"$handle/app\", \"description\", opt \"smoke test app\")" | grep -q 'Ok'
echo "--- set_record $handle/www -> alias $handle/app"
call set_record "(\"$handle/www\", variant { alias = \"$handle/app\" })" | grep -q 'Ok'

echo "--- list_names"
call list_names "(\"$handle\")" | grep -q "$handle/app" 

echo "--- resolve $handle/www (one alias hop)"
out=$(call resolve "(\"$handle/www\")")
echo "$out" | grep -q "canister = principal \"$target\"" || { echo "wrong canister in resolve:"; echo "$out"; exit 1; }
echo "$out" | grep -q 'certificate = opt blob' || { echo "no certificate in resolve:"; echo "$out"; exit 1; }
echo "$out" | grep -q 'witness = blob' || { echo "no witness in resolve:"; echo "$out"; exit 1; }
echo "$out" | grep -q 'smoke test app' || { echo "text record missing from chain:"; echo "$out"; exit 1; }
hops=$(echo "$out" | grep -o 'name = "' | wc -l | tr -d ' ')
# Resolved.name plus two chain entries.
[ "$hops" = 3 ] || { echo "expected 2 hops in chain, got $((hops-1))"; echo "$out"; exit 1; }

echo "--- resolve of a missing name is Err"
call resolve "(\"$handle/missing\")" | grep -q 'Err' 

echo "--- alias loop is refused"
call set_record "(\"$handle/a\", variant { alias = \"$handle/b\" })" | grep -q 'Ok'
call set_record "(\"$handle/b\", variant { alias = \"$handle/a\" })" | grep -q 'Ok'
call resolve "(\"$handle/a\")" | grep -q 'alias loop' 

echo "--- delete_record then resolve is Err"
call delete_record "(\"$handle/www\")" | grep -q 'Ok'
call resolve "(\"$handle/www\")" | grep -q 'Err'

echo "--- other identity cannot write under $handle"
dfx identity new --storage-mode plaintext smoke-other >/dev/null 2>&1 || true
dfx canister call --identity smoke-other names set_record \
  "(\"$handle/app\", variant { address = principal \"aaaaa-aa\" })" | grep -q 'does not own' 

echo "--- upgrade keeps records and re-certifies"
dfx deploy --identity "$id" names --upgrade-unchanged >/dev/null 2>&1
out=$(call resolve "(\"$handle/app\")")
echo "$out" | grep -q "canister = principal \"$target\"" || { echo "record lost across upgrade"; exit 1; }
echo "$out" | grep -q 'certificate = opt blob' || { echo "no certificate after upgrade"; exit 1; }

echo "SMOKE OK"

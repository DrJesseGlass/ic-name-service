#!/usr/bin/env bash
# End-to-end check against a running local replica (`dfx start`).
# Deploys the names canister, registers a handle, sets an address and an
# alias, resolves both, runs the independent verifier (tools/verify) on the
# answer and on two forged answers, exercises announce through the deployer
# allowlist, and hits the HTTP gateway through the local dfx gateway.
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
dfx deploy --identity "$id" names >/dev/null 2>&1
names=$(dfx canister id names)
echo "names canister      : $names"

# A target to point at. The names canister itself will do.
target=$names
handle="smoke-$RANDOM"

call() { dfx canister call --identity "$id" names "$@"; }

# An earlier aborted run may have left this identity listed as a deployer.
call remove_deployer "(principal \"$me\")" >/dev/null 2>&1 || true

echo "--- register handle $handle"
call register_handle "(\"$handle\")" | grep >/dev/null 'Ok' || { echo "register_handle failed" >&2; exit 1; }
echo "--- taken handle is refused"
call register_handle "(\"$handle\")" | grep >/dev/null 'Err' || { echo "expected Err on duplicate handle" >&2; exit 1; }

echo "--- set_record $handle/app -> address $target"
call set_record "(\"$handle/app\", variant { address = principal \"$target\" })" | grep >/dev/null 'Ok'
echo "--- set_text description"
call set_text "(\"$handle/app\", \"description\", opt \"smoke test app\")" | grep >/dev/null 'Ok'
echo "--- set_record $handle/www -> alias $handle/app"
call set_record "(\"$handle/www\", variant { alias = \"$handle/app\" })" | grep >/dev/null 'Ok'

echo "--- list_names"
call list_names "(\"$handle\")" | grep >/dev/null "$handle/app" 

echo "--- resolve $handle/www (one alias hop)"
out=$(call resolve "(\"$handle/www\")")
echo "$out" | grep >/dev/null "canister = principal \"$target\"" || { echo "wrong canister in resolve:"; echo "$out"; exit 1; }
echo "$out" | grep >/dev/null 'certificate = opt blob' || { echo "no certificate in resolve:"; echo "$out"; exit 1; }
echo "$out" | grep >/dev/null 'witness = blob' || { echo "no witness in resolve:"; echo "$out"; exit 1; }
echo "$out" | grep >/dev/null 'smoke test app' || { echo "text record missing from chain:"; echo "$out"; exit 1; }
hops=$(echo "$out" | grep -o 'name = "' | wc -l | tr -d ' ')
# Resolved.name plus two chain entries.
[ "$hops" = 3 ] || { echo "expected 2 hops in chain, got $((hops-1))"; echo "$out"; exit 1; }

echo "--- resolve of a missing name is Err"
call resolve "(\"$handle/missing\")" | grep >/dev/null 'Err' 

echo "--- alias loop is refused"
call set_record "(\"$handle/a\", variant { alias = \"$handle/b\" })" | grep >/dev/null 'Ok'
call set_record "(\"$handle/b\", variant { alias = \"$handle/a\" })" | grep >/dev/null 'Ok'
call resolve "(\"$handle/a\")" | grep >/dev/null 'alias loop' 

echo "--- delete_record then resolve is Err"
call delete_record "(\"$handle/www\")" | grep >/dev/null 'Ok'
call resolve "(\"$handle/www\")" | grep >/dev/null 'Err'

echo "--- other identity cannot write under $handle"
dfx identity new --storage-mode plaintext smoke-other >/dev/null 2>&1 || true
dfx canister call --identity smoke-other names set_record \
  "(\"$handle/app\", variant { address = principal \"aaaaa-aa\" })" | grep >/dev/null 'does not own' 

echo "--- independent verifier: certificate, root, leaves, chain"
verify=tools/verify/target/release/names-verify
if [ ! -x "$verify" ]; then
  (cd tools/verify && cargo build --release >/dev/null 2>&1)
fi
$verify --url http://127.0.0.1:4943 --insecure-local-root-key --canister "$names" "$handle/app" | grep >/dev/null '^VERIFIED' 
echo "--- forged witness fails at B"
# The verifier exits 1 on a failed check, which under pipefail would end
# the script before grep sees the line, so capture first.
out=$($verify --url http://127.0.0.1:4943 --insecure-local-root-key --canister "$names" --tamper witness "$handle/app" || true)
echo "$out" | grep >/dev/null '^FAILED at B' || { echo "tampered witness not caught:"; echo "$out"; exit 1; }
echo "--- forged record fails at C"
out=$($verify --url http://127.0.0.1:4943 --insecure-local-root-key --canister "$names" --tamper record "$handle/app" || true)
echo "$out" | grep >/dev/null '^FAILED at C' || { echo "tampered record not caught:"; echo "$out"; exit 1; }

echo "--- announce: not a deployer is refused"
commit=$(printf 'ab%.0s' $(seq 20))
hash=$(printf 'cd%.0s' $(seq 32))
ann="(record { name = \"$handle/pushed\"; canister = principal \"$target\"; repo = \"pushed\"; commit = \"$commit\"; module_hash = \"$hash\" })"
call announce "$ann" | grep >/dev/null 'not a listed deployer' 
echo "--- add_deployer by a non-controller is refused"
dfx canister call --identity smoke-other names add_deployer "(principal \"$me\")" | grep >/dev/null 'not a controller' 
echo "--- controller lists the smoke identity as a deployer"
call add_deployer "(principal \"$me\")" | grep >/dev/null 'Ok'
call list_deployers | grep >/dev/null "$me"
echo "--- announce under own handle fills provenance"
call announce "$ann" | grep >/dev/null 'Ok'
out=$(call get_record "(\"$handle/pushed\")")
echo "$out" | grep >/dev/null "\"$hash\"" || { echo "module_hash missing:"; echo "$out"; exit 1; }
echo "$out" | grep >/dev/null "\"$commit\"" || { echo "commit missing:"; echo "$out"; exit 1; }
echo "--- announce under an unregistered handle registers it to the deployer"
call announce "(record { name = \"$handle-auto/x\"; canister = principal \"$target\"; repo = \"x\"; commit = \"$commit\"; module_hash = \"$hash\" })" | grep >/dev/null 'Ok'
call handle_owner "(\"$handle-auto\")" | grep >/dev/null "$me"
echo "--- announce under another owner's handle needs set_handle_deployer"
other=$(dfx identity get-principal --identity smoke-other)
dfx canister call --identity smoke-other names register_handle "(\"$handle-o\")" | grep >/dev/null 'Ok'
call announce "(record { name = \"$handle-o/y\"; canister = principal \"$target\"; repo = \"y\"; commit = \"$commit\"; module_hash = \"$hash\" })" | grep >/dev/null 'does not allow deployer' 
dfx canister call --identity smoke-other names set_handle_deployer "(\"$handle-o\", opt principal \"$me\")" | grep >/dev/null 'Ok'
call announce "(record { name = \"$handle-o/y\"; canister = principal \"$target\"; repo = \"y\"; commit = \"$commit\"; module_hash = \"$hash\" })" | grep >/dev/null 'Ok'
call get_record "(\"$handle-o/y\")" | grep >/dev/null "owner = principal \"$other\"" 
echo "--- bad module_hash is refused"
call announce "(record { name = \"$handle/pushed\"; canister = principal \"$target\"; repo = \"pushed\"; commit = \"$commit\"; module_hash = \"nothex\" })" | grep >/dev/null 'Err'
echo "--- remove_deployer"
call remove_deployer "(principal \"$me\")" | grep >/dev/null 'Ok'
call announce "$ann" | grep >/dev/null 'not a listed deployer' 

echo "--- tags: bad values refused, good value indexed"
call set_text "(\"$handle/app\", \"tags\", opt \"git, deploy\")" | grep >/dev/null 'Err'
call set_text "(\"$handle/app\", \"tags\", opt \"git,git\")" | grep >/dev/null 'Err'
call set_text "(\"$handle/app\", \"tags\", opt \"git,smoke-$handle\")" | grep >/dev/null 'Ok'
call tags | grep >/dev/null "smoke-$handle"
echo "--- search by substring of the description"
out=$(call search "(record { q = opt \"SMOKE TEST\" })")
echo "$out" | grep >/dev/null "$handle/app" || { echo "search by description failed:"; echo "$out"; exit 1; }
echo "--- search by tag, paged"
out=$(call search "(record { tag = opt \"smoke-$handle\"; limit = opt 1 })")
echo "$out" | grep >/dev/null 'total = 1 : nat32' || { echo "search by tag failed:"; echo "$out"; exit 1; }
echo "--- retag drops the old tag"
call set_text "(\"$handle/app\", \"tags\", opt \"deploy\")" | grep >/dev/null 'Ok'
out=$(call search "(record { tag = opt \"smoke-$handle\" })")
echo "$out" | grep >/dev/null 'total = 0 : nat32' || { echo "old tag still indexed:"; echo "$out"; exit 1; }
echo "--- announce with the real module hash, then verifier check E passes"
live=$(dfx canister info names | awk '/Module hash/{sub(/^0x/, "", $3); print $3}')
call add_deployer "(principal \"$me\")" | grep >/dev/null 'Ok'
call announce "(record { name = \"$handle/self\"; canister = principal \"$target\"; repo = \"ic-name-service\"; commit = \"$commit\"; module_hash = \"$live\" })" | grep >/dev/null 'Ok'
out=$($verify --url http://127.0.0.1:4943 --insecure-local-root-key --canister "$names" "$handle/self" || true)
echo "$out" | grep >/dev/null '^E module hash       : ok' || { echo "check E did not pass on a true pin:"; echo "$out"; exit 1; }
echo "--- a stale pin fails check E"
call announce "(record { name = \"$handle/stale\"; canister = principal \"$target\"; repo = \"ic-name-service\"; commit = \"$commit\"; module_hash = \"$hash\" })" | grep >/dev/null 'Ok'
out=$($verify --url http://127.0.0.1:4943 --insecure-local-root-key --canister "$names" "$handle/stale" || true)
echo "$out" | grep >/dev/null '^FAILED at E' || { echo "stale pin not caught:"; echo "$out"; exit 1; }
call remove_deployer "(principal \"$me\")" | grep >/dev/null 'Ok'

echo "--- http gateway through the local dfx gateway"
gw() { curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $names.localhost:4943" "http://127.0.0.1:4943$1"; }
got=$(gw "/$handle/app")
[ "$got" = "302 https://$target.icp0.io/" ] || { echo "redirect wrong: $got"; exit 1; }
got=$(gw "/$handle/missing")
[ "${got%% *}" = 404 ] || { echo "expected 404, got: $got"; exit 1; }
got=$(gw "/")
[ "${got%% *}" = 200 ] || { echo "index expected 200, got: $got"; exit 1; }
echo "--- /api/resolve JSON carries certificate and witness (raw query)"
json=$(curl -s -H "Host: $names.raw.localhost:4943" "http://127.0.0.1:4943/api/resolve/$handle/app")
echo "$json" | grep >/dev/null "\"canister\":\"$target\"" || { echo "api json wrong:"; echo "$json"; exit 1; }
echo "$json" | grep >/dev/null '"certificate":"' || { echo "api json lacks certificate"; exit 1; }
echo "$json" | grep >/dev/null '"witness":"' || { echo "api json lacks witness"; exit 1; }
echo "$json" | grep >/dev/null '"created_ns":"[0-9]*"' || { echo "api json timestamps must be decimal strings"; echo "$json"; exit 1; }
echo "--- /api/search and /api/tags JSON (raw query)"
json=$(curl -s -H "Host: $names.raw.localhost:4943" "http://127.0.0.1:4943/api/search?q=smoke+test&tag=deploy&limit=5")
echo "$json" | grep >/dev/null "\"name\":\"$handle/app\"" || { echo "api search wrong:"; echo "$json"; exit 1; }
echo "$json" | grep >/dev/null '"updated_ns":"[0-9]*"' || { echo "api search timestamps must be strings"; echo "$json"; exit 1; }
json=$(curl -s -H "Host: $names.raw.localhost:4943" "http://127.0.0.1:4943/api/tags")
echo "$json" | grep >/dev/null '"tag":"deploy"' || { echo "api tags wrong:"; echo "$json"; exit 1; }

echo "--- upgrade keeps records and re-certifies"
dfx deploy --identity "$id" names --upgrade-unchanged >/dev/null 2>&1
out=$(call resolve "(\"$handle/app\")")
echo "$out" | grep >/dev/null "canister = principal \"$target\"" || { echo "record lost across upgrade"; exit 1; }
echo "$out" | grep >/dev/null 'certificate = opt blob' || { echo "no certificate after upgrade"; exit 1; }

echo "SMOKE OK"

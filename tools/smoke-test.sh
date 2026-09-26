#!/usr/bin/env bash
# End-to-end check against a running local replica (`dfx start`).
# Deploys the names canister, registers a handle, sets an address and an
# alias, resolves both, runs the independent verifier (tools/verify) on the
# answer and on two forged answers, exercises announce through the deployer
# allowlist, hits the HTTP gateway through the local dfx gateway, and runs
# flat names through sealed-bid auctions (first sale, a lapsed name, a
# forfeit, the market flag), buy, withdraw, lapse and release against the
# local cycles ledger (dfx deps deploy installs it; the script funds the
# test identities from their local wallets).
#
#   tools/smoke-test.sh
#
# Runs as DFX_IDENTITY (default: a plaintext local-only identity named
# smoke-local, created on first run), because an encrypted default identity
# prompts for a password on every call and cannot run unattended.
set -euo pipefail
# Most checks are a bare grep; name the line that failed.
trap 'echo "FAILED at line $LINENO" >&2' ERR
cd "$(dirname "$0")/.."

id=${DFX_IDENTITY:-smoke-local}
if ! dfx identity list 2>/dev/null | grep -qx "$id"; then
  dfx identity new --storage-mode plaintext "$id" >/dev/null
fi
export DFX_IDENTITY=$id
me=$(dfx identity get-principal --identity "$id")
echo "identity            : $id ($me)"
dfx deploy --yes --identity "$id" names >/dev/null 2>&1
names=$(dfx canister id names)
echo "names canister      : $names"

# A target to point at. The names canister itself will do.
target=$names
# Every name in a run carries the run's epoch second, so runs against the
# same long-lived local canister never collide (RANDOM alone did).
run=$(date +%s)
handle="smoke-$run"

call() { dfx canister call --identity "$id" names "$@"; }
treasury_field() { call treasury | grep -o "$1 = [0-9_]*" | tr -d '_' | awk '{print $3}'; }

# An earlier aborted run may have left this identity listed as a deployer.
call remove_deployer "(principal \"$me\")" >/dev/null 2>&1 || true

echo "--- register handle $handle"
call register_handle "(\"$handle\")" | grep >/dev/null 'Ok' || { echo "register_handle failed" >&2; exit 1; }
echo "--- taken handle is refused"
call register_handle "(\"$handle\")" | grep >/dev/null 'Err' || { echo "expected Err on duplicate handle" >&2; exit 1; }

echo "--- set_record $handle/app -> address $target"
call set_record "(\"$handle/app\", variant { address = principal \"$target\" })" | grep >/dev/null 'Ok'
echo "--- set_text description"
call set_text "(\"$handle/app\", \"description\", opt \"smoke test app $handle\")" | grep >/dev/null 'Ok'
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
out=$(call search "(record { q = opt \"SMOKE TEST APP $handle\" })")
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

echo "--- flat names: local cycles ledger"
ledger=um5iw-rqaaa-aaaaq-qaaba-cai
if ! dfx canister id cycles_ledger >/dev/null 2>&1 || ! dfx canister call --identity "$id" $ledger icrc1_fee '()' >/dev/null 2>&1; then
  dfx deps deploy --identity "$id" >/dev/null 2>&1
fi
fund() { # fund <identity> <cycles>: deposit from the identity's local wallet
  local who=$1 amount=$2 p wallet
  p=$(dfx identity get-principal --identity "$who")
  wallet=$(dfx identity get-wallet --identity "$who")
  # Local replica only: mint cycles into the wallet so repeated runs never
  # drain it. (Refused on mainnet, where cycles are real.)
  dfx ledger fabricate-cycles --identity "$who" --canister "$wallet" --t 100 >/dev/null 2>&1 || true
  dfx canister call --identity "$who" --wallet "$wallet" \
    --with-cycles "$amount" $ledger deposit "(record { to = record { owner = principal \"$p\" } })" >/dev/null
}
approve() { # approve <identity>: let the names canister pull up to 10T
  dfx canister call --identity "$1" $ledger icrc2_approve \
    "(record { spender = record { owner = principal \"$names\" }; amount = 10_000_000_000_000 })" | grep >/dev/null 'Ok'
}
bal() { dfx canister call --identity "$id" $ledger icrc1_balance_of "(record { owner = principal \"$1\" })" | tr -d '_ ()nat:' ; }
fund smoke-local 5000000000000
fund smoke-other 5000000000000
approve smoke-local
approve smoke-other
# Auctions: the commitment comes from the canister's helper (tests only;
# a real bidder computes it locally), and a phase is waited for by polling.
auction_cfg() { # auction_cfg <commit s> <reveal s>
  call set_auction_config "(record { commit_ns = $1_000_000_000 : nat64; reveal_ns = $2_000_000_000 : nat64; reserve = 0 })" | grep >/dev/null 'Ok'
}
harb_cfg() { # harb_cfg <rate_bps> <grace s> <open>
  call set_harberger_config "(record { ledger = principal \"$ledger\"; rate_bps = $1 : nat32; min_price = 1_000_000_000; grace_ns = $2_000_000_000 : nat64; fee = 0; flat_names_open = $3; handover_warn_ns = 30_000_000_000 : nat64 })" | grep >/dev/null 'Ok'
}
commitment() { # commitment <identity> <amount> <salt>: a candid blob literal
  local p; p=$(dfx identity get-principal --identity "$1")
  call auction_commitment "(principal \"$p\", $2, blob \"$3\")" | tr -d '\n' | sed -E 's/^\( *//; s/,? *\)$//'
}
bid_as() { # bid_as <identity> <name> <amount> <deposit> <salt>
  dfx canister call --identity "$1" names bid "(\"$2\", $(commitment "$1" "$3" "$5"), $4)"
}
reveal_as() { # reveal_as <identity> <name> <amount> <salt> <alias_to>
  dfx canister call --identity "$1" names reveal "(\"$2\", $3, blob \"$4\", \"$5\")"
}
phase() { call auction_status "(\"$1\")" | grep -o 'phase = variant { [a-z]* }' | awk '{print $5}'; }
wait_phase() { # wait_phase <name> <phase>: 40 s at most
  local i
  for i in $(seq 80); do [ "$(phase "$1")" = "$2" ] && return 0; sleep 0.5; done
  echo "auction $1 never reached $2"; call auction_status "(\"$1\")"; exit 1
}
win() { # win <identity> <name> <alias_to> <amount> <deposit>: a lone bid through a whole auction
  bid_as "$1" "$2" "$4" "$5" "s-$2" | grep >/dev/null 'Ok' || { echo "bid on $2 failed"; exit 1; }
  wait_phase "$2" reveal
  reveal_as "$1" "$2" "$4" "s-$2" "$3" | grep >/dev/null 'Ok' || { echo "reveal on $2 failed"; exit 1; }
  wait_phase "$2" closed
  call close_auction "(\"$2\")" | grep >/dev/null 'Ok' || { echo "close of $2 failed"; exit 1; }
}
credit_of() { call credit "(principal \"$1\")" | tr -d '_ ()nat:'; }
other=$(dfx identity get-principal --identity smoke-other)

echo "--- the market is closed by default: bidding is refused"
call harberger_config | grep >/dev/null 'flat_names_open = false' || call set_harberger_config "(record { ledger = principal \"$ledger\"; rate_bps = 700 : nat32; min_price = 100_000_000_000; grace_ns = 2_592_000_000_000_000 : nat64; fee = 0; flat_names_open = false; handover_warn_ns = 30_000_000_000 : nat64 })" | grep >/dev/null 'Ok'
bid_as smoke-local "closed$run" 1_000_000_000_000 1_100_000_000_000 x | grep >/dev/null 'not open'
echo "--- fast tax and auctions for the test: 100 percent per year, 10 second grace, 15+30 second phases, market open"
# Phases and grace are wall-clock; they are generous because the local
# replica is shared, and another project's tests can slow every call.
harb_cfg 10000 10 true
auction_cfg 15 30
call auction_config | grep >/dev/null 'commit_ns = 15_000_000_000'
flat="fl$run-a"
echo "--- auction $flat: bad bids are refused before any pull"
call bid "(\"$flat\", blob \"short\", 1_100_000_000_000)" | grep >/dev/null '32 bytes'
bid_as smoke-local "$flat" 1_000_000_000_000 1 s-a | grep >/dev/null 'reserve'
call bid "(\"$handle/app\", $(commitment smoke-local 1 x), 1_100_000_000_000)" | grep >/dev/null 'Err'
echo "--- two sealed bids: 1T from $id, 400B from smoke-other"
bid_as smoke-local "$flat" 1_000_000_000_000 1_100_000_000_000 s-a | grep >/dev/null 'Ok'
bid_as smoke-other "$flat" 400_000_000_000 500_000_000_000 s-b | grep >/dev/null 'Ok'
out=$(call auction_status "(\"$flat\")")
echo "$out" | grep >/dev/null "principal \"$me\"" && echo "$out" | grep >/dev/null "principal \"$other\"" || { echo "bidders missing:"; echo "$out"; exit 1; }
[ "$(treasury_field escrowed)" -ge 1600000000000 ] || { echo "escrow not counted"; call treasury; exit 1; }
reveal_as smoke-local "$flat" 1_000_000_000_000 s-a "$handle/app" | grep >/dev/null 'not started'
call auctions | grep >/dev/null "name = \"$flat\""
echo "--- closing the market stops new bids, not reveals or the close"
harb_cfg 10000 10 false
bid_as smoke-other "fl$run-z" 400_000_000_000 500_000_000_000 s-z | grep >/dev/null 'not open'
wait_phase "$flat" reveal
call close_auction "(\"$flat\")" | grep >/dev/null 'still open'
bid_as smoke-other "$flat" 400_000_000_000 500_000_000_000 s-b | grep >/dev/null 'Err'
reveal_as smoke-local "$flat" 1_000_000_000_000 s-a nope | grep >/dev/null 'must alias a scoped name'
reveal_as smoke-local "$flat" 1_000_000_000_000 wrong "$handle/app" | grep >/dev/null 'do not match'
reveal_as smoke-local "$flat" 1_000_000_000_000 s-a "$handle/app" | grep >/dev/null 'Ok'
reveal_as smoke-other "$flat" 400_000_000_000 s-b "$handle/app" | grep >/dev/null 'Ok'
wait_phase "$flat" closed
out=$(call auction_status "(\"$flat\")" | tr -d '_')
echo "$out" | grep >/dev/null "winner = opt principal \"$me\"" || { echo "wrong winner:"; echo "$out"; exit 1; }
echo "--- anyone closes it: the higher bid wins at the lower; losers and change are credited"
mc0=$(credit_of "$me"); oc0=$(credit_of "$other"); a0=$(treasury_field auctioned)
out=$(dfx canister call --identity smoke-other names close_auction "(\"$flat\")" | tr -d '_')
echo "$out" | grep >/dev/null 'price = 400000000000 ' || { echo "not a second-price close:"; echo "$out"; exit 1; }
echo "$out" | grep >/dev/null 'assessed = 1000000000000 ' || { echo "winner not assessed at their bid:"; echo "$out"; exit 1; }
# Opening balance is one grace period of tax at 1T; top it up before it runs out.
call deposit "(\"$flat\", 100_000_000_000)" | grep >/dev/null 'Ok'
harb_cfg 10000 2 true
[ $(( $(credit_of "$other") - oc0 )) -eq 500000000000 ] || { echo "loser not refunded in full"; exit 1; }
change=$(( $(credit_of "$me") - mc0 ))
[ "$change" -gt 699000000000 ] && [ "$change" -lt 700000000000 ] || { echo "winner change wrong: $change"; exit 1; }
[ $(( $(treasury_field auctioned) - a0 )) -eq 400000000000 ] || { echo "price not in the treasury"; call treasury; exit 1; }
call auction_status "(\"$flat\")" | grep >/dev/null '(null)'
out=$(call flat_status "(\"$flat\")")
echo "$out" | grep >/dev/null 'status = variant { active }' && echo "$out" | grep >/dev/null "owner = principal \"$me\"" || { echo "winner does not hold $flat:"; echo "$out"; exit 1; }
echo "--- a held name cannot be bid on"
bid_as smoke-other "$flat" 400_000_000_000 500_000_000_000 s-b | grep >/dev/null 'is owned by'
echo "--- flat name resolves through its alias and verifies (chain of 2)"
out=$($verify --url http://127.0.0.1:4943 --insecure-local-root-key --canister "$names" "$flat" || true)
echo "$out" | grep >/dev/null '^VERIFIED' || { echo "flat name did not verify:"; echo "$out"; exit 1; }
echo "$out" | grep >/dev/null 'chain               : 2'
echo "--- owner reassesses to 2T; a stranger cannot"
dfx canister call --identity smoke-other names set_price "(\"$flat\", 2_000_000_000_000)" | grep >/dev/null 'does not own'
call set_price "(\"$flat\", 2_000_000_000_000)" | grep >/dev/null 'Ok'
echo "--- buyer takes it at 2T, assessing 3T; seller is credited price plus unspent balance"
credit0=$(call credit "(principal \"$me\")" | tr -d '_ ()nat:')
echo "--- a buy capped below the current price is refused"
dfx canister call --identity smoke-other names buy "(\"$flat\", \"$handle/app\", 3_000_000_000_000, 100_000_000_000, 1_000_000_000_000)" | grep >/dev/null 'above your limit'
dfx canister call --identity smoke-other names buy "(\"$flat\", \"$handle/app\", 3_000_000_000_000, 100_000_000_000, 2_000_000_000_000)" | grep >/dev/null 'Ok'
call flat_status "(\"$flat\")" | grep >/dev/null "owner = principal \"$other\""
echo "--- closing the market does not stop a buy of a held name"
call set_harberger_config "(record { ledger = principal \"$ledger\"; rate_bps = 10000 : nat32; min_price = 1_000_000_000; grace_ns = 2_000_000_000 : nat64; fee = 0; flat_names_open = false; handover_warn_ns = 30_000_000_000 : nat64 })" | grep >/dev/null 'Ok'
bid_as smoke-local "closed$run" 1_000_000_000_000 1_100_000_000_000 x | grep >/dev/null 'not open'
# Repoint at $handle/self, whose pinned module hash is the live one, so
# the verifier's check E passes on the chain through this flat name.
call buy "(\"$flat\", \"$handle/self\", 3_000_000_000_000, 100_000_000_000, 3_000_000_000_000)" | grep >/dev/null 'Ok'
call set_harberger_config "(record { ledger = principal \"$ledger\"; rate_bps = 10000 : nat32; min_price = 1_000_000_000; grace_ns = 2_000_000_000 : nat64; fee = 0; flat_names_open = true; handover_warn_ns = 30_000_000_000 : nat64 })" | grep >/dev/null 'Ok'
call flat_status "(\"$flat\")" | grep >/dev/null "owner = principal \"$me\""
echo "--- the sold name remembers where it pointed, and the gateway warns instead of redirecting"
call get_record "(\"$flat\")" | grep >/dev/null "previous_target = opt variant { alias = \"$handle/app\" }"
page=$(curl -s -H "Host: $names.localhost:4943" "http://127.0.0.1:4943/$flat")
echo "$page" | grep >/dev/null "<h1>$flat changed hands</h1>" || { echo "no handover page:"; echo "$page" | head -5; exit 1; }
echo "$page" | grep >/dev/null "Continue to $handle/self"
echo "$page" | grep >/dev/null "Go to $handle/app instead"
echo "--- the verifier warns about the recent change of target, and not outside its window"
out=$($verify --url http://127.0.0.1:4943 --insecure-local-root-key --canister "$names" "$flat" || true)
echo "$out" | grep >/dev/null "^WARNING             : $flat changed hands" || { echo "verifier did not warn:"; echo "$out"; exit 1; }
echo "$out" | grep >/dev/null '^VERIFIED' || { echo "sold name did not verify:"; echo "$out"; exit 1; }
out=$($verify --url http://127.0.0.1:4943 --insecure-local-root-key --canister "$names" --handover-warn-days 0 "$flat" || true)
echo "$out" | grep >/dev/null '^WARNING' && { echo "verifier warned outside its window"; exit 1; }
echo "$out" | grep >/dev/null '^VERIFIED' || { echo "sold name did not verify with a zero window:"; echo "$out"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $names.localhost:4943" "http://127.0.0.1:4943/$flat")
[ "$code" = 200 ] || { echo "handover page status $code"; exit 1; }
echo "--- expiring lists the name with a deadline; a short window does not"
call expiring "(1_000_000_000_000_000_000 : nat64)" | grep >/dev/null "name = \"$flat\""
call expiring "(1 : nat64)" | grep >/dev/null "name = \"$flat\"" && { echo "expiring listed a name far from its deadline"; exit 1; }
json=$(curl -s -H "Host: $names.localhost:4943" "http://127.0.0.1:4943/api/expiring?days=3650")
echo "$json" | grep >/dev/null "\"name\":\"$flat\"" || { echo "api expiring wrong:"; echo "$json"; exit 1; }
credit=$(( $(call credit "(principal \"$me\")" | tr -d '_ ()nat:') - credit0 ))
[ "$credit" -gt 2000000000000 ] && [ "$credit" -le 2100000000000 ] || { echo "seller credit delta wrong: $credit"; exit 1; }
echo "--- seller withdraws 1T of credit to the ledger"
before=$(bal "$me")
call withdraw "(1_000_000_000_000)" | grep >/dev/null 'Ok'
after=$(bal "$me")
[ $((after - before)) -eq $((1000000000000 - 100000000)) ] || { echo "withdraw moved $((after - before)), expected 1T minus the fee"; exit 1; }
echo "--- the fee comes from the ledger, and the ledger cannot change while funds are held"
call harberger_config | grep >/dev/null 'fee = 100_000_000 : nat'
call set_harberger_config "(record { ledger = principal \"$names\"; rate_bps = 10000 : nat32; min_price = 1_000_000_000; grace_ns = 2_000_000_000 : nat64; fee = 0; flat_names_open = true; handover_warn_ns = 30_000_000_000 : nat64 })" | grep >/dev/null 'funds are held'
echo "--- a rate change settles every flat name first (collected tax grows)"
c0=$(treasury_field collected)
call set_harberger_config "(record { ledger = principal \"$ledger\"; rate_bps = 9000 : nat32; min_price = 1_000_000_000; grace_ns = 2_000_000_000 : nat64; fee = 0; flat_names_open = true; handover_warn_ns = 30_000_000_000 : nat64 })" | grep >/dev/null 'Ok'
[ "$(treasury_field collected)" -gt "$c0" ] || { echo "rate change did not settle"; exit 1; }
call set_harberger_config "(record { ledger = principal \"$ledger\"; rate_bps = 10000 : nat32; min_price = 1_000_000_000; grace_ns = 2_000_000_000 : nat64; fee = 0; flat_names_open = true; handover_warn_ns = 30_000_000_000 : nat64 })" | grep >/dev/null 'Ok'

echo "--- a name whose deposit runs out lapses, frees, and goes back to auction"
lapse="fl$run-b"
# One or two bids per auction from here on: shorter phases.
auction_cfg 10 10
# $id wins alone at the reserve; smoke-other commits and never reveals.
bid_as smoke-other "$lapse" 5_000_000_000 5_000_000_000 s-never | grep >/dev/null 'Ok'
win smoke-local "$lapse" "$handle/app" 2_000_000_000 10_000_000_000
# At the maximum price the opening balance is gone at once: grace, then free.
call set_price "(\"$lapse\", 1_000_000_000_000_000_000)" | grep >/dev/null 'Ok'
sleep 4
call flat_status "(\"$lapse\")" | grep >/dev/null 'status = variant { free }' || { echo "expected free after grace"; call flat_status "(\"$lapse\")"; exit 1; }
call resolve "(\"$lapse\")" | grep >/dev/null 'has lapsed'
call deposit "(\"$lapse\", 1_000_000)" | grep >/dev/null 'bid for it instead'
call buy "(\"$lapse\", \"$handle/app\", 1_000_000_000_000, 100_000_000_000, 1_000_000_000_000_000_000)" | grep >/dev/null 'bid for it instead'
# A longer grace, so the top-up below lands before the opening balance and
# its grace run out.
harb_cfg 10000 10 true
win smoke-other "$lapse" "$handle/self" 1_000_000_000_000 1_100_000_000_000
echo "--- top up keeps a name active"
out=$(dfx canister call --identity smoke-other names deposit "(\"$lapse\", 1_000_000_000)")
echo "$out" | grep >/dev/null 'Ok' || { echo "top-up after the re-sale failed: $out"; exit 1; }
out=$(call get_record "(\"$lapse\")")
echo "$out" | grep >/dev/null "owner = principal \"$other\"" || { echo "lapsed name not re-sold:"; echo "$out"; exit 1; }
echo "$out" | grep >/dev/null "previous_target = opt variant { alias = \"$handle/app\" }" || { echo "re-sold name forgot its target:"; echo "$out"; exit 1; }
echo "--- auction proceeds and tax were collected and the controller can fund the canister from them"
collected=$(treasury_field collected)
available=$((collected - $(treasury_field withdrawn)))
[ "$available" -gt 100000000 ] || { echo "not enough to withdraw past the ledger fee (collected $collected)"; exit 1; }
call fund_self "($((available + 1)))" | grep >/dev/null 'available to withdraw'
call fund_self "(1)" | grep >/dev/null 'exceed the ledger fee'
call fund_self "($available)" | grep >/dev/null 'Ok'
[ "$(treasury_field withdrawn)" = "$collected" ] || { echo "withdrawn != collected after fund_self"; call treasury; exit 1; }
echo "--- a top-up must leave one grace period of tax: dust on an empty name is refused"
# At the maximum price and 100 percent a year the tax is about 3.2e10 per
# second. With an 8 second grace, a 380B balance lapses at 12 s and is
# free at 20 s, so a check at about 14 s lands inside grace with room for
# call latency on either side.
harb_cfg 10000 8 true
dust="fl$run-c"
win smoke-local "$dust" "$handle/app" 2_000_000_000 10_000_000_000
call deposit "(\"$dust\", 380_000_000_000)" | grep >/dev/null 'Ok'
call set_price "(\"$dust\", 1_000_000_000_000_000_000)" | grep >/dev/null 'Ok'
sleep 13
call flat_status "(\"$dust\")" | grep >/dev/null 'grace = record' || { echo "expected grace"; call flat_status "(\"$dust\")"; exit 1; }
call deposit "(\"$dust\", 1_000)" | grep >/dev/null 'one grace period of tax'
call deposit "(\"$dust\", 400_000_000_000)" | grep >/dev/null 'Ok'
call flat_status "(\"$dust\")" | grep >/dev/null 'status = variant { active }'
harb_cfg 10000 2 true
echo "--- release refunds the balance as credit"
ocredit=$(credit_of "$other")
dfx canister call --identity smoke-other names delete_record "(\"$lapse\")" | grep >/dev/null 'Ok'
[ "$(credit_of "$other")" -gt "$ocredit" ] || { echo "release did not credit the balance"; exit 1; }
call flat_status "(\"$lapse\")" | grep >/dev/null '(null)'
echo "--- an auction left open across the upgrade below"
held="fl$run-d"
bid_as smoke-other "$held" 5_000_000_000 5_000_000_000 s-held | grep >/dev/null 'Ok'

echo "--- gateway domains: admin sets them, /.well-known/ic-domains serves them"
call set_domains '(vec { "names.example"; "bad host" })' | grep >/dev/null 'Err'
call set_domains '(vec { "foo..example" })' | grep >/dev/null 'Err'
call set_domains '(vec { "-foo.example" })' | grep >/dev/null 'Err'
call set_domains '(vec { "example" })' | grep >/dev/null 'Err'
call set_domains '(vec { "names.example"; "alt.names.example" })' | grep >/dev/null 'Ok'
dfx canister call --identity smoke-other names set_domains '(vec {})' | grep >/dev/null 'not a controller'
wk=$(curl -s -H "Host: $names.localhost:4943" "http://127.0.0.1:4943/.well-known/ic-domains")
[ "$wk" = "$(printf 'names.example\nalt.names.example\n')" ] || { echo "ic-domains wrong: [$wk]"; exit 1; }

echo "--- http gateway through the local dfx gateway"
gw() { curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H "Host: $names.localhost:4943" "http://127.0.0.1:4943$1"; }
got=$(gw "/$handle/app")
[ "$got" = "302 https://$target.icp0.io/" ] || { echo "redirect wrong: $got"; exit 1; }
got=$(gw "/$handle/missing")
[ "${got%% *}" = 404 ] || { echo "expected 404, got: $got"; exit 1; }
got=$(gw "/")
[ "${got%% *}" = 200 ] || { echo "index expected 200, got: $got"; exit 1; }
echo "--- /api/resolve JSON on the verifying host: certified query response"
json=$(curl -s -H "Host: $names.localhost:4943" "http://127.0.0.1:4943/api/resolve/$handle/app")
hdr=$(curl -s -D - -o /dev/null -H "Host: $names.localhost:4943" "http://127.0.0.1:4943/api/resolve/$handle/app")
echo "$hdr" | grep -i >/dev/null '^ic-certificateexpression:' || { echo "no IC-CertificateExpression header:"; echo "$hdr"; exit 1; }
echo "$json" | grep >/dev/null "\"canister\":\"$target\"" || { echo "api json wrong:"; echo "$json"; exit 1; }
echo "$json" | grep >/dev/null '"certificate":"' || { echo "api json lacks certificate"; exit 1; }
echo "$json" | grep >/dev/null '"witness":"' || { echo "api json lacks witness"; exit 1; }
echo "$json" | grep >/dev/null '"created_ns":"[0-9]*"' || { echo "api json timestamps must be decimal strings"; echo "$json"; exit 1; }
echo "--- /api/search and /api/tags JSON on the verifying host"
json=$(curl -s -H "Host: $names.localhost:4943" "http://127.0.0.1:4943/api/search?q=$handle&tag=deploy&limit=5")
echo "$json" | grep >/dev/null "\"name\":\"$handle/app\"" || { echo "api search wrong:"; echo "$json"; exit 1; }
echo "$json" | grep >/dev/null '"updated_ns":"[0-9]*"' || { echo "api search timestamps must be strings"; echo "$json"; exit 1; }
json=$(curl -s -H "Host: $names.localhost:4943" "http://127.0.0.1:4943/api/tags")
echo "$json" | grep >/dev/null '"tag":"deploy"' || { echo "api tags wrong:"; echo "$json"; exit 1; }

echo "--- upgrade keeps records, re-certifies, and lands on the current schema"
dfx deploy --yes --identity "$id" names --upgrade-unchanged >/dev/null 2>&1
out=$(call resolve "(\"$handle/app\")")
echo "$out" | grep >/dev/null "canister = principal \"$target\"" || { echo "record lost across upgrade"; exit 1; }
echo "$out" | grep >/dev/null 'certificate = opt blob' || { echo "no certificate after upgrade"; exit 1; }
call schema_version | grep >/dev/null '(3 : nat32)' || { echo "schema not at 3 after upgrade"; exit 1; }
call search "(record { tag = opt \"deploy\" })" | grep >/dev/null "$handle/app" || { echo "tag index lost across upgrade"; exit 1; }
call auction_status "(\"$held\")" | grep >/dev/null "principal \"$other\"" || { echo "auction lost across upgrade"; exit 1; }
echo "--- the unrevealed commitment forfeits at close"
wait_phase "$held" closed
call close_auction "(\"$held\")" | tr -d '_' | grep >/dev/null 'forfeited = 5000000000 ' || { echo "unrevealed deposit not forfeited"; exit 1; }

echo "SMOKE OK"

#!/bin/zsh
# Runs the fixed-rate channel flow end to end: anvil + escrow via the demo harness, driving the
# real flamingo verifier host with a mocked enclave. Two processes, one command.
#
#   FLAMINGO_DIR=../flamingo scripts/local-e2e.sh
set -u
ROOT=${0:a:h:h}
FL=${FLAMINGO_DIR:-$ROOT/../flamingo}
LOG=${LOCAL_E2E_LOG_DIR:-$ROOT/target}
mkdir -p "$LOG"

pgrep -x anvil >/dev/null && { echo "stopping a running anvil"; pkill -x anvil; sleep 1; }
lsof -iTCP:8000 -sTCP:LISTEN -t | xargs -r kill 2>/dev/null

[[ -f $ROOT/contracts/out/WorldIDFeeEscrow.sol/WorldIDFeeEscrow.json ]] || (cd "$ROOT/contracts" && forge build >/dev/null)
(cd "$FL" && cargo build -q -p flamingo-verifier-host --features mock-enclave) || { echo "host build failed"; exit 1; }
(cd "$ROOT" && cargo build -q -p world-id-fee-channel-demo) || { echo "harness build failed"; exit 1; }

rm -f "$ROOT/target/local-e2e.env"
(cd "$ROOT" && ./target/debug/world-id-fee-channel-demo local-e2e > "$LOG/harness.log" 2>&1) & HPID=$!
for _ in $(seq 1 90); do [[ -f $ROOT/target/local-e2e.env ]] && break; sleep 1; done
[[ -f $ROOT/target/local-e2e.env ]] || { echo "harness never wrote its env"; tail -20 "$LOG/harness.log"; kill $HPID 2>/dev/null; exit 1; }

set -a; source "$ROOT/target/local-e2e.env"; set +a
(cd "$FL" && ./target/debug/flamingo-verifier-host > "$LOG/host.log" 2>&1) & HOSTPID=$!

wait $HPID; RC=$?
kill $HOSTPID 2>/dev/null; pkill -x anvil 2>/dev/null
tail -15 "$LOG/harness.log"
[[ $RC -eq 0 ]] && echo "local e2e: PASS" || { echo "local e2e: FAIL (exit $RC); see $LOG/harness.log and $LOG/host.log"; }
exit $RC

#!/bin/bash
set -euo pipefail

# Configuration
LEDGER_DIR=".anchor/test-ledger"
PID_FILE=".localnet.pid"
RPC_URL="http://127.0.0.1:8899"
STARTUP_TIMEOUT_S="${STARTUP_TIMEOUT_S:-60}"
BIND_ADDRESS="${BIND_ADDRESS:-127.0.0.1}"
FAUCET_PORT="${FAUCET_PORT:-9900}"
REQUIRED_SOLANA_VERSION="${SOLANA_VERSION:-3.1.10}"

if ! command -v solana-test-validator >/dev/null 2>&1; then
    echo "solana-test-validator is required. Install Agave/Solana CLI ${REQUIRED_SOLANA_VERSION}."
    exit 1
fi
ACTUAL_SOLANA_VERSION="$(solana-test-validator --version | awk '{print $2}')"
if [ "${ACTUAL_SOLANA_VERSION}" != "${REQUIRED_SOLANA_VERSION}" ]; then
    echo "Unsupported local validator version: ${ACTUAL_SOLANA_VERSION}; required ${REQUIRED_SOLANA_VERSION}."
    exit 1
fi
echo "Using authoritative local Agave/Solana validator ${ACTUAL_SOLANA_VERSION}"

is_pid_alive() {
    local pid="$1"
    kill -0 "$pid" 2>/dev/null
}

if [ -f "$PID_FILE" ]; then
    OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "${OLD_PID:-}" ] && is_pid_alive "$OLD_PID"; then
        echo "Localnet seems to be running (PID $OLD_PID). Stop it first."
        exit 1
    fi
    echo "Removing stale pid file: $PID_FILE"
    rm -f "$PID_FILE"
fi

echo "Starting Solana Test Validator..."
mkdir -p "$LEDGER_DIR"

# Start in background (keep args compatible across Solana CLI versions)
solana-test-validator \
    --reset \
    --bind-address "$BIND_ADDRESS" \
    --rpc-port 8899 \
    --faucet-port "$FAUCET_PORT" \
    --ledger "$LEDGER_DIR" \
    > validator.log 2>&1 &
PID=$!
echo "$PID" > "$PID_FILE"

echo "Waiting for RPC..."
START_TS="$(date +%s)"
until curl -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1, "method":"getVersion"}' "$RPC_URL" > /dev/null; do
    if ! is_pid_alive "$PID"; then
        echo ""
        echo "Validator exited before RPC became ready. Last validator.log lines:"
        tail -n 40 validator.log || true
        rm -f "$PID_FILE"
        exit 1
    fi
    NOW_TS="$(date +%s)"
    ELAPSED="$((NOW_TS - START_TS))"
    if [ "$ELAPSED" -ge "$STARTUP_TIMEOUT_S" ]; then
        echo ""
        echo "Timed out waiting for RPC after ${STARTUP_TIMEOUT_S}s. Last validator.log lines:"
        tail -n 40 validator.log || true
        exit 1
    fi
    sleep 1
    echo -n "."
done

echo ""
echo "READY. PID: $PID"

#!/bin/bash
set -e

# Configuration
LEDGER_DIR=".anchor/test-ledger"
PID_FILE=".localnet.pid"
RPC_URL="http://127.0.0.1:8899"
MAX_WAIT_SECONDS=120

if [ -f "$PID_FILE" ]; then
    echo "Localnet seems to be running (pid file exists). Stop it first."
    exit 1
fi

echo "Starting Solana Test Validator..."
mkdir -p $LEDGER_DIR

# Start in background
COPYFILE_DISABLE=1 solana-test-validator --reset \
    --ledger $LEDGER_DIR \
    --bind-address 127.0.0.1 \
    --rpc-port 8899 \
    --faucet-port 9901 \
    --gossip-port 10256 \
    --dynamic-port-range 10240-10300 > validator.log 2>&1 &
PID=$!
echo $PID > $PID_FILE

echo "Waiting for RPC..."
SECONDS_WAITED=0
until curl -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1, "method":"getVersion"}' $RPC_URL > /dev/null; do
    if ! kill -0 "$PID" >/dev/null 2>&1; then
        echo ""
        echo "Validator exited before RPC became ready. See validator.log"
        rm -f "$PID_FILE"
        exit 1
    fi

    if [ "$SECONDS_WAITED" -ge "$MAX_WAIT_SECONDS" ]; then
        echo ""
        echo "Timed out waiting for RPC after ${MAX_WAIT_SECONDS}s. See validator.log"
        kill "$PID" >/dev/null 2>&1 || true
        wait "$PID" >/dev/null 2>&1 || true
        rm -f "$PID_FILE"
        exit 1
    fi

    sleep 1
    SECONDS_WAITED=$((SECONDS_WAITED + 1))
    echo -n "."
done

echo ""
echo "READY. PID: $PID"

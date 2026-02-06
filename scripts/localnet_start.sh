#!/bin/bash
set -e

# Configuration
LEDGER_DIR=".anchor/test-ledger"
PID_FILE=".localnet.pid"
RPC_URL="http://127.0.0.1:8899"

if [ -f "$PID_FILE" ]; then
    echo "Localnet seems to be running (pid file exists). Stop it first."
    exit 1
fi

echo "Starting Solana Test Validator..."
mkdir -p $LEDGER_DIR

# Start in background
solana-test-validator --reset --rpc-port 8899 --ws-port 8900 --ledger $LEDGER_DIR > validator.log 2>&1 &
PID=$!
echo $PID > $PID_FILE

echo "Waiting for RPC..."
until curl -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1, "method":"getVersion"}' $RPC_URL > /dev/null; do
    sleep 1
    echo -n "."
done

echo ""
echo "READY. PID: $PID"
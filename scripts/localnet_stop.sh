#!/bin/bash

PID_FILE=".localnet.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "No pid file found. Is localnet running?"
    # Fallback cleanup just in case
    pkill -f solana-test-validator || true
    exit 0
fi

PID=$(cat $PID_FILE)
echo "Stopping validator (PID: $PID)..."

kill $PID || true
rm $PID_FILE

echo "Stopped."
#!/bin/bash
set -euo pipefail

PID_FILE=".localnet.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "No pid file found. Is localnet running?"
    # Fallback cleanup just in case
    pkill -f solana-test-validator || true
    exit 0
fi

PID=$(cat "$PID_FILE")
echo "Stopping validator (PID: $PID)..."

if kill -0 "$PID" 2>/dev/null; then
    kill "$PID" || true
    # Give it a brief moment to stop cleanly.
    for _ in 1 2 3 4 5; do
        if ! kill -0 "$PID" 2>/dev/null; then
            break
        fi
        sleep 1
    done
fi
rm -f "$PID_FILE"

echo "Stopped."

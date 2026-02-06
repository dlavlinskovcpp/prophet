#!/bin/bash
set -e

# Configuration
CLUSTER="devnet"
KEYPAIR="$HOME/.config/solana/id.json"
PROGRAM_KEYPAIR="target/deploy/prophet-keypair.json"

echo "--- Deploying Prophet to $CLUSTER ---"

# 1. Check for Program Keypair
if [ ! -f "$PROGRAM_KEYPAIR" ]; then
    echo "Error: Program keypair not found at $PROGRAM_KEYPAIR"
    echo "Run 'anchor build' first."
    exit 1
fi

PROGRAM_ID=$(solana address -k $PROGRAM_KEYPAIR)
echo "Program ID: $PROGRAM_ID"

# 2. Build
echo "Building..."
anchor build

# 3. Deploy
echo "Deploying..."
anchor deploy --provider.cluster $CLUSTER --provider.wallet $KEYPAIR

# 4. Initialize/Upgrade IDL
echo "Syncing IDL..."
IDL_PATH="target/idl/prophet.json"

# Try init first (will fail if already exists), then upgrade
anchor idl init --provider.cluster $CLUSTER --provider.wallet $KEYPAIR --filepath $IDL_PATH $PROGRAM_ID || \
anchor idl upgrade --provider.cluster $CLUSTER --provider.wallet $KEYPAIR --filepath $IDL_PATH $PROGRAM_ID

echo "--- Deployment Complete ---"
echo "Program ID: $PROGRAM_ID"
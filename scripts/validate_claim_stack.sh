#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RPC_URL="${RPC_URL:-http://127.0.0.1:8899}"
PROGRAM_ID="${PROPHET_PROGRAM_ID:-}"
WALLET_PATH="${ANCHOR_WALLET:-$HOME/.config/solana/id.json}"
TEST_FILE="tests/claim_signed.ts"
ATTESTER_PORT=8000
RESOLVER_HTTP_PORT="${RESOLVER_HTTP_PORT:-18080}"
REQUIRE_ZKTLS="${REQUIRE_ZKTLS:-0}"
BOND_ATOMS="${BOND_ATOMS:-1234}"
CLAIM_PUBKEY=""
CLAIM_OUTCOME="PASS"
PROOF_B64="cHJvb2Y="
PUBLIC_INPUTS_B64="eyJzdGF0dXMiOjIwMH0="
SKIP_ATTESTER=0
KEEP_LOCALNET=0
SKIP_TS_TEST=0

STARTED_LOCALNET=0
ATTESTER_PID=""
RESOLVER_HTTP_PID=""
AUTO_CTX_PATH=""
CLAIM_VALIDATION_DIR="$ROOT_DIR/scripts/claim_validation"

usage() {
  cat <<'EOF'
Usage: scripts/validate_claim_stack.sh [options]

Validates PR4 in two layers:
1) SDK/API sanity (smoke + deploy + optional TS test)
2) Full PR4 flow: SDK create_claim -> attester /resolve-claim -> SDK redeem_claim

Default behavior (no --claim-pubkey):
- Auto-creates test mint + claim through SDK, resolves through attester, and redeems through SDK.

Options:
  --test-file <path>          TS test file to run (default: tests/claim_signed.ts)
  --skip-ts-test              Skip TS claim test
  --claim-pubkey <pubkey>     Existing open claim pubkey (manual mode for resolve only)
  --claim-outcome <PASS|FAIL|INVALID>
                              Outcome for /resolve-claim (default: PASS)
  --proof-b64 <base64>        Proof bytes payload (default: "proof")
  --public-inputs-b64 <base64>
                              Public inputs payload (default: {"status":200})
  --bond-atoms <u64>          Bond amount for auto-created claim (default: 1234)
  --attester-port <port>      Attester port (default: 8000)
  --resolver-http-port <port> Local JSON endpoint port for resolver URL (default: 18080)
  --skip-attester             Skip attester + PR4 flow
  --keep-localnet             Do not stop validator if script started it
  -h, --help                  Show this help

Environment overrides:
  RPC_URL, PROPHET_PROGRAM_ID, ANCHOR_WALLET, REQUIRE_ZKTLS, BOND_ATOMS, RESOLVER_HTTP_PORT
EOF
}

log() {
  echo "[validate-claims] $*"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
}

resolve_program_id() {
  local keypair_path="target/deploy/prophet-keypair.json"
  local deployed_keypair_id=""
  if [[ -f "$keypair_path" ]]; then
    deployed_keypair_id="$(solana-keygen pubkey "$keypair_path" 2>/dev/null || true)"
  fi

  if [[ -n "${PROPHET_PROGRAM_ID:-}" ]]; then
    PROGRAM_ID="$PROPHET_PROGRAM_ID"
    if [[ -n "$deployed_keypair_id" && "$PROGRAM_ID" != "$deployed_keypair_id" ]]; then
      echo "PROPHET_PROGRAM_ID ($PROGRAM_ID) does not match deployed keypair id ($deployed_keypair_id)." >&2
      echo "Unset PROPHET_PROGRAM_ID or set it to $deployed_keypair_id for this localnet deploy." >&2
      exit 1
    fi
    log "Using program id from PROPHET_PROGRAM_ID: $PROGRAM_ID"
    return
  fi

  if [[ -n "$deployed_keypair_id" ]]; then
      PROGRAM_ID="$deployed_keypair_id"
      export PROPHET_PROGRAM_ID="$PROGRAM_ID"
      log "Using program id from $keypair_path: $PROGRAM_ID"
      return
  fi

  local anchor_toml_id
  anchor_toml_id="$(sed -nE 's/^prophet = "([A-Za-z0-9]+)"/\1/p' Anchor.toml | head -n1)"
  if [[ -n "$anchor_toml_id" ]]; then
    PROGRAM_ID="$anchor_toml_id"
    export PROPHET_PROGRAM_ID="$PROGRAM_ID"
    log "Using program id from Anchor.toml: $PROGRAM_ID"
    return
  fi

  echo "Unable to resolve program id. Set PROPHET_PROGRAM_ID or ensure target/deploy/prophet-keypair.json exists." >&2
  exit 1
}

json_get() {
  local file="$1"
  local key="$2"
  python3 - "$file" "$key" <<'PY'
import json
import sys

with open(sys.argv[1], "r") as f:
    data = json.load(f)
v = data[sys.argv[2]]
if isinstance(v, bool):
    print("true" if v else "false")
else:
    print(v)
PY
}

wait_chain_time_ge() {
  local target_ts="$1"
  PYTHONPATH="$ROOT_DIR/sdk/python" \
    venv/bin/python "$CLAIM_VALIDATION_DIR/wait_chain_time.py" "$RPC_URL" "$target_ts"
}

start_attester() {
  mkdir -p .logs
  pushd apps/oracle-attester >/dev/null
  RPC_URL="$RPC_URL" \
  PROPHET_PROGRAM_ID="$PROGRAM_ID" \
  ORACLE_KEYPAIR_PATH="$WALLET_PATH" \
  REQUIRE_ZKTLS="$REQUIRE_ZKTLS" \
  poetry run uvicorn src.main:app --host 127.0.0.1 --port "$ATTESTER_PORT" \
    > "$ROOT_DIR/.logs/attester.log" 2>&1 &
  ATTESTER_PID=$!
  popd >/dev/null

  for _ in $(seq 1 40); do
    if curl -s "http://127.0.0.1:${ATTESTER_PORT}/health" | grep -q '"ok"'; then
      log "Attester is healthy"
      return
    fi
    sleep 1
  done

  echo "Attester failed health check. See .logs/attester.log" >&2
  exit 1
}

start_resolver_http_server() {
  if curl -s "http://127.0.0.1:${RESOLVER_HTTP_PORT}/status" 2>/dev/null | grep -q '"status"'; then
    log "Local resolver HTTP server already running on :${RESOLVER_HTTP_PORT}"
    return
  fi

  venv/bin/python "$CLAIM_VALIDATION_DIR/resolver_http_server.py" "$RESOLVER_HTTP_PORT" \
    > "$ROOT_DIR/.logs/resolver_http.log" 2>&1 &
  RESOLVER_HTTP_PID=$!

  for _ in $(seq 1 20); do
    if curl -s "http://127.0.0.1:${RESOLVER_HTTP_PORT}/status" 2>/dev/null | grep -q '"status"'; then
      log "Local resolver HTTP server ready on :${RESOLVER_HTTP_PORT}"
      return
    fi
    sleep 1
  done

  echo "Resolver HTTP server failed to start. See .logs/resolver_http.log" >&2
  exit 1
}

resolve_claim_via_attester() {
  local claim_pubkey="$1"
  local response_file="$2"

  local payload
  payload="$(cat <<JSON
{"claim":"${claim_pubkey}","outcome":"${CLAIM_OUTCOME}","proof_bytes_b64":"${PROOF_B64}","public_inputs_bytes_b64":"${PUBLIC_INPUTS_B64}"}
JSON
)"

  local code
  for attempt in $(seq 1 90); do
    code="$(curl -sS -o "$response_file" -w "%{http_code}" \
      -X POST "http://127.0.0.1:${ATTESTER_PORT}/resolve-claim" \
      -H "Content-Type: application/json" \
      --data "$payload")"

    if [[ "$code" == "200" ]]; then
      python3 - "$response_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r") as f:
    d = json.load(f)
if not d.get("signature"):
    raise SystemExit("resolve-claim response missing signature")
if int(d.get("resolved_ts", 0)) <= 0:
    raise SystemExit("resolve-claim response has invalid resolved_ts")
print(json.dumps(d))
PY
      return
    fi

    # Localnet time can lag a bit vs our caller clock; retry this transient.
    if [[ "$code" == "409" ]] && grep -qi "not resolvable yet" "$response_file"; then
      sleep 1
      continue
    fi

    echo "Attester /resolve-claim failed with HTTP $code" >&2
    cat "$response_file" >&2 || true
    exit 1
  done

  echo "Attester /resolve-claim did not become resolvable in time (90s)" >&2
  cat "$response_file" >&2 || true
  exit 1
}

cleanup() {
  if [[ -n "$ATTESTER_PID" ]]; then
    log "Stopping attester (pid=$ATTESTER_PID)"
    kill "$ATTESTER_PID" >/dev/null 2>&1 || true
    wait "$ATTESTER_PID" >/dev/null 2>&1 || true
  fi

  if [[ -n "$RESOLVER_HTTP_PID" ]]; then
    log "Stopping resolver HTTP server (pid=$RESOLVER_HTTP_PID)"
    kill "$RESOLVER_HTTP_PID" >/dev/null 2>&1 || true
    wait "$RESOLVER_HTTP_PID" >/dev/null 2>&1 || true
  fi

  if [[ "$STARTED_LOCALNET" -eq 1 && "$KEEP_LOCALNET" -eq 0 ]]; then
    log "Stopping localnet started by this script"
    bash ./scripts/localnet_stop.sh >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --test-file)
      TEST_FILE="$2"
      shift 2
      ;;
    --skip-ts-test)
      SKIP_TS_TEST=1
      shift
      ;;
    --claim-pubkey)
      CLAIM_PUBKEY="$2"
      shift 2
      ;;
    --claim-outcome)
      CLAIM_OUTCOME="$2"
      shift 2
      ;;
    --proof-b64)
      PROOF_B64="$2"
      shift 2
      ;;
    --public-inputs-b64)
      PUBLIC_INPUTS_B64="$2"
      shift 2
      ;;
    --bond-atoms)
      BOND_ATOMS="$2"
      shift 2
      ;;
    --attester-port)
      ATTESTER_PORT="$2"
      shift 2
      ;;
    --resolver-http-port)
      RESOLVER_HTTP_PORT="$2"
      shift 2
      ;;
    --skip-attester)
      SKIP_ATTESTER=1
      shift
      ;;
    --keep-localnet)
      KEEP_LOCALNET=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

require_cmd anchor
require_cmd solana-test-validator
require_cmd solana-keygen
require_cmd curl
require_cmd yarn
require_cmd node
require_cmd python3

if [[ ! -x "venv/bin/pytest" ]]; then
  echo "Missing test runner: venv/bin/pytest" >&2
  exit 1
fi
if [[ ! -x "venv/bin/python" ]]; then
  echo "Missing Python runner: venv/bin/python" >&2
  exit 1
fi
for helper in \
  "$CLAIM_VALIDATION_DIR/wait_chain_time.py" \
  "$CLAIM_VALIDATION_DIR/resolver_http_server.py" \
  "$CLAIM_VALIDATION_DIR/prepare_token_context.js" \
  "$CLAIM_VALIDATION_DIR/create_claim_context.py" \
  "$CLAIM_VALIDATION_DIR/redeem_claim_assert.py"; do
  if [[ ! -f "$helper" ]]; then
    echo "Missing helper script: $helper" >&2
    exit 1
  fi
done
if [[ ! -f "$TEST_FILE" && "$SKIP_TS_TEST" -eq 0 ]]; then
  echo "Test file not found: $TEST_FILE" >&2
  exit 1
fi

mkdir -p .logs

log "Step 1/9: SDK smoke tests"
venv/bin/pytest -q sdk/python/tests/test_smoke.py

log "Step 2/9: Anchor sync + build"
anchor keys sync -p prophet
anchor build

log "Step 3/9: Ensure localnet running at $RPC_URL"
if curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"getVersion"}' | grep -q '"result"'; then
  log "Localnet already running"
else
  log "Starting localnet"
  bash ./scripts/localnet_start.sh
  STARTED_LOCALNET=1
fi

log "Step 4/9: Deploy program"
anchor deploy --provider.cluster localnet
resolve_program_id

if [[ "$SKIP_TS_TEST" -eq 0 ]]; then
  log "Step 5/9: TS claim test"
  yarn run ts-mocha -p ./tsconfig.json -t 1000000 "$TEST_FILE"
else
  log "Step 5/9: TS claim test skipped (--skip-ts-test)"
fi

if [[ "$SKIP_ATTESTER" -eq 1 ]]; then
  log "Steps 6-9 skipped (--skip-attester)"
  log "Validation completed"
  exit 0
fi

require_cmd poetry

log "Step 6/9: Start attester + health"
start_attester

if [[ -z "$CLAIM_PUBKEY" ]]; then
  log "Step 7/9: Auto PR4 flow - SDK create_claim context setup"
  start_resolver_http_server

  RESOLVER_DEF_PATH="$ROOT_DIR/.logs/pr4_resolver.json"
  cat > "$RESOLVER_DEF_PATH" <<JSON
{"url":"http://127.0.0.1:${RESOLVER_HTTP_PORT}/status","method":"GET","path":"status","predicate":"equals","target_value":200}
JSON
  python3 scripts/seed_resolver.py "$RESOLVER_DEF_PATH" --store-dir apps/oracle-attester/resolver_store >/dev/null

  RESOLVER_HASH="$(
    PYTHONPATH="$ROOT_DIR/sdk/python" venv/bin/python - "$RESOLVER_DEF_PATH" <<'PY'
import json
import sys
from prophet_sdk.resolver_hash import compute_resolver_hash_hex

with open(sys.argv[1], "r") as f:
    resolver_def = json.load(f)
print(compute_resolver_hash_hex(resolver_def))
PY
  )"

  TOKEN_CTX_PATH="$ROOT_DIR/.logs/pr4_token_ctx.json"
  RPC_URL="$RPC_URL" \
  WALLET_PATH="$WALLET_PATH" \
  node "$CLAIM_VALIDATION_DIR/prepare_token_context.js" > "$TOKEN_CTX_PATH"

  QUOTE_MINT="$(json_get "$TOKEN_CTX_PATH" "quote_mint")"
  ISSUER_ATA="$(json_get "$TOKEN_CTX_PATH" "issuer_ata")"
  FAIL_RECIPIENT_PUBKEY="$(json_get "$TOKEN_CTX_PATH" "fail_recipient_pubkey")"
  FAIL_RECIPIENT_SECRET_B64="$(json_get "$TOKEN_CTX_PATH" "fail_recipient_secret_b64")"
  FAIL_RECIPIENT_ATA="$(json_get "$TOKEN_CTX_PATH" "fail_recipient_ata")"
  ORACLE_PUBKEY_TOKEN_CTX="$(json_get "$TOKEN_CTX_PATH" "oracle_pubkey")"

  AUTO_CTX_PATH="$ROOT_DIR/.logs/pr4_auto_ctx.json"
  PYTHONPATH="$ROOT_DIR/sdk/python" \
  RPC_URL="$RPC_URL" \
  PROPHET_PROGRAM_ID="$PROGRAM_ID" \
  WALLET_PATH="$WALLET_PATH" \
  QUOTE_MINT="$QUOTE_MINT" \
  ISSUER_ATA="$ISSUER_ATA" \
  FAIL_RECIPIENT_PUBKEY="$FAIL_RECIPIENT_PUBKEY" \
  ORACLE_PUBKEY_TOKEN_CTX="$ORACLE_PUBKEY_TOKEN_CTX" \
  RESOLVER_HASH="$RESOLVER_HASH" \
  BOND_ATOMS="$BOND_ATOMS" \
  venv/bin/python "$CLAIM_VALIDATION_DIR/create_claim_context.py" > "$AUTO_CTX_PATH"

  CLAIM_PUBKEY="$(json_get "$AUTO_CTX_PATH" "claim_pubkey")"
  TARGET_RESOLVE_TS="$(json_get "$AUTO_CTX_PATH" "resolve_ts")"
  ISSUER_ATA="$(json_get "$AUTO_CTX_PATH" "issuer_ata")"
  ORACLE_PUBKEY_AUTO="$(json_get "$AUTO_CTX_PATH" "oracle_pubkey")"
  if [[ "$ORACLE_PUBKEY_AUTO" != "$ORACLE_PUBKEY_TOKEN_CTX" ]]; then
    echo "Oracle pubkey mismatch between contexts: auto=${ORACLE_PUBKEY_AUTO} token=${ORACLE_PUBKEY_TOKEN_CTX}" >&2
    exit 1
  fi

  ISSUER_BAL_BEFORE_CREATE="$(json_get "$AUTO_CTX_PATH" "issuer_balance_before_create")"
  ISSUER_BAL_AFTER_CREATE="$(json_get "$AUTO_CTX_PATH" "issuer_balance_after_create")"

  log "Auto-created claim via SDK: $CLAIM_PUBKEY"
  log "Waiting for chain time >= resolve_ts ($TARGET_RESOLVE_TS)"
  wait_chain_time_ge "$TARGET_RESOLVE_TS" >/dev/null

  log "Step 8/9: Resolve auto-created claim via attester"
  RESOLVE_RESPONSE_FILE="$ROOT_DIR/.logs/pr4_resolve_response.json"
  resolve_claim_via_attester "$CLAIM_PUBKEY" "$RESOLVE_RESPONSE_FILE"

  log "Step 9/9: SDK redeem_claim + state/balance assertions"
  PYTHONPATH="$ROOT_DIR/sdk/python" \
  RPC_URL="$RPC_URL" \
  PROPHET_PROGRAM_ID="$PROGRAM_ID" \
  WALLET_PATH="$WALLET_PATH" \
  CLAIM_PUBKEY="$CLAIM_PUBKEY" \
  CLAIM_OUTCOME="$CLAIM_OUTCOME" \
  BOND_ATOMS="$BOND_ATOMS" \
  ISSUER_ATA="$ISSUER_ATA" \
  ISSUER_BAL_BEFORE_CREATE="$ISSUER_BAL_BEFORE_CREATE" \
  ISSUER_BAL_AFTER_CREATE="$ISSUER_BAL_AFTER_CREATE" \
  FAIL_RECIPIENT_PUBKEY="$FAIL_RECIPIENT_PUBKEY" \
  FAIL_RECIPIENT_ATA="$FAIL_RECIPIENT_ATA" \
  FAIL_RECIPIENT_SECRET_B64="$FAIL_RECIPIENT_SECRET_B64" \
  venv/bin/python "$CLAIM_VALIDATION_DIR/redeem_claim_assert.py"
else
  log "Step 7/9-9/9 (manual mode): resolve existing claim via attester only"
  log "Manual mode does not auto-check SDK create/redeem. Omit --claim-pubkey for full PR4 validation."
  RESOLVE_RESPONSE_FILE="$ROOT_DIR/.logs/pr4_resolve_response_manual.json"
  resolve_claim_via_attester "$CLAIM_PUBKEY" "$RESOLVE_RESPONSE_FILE"
fi

log "Validation completed"

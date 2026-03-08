#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "[zktls-audit] checking config defaults and runtime non-mock enforcement..."

search() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg -n "$pattern" "$@"
  else
    grep -REn "$pattern" "$@"
  fi
}

# 1) Example config must not advertise insecure defaults.
if search "ZKTLS_MODE=mock|REQUIRE_ZKTLS=0|ALLOW_MOCK_ZKTLS=1" apps/oracle-attester/.env.example; then
  echo "[zktls-audit] insecure defaults found in apps/oracle-attester/.env.example"
  exit 1
fi

# 2) Runtime code should not contain mock artifacts in active paths.
if search "mock-proof-id|mock_sig|MockZkTlsVerifier" sdk/python/examples sdk/python/prophet_sdk apps/oracle-attester/src; then
  echo "[zktls-audit] mock zkTLS artifacts found in runtime code"
  exit 1
fi

# 3) Runtime config implementation must enforce non-mock policy.
if search "ZKTLS_MODE\\s*=\\s*os.getenv\\(\"ZKTLS_MODE\",\\s*\"mock\"\\)" apps/oracle-attester/src/config.py; then
  echo "[zktls-audit] insecure default ZKTLS_MODE=mock detected in runtime config"
  exit 1
fi

if search "REQUIRE_ZKTLS\\s*=\\s*_env_bool\\(\"REQUIRE_ZKTLS\",\\s*False\\)" apps/oracle-attester/src/config.py; then
  echo "[zktls-audit] insecure default REQUIRE_ZKTLS=False detected in runtime config"
  exit 1
fi

if search "ALLOW_MOCK_ZKTLS\\s*=\\s*_env_bool\\(\"ALLOW_MOCK_ZKTLS\",\\s*True\\)" apps/oracle-attester/src/config.py; then
  echo "[zktls-audit] insecure default ALLOW_MOCK_ZKTLS=True detected in runtime config"
  exit 1
fi

if ! search "if mode != \"reclaim_http\"" apps/oracle-attester/src/config.py >/dev/null; then
  echo "[zktls-audit] missing reclaim_http mode enforcement"
  exit 1
fi

if ! search "if not self.REQUIRE_ZKTLS" apps/oracle-attester/src/config.py >/dev/null; then
  echo "[zktls-audit] missing REQUIRE_ZKTLS hard enforcement"
  exit 1
fi

if ! search "if not self.RECLAIM_VERIFY_URL" apps/oracle-attester/src/config.py >/dev/null; then
  echo "[zktls-audit] missing RECLAIM_VERIFY_URL requirement"
  exit 1
fi

echo "[zktls-audit] passed"

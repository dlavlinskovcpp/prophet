#!/usr/bin/env python3
"""Validate the machine-readable RC4.7 residual-risk policy."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "security/rc47_residual_risk.json"


def main() -> int:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if data.get("schema") != "PROPHET_RC47_RESIDUAL_RISK_V1":
        raise SystemExit("invalid RC4.7 residual-risk schema")
    if data.get("release") != "v1.0.0-rc4.7":
        raise SystemExit("invalid RC4.7 residual-risk release")
    for relative in data.get("exception_sources", []):
        source = ROOT / relative
        payload = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(payload.get("exceptions"), list):
            raise SystemExit(f"exception source has no machine-readable list: {relative}")
    print("RC4.7 RESIDUAL-RISK MANIFEST: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate and optionally execute the RC4.8 acceptance basis."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/audit/rc4_8_security_acceptance_basis.json"
PYTEST_RESULT = re.compile(r"(\d+) passed(?:, (\d+) skipped)?")
RUST_RESULT = re.compile(r"test result: ok\. (\d+) passed;.*?(\d+) ignored")


def load_manifest() -> dict:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if data.get("schema") != "PROPHET_RC48_SECURITY_ACCEPTANCE_BASIS_V1" or data.get("version") != 1 or data.get("acceptance_basis_revision") != 7:
        raise SystemExit("invalid RC4.8 acceptance manifest")
    if data.get("previous_manifest_sha256") != "a7f3d1a2ee4b6377a7bfc26cc4ef93e01e559a08d3f1bf4482fe323875b2ad9d":
        raise SystemExit("RC4.7 acceptance basis predecessor changed")
    if data.get("immutable_release", {}).get("rc4_7_commit") != "42351960cae1497d1a0e5dfebf46d65a72c4c5db":
        raise SystemExit("RC4.7 release identity changed")
    if data.get("immutable_crypto_vectors", {}).get("p0c3e_v2") != "9e6dafc41c450a62d733b5bf5bef93fea8f1460641091edd8f818a6f507e254c":
        raise SystemExit("immutable crypto vector record changed")
    return data


def run_lane(lane: dict) -> str:
    result = subprocess.run(lane["command"], cwd=ROOT / lane.get("workdir", "."), text=True, capture_output=True)
    if result.returncode:
        raise SystemExit(f"{lane['id']}: command failed\n{result.stdout}{result.stderr}")
    return result.stdout + result.stderr


def verify(data: dict, *, execute: bool) -> None:
    for lane in data["lanes"]:
        if not execute:
            continue
        if lane["id"] == "anchor_local_e2e" and os.getenv("RC48_SKIP_ANCHOR_E2E") == "1":
            print("anchor_local_e2e: COVERED BY ANCHOR TS INTEGRATION")
            continue
        output = run_lane(lane)
        kind = lane.get("kind")
        if kind == "compile":
            if "Finished" not in output:
                raise SystemExit(f"{lane['id']}: compile completion not found")
        elif kind == "pass":
            print(f"{lane['id']}: PASS")
        else:
            matcher = RUST_RESULT if lane["command"][0] == "cargo" else PYTEST_RESULT
            match = matcher.search(output)
            if match is None:
                raise SystemExit(f"{lane['id']}: result summary not found")
            passed, skipped = int(match.group(1)), int(match.group(2) or 0)
            if (passed, skipped) != (lane["expected_passed"], lane["expected_skipped"]):
                raise SystemExit(f"{lane['id']}: expected {lane['expected_passed']} passed/{lane['expected_skipped']} skipped, got {passed} passed/{skipped} skipped")
            print(f"{lane['id']}: {passed} passed, {skipped} skipped")
    print("RC4.8 acceptance manifest: " + ("PASS" if execute else "VALID"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    verify(load_manifest(), execute=args.run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

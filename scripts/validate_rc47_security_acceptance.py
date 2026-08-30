#!/usr/bin/env python3
"""Validate and optionally run the repository-backed RC4.7 acceptance basis."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/audit/rc4_7_security_acceptance_basis.json"
PYTEST_RESULT = re.compile(r"(\d+) passed(?:, (\d+) skipped)?")
RUST_RESULT = re.compile(r"test result: ok\. (\d+) passed;.*?(\d+) ignored")


def load_manifest() -> dict:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if data.get("schema") != "PROPHET_RC47_SECURITY_ACCEPTANCE_BASIS_V1" or data.get("version") != 1:
        raise SystemExit("invalid RC4.7 acceptance manifest schema")
    if data.get("acceptance_basis_revision") != 6:
        raise SystemExit("invalid RC4.7 acceptance manifest revision")
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
        output = run_lane(lane)
        if lane.get("kind") == "compile":
            if "Finished" not in output:
                raise SystemExit(f"{lane['id']}: compile completion not found")
            print(f"{lane['id']}: PASS")
            continue
        if lane.get("kind") == "pass":
            if "PASS" not in output:
                raise SystemExit(f"{lane['id']}: pass marker not found")
            print(f"{lane['id']}: PASS")
            continue
        matcher = RUST_RESULT if lane["command"][0] == "cargo" else PYTEST_RESULT
        match = matcher.search(output)
        if match is None:
            raise SystemExit(f"{lane['id']}: result summary not found")
        passed = int(match.group(1))
        skipped = int(match.group(2) or 0) if matcher is PYTEST_RESULT else int(match.group(2))
        if passed != lane["expected_passed"] or skipped != lane["expected_skipped"]:
            raise SystemExit(f"{lane['id']}: expected {lane['expected_passed']} passed/{lane['expected_skipped']} skipped, got {passed} passed/{skipped} skipped")
        print(f"{lane['id']}: {passed} passed, {skipped} skipped")
    if not execute:
        print("RC4.7 acceptance manifest: VALID")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    verify(load_manifest(), execute=args.run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

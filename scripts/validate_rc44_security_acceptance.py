#!/usr/bin/env python3
"""Validate the one manifest-backed RC4.4 reproducible security basis."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/audit/rc4_4_security_acceptance_basis.json"
PYTEST_COLLECTED = re.compile(r"(\d+) tests collected")
PYTEST_RESULT = re.compile(r"(\d+) passed(?:, (\d+) skipped)?")
RUST_RESULT = re.compile(r"test result: ok\. (\d+) passed;.*?(\d+) ignored")


def load_manifest() -> dict:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if data.get("schema") != "PROPHET_RC44_SECURITY_ACCEPTANCE_BASIS_V1" or data.get("version") != 1:
        raise SystemExit("invalid RC4.4 acceptance manifest schema")
    if data.get("acceptance_basis_revision") != 3:
        raise SystemExit("invalid RC4.4 acceptance manifest revision")
    supersession = data.get("supersession")
    if not isinstance(supersession, dict) or set(supersession) != {
        "previous_acceptance_basis", "previous_manifest_sha256",
        "current_acceptance_basis", "reason", "lane_reconciliations",
    }:
        raise SystemExit("invalid RC4.4 acceptance manifest supersession")
    if (supersession["previous_acceptance_basis"], supersession["current_acceptance_basis"]) != ("POST-I5", "POST-R5"):
        raise SystemExit("invalid RC4.4 acceptance basis transition")
    if not re.fullmatch(r"[0-9a-f]{64}", supersession["previous_manifest_sha256"]):
        raise SystemExit("invalid RC4.4 previous manifest digest")
    if supersession["previous_manifest_sha256"] != "439ff97be38b52a7c5ac05de19ae8167d20d38660fd9b5815feee80e13647840":
        raise SystemExit("invalid RC4.4 revision-2 predecessor digest")
    if supersession["reason"] != "20 permanent R5 signed-package temporal-authority regressions":
        raise SystemExit("invalid RC4.4 post-R5 supersession reason")
    reconciliations = supersession["lane_reconciliations"]
    if not isinstance(reconciliations, dict) or set(reconciliations) != {"p0c3e1", "oracle_attester"}:
        raise SystemExit("invalid RC4.4 lane reconciliation")
    for lane_id, expected in (("p0c3e1", (295, 315, 20)), ("oracle_attester", (1300, 1320, 20))):
        row = reconciliations[lane_id]
        if not isinstance(row, dict) or (row.get("previous_passed"), row.get("current_passed"), row.get("delta_passed")) != expected:
            raise SystemExit(f"invalid RC4.4 {lane_id} reconciliation")
    oracle = reconciliations["oracle_attester"]
    if (oracle.get("previous_skipped"), oracle.get("current_skipped"), oracle.get("delta_skipped")) != (3, 3, 0):
        raise SystemExit("invalid RC4.4 oracle skip reconciliation")
    if data.get("acceptance_semantics") != {
        "authority_root": "FRESH VERIFIED SIGNED PACKAGE + RAW EVIDENCE + TRUSTED CONTEXT ONLY",
        "package_deadline_source": "VERIFIED SIGNED PACKAGE.valid_until ONLY",
        "caller_package_deadline_authority": "NONE",
        "one_trusted_now_per_decision": True,
        "subordinate_containment_deadline": "SIGNED PACKAGE DEADLINE",
    }:
        raise SystemExit("invalid RC4.4 post-R5 authority acceptance semantics")
    if not isinstance(data.get("lanes"), list) or not data["lanes"]:
        raise SystemExit("RC4.4 acceptance manifest has no lanes")
    ids = [lane.get("id") for lane in data["lanes"]]
    if len(ids) != len(set(ids)) or any(not isinstance(value, str) or not value for value in ids):
        raise SystemExit("RC4.4 acceptance manifest lane IDs are invalid")
    commands = [tuple(lane.get("command", ())) for lane in data["lanes"]]
    if any(not command for command in commands) or len(commands) != len(set(commands)):
        raise SystemExit("RC4.4 acceptance manifest selector ownership is invalid")
    by_id = {lane["id"]: lane for lane in data["lanes"]}
    if by_id.get("i5_i2b", {}).get("expected_passed") != 39:
        raise SystemExit("RC4.4 I5 acceptance lane is invalid")
    if by_id.get("r5", {}).get("expected_passed") != 20:
        raise SystemExit("RC4.4 R5 acceptance lane is invalid")
    if by_id.get("p0c3e1", {}).get("expected_passed") != 315 or by_id.get("oracle_attester", {}).get("expected_passed") != 1320:
        raise SystemExit("RC4.4 post-R5 acceptance counts are invalid")
    return data


def run(lane: dict, *, collect_only: bool) -> str:
    command = list(lane["command"])
    if collect_only:
        try:
            index = command.index("-q")
        except ValueError as exc:
            raise SystemExit(f"{lane['id']}: command is not a pytest selector") from exc
        command[index:index + 1] = ["--collect-only", "-q"]
    result = subprocess.run(command, cwd=ROOT / lane["workdir"], text=True, capture_output=True)
    if result.returncode:
        raise SystemExit(f"{lane['id']}: command failed\n{result.stdout}{result.stderr}")
    return result.stdout + result.stderr


def verify_collection(data: dict) -> None:
    for lane in data["lanes"]:
        if lane["command"][0] != "poetry":
            continue
        output = run(lane, collect_only=True)
        match = PYTEST_COLLECTED.search(output)
        if match is None or int(match.group(1)) != lane["expected_passed"] + lane["expected_skipped"]:
            raise SystemExit(f"{lane['id']}: collected membership/count drift")
    print("RC4.4 acceptance collection contract: PASS")


def verify_execution(data: dict) -> None:
    for lane in data["lanes"]:
        output = run(lane, collect_only=False)
        matcher = RUST_RESULT if lane["command"][0] == "cargo" else PYTEST_RESULT
        match = matcher.search(output)
        if match is None:
            raise SystemExit(f"{lane['id']}: result summary not found")
        passed = int(match.group(1))
        skipped = int(match.group(2) or 0) if matcher is PYTEST_RESULT else 0
        if passed != lane["expected_passed"] or skipped != lane["expected_skipped"]:
            raise SystemExit(f"{lane['id']}: expected {lane['expected_passed']} passed/{lane['expected_skipped']} skipped, got {passed} passed/{skipped} skipped")
        print(f"{lane['id']}: {passed} passed, {skipped} skipped")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true", help="execute every acceptance lane")
    parser.add_argument("--verify-collection", action="store_true", help="verify manifest-backed pytest collection counts")
    args = parser.parse_args()
    data = load_manifest()
    if not args.run and not args.verify_collection:
        parser.error("one of --run or --verify-collection is required")
    verify_collection(data)
    if args.run:
        verify_execution(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

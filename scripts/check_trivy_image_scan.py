#!/usr/bin/env python3
"""Fail closed on unreviewed HIGH/CRITICAL final-runtime image findings."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any


class ScanPolicyError(ValueError):
    """The scan report does not satisfy the explicit exception policy."""


def _findings(report: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for result in report.get("Results", []):
        for vulnerability in result.get("Vulnerabilities") or []:
            if vulnerability.get("Severity") not in {"HIGH", "CRITICAL"}:
                continue
            findings.append(
                {
                    "vulnerability_id": str(vulnerability.get("VulnerabilityID", "")),
                    "package": str(vulnerability.get("PkgName", "")),
                    "installed_version": str(vulnerability.get("InstalledVersion", "")),
                    "ecosystem": str(result.get("Type", "")),
                    "status": str(vulnerability.get("Status", "")),
                }
            )
    return findings


def _exception_key(entry: dict[str, Any], role: str) -> tuple[str, str, str, str] | None:
    required = (
        "vulnerability_id",
        "package",
        "installed_version",
        "ecosystem",
        "disposition",
        "reason",
        "removal_assessment",
        "compensating_controls",
        "owner",
        "review_by",
        "expires_on",
    )
    missing = [field for field in required if not entry.get(field)]
    if missing:
        raise ScanPolicyError(f"exception is missing required fields: {', '.join(missing)}")
    if entry["disposition"] != "affected_with_temporary_exception":
        raise ScanPolicyError(f"invalid disposition for {entry['vulnerability_id']}")
    if role not in entry.get("roles", []):
        return None
    try:
        review_by = dt.date.fromisoformat(entry["review_by"])
        expires_on = dt.date.fromisoformat(entry["expires_on"])
    except ValueError as error:
        raise ScanPolicyError(f"invalid exception date: {error}") from error
    today = dt.date.today()
    if review_by < today or expires_on < today:
        raise ScanPolicyError(f"expired exception for {entry['vulnerability_id']}")
    return (
        entry["vulnerability_id"],
        entry["package"],
        entry["installed_version"],
        entry["ecosystem"],
    )


def validate(report: dict[str, Any], policy: dict[str, Any] | None, role: str) -> None:
    if policy is None:
        findings = _findings(report)
        if findings:
            raise ScanPolicyError(f"unexplained findings: {findings!r}")
        return
    if policy.get("schema_version") != 1:
        raise ScanPolicyError("unsupported exception policy schema")
    allowed: set[tuple[str, str, str, str]] = set()
    for entry in policy.get("exceptions", []):
        key = _exception_key(entry, role)
        if key is not None:
            if key in allowed:
                raise ScanPolicyError(f"duplicate exception for {key[0]} / {key[1]}")
            allowed.add(key)

    observed = {
        (
            finding["vulnerability_id"],
            finding["package"],
            finding["installed_version"],
            finding["ecosystem"],
        )
        for finding in _findings(report)
    }
    unexplained = sorted(observed - allowed)
    stale = sorted(allowed - observed)
    if unexplained or stale:
        lines = []
        if unexplained:
            lines.append("unexplained findings: " + repr(unexplained))
        if stale:
            lines.append("stale exceptions: " + repr(stale))
        raise ScanPolicyError("; ".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--exceptions", type=Path)
    parser.add_argument("--role", required=True, choices=("oracle", "keeper"))
    args = parser.parse_args()
    try:
        validate(
            json.loads(args.report.read_text(encoding="utf-8")),
            (
                json.loads(args.exceptions.read_text(encoding="utf-8"))
                if args.exceptions is not None
                else None
            ),
            args.role,
        )
    except (OSError, json.JSONDecodeError, ScanPolicyError) as error:
        print(f"TRIVY IMAGE SCAN POLICY FAILED: {error}", file=sys.stderr)
        return 1
    print(f"TRIVY FINAL-RUNTIME SCAN POLICY PASSED ({args.role})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

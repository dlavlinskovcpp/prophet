#!/usr/bin/env python3
"""Fail closed on RustSec findings not covered by reviewed temporary exceptions."""

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXCEPTIONS = ROOT / "security" / "cargo-audit-exceptions.json"


def finding_id(kind: str, row: dict) -> str:
    advisory = row.get("advisory")
    if advisory:
        return advisory["id"]
    package = row["package"]
    return f"{kind.upper()}:{package['name']}@{package['version']}"


parser = argparse.ArgumentParser()
parser.add_argument("--db", required=True, help="checked-out RustSec advisory database")
args = parser.parse_args()

policy = json.loads(EXCEPTIONS.read_text(encoding="utf-8"))
today = dt.date.today()
allowed = {}
for item in policy.get("exceptions", []):
    review_by = dt.date.fromisoformat(item["review_by"])
    key = (item["id"], item["package"], item["kind"])
    if key in allowed:
        raise SystemExit(f"DUPLICATE CARGO AUDIT EXCEPTION: {key}")
    if today > review_by:
        raise SystemExit(
            f"EXPIRED CARGO AUDIT EXCEPTION: {item['id']} "
            f"(review_by={item['review_by']})"
        )
    allowed[key] = item

proc = subprocess.run(
    ["cargo", "audit", "--format", "json", "--db", args.db, "--file", "Cargo.lock"],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
try:
    report = json.loads(proc.stdout)
except json.JSONDecodeError:
    sys.stderr.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    raise SystemExit("CARGO AUDIT TOOL/NETWORK FAILURE: no machine-readable report")

findings = set()
for kind, rows in report.get("warnings", {}).items():
    for row in rows:
        findings.add((finding_id(kind, row), row["package"]["name"], kind))
for row in report.get("vulnerabilities", {}).get("list", []):
    findings.add((finding_id("vulnerability", row), row["package"]["name"], "vulnerability"))

unexpected = findings - set(allowed)
stale = set(allowed) - findings
if unexpected:
    for finding in sorted(unexpected):
        print("UNAPPROVED CARGO AUDIT FINDING:", " | ".join(finding))
    raise SystemExit(1)
if stale:
    for finding in sorted(stale):
        print("STALE CARGO AUDIT EXCEPTION:", " | ".join(finding))
    raise SystemExit(1)
if proc.returncode:
    sys.stderr.write(proc.stderr)
    raise SystemExit(f"CARGO AUDIT FAILED WITH EXIT CODE {proc.returncode}")

print(f"CARGO AUDIT PASSED WITH {len(findings)} EXPLICIT TEMPORARY EXCEPTION(S)")

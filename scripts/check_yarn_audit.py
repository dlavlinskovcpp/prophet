#!/usr/bin/env python3

import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCEPTIONS = ROOT / "security" / "yarn-audit-exceptions.json"

policy = json.loads(EXCEPTIONS.read_text(encoding="utf-8"))
exceptions = policy.get("exceptions", [])

today = dt.date.today()
allowed = {}

for item in exceptions:
    review_by = dt.date.fromisoformat(item["review_by"])
    if today > review_by:
        raise SystemExit(
            f"EXPIRED YARN AUDIT EXCEPTION: {item['advisory']} "
            f"(review_by={review_by})"
        )

    key = (
        item["advisory"],
        item["package"],
        item["severity"].lower(),
        item["path"],
    )
    if key in allowed:
        raise SystemExit(f"DUPLICATE YARN AUDIT EXCEPTION: {key}")
    allowed[key] = item

proc = subprocess.run(
    ["yarn", "audit", "--json"],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

findings = set()
saw_summary = False

for raw in proc.stdout.splitlines():
    try:
        row = json.loads(raw)
    except json.JSONDecodeError:
        continue

    if row.get("type") == "auditSummary":
        saw_summary = True
        continue

    if row.get("type") != "auditAdvisory":
        continue

    data = row["data"]
    advisory = data["advisory"]

    findings.add(
        (
            advisory["github_advisory_id"],
            advisory["module_name"],
            advisory["severity"].lower(),
            data["resolution"]["path"],
        )
    )

if not saw_summary:
    sys.stderr.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    raise SystemExit("YARN AUDIT TOOL/NETWORK FAILURE: no auditSummary received")

unexpected = findings - set(allowed)
stale = set(allowed) - findings

if unexpected:
    for finding in sorted(unexpected):
        print("UNAPPROVED YARN ADVISORY:", " | ".join(finding))
    raise SystemExit(1)

if stale:
    for finding in sorted(stale):
        print("STALE YARN AUDIT EXCEPTION:", " | ".join(finding))
    raise SystemExit(1)

print(
    f"YARN AUDIT PASSED WITH "
    f"{len(findings)} EXPLICIT TEMPORARY EXCEPTION(S)"
)

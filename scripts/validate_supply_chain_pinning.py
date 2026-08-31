#!/usr/bin/env python3
"""Reject mutable GitHub Actions and download/tooling identities."""
from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
OPERATED_COMPOSE = ROOT / "deploy" / "operated" / "public-devnet" / "docker-compose.yml"
USES = re.compile(r"^\s*uses:\s*([^\s#]+)(?:\s+#\s*(.+))?$", re.MULTILINE)
SHA = re.compile(r"^[0-9a-f]{40}$")


def validate() -> list[str]:
    errors: list[str] = []
    for workflow in sorted(WORKFLOW_ROOT.glob("*.y*ml")):
        text = workflow.read_text(encoding="utf-8")
        if workflow.name == "ci.yml" and not re.search(r"(?m)^permissions:\s*\n\s+contents:\s+read\s*$", text):
            errors.append(f"{workflow}: workflow default permissions must be contents: read")
        if re.search(r"(?m)^\s+(?:contents|packages|actions|pull-requests|id-token):\s*(?:write|write-all)\s*$", text):
            errors.append(f"{workflow}: broad write token permission requires explicit security review")
        for match in USES.finditer(text):
            reference, comment = match.groups()
            if reference.startswith("./") or reference.startswith(".github/"):
                continue
            if "@" not in reference:
                errors.append(f"{workflow}: action has no ref: {reference}")
                continue
            owner_repo, ref = reference.rsplit("@", 1)
            if "/" not in owner_repo or not SHA.fullmatch(ref):
                errors.append(f"{workflow}: action is not pinned to a full SHA: {reference}")
            if not comment or not comment.strip():
                errors.append(f"{workflow}: pinned action lacks human version comment: {reference}")
        if re.search(r"curl[^\n|]*\|\s*(?:ba)?sh|sh\s+-c\s+.*\$\(.*curl", text):
            errors.append(f"{workflow}: unauthenticated curl-to-shell execution")
        if "aquasec/trivy:" in text or "anchore/syft:" in text:
            errors.append(f"{workflow}: scanner image uses a mutable tag")
    if OPERATED_COMPOSE.is_file():
        for lineno, raw_line in enumerate(OPERATED_COMPOSE.read_text(encoding="utf-8").splitlines(), start=1):
            match = re.match(r"^\s*image:\s*([^\s#]+)", raw_line)
            if match and "@sha256:" not in match.group(1):
                errors.append(f"{OPERATED_COMPOSE}:{lineno}: operated image is not digest pinned: {match.group(1)}")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(error)
        return 1
    print("SUPPLY-CHAIN PINNING: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

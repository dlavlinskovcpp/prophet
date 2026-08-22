#!/usr/bin/env python3
"""Scan tracked release/deployment material for accidental credential material.

Only Git-tracked files are inspected. Operator secret directories and untracked
local files are deliberately outside this CI scanner's boundary.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUSPICIOUS_FILE = re.compile(r"(?:^|/)(?:id|wallet|oracle-keypair|.*-keypair)\.json$", re.I)
TOKEN_ASSIGNMENT = re.compile(r"(?i)\b(?:VAULT_TOKEN|BEARER_TOKEN|AUTH_TOKEN|API_KEY)\s*[=:]\s*([^\s#]+)")
SAFE_MARKERS = ("replace-me", "replace_", "configure_", "example", "external_secret_manager_reference", "${", "<")


def _keypair_shape(value) -> bool:
    if isinstance(value, list):
        if len(value) == 64 and all(type(item) is int and 0 <= item <= 255 for item in value):
            return True
        return any(_keypair_shape(item) for item in value)
    if isinstance(value, dict):
        return any(_keypair_shape(item) for item in value.values())
    return False


def tracked_files() -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    )
    return [ROOT / raw.decode() for raw in proc.stdout.split(b"\0") if raw]


def main() -> int:
    errors: list[str] = []
    for path in tracked_files():
        rel = path.relative_to(ROOT).as_posix()
        name = path.name
        if name == ".env" or rel.endswith("/.env"):
            errors.append(f"tracked .env file: {rel}")
        if SUSPICIOUS_FILE.search(rel) and not rel.startswith("tests/fixtures/"):
            errors.append(f"tracked local-wallet/keypair-shaped file: {rel}")
        if path.suffix.lower() == ".json" and rel.startswith(("deploy/", "releases/")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                value = None
            if value is not None and _keypair_shape(value):
                errors.append(f"Solana secret-key-array-shaped JSON: {rel}")

        # Credential literals are relevant in deployment/release material. Tests
        # and CI intentionally contain local-only dummy tokens and are not release
        # material, so keep the scanner boundary precise rather than whitelisting
        # arbitrary secret-looking values repository-wide.
        if rel.startswith(("deploy/", "releases/")) and path.is_file():
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for match in TOKEN_ASSIGNMENT.finditer(text):
                value = match.group(1).strip('"\'')
                lower = value.lower()
                if value and not any(marker in lower for marker in SAFE_MARKERS):
                    errors.append(f"credential-like literal in {rel}")
                    break

    if errors:
        print("RELEASE SECRET HYGIENE FAILED")
        for error in sorted(set(errors)):
            print(f"- {error}")
        return 1
    print("RELEASE SECRET HYGIENE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

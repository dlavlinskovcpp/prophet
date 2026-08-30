#!/usr/bin/env python3
"""Validate static reproducibility inputs for both production Dockerfiles."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    policy = json.loads((ROOT / "security/rc47_container_reproducibility.json").read_text(encoding="utf-8"))
    base = policy["base_image"]
    sqlite = policy["sqlite"]
    build = policy["debian_packages"]
    for dockerfile in (ROOT / "apps/oracle-attester/Dockerfile", ROOT / "apps/matching-keeper/Dockerfile"):
        text = dockerfile.read_text(encoding="utf-8")
        for required in (base, sqlite["source_url"], sqlite["source_sha256"], 'test "$(',
                         f'build-essential=${{BUILD_ESSENTIAL_VERSION}}', f'ca-certificates=${{CA_CERTIFICATES_VERSION}}'):
            if required not in text:
                raise SystemExit(f"{dockerfile}: missing reproducibility input {required}")
        if text.count("sqlite3.sqlite_version == \"3.53.4\"") != 1:
            raise SystemExit(f"{dockerfile}: missing SQLite runtime ABI assertion")
    print("CONTAINER REPRODUCIBILITY INPUTS: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

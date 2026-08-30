#!/usr/bin/env python3
"""Small checked-in static gate for security-sensitive Python modules."""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECURITY_DIRS = (ROOT / "apps/oracle-attester/src", ROOT / "sdk/python/prophet_sdk")


def main() -> int:
    for directory in SECURITY_DIRS:
        for path in directory.rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            if "# type: ignore" in source:
                print(f"forbidden type suppression marker: {path}")
                return 1
            for node in ast.walk(tree):
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                    if isinstance(node.value.value, str) and "# type: ignore" in node.value.value:
                        print(f"forbidden type suppression marker: {path}:{node.lineno}")
                        return 1
    print("PYTHON SECURITY STATIC: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

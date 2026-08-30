#!/usr/bin/env python3
"""Retired compatibility entrypoint for the former dual-token recovery smoke.

Recovery is role-local in RC4.4 P0C4. Keeping this name as a hard failure
prevents old operator automation from reconstructing a same-process A+B
credential capability.
"""
from __future__ import annotations


def main() -> int:
    raise SystemExit("secure_vault_2of2_smoke_retired_role_local_recovery_required")


if __name__ == "__main__":
    main()

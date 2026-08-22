#!/usr/bin/env python3
"""Structural RC4 validation for production-shaped operated compose/config."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENTS = ("devnet", "public-devnet", "mainnet-beta")
REQUIRED_SERVICES = {
    "resolver-registry",
    "verifier-a",
    "verifier-b",
    "coordinator",
    "secure-settlement",
    "matching-keeper",
}


def _service_names(text: str) -> set[str]:
    return set(re.findall(r"(?m)^  ([a-z0-9-]+):\s*$", text))


def _block(text: str, service: str) -> str:
    match = re.search(rf"(?ms)^  {re.escape(service)}:\s*\n(.*?)(?=^  [a-z0-9-]+:\s*$|^networks:|\Z)", text)
    if not match:
        raise ValueError(f"missing service {service}")
    return match.group(1)


def validate_environment(name: str) -> list[str]:
    errors: list[str] = []
    base = ROOT / "deploy/operated" / name
    compose = base / "docker-compose.yml"
    text = compose.read_text(encoding="utf-8")
    services = _service_names(text)
    for missing in sorted(REQUIRED_SERVICES - services):
        errors.append(f"{name}: compose missing {missing}")
    for forbidden in ("oracle-attester", "remote-signer"):
        if forbidden in services:
            errors.append(f"{name}: forbidden legacy settlement service {forbidden}")

    for service in ("resolver-registry", "verifier-a", "verifier-b", "coordinator", "secure-settlement"):
        try:
            block = _block(text, service)
        except ValueError as exc:
            errors.append(f"{name}: {exc}")
            continue
        if "build: { context: ../../.., dockerfile: apps/oracle-attester/Dockerfile }" not in block:
            errors.append(f"{name}: {service} must use repo-root oracle Docker build context")
    try:
        keeper = _block(text, "matching-keeper")
        if "build: { context: ../../.., dockerfile: apps/matching-keeper/Dockerfile }" not in keeper:
            errors.append(f"{name}: keeper must use repo-root production Docker build context")
    except ValueError as exc:
        errors.append(f"{name}: {exc}")

    try:
        registry = _block(text, "resolver-registry")
        if "/resolver_audit:/app/audit" not in registry:
            errors.append(f"{name}: resolver audit is not on persistent runtime storage")
    except ValueError:
        pass
    for service in ("coordinator", "secure-settlement"):
        try:
            block = _block(text, service)
            if f"/state:/var/lib/prophet/{name}" not in block:
                errors.append(f"{name}: {service} durable state mount missing")
        except ValueError:
            pass

    resolver_env = base / "resolver-registry.env.example"
    if not resolver_env.exists():
        errors.append(f"{name}: resolver-registry.env.example missing")
    else:
        env = resolver_env.read_text(encoding="utf-8")
        for required in (
            "RATE_LIMIT_TRUST_X_FORWARDED_FOR=0",
            "RATE_LIMIT_MAX_IDENTITIES=",
            "RESOLVER_REGISTRY_MAX_REQUEST_BYTES=",
            "RESOLVER_REGISTRY_AUDIT_LOG_PATH=/app/audit/",
        ):
            if required not in env:
                errors.append(f"{name}: resolver bounded/safe-default config missing {required}")

    for runtime in sorted(base.glob("verifier-*-runtime.example.yaml")):
        value = runtime.read_text(encoding="utf-8")
        if "limits:" not in value or "request_max_bytes:" not in value:
            errors.append(f"{name}: {runtime.name} lacks bounded request/response policy")

    oracle_env = base / "oracle-attester.env.example"
    if oracle_env.exists():
        env = oracle_env.read_text(encoding="utf-8")
        for required in (
            "PROOF_HTTP_MAX_RESPONSE_BYTES=",
            "RESOLVER_REGISTRY_MAX_RESPONSE_BYTES=",
            "RATE_LIMIT_MAX_IDENTITIES=",
            "RATE_LIMIT_TRUST_X_FORWARDED_FOR=0",
        ):
            if required not in env:
                errors.append(f"{name}: oracle bounded-resource config missing {required}")
    return errors


def main() -> int:
    errors = [error for name in ENVIRONMENTS for error in validate_environment(name)]
    if errors:
        print("OPERATED STRUCTURAL VALIDATION FAILED")
        for error in errors:
            print(f"- {error}")
        return 1
    print("OPERATED STRUCTURAL VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


ROOT = Path(__file__).resolve().parent.parent
OPERATED_DIR = ROOT / "deploy" / "operated"
ENVIRONMENTS_DIR = ROOT / "deploy" / "environments"
SERVICES = (
    "oracle-attester",
    "remote-signer",
    "resolver-registry",
    "matching-keeper",
)
COMMON_REQUIRED_VALUES = (
    "ATTESTER_BASE_URL",
    "REMOTE_SIGNER_PUBLIC_URL",
    "RESOLVER_REGISTRY_PUBLIC_URL",
    "MATCHING_KEEPER_BASE_URL",
    "RECLAIM_VERIFY_URL",
)
AWS_KMS_REQUIRED_VALUES = (
    "REMOTE_SIGNER_AWS_KMS_REGION",
    "REMOTE_SIGNER_AWS_KMS_KEY_IDS",
)
COMMAND_REQUIRED_VALUES = (
    "REMOTE_SIGNER_COMMAND",
    "REMOTE_SIGNER_COMMAND_PUBLIC_KEYS",
)
SECRET_VALUE_KEYS = (
    "REMOTE_SIGNER_API_KEY",
    "RESOLVER_REGISTRY_SERVICE_API_KEY",
    "API_AUTH_TOKEN",
)
SUPPORTED_REMOTE_SIGNER_BACKENDS = {"aws_kms", "command"}


class RenderError(RuntimeError):
    pass


def _parse_env_lines(lines: Iterable[str]) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def _read_env_file(path: Path) -> Dict[str, str]:
    if not path.exists():
        raise RenderError(f"Missing values file: {path}")
    return _parse_env_lines(path.read_text(encoding="utf-8").splitlines())


def _load_environment_config(env_name: str) -> Tuple[Path, Dict[str, object]]:
    path = ENVIRONMENTS_DIR / f"{env_name}.json"
    if not path.exists():
        raise RenderError(f"Unknown environment '{env_name}': {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RenderError(f"Invalid JSON in {path}: {exc}") from exc
    if payload.get("environment") != env_name:
        raise RenderError(
            f"Environment config mismatch in {path}: expected {env_name!r}, found {payload.get('environment')!r}"
        )
    return path, payload


def _derive_ws_url(rpc_url: str) -> str:
    if rpc_url.startswith("https://"):
        return "wss://" + rpc_url[len("https://") :]
    if rpc_url.startswith("http://"):
        return "ws://" + rpc_url[len("http://") :]
    return rpc_url


def _is_https(url: str) -> str:
    return "1" if url.startswith("https://") else "0"


def _merge_values(base: Dict[str, str], overrides: Iterable[str]) -> Dict[str, str]:
    merged = dict(base)
    for item in overrides:
        if "=" not in item:
            raise RenderError(f"Invalid --set value {item!r}; expected KEY=VALUE.")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise RenderError(f"Invalid --set value {item!r}; missing key.")
        merged[key] = value.strip()
    return merged


def _final_values(
    *,
    env_name: str,
    env_config: Dict[str, object],
    loaded: Dict[str, str],
    generate_secrets: bool,
) -> Dict[str, str]:
    defaults = {
        "RPC_URL": str(env_config["rpc_url"]),
        "WS_URL": _derive_ws_url(str(loaded.get("RPC_URL", env_config["rpc_url"]))),
        "PROPHET_PROGRAM_ID": str(loaded.get("PROPHET_PROGRAM_ID", env_config["expected_program_id"])),
        "PROPHET_RUNTIME_ROOT": f"/var/lib/prophet/{env_name}",
        "PROPHET_SECRET_ROOT": f"/etc/prophet/{env_name}",
        "REMOTE_SIGNER_INTERNAL_URL": "http://remote-signer:8100/sign",
        "RESOLVER_REGISTRY_INTERNAL_URL": "http://resolver-registry:8200/resolvers",
        "REMOTE_SIGNER_BACKEND": "aws_kms",
        "REMOTE_SIGNER_COMMAND": "",
        "REMOTE_SIGNER_COMMAND_TIMEOUT_S": "5",
        "REMOTE_SIGNER_COMMAND_PUBLIC_KEYS": "",
        "REMOTE_SIGNER_AWS_KMS_REGION": "",
        "REMOTE_SIGNER_AWS_KMS_KEY_IDS": "",
        "RECLAIM_API_KEY": "",
        "REMOTE_SIGNER_AWS_KMS_ENDPOINT_URL": "",
        "MARKET_DISCOVERY_MODE": "program_scan",
        "MARKETS": "",
        "COMPUTE_UNIT_LIMIT": "",
        "COMPUTE_UNIT_PRICE_MICRO_LAMPORTS": "",
        "LOG_LEVEL": "INFO",
    }

    values = dict(defaults)
    values.update(loaded)
    if not values.get("WS_URL"):
        values["WS_URL"] = _derive_ws_url(values["RPC_URL"])

    backend = str(values.get("REMOTE_SIGNER_BACKEND", "aws_kms")).strip().lower()
    if backend not in SUPPORTED_REMOTE_SIGNER_BACKENDS:
        raise RenderError(
            "REMOTE_SIGNER_BACKEND must be one of: aws_kms, command."
        )
    values["REMOTE_SIGNER_BACKEND"] = backend

    if generate_secrets:
        for key in SECRET_VALUE_KEYS:
            if not values.get(key):
                values[key] = secrets.token_urlsafe(32)

    missing = [key for key in COMMON_REQUIRED_VALUES if not values.get(key)]
    if backend == "aws_kms":
        missing.extend(key for key in AWS_KMS_REQUIRED_VALUES if not values.get(key))
    if backend == "command":
        missing.extend(key for key in COMMAND_REQUIRED_VALUES if not values.get(key))
    missing.extend(key for key in SECRET_VALUE_KEYS if not values.get(key))
    if missing:
        joined = ", ".join(sorted(set(missing)))
        raise RenderError(
            f"Missing required operated stack values for {env_name}: {joined}. "
            "Fill stack.env or pass --generate-secrets for auth tokens."
        )
    return values


def _render_env_template(template_path: Path, replacements: Dict[str, str], output_path: Path) -> None:
    lines = template_path.read_text(encoding="utf-8").splitlines()
    output: List[str] = [
        f"# Generated by scripts/render_operated_stack.py from {template_path.name}.",
        "# Do not edit by hand; update stack.env or rerun the renderer.",
    ]
    if lines and lines[0].startswith("# Copy to "):
        lines = lines[1:]
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            output.append(raw_line)
            continue
        key, _ = raw_line.split("=", 1)
        key = key.strip()
        if key in replacements:
            output.append(f"{key}={replacements[key]}")
        else:
            output.append(raw_line)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(output) + "\n", encoding="utf-8")


def _write_compose_env(output_path: Path, values: Dict[str, str]) -> None:
    lines = [
        "# Generated by scripts/render_operated_stack.py.",
        f"PROPHET_RUNTIME_ROOT={values['PROPHET_RUNTIME_ROOT']}",
        f"PROPHET_SECRET_ROOT={values['PROPHET_SECRET_ROOT']}",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sync_environment_json(env_path: Path, env_config: Dict[str, object], values: Dict[str, str]) -> None:
    service_endpoints = dict(env_config.get("service_endpoints", {}))
    service_endpoints.update(
        {
            "attester_base_url": values["ATTESTER_BASE_URL"],
            "remote_signer_url": values["REMOTE_SIGNER_PUBLIC_URL"],
            "resolver_registry_url": values["RESOLVER_REGISTRY_PUBLIC_URL"],
            "matching_keeper_base_url": values["MATCHING_KEEPER_BASE_URL"],
        }
    )
    env_config["service_endpoints"] = service_endpoints
    env_config["expected_program_id"] = values["PROPHET_PROGRAM_ID"]
    env_path.write_text(json.dumps(env_config, indent=2) + "\n", encoding="utf-8")


def _service_replacements(values: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    return {
        "oracle-attester": {
            "RPC_URL": values["RPC_URL"],
            "PROPHET_PROGRAM_ID": values["PROPHET_PROGRAM_ID"],
            "RECLAIM_VERIFY_URL": values["RECLAIM_VERIFY_URL"],
            "RECLAIM_API_KEY": values["RECLAIM_API_KEY"],
            "REMOTE_SIGNER_URL": values["REMOTE_SIGNER_INTERNAL_URL"],
            "REMOTE_SIGNER_API_KEY": values["REMOTE_SIGNER_API_KEY"],
            "REMOTE_SIGNER_REQUIRE_TLS": _is_https(values["REMOTE_SIGNER_INTERNAL_URL"]),
            "RESOLVER_REGISTRY_URL": values["RESOLVER_REGISTRY_INTERNAL_URL"],
            "RESOLVER_REGISTRY_API_KEY": values["RESOLVER_REGISTRY_SERVICE_API_KEY"],
            "RESOLVER_REGISTRY_REQUIRE_TLS": _is_https(values["RESOLVER_REGISTRY_INTERNAL_URL"]),
            "API_AUTH_TOKEN": values["API_AUTH_TOKEN"],
        },
        "remote-signer": {
            "REMOTE_SIGNER_BACKEND": values["REMOTE_SIGNER_BACKEND"],
            "REMOTE_SIGNER_API_KEY": values["REMOTE_SIGNER_API_KEY"],
            "REMOTE_SIGNER_COMMAND": values["REMOTE_SIGNER_COMMAND"],
            "REMOTE_SIGNER_COMMAND_TIMEOUT_S": values["REMOTE_SIGNER_COMMAND_TIMEOUT_S"],
            "REMOTE_SIGNER_COMMAND_PUBLIC_KEYS": values["REMOTE_SIGNER_COMMAND_PUBLIC_KEYS"],
            "REMOTE_SIGNER_AWS_KMS_REGION": values["REMOTE_SIGNER_AWS_KMS_REGION"],
            "REMOTE_SIGNER_AWS_KMS_KEY_IDS": values["REMOTE_SIGNER_AWS_KMS_KEY_IDS"],
            "REMOTE_SIGNER_AWS_KMS_ENDPOINT_URL": values["REMOTE_SIGNER_AWS_KMS_ENDPOINT_URL"],
        },
        "resolver-registry": {
            "RESOLVER_REGISTRY_SERVICE_API_KEY": values["RESOLVER_REGISTRY_SERVICE_API_KEY"],
        },
        "matching-keeper": {
            "RPC_URL": values["RPC_URL"],
            "WS_URL": values["WS_URL"],
            "PROPHET_PROGRAM_ID": values["PROPHET_PROGRAM_ID"],
            "MARKET_DISCOVERY_MODE": values["MARKET_DISCOVERY_MODE"],
            "MARKETS": values["MARKETS"],
            "COMPUTE_UNIT_LIMIT": values["COMPUTE_UNIT_LIMIT"],
            "COMPUTE_UNIT_PRICE_MICRO_LAMPORTS": values["COMPUTE_UNIT_PRICE_MICRO_LAMPORTS"],
            "LOG_LEVEL": values["LOG_LEVEL"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Render operated Prophet deploy env files from one values file.")
    parser.add_argument("--environment", required=True, help="Environment name under deploy/operated and deploy/environments.")
    parser.add_argument(
        "--values-file",
        default="",
        help="Path to stack.env values file. Defaults to deploy/operated/<environment>/stack.env.",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Directory for rendered compose/env files. Defaults to deploy/operated/<environment>/.",
    )
    parser.add_argument(
        "--skip-sync-env-json",
        action="store_true",
        help="Do not rewrite deploy/environments/<environment>.json with rendered service endpoints.",
    )
    parser.add_argument(
        "--generate-secrets",
        action="store_true",
        help="Generate missing API tokens for REMOTE_SIGNER_API_KEY, RESOLVER_REGISTRY_SERVICE_API_KEY, and API_AUTH_TOKEN.",
    )
    parser.add_argument(
        "--set",
        dest="sets",
        action="append",
        default=[],
        help="Override a values entry inline, e.g. --set ATTESTER_BASE_URL=https://attester.example.",
    )
    args = parser.parse_args()

    env_name = args.environment
    env_dir = OPERATED_DIR / env_name
    if not env_dir.exists():
        raise SystemExit(f"render error: unknown operated environment '{env_name}': {env_dir}")

    values_path = Path(args.values_file) if args.values_file else env_dir / "stack.env"
    if not values_path.is_absolute():
        values_path = (ROOT / values_path).resolve()

    output_dir = Path(args.output_dir) if args.output_dir else env_dir
    if not output_dir.is_absolute():
        output_dir = (ROOT / output_dir).resolve()

    try:
        env_path, env_config = _load_environment_config(env_name)
        loaded = _merge_values(_read_env_file(values_path), args.sets)
        values = _final_values(
            env_name=env_name,
            env_config=env_config,
            loaded=loaded,
            generate_secrets=args.generate_secrets,
        )

        replacements = _service_replacements(values)
        for service in SERVICES:
            template_path = env_dir / f"{service}.env.example"
            output_path = output_dir / f"{service}.env"
            _render_env_template(template_path, replacements[service], output_path)
            print(f"wrote {output_path}")

        _write_compose_env(output_dir / ".env", values)
        print(f"wrote {output_dir / '.env'}")

        if not args.skip_sync_env_json:
            _sync_environment_json(env_path, env_config, values)
            print(f"updated {env_path}")

        return 0
    except RenderError as exc:
        print(f"render error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

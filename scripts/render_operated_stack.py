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
    "resolver-registry",
    "matching-keeper",
)
COMMON_REQUIRED_VALUES = (
    "VERIFIER_A_BASE_URL",
    "VERIFIER_B_BASE_URL",
    "COORDINATOR_BASE_URL",
    "SECURE_SETTLEMENT_BASE_URL",
    "RESOLVER_REGISTRY_PUBLIC_URL",
    "MATCHING_KEEPER_BASE_URL",
    "VERIFIER_A_IDENTITY",
    "VERIFIER_B_IDENTITY",
    "VERIFIER_A_AUTH_REF",
    "VERIFIER_B_AUTH_REF",
    "VERIFIER_A_PROOF_BACKEND_URL",
    "VERIFIER_B_PROOF_BACKEND_URL",
    "COORDINATOR_SQLITE_PATH",
    "SIGNING_JOURNAL_PATH",
    "SUBMISSION_JOURNAL_PATH",
    "SIGNER_A_IDENTITY",
    "SIGNER_B_IDENTITY",
    "SIGNER_A_VAULT_KEY",
    "SIGNER_B_VAULT_KEY",
    "SIGNER_A_AUTH_REF",
    "SIGNER_B_AUTH_REF",
)
SECRET_VALUE_KEYS = ("RESOLVER_REGISTRY_SERVICE_API_KEY",)
LEGACY_SETTLEMENT_KEYS = (
    "ATTESTER_BASE_URL",
    "REMOTE_SIGNER_PUBLIC_URL",
    "REMOTE_SIGNER_INTERNAL_URL",
    "REMOTE_SIGNER_API_KEY",
    "REMOTE_SIGNER_BACKEND",
    "REMOTE_SIGNER_COMMAND",
    "REMOTE_SIGNER_COMMAND_PUBLIC_KEYS",
    "REMOTE_SIGNER_AWS_KMS_KEY_IDS",
    "NOTARY_SIGNER_MODE",
)


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


def _persistent_absolute(value: str) -> bool:
    return bool(value and value != ":memory:" and Path(value).is_absolute())


def _require_https(values: Dict[str, str], keys: Iterable[str]) -> None:
    insecure = [key for key in keys if not values.get(key, "").startswith("https://")]
    if insecure:
        raise RenderError(
            "Production-shaped secure topology requires https for: " + ", ".join(sorted(insecure))
        )


def _final_values(
    *,
    env_name: str,
    env_config: Dict[str, object],
    loaded: Dict[str, str],
    generate_secrets: bool,
) -> Dict[str, str]:
    endpoints = env_config.get("service_endpoints", {})
    secure = env_config.get("secure_settlement", {})
    if not isinstance(endpoints, dict) or not isinstance(secure, dict):
        raise RenderError("Environment config is missing secure settlement topology metadata.")
    verifier_a = secure.get("verifier_a", {})
    verifier_b = secure.get("verifier_b", {})
    signer_a = secure.get("signer_a", {})
    signer_b = secure.get("signer_b", {})
    if not all(isinstance(value, dict) for value in (verifier_a, verifier_b, signer_a, signer_b)):
        raise RenderError("Environment secure settlement identity metadata is malformed.")

    legacy = sorted(key for key in LEGACY_SETTLEMENT_KEYS if key in loaded)
    if legacy:
        raise RenderError(
            "Legacy direct-attester/generic-signer settlement values are forbidden: "
            + ", ".join(legacy)
        )

    runtime_root = str(loaded.get("PROPHET_RUNTIME_ROOT", f"/var/lib/prophet/{env_name}"))
    defaults = {
        "RPC_URL": str(env_config["rpc_url"]),
        "WS_URL": _derive_ws_url(str(loaded.get("RPC_URL", env_config["rpc_url"]))),
        "PROPHET_PROGRAM_ID": str(loaded.get("PROPHET_PROGRAM_ID", env_config["expected_program_id"])),
        "PROPHET_RUNTIME_ROOT": runtime_root,
        "PROPHET_SECRET_ROOT": f"/etc/prophet/{env_name}",
        "RESOLVER_REGISTRY_INTERNAL_URL": "http://resolver-registry:8200/resolvers",
        "VERIFIER_A_BASE_URL": str(endpoints.get("verifier_a_base_url", "")),
        "VERIFIER_B_BASE_URL": str(endpoints.get("verifier_b_base_url", "")),
        "COORDINATOR_BASE_URL": str(endpoints.get("coordinator_base_url", "")),
        "SECURE_SETTLEMENT_BASE_URL": str(endpoints.get("secure_settlement_base_url", "")),
        "RESOLVER_REGISTRY_PUBLIC_URL": str(endpoints.get("resolver_registry_url", "")),
        "MATCHING_KEEPER_BASE_URL": str(endpoints.get("matching_keeper_base_url", "")),
        "RESOLUTION_MODE": str(secure.get("resolution_mode", "secure-coordinator")),
        "DIRECT_ATTESTER_SETTLEMENT_ENABLED": "1" if secure.get("direct_attester_settlement_enabled") is True else "0",
        "GENERIC_REMOTE_SIGNER_SETTLEMENT_ENABLED": "1" if secure.get("generic_remote_signer_settlement_enabled") is True else "0",
        "STRICT_SIGNER_COUNT": str(secure.get("required_signer_count", 2)),
        "COORDINATOR_SQLITE_PATH": str(secure.get("coordinator_sqlite_path", f"{runtime_root}/coordinator.sqlite")),
        "SIGNING_JOURNAL_PATH": str(secure.get("signing_journal_path", f"{runtime_root}/signing-journal.sqlite")),
        "SUBMISSION_JOURNAL_PATH": str(secure.get("submission_journal_path", f"{runtime_root}/submission-journal.sqlite")),
        "VERIFIER_A_IDENTITY": str(verifier_a.get("identity", "")),
        "VERIFIER_B_IDENTITY": str(verifier_b.get("identity", "")),
        "VERIFIER_A_AUTH_REF": str(verifier_a.get("auth_ref", "")),
        "VERIFIER_B_AUTH_REF": str(verifier_b.get("auth_ref", "")),
        "VERIFIER_A_PROOF_BACKEND_URL": "",
        "VERIFIER_B_PROOF_BACKEND_URL": "",
        "SIGNER_A_IDENTITY": str(signer_a.get("identity", "")),
        "SIGNER_B_IDENTITY": str(signer_b.get("identity", "")),
        "SIGNER_A_VAULT_KEY": str(signer_a.get("vault_key_ref", "")),
        "SIGNER_B_VAULT_KEY": str(signer_b.get("vault_key_ref", "")),
        "SIGNER_A_AUTH_REF": str(signer_a.get("auth_ref", "")),
        "SIGNER_B_AUTH_REF": str(signer_b.get("auth_ref", "")),
        "RESOLVER_REGISTRY_SERVICE_API_KEY": "",
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

    if generate_secrets and not values.get("RESOLVER_REGISTRY_SERVICE_API_KEY"):
        values["RESOLVER_REGISTRY_SERVICE_API_KEY"] = secrets.token_urlsafe(32)

    missing = [key for key in COMMON_REQUIRED_VALUES if not values.get(key)]
    missing.extend(key for key in SECRET_VALUE_KEYS if not values.get(key))
    if missing:
        raise RenderError(
            f"Missing required secure operated-stack values for {env_name}: "
            + ", ".join(sorted(set(missing)))
        )

    if values.get("RESOLUTION_MODE") != "secure-coordinator":
        raise RenderError("RESOLUTION_MODE must be secure-coordinator.")
    if values.get("DIRECT_ATTESTER_SETTLEMENT_ENABLED") != "0":
        raise RenderError("Direct attester settlement must be disabled.")
    if values.get("GENERIC_REMOTE_SIGNER_SETTLEMENT_ENABLED") != "0":
        raise RenderError("Generic remote signer settlement must be disabled.")
    if values.get("STRICT_SIGNER_COUNT") != "2":
        raise RenderError("Secure settlement requires strict 2/2 signing.")

    for key in ("COORDINATOR_SQLITE_PATH", "SIGNING_JOURNAL_PATH", "SUBMISSION_JOURNAL_PATH"):
        if not _persistent_absolute(values[key]):
            raise RenderError(f"{key} must be a persistent absolute path.")

    if values["VERIFIER_A_BASE_URL"].rstrip("/") == values["VERIFIER_B_BASE_URL"].rstrip("/"):
        raise RenderError("Verifier A/B service URLs must be distinct.")
    if values["VERIFIER_A_IDENTITY"] == values["VERIFIER_B_IDENTITY"]:
        raise RenderError("Verifier A/B identities must be distinct.")
    if values["VERIFIER_A_AUTH_REF"] == values["VERIFIER_B_AUTH_REF"]:
        raise RenderError("Verifier A/B auth references must be distinct.")
    if values["VERIFIER_A_PROOF_BACKEND_URL"].rstrip("/") == values["VERIFIER_B_PROOF_BACKEND_URL"].rstrip("/"):
        raise RenderError("Verifier A/B proof backend URLs must be distinct.")
    if values["SIGNER_A_IDENTITY"] == values["SIGNER_B_IDENTITY"]:
        raise RenderError("Signer A/B identities must be distinct.")
    if values["SIGNER_A_VAULT_KEY"] == values["SIGNER_B_VAULT_KEY"]:
        raise RenderError("Signer A/B Vault key references must be distinct.")
    if values["SIGNER_A_AUTH_REF"] == values["SIGNER_B_AUTH_REF"]:
        raise RenderError("Signer A/B auth references must be distinct.")

    _require_https(
        values,
        (
            "VERIFIER_A_BASE_URL",
            "VERIFIER_B_BASE_URL",
            "COORDINATOR_BASE_URL",
            "SECURE_SETTLEMENT_BASE_URL",
            "RESOLVER_REGISTRY_PUBLIC_URL",
            "MATCHING_KEEPER_BASE_URL",
            "VERIFIER_A_PROOF_BACKEND_URL",
            "VERIFIER_B_PROOF_BACKEND_URL",
        ),
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
    env_config["service_endpoints"] = {
        "verifier_a_base_url": values["VERIFIER_A_BASE_URL"],
        "verifier_b_base_url": values["VERIFIER_B_BASE_URL"],
        "coordinator_base_url": values["COORDINATOR_BASE_URL"],
        "secure_settlement_base_url": values["SECURE_SETTLEMENT_BASE_URL"],
        "resolver_registry_url": values["RESOLVER_REGISTRY_PUBLIC_URL"],
        "matching_keeper_base_url": values["MATCHING_KEEPER_BASE_URL"],
    }
    env_config["secure_settlement"] = {
        "resolution_mode": values["RESOLUTION_MODE"],
        "direct_attester_settlement_enabled": False,
        "generic_remote_signer_settlement_enabled": False,
        "coordinator_sqlite_path": values["COORDINATOR_SQLITE_PATH"],
        "signing_journal_path": values["SIGNING_JOURNAL_PATH"],
        "submission_journal_path": values["SUBMISSION_JOURNAL_PATH"],
        "required_signer_count": 2,
        "verifier_a": {
            "identity": values["VERIFIER_A_IDENTITY"],
            "backend_ref": values["VERIFIER_A_PROOF_BACKEND_URL"],
            "auth_ref": values["VERIFIER_A_AUTH_REF"],
        },
        "verifier_b": {
            "identity": values["VERIFIER_B_IDENTITY"],
            "backend_ref": values["VERIFIER_B_PROOF_BACKEND_URL"],
            "auth_ref": values["VERIFIER_B_AUTH_REF"],
        },
        "signer_a": {
            "identity": values["SIGNER_A_IDENTITY"],
            "vault_key_ref": values["SIGNER_A_VAULT_KEY"],
            "auth_ref": values["SIGNER_A_AUTH_REF"],
        },
        "signer_b": {
            "identity": values["SIGNER_B_IDENTITY"],
            "vault_key_ref": values["SIGNER_B_VAULT_KEY"],
            "auth_ref": values["SIGNER_B_AUTH_REF"],
        },
    }
    env_config["expected_program_id"] = values["PROPHET_PROGRAM_ID"]
    env_path.write_text(json.dumps(env_config, indent=2) + "\n", encoding="utf-8")


def _service_replacements(values: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    return {
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
    parser = argparse.ArgumentParser(description="Render secure operated Prophet deploy metadata/env files from one values file.")
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
        help="Do not rewrite deploy/environments/<environment>.json with rendered secure service endpoints.",
    )
    parser.add_argument(
        "--generate-secrets",
        action="store_true",
        help="Generate a missing resolver-registry service API token only. Settlement/Vault credentials remain external.",
    )
    parser.add_argument(
        "--set",
        dest="sets",
        action="append",
        default=[],
        help="Override a values entry inline, e.g. --set VERIFIER_A_BASE_URL=https://verifier-a.example.",
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

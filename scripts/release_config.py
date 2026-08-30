"""RC4 checked-in deployment configuration and release-authorization policy."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

PUBLIC_DEVNET_PROGRAM_ID = "3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE"
CHECKED_IN_ENVIRONMENTS = ("localnet", "devnet", "public-devnet", "mainnet-beta")
SOURCE_MATCH_ENVIRONMENTS = frozenset(("localnet", "devnet", "public-devnet"))
PLACEHOLDER_MARKERS = (
    ".example",
    "replace-me",
    "replace_",
    "configure_",
    "placeholder",
)
EXTERNAL_SECRET_PREFIX = "EXTERNAL_SECRET_MANAGER_REFERENCE:"
_REQUIRED_SECURE_ENDPOINTS = (
    "verifier_a_base_url",
    "verifier_b_base_url",
    "coordinator_base_url",
    "secure_settlement_base_url",
    "resolver_registry_url",
    "matching_keeper_base_url",
)
_REQUIRED_LOCAL_ENDPOINTS = (
    "resolver_registry_url",
    "matching_keeper_base_url",
)
_REQUIRED_DEPLOYMENT_ARTIFACTS = (
    "compose_manifest",
    "stack_values_template",
    "resolver_registry_env_template",
    "matching_keeper_env_template",
)


class ConfigValidationError(ValueError):
    pass


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigValidationError(f"{field} must be non-empty text")
    return value.strip()


def _placeholder(value: str) -> bool:
    lower = value.lower()
    return any(marker in lower for marker in PLACEHOLDER_MARKERS)


def _contains_unresolved(value: Any) -> bool:
    if isinstance(value, str):
        return _placeholder(value) or value.strip().startswith(EXTERNAL_SECRET_PREFIX)
    if isinstance(value, Mapping):
        return any(_contains_unresolved(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_unresolved(item) for item in value)
    return False


def _source_program_id(root: Path) -> str:
    source = (root / "programs/prophet/src/lib.rs").read_text(encoding="utf-8")
    match = re.search(r'declare_id!\("([1-9A-HJ-NP-Za-km-z]+)"\)', source)
    if not match:
        raise ConfigValidationError("unable to read source declare_id")
    return match.group(1)


def _anchor_program_id(root: Path) -> str:
    text = (root / "Anchor.toml").read_text(encoding="utf-8")
    match = re.search(
        r'(?ms)^\[programs\.localnet\]\s*.*?^prophet\s*=\s*"([1-9A-HJ-NP-Za-km-z]+)"',
        text,
    )
    if not match:
        raise ConfigValidationError("unable to read Anchor programs.localnet prophet identity")
    return match.group(1)


def _idl_program_id(path: Path | None) -> str | None:
    if path is None or not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigValidationError(f"invalid IDL JSON: {path}") from exc
    address = payload.get("address")
    return _text(address, "idl.address")


def _repo_relative_path(root: Path, value: Any, field: str, *, must_exist: bool) -> Path:
    raw = _text(value, field)
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        raise ConfigValidationError(f"{field} must be repository-relative")
    resolved = (root / path).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ConfigValidationError(f"{field} escapes repository root") from exc
    if must_exist and not resolved.exists():
        raise ConfigValidationError(f"{field} does not exist: {raw}")
    return resolved


def _validate_endpoint(value: Any, field: str, *, live: bool) -> str:
    endpoint = _text(value, field)
    if _placeholder(endpoint):
        if live:
            raise ConfigValidationError(f"{field} contains an unresolved placeholder")
        return endpoint
    try:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ConfigValidationError(f"{field} is malformed") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port == 0
    ):
        raise ConfigValidationError(f"{field} is malformed")
    return endpoint


def _persistent_absolute(value: Any, field: str) -> str:
    path = _text(value, field)
    if path == ":memory:" or not Path(path).is_absolute():
        raise ConfigValidationError(f"{field} must be a persistent absolute path")
    return path


def _secure_topology(config: Mapping[str, Any], env_name: str) -> None:
    if env_name == "localnet":
        return
    secure = config.get("secure_settlement")
    if not isinstance(secure, Mapping):
        raise ConfigValidationError("secure_settlement metadata is required")
    if secure.get("resolution_mode") != "secure-coordinator":
        raise ConfigValidationError("secure settlement mode must be secure-coordinator")
    if secure.get("direct_attester_settlement_enabled") is not False:
        raise ConfigValidationError("direct attester settlement must be disabled")
    if secure.get("generic_remote_signer_settlement_enabled") is not False:
        raise ConfigValidationError("generic settlement signer must be disabled")
    if secure.get("required_signer_count") != 2:
        raise ConfigValidationError("secure settlement must require strict 2/2 signing")
    for key in ("coordinator_sqlite_path", "signing_journal_path", "submission_journal_path"):
        _persistent_absolute(secure.get(key), f"secure_settlement.{key}")

    def row(name: str, keys: tuple[str, ...]) -> tuple[str, ...]:
        value = secure.get(name)
        if not isinstance(value, Mapping) or set(value) != set(keys):
            raise ConfigValidationError(f"secure_settlement.{name} metadata is malformed")
        return tuple(_text(value.get(key), f"secure_settlement.{name}.{key}") for key in keys)

    verifier_a = row("verifier_a", ("identity", "backend_ref", "auth_ref"))
    verifier_b = row("verifier_b", ("identity", "backend_ref", "auth_ref"))
    signer_a = row("signer_a", ("identity", "vault_key_ref"))
    signer_b = row("signer_b", ("identity", "vault_key_ref"))
    if any(a == b for a, b in zip(verifier_a, verifier_b)):
        raise ConfigValidationError("verifier A/B identity/backend/auth must be distinct")
    if any(a == b for a, b in zip(signer_a, signer_b)):
        raise ConfigValidationError("signer A/B identity/key must be distinct")


def validate_environment_config(
    config: Mapping[str, Any],
    *,
    env_name: str,
    root: Path,
    live: bool = False,
    check_artifacts: bool = True,
    idl_path: Path | None = None,
) -> None:
    if config.get("environment") != env_name:
        raise ConfigValidationError(f"environment name mismatch for {env_name}")

    expected_cluster = {
        "localnet": "localnet",
        "devnet": "devnet",
        "public-devnet": "devnet",
        "mainnet-beta": "mainnet-beta",
    }.get(env_name)
    if expected_cluster is None or config.get("cluster_name") != expected_cluster:
        raise ConfigValidationError(f"cluster policy mismatch for {env_name}")

    authorized = config.get("deployment_authorized")
    if type(authorized) is not bool:
        raise ConfigValidationError("deployment_authorized must be a JSON boolean")
    policy = _text(config.get("program_identity_policy"), "program_identity_policy")
    source_id = _source_program_id(root)
    anchor_id = _anchor_program_id(root)
    expected_id = _text(config.get("expected_program_id"), "expected_program_id")
    if source_id != anchor_id:
        raise ConfigValidationError("source and Anchor program identities drifted")

    if env_name in SOURCE_MATCH_ENVIRONMENTS:
        if policy != "match-source":
            raise ConfigValidationError(f"{env_name} must use match-source identity policy")
        if expected_id != source_id:
            raise ConfigValidationError(f"{env_name} expected_program_id must match source/Anchor")
        idl_id = _idl_program_id(idl_path)
        if idl_id is not None and idl_id != expected_id:
            raise ConfigValidationError(f"{env_name} IDL identity mismatch")
    elif env_name == "mainnet-beta":
        if policy not in {"future-unapproved", "mainnet-approved"}:
            raise ConfigValidationError("mainnet program identity policy is invalid")
        if policy == "future-unapproved" and authorized is not False:
            raise ConfigValidationError("future-unapproved mainnet must not be deployment authorized")

    if env_name == "public-devnet" and expected_id != PUBLIC_DEVNET_PROGRAM_ID:
        raise ConfigValidationError("public-devnet intended program identity drifted")

    for field in ("binary_path", "idl_path", "ts_types_path"):
        _repo_relative_path(root, config.get(field), field, must_exist=False)

    endpoints = config.get("service_endpoints")
    if not isinstance(endpoints, Mapping):
        raise ConfigValidationError("service_endpoints must be an object")
    required_endpoints = _REQUIRED_LOCAL_ENDPOINTS if env_name == "localnet" else _REQUIRED_SECURE_ENDPOINTS
    missing = [key for key in required_endpoints if key not in endpoints]
    if missing:
        raise ConfigValidationError("missing service endpoint(s): " + ", ".join(missing))
    for key in required_endpoints:
        _validate_endpoint(endpoints[key], f"service_endpoints.{key}", live=live)
    if env_name != "localnet":
        if "remote_signer_url" in endpoints:
            raise ConfigValidationError("secure topology must not expose generic remote signer")
        if endpoints["verifier_a_base_url"].rstrip("/") == endpoints["verifier_b_base_url"].rstrip("/"):
            raise ConfigValidationError("verifier A/B endpoints must be distinct")

    _secure_topology(config, env_name)

    artifacts = config.get("deployment_artifacts", {})
    if env_name != "localnet":
        if not isinstance(artifacts, Mapping):
            raise ConfigValidationError("deployment_artifacts must be an object")
        missing = [key for key in _REQUIRED_DEPLOYMENT_ARTIFACTS if key not in artifacts]
        if missing:
            raise ConfigValidationError("missing deployment artifact(s): " + ", ".join(missing))
        for key in _REQUIRED_DEPLOYMENT_ARTIFACTS:
            _repo_relative_path(
                root,
                artifacts[key],
                f"deployment_artifacts.{key}",
                must_exist=check_artifacts,
            )

    if live:
        if authorized is not True:
            raise ConfigValidationError("live deployment is not authorized")
        if policy == "future-unapproved":
            raise ConfigValidationError("future-unapproved identity cannot be deployed")
        live_fields = {
            "service_endpoints": endpoints,
            "wallet_path": config.get("wallet_path"),
            "program_keypair_path": config.get("program_keypair_path"),
            "deployment_artifacts": artifacts,
        }
        if _contains_unresolved(live_fields):
            raise ConfigValidationError("live deployment contains placeholder or unresolved secret reference")


def validate_checked_in_environments(root: Path, *, idl_path: Path | None = None) -> dict[str, Mapping[str, Any]]:
    env_dir = root / "deploy/environments"
    loaded: dict[str, Mapping[str, Any]] = {}
    for name in CHECKED_IN_ENVIRONMENTS:
        path = env_dir / f"{name}.json"
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigValidationError(f"unable to read checked-in environment {name}") from exc
        validate_environment_config(
            config,
            env_name=name,
            root=root,
            live=False,
            check_artifacts=True,
            idl_path=idl_path if name in SOURCE_MATCH_ENVIRONMENTS else None,
        )
        loaded[name] = config

    mainnet = loaded["mainnet-beta"]
    if mainnet.get("program_identity_policy") != "future-unapproved" or mainnet.get("deployment_authorized") is not False:
        raise ConfigValidationError("checked-in mainnet must remain future-unapproved and unauthorized")
    if mainnet.get("expected_program_id") == loaded["public-devnet"].get("expected_program_id"):
        raise ConfigValidationError("future/unapproved mainnet must not silently inherit public-devnet identity")
    return loaded

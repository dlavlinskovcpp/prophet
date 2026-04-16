import base64
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

import httpx
from solders.pubkey import Pubkey

from .signer_backend import _ed25519_pubkey_from_spki


LOCAL_VAULT_PREFIXES = ("http://127.0.0.1", "http://localhost")


class VaultTransitError(RuntimeError):
    def __init__(self, message: str, *, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _normalize_key_names(items: Iterable[str]) -> list[str]:
    names: list[str] = []
    seen = set()
    for raw in items:
        text = str(raw or "").strip()
        if not text:
            continue
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            for item in line.split(","):
                key_name = item.strip()
                if not key_name or key_name in seen:
                    continue
                seen.add(key_name)
                names.append(key_name)
    return names


def _vault_verify_arg(cacert: str, skip_verify: bool):
    if skip_verify:
        return False
    if cacert:
        return cacert
    return True


def _read_vault_token(token: str = "", token_file: str = "") -> str:
    value = str(token or "").strip()
    if value:
        return value

    path = str(token_file or "").strip()
    if path:
        return Path(path).read_text(encoding="utf-8").strip()

    env_token = str(os.getenv("VAULT_TOKEN", "")).strip()
    if env_token:
        return env_token

    env_token_file = str(os.getenv("VAULT_TOKEN_FILE", "")).strip()
    if env_token_file:
        return Path(env_token_file).read_text(encoding="utf-8").strip()

    raise ValueError("Vault token is required. Set VAULT_TOKEN or VAULT_TOKEN_FILE.")


def _coerce_ed25519_public_key(raw_key: bytes) -> bytes:
    if len(raw_key) == 32:
        return raw_key
    return _ed25519_pubkey_from_spki(raw_key)


def _decode_public_key_blob(raw_value: str) -> bytes:
    value = str(raw_value or "").strip()
    if not value:
        raise ValueError("Vault public key payload is empty.")

    if value.startswith("-----BEGIN "):
        body = "".join(
            line.strip()
            for line in value.splitlines()
            if line.strip() and not line.startswith("-----")
        )
        if not body:
            raise ValueError("Vault PEM public key payload is empty.")
        der = base64.b64decode(body, validate=True)
        return _coerce_ed25519_public_key(der)

    try:
        return bytes(Pubkey.from_string(value))
    except Exception:
        pass

    decoded = base64.b64decode(value, validate=True)
    return _coerce_ed25519_public_key(decoded)


def parse_vault_public_key(raw_value: Any) -> str:
    candidate = raw_value
    if isinstance(raw_value, Mapping):
        candidate = (
            raw_value.get("public_key")
            or raw_value.get("publickey")
            or raw_value.get("key")
            or ""
        )
    if not isinstance(candidate, str):
        raise ValueError("Vault public key payload must be a string.")
    return str(Pubkey.from_bytes(_decode_public_key_blob(candidate)))


def _select_versioned_key_entry(
    items: Mapping[str, Any],
    *,
    version: str = "latest",
    latest_version: Any = None,
) -> Any:
    if version and version != "latest" and version in items:
        return items[version]

    if latest_version is not None:
        latest_key = str(latest_version).strip()
        if latest_key and latest_key in items:
            return items[latest_key]

    numbered = [(int(k), value) for k, value in items.items() if str(k).isdigit()]
    if numbered:
        return sorted(numbered)[-1][1]

    return next(iter(items.values()))


def _public_key_from_key_metadata(metadata: Mapping[str, Any], *, version: str = "latest") -> str:
    candidates: list[Any] = []

    for field in ("public_key", "publickey", "key"):
        value = metadata.get(field)
        if value not in (None, ""):
            candidates.append(value)

    keys = metadata.get("keys")
    if isinstance(keys, Mapping) and keys:
        try:
            candidates.append(
                _select_versioned_key_entry(
                    keys,
                    version=version,
                    latest_version=metadata.get("latest_version"),
                )
            )
        except Exception:
            pass

    for candidate in candidates:
        try:
            return parse_vault_public_key(candidate)
        except Exception:
            continue

    raise ValueError("Vault key metadata does not include a parseable public key.")


def parse_vault_signature(raw_value: str) -> bytes:
    value = str(raw_value or "").strip()
    if not value:
        raise ValueError("Vault signature payload is empty.")

    if value.startswith("vault:v"):
        parts = value.split(":", 2)
        if len(parts) != 3:
            raise ValueError("Vault signature payload has an invalid prefix.")
        value = parts[2]

    signature = base64.b64decode(value, validate=True)
    if len(signature) != 64:
        raise ValueError(f"Vault signature length invalid: {len(signature)}")
    return signature


def build_vault_key_map_payload(
    entries: Iterable[Mapping[str, str]],
    *,
    mount: str,
) -> Dict[str, Any]:
    keys: Dict[str, Dict[str, str]] = {}
    for entry in entries:
        pubkey = str(Pubkey.from_string(str(entry["solana_pubkey"])))
        key_name = str(entry["key_name"]).strip()
        if not key_name:
            raise ValueError(f"Missing key_name for Vault signer {pubkey}")
        keys[pubkey] = {"key_name": key_name}
    return {
        "format": "prophet-vault-transit-key-map-v1",
        "mount": str(mount or "transit").strip() or "transit",
        "keys": keys,
    }


def parse_vault_key_map(payload: Mapping[str, Any]) -> Dict[str, Dict[str, str]]:
    if "keys" in payload and isinstance(payload["keys"], Mapping):
        source = payload["keys"]
    else:
        source = payload

    out: Dict[str, Dict[str, str]] = {}
    for raw_pubkey, raw_value in source.items():
        pubkey = str(Pubkey.from_string(str(raw_pubkey)))
        if isinstance(raw_value, str):
            key_name = raw_value.strip()
        elif isinstance(raw_value, Mapping):
            key_name = str(
                raw_value.get("key_name")
                or raw_value.get("key")
                or raw_value.get("name")
                or ""
            ).strip()
        else:
            raise ValueError(f"Unsupported Vault key-map entry for {pubkey}")
        if not key_name:
            raise ValueError(f"Vault key-map entry for {pubkey} is missing key_name")
        out[pubkey] = {"key_name": key_name}
    return out


def read_vault_key_map(path: str) -> Dict[str, Dict[str, str]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Vault key map JSON must be an object.")
    return parse_vault_key_map(payload)


def write_vault_key_map_file(path: str, payload: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_path, target)
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


@dataclass(frozen=True)
class VaultTransitConfig:
    addr: str
    namespace: str
    token: str
    mount: str
    timeout_s: float
    cacert: str
    skip_verify: bool
    key_name: str
    key_map_path: str

    @classmethod
    def from_env(cls) -> "VaultTransitConfig":
        return build_vault_transit_config(
            addr=str(os.getenv("VAULT_ADDR", "")).strip(),
            namespace=str(os.getenv("VAULT_NAMESPACE", "")).strip(),
            token=str(os.getenv("VAULT_TOKEN", "")).strip(),
            token_file=str(os.getenv("VAULT_TOKEN_FILE", "")).strip(),
            mount=str(os.getenv("VAULT_TRANSIT_MOUNT", "transit")).strip() or "transit",
            timeout_s=float(str(os.getenv("VAULT_TRANSIT_TIMEOUT_S", "5")).strip()),
            cacert=str(os.getenv("VAULT_CACERT", "")).strip(),
            skip_verify=_env_bool("VAULT_SKIP_VERIFY", False),
            key_name=str(os.getenv("VAULT_TRANSIT_KEY_NAME", "")).strip(),
            key_map_path=str(os.getenv("VAULT_TRANSIT_KEY_MAP_PATH", "")).strip(),
        )


def build_vault_transit_config(
    *,
    addr: str,
    namespace: str = "",
    token: str = "",
    token_file: str = "",
    mount: str = "transit",
    timeout_s: float = 5.0,
    cacert: str = "",
    skip_verify: bool = False,
    key_name: str = "",
    key_map_path: str = "",
) -> VaultTransitConfig:
    clean_addr = str(addr or "").strip()
    if not clean_addr:
        raise ValueError("VAULT_ADDR is required.")
    if not clean_addr.startswith("https://") and not clean_addr.startswith(LOCAL_VAULT_PREFIXES):
        raise ValueError(
            "VAULT_ADDR must use https when connecting off-box "
            "(localhost/127.0.0.1 exempted)."
        )
    if timeout_s <= 0:
        raise ValueError("VAULT_TRANSIT_TIMEOUT_S must be > 0.")

    return VaultTransitConfig(
        addr=clean_addr.rstrip("/"),
        namespace=str(namespace or "").strip(),
        token=_read_vault_token(token, token_file),
        mount=str(mount or "transit").strip() or "transit",
        timeout_s=float(timeout_s),
        cacert=str(cacert or "").strip(),
        skip_verify=bool(skip_verify),
        key_name=str(key_name or "").strip(),
        key_map_path=str(key_map_path or "").strip(),
    )


class VaultTransitClient:
    def __init__(self, config: VaultTransitConfig, *, client: Optional[httpx.Client] = None):
        self.config = config
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=config.timeout_s,
            verify=_vault_verify_arg(config.cacert, config.skip_verify),
        )
        self._headers = {"X-Vault-Token": config.token}
        if config.namespace:
            self._headers["X-Vault-Namespace"] = config.namespace

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "VaultTransitClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _url(self, path: str) -> str:
        return f"{self.config.addr}/v1/{self.config.mount}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, *, json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = self._url(path)
        try:
            response = self._client.request(
                method,
                url,
                headers=self._headers,
                json=json_body,
            )
        except Exception as exc:
            raise VaultTransitError(f"Vault request failed for {method} {url}: {exc}")

        if response.status_code >= 400:
            detail = response.text.strip()
            try:
                payload = response.json()
                errors = payload.get("errors")
                if isinstance(errors, list) and errors:
                    detail = "; ".join(str(item) for item in errors)
            except Exception:
                pass
            raise VaultTransitError(
                f"Vault request failed for {method} {url}: {detail or response.reason_phrase}",
                status_code=response.status_code,
            )

        if not response.content:
            return {}

        try:
            payload = response.json()
        except Exception as exc:
            raise VaultTransitError(f"Vault returned invalid JSON for {method} {url}: {exc}")
        if not isinstance(payload, dict):
            raise VaultTransitError(f"Vault returned non-object JSON for {method} {url}")

        data = payload.get("data")
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise VaultTransitError(f"Vault returned invalid data payload for {method} {url}")
        return data

    def read_key_metadata(self, key_name: str) -> Dict[str, Any]:
        return self._request("GET", f"keys/{key_name}")

    def create_ed25519_key(
        self,
        key_name: str,
        *,
        exportable: bool = False,
        allow_plaintext_backup: bool = False,
    ) -> None:
        self._request(
            "POST",
            f"keys/{key_name}",
            json_body={
                "type": "ed25519",
                "exportable": bool(exportable),
                "allow_plaintext_backup": bool(allow_plaintext_backup),
            },
        )

    def ensure_ed25519_key(
        self,
        key_name: str,
        *,
        create_missing: bool = False,
        exportable: bool = False,
        allow_plaintext_backup: bool = False,
    ) -> Tuple[Dict[str, Any], bool]:
        try:
            metadata = self.read_key_metadata(key_name)
            return metadata, False
        except VaultTransitError as exc:
            if not create_missing or exc.status_code != 404:
                raise

        self.create_ed25519_key(
            key_name,
            exportable=exportable,
            allow_plaintext_backup=allow_plaintext_backup,
        )
        return self.read_key_metadata(key_name), True

    def export_public_key(self, key_name: str, *, version: str = "latest") -> str:
        metadata = self.read_key_metadata(key_name)
        try:
            return _public_key_from_key_metadata(metadata, version=version)
        except ValueError:
            pass

        path = f"export/public-key/{key_name}"
        if version:
            path += f"/{version}"
        data = self._request("GET", path)
        keys = data.get("keys")
        if not isinstance(keys, Mapping) or not keys:
            raise VaultTransitError(f"Vault export/public-key returned no keys for {key_name}")

        entry = _select_versioned_key_entry(
            keys,
            version=version,
            latest_version=metadata.get("latest_version"),
        )
        return parse_vault_public_key(entry)

    def sign(self, key_name: str, message: bytes) -> bytes:
        data = self._request(
            "POST",
            f"sign/{key_name}",
            json_body={
                "input": base64.b64encode(message).decode("ascii"),
            },
        )
        signature = data.get("signature")
        if not isinstance(signature, str):
            raise VaultTransitError(f"Vault transit sign response missing signature for {key_name}")
        return parse_vault_signature(signature)


def bootstrap_vault_transit_keys(
    *,
    config: VaultTransitConfig,
    key_names: Iterable[str],
    create_missing: bool = False,
    exportable: bool = False,
    allow_plaintext_backup: bool = False,
    client: Optional[Any] = None,
) -> Dict[str, Any]:
    resolved_names = _normalize_key_names(key_names)
    if not resolved_names:
        raise ValueError("At least one Vault Transit key name is required.")

    transport = client or VaultTransitClient(config)
    owns_client = client is None
    try:
        keys = []
        seen_pubkeys: Dict[str, str] = {}
        for key_name in resolved_names:
            metadata, created = transport.ensure_ed25519_key(
                key_name,
                create_missing=create_missing,
                exportable=exportable,
                allow_plaintext_backup=allow_plaintext_backup,
            )
            key_type = str(metadata.get("type", "")).strip()
            if key_type and key_type != "ed25519":
                raise ValueError(
                    f"Vault Transit key {key_name} has unsupported type {key_type!r}; expected 'ed25519'."
                )

            pubkey = transport.export_public_key(key_name)
            existing = seen_pubkeys.get(pubkey)
            if existing and existing != key_name:
                raise ValueError(
                    f"Configured Vault Transit keys map to the same Solana pubkey {pubkey}: "
                    f"{existing} vs {key_name}"
                )
            seen_pubkeys[pubkey] = key_name
            keys.append(
                {
                    "key_name": key_name,
                    "solana_pubkey": pubkey,
                    "created": created,
                    "latest_version": metadata.get("latest_version"),
                    "supports_signing": metadata.get("supports_signing"),
                }
            )

        key_map = build_vault_key_map_payload(keys, mount=config.mount)
        allowlist_pubkeys = [entry["solana_pubkey"] for entry in keys]
        return {
            "vault_addr": config.addr,
            "vault_namespace": config.namespace,
            "transit_mount": config.mount,
            "keys": keys,
            "allowlist_pubkeys": allowlist_pubkeys,
            "command_public_keys_csv": ",".join(allowlist_pubkeys),
            "key_map": key_map,
        }
    finally:
        if owns_client:
            transport.close()


def resolve_vault_key_name(
    public_key: str,
    *,
    client: VaultTransitClient,
    key_name: str = "",
    key_map_path: str = "",
) -> str:
    normalized_pubkey = str(Pubkey.from_string(public_key))

    map_path = str(key_map_path or "").strip()
    if map_path:
        entries = read_vault_key_map(map_path)
        item = entries.get(normalized_pubkey)
        if item is None:
            raise PermissionError(f"Vault key map does not include {normalized_pubkey}")
        return item["key_name"]

    candidate = str(key_name or "").strip()
    if not candidate:
        raise ValueError(
            "VAULT_TRANSIT_KEY_MAP_PATH or VAULT_TRANSIT_KEY_NAME is required for the Vault signer wrapper."
        )

    exported_pubkey = client.export_public_key(candidate)
    if exported_pubkey != normalized_pubkey:
        raise PermissionError(
            f"Vault Transit key {candidate} resolves to {exported_pubkey}, not {normalized_pubkey}"
        )
    return candidate

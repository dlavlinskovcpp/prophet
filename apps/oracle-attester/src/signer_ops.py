import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence
from urllib.parse import urlsplit, urlunsplit

import httpx
from solders.pubkey import Pubkey

from .signer_allowlist import _parse_allowed_pubkeys
from .durable_files import atomic_write_bytes
from .signer_backend import (
    SignerBackend,
    _make_aws_kms_client,
    _parse_aws_kms_public_key_response,
)


def normalize_pubkeys(pubkeys: Iterable[str]) -> List[str]:
    normalized: List[str] = []
    for raw in pubkeys:
        raw = str(raw or "").strip()
        if not raw:
            continue
        for line in raw.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            for item in line.split(","):
                item = item.strip()
                if item:
                    normalized.append(str(Pubkey.from_string(item)))
    return sorted(dict.fromkeys(normalized))


def read_pubkeys_file(path: str) -> List[str]:
    return normalize_pubkeys([Path(path).read_text(encoding="utf-8")])


def write_allowlist_file(path: str, pubkeys: Iterable[str]) -> List[str]:
    entries = normalize_pubkeys(pubkeys)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    atomic_write_bytes(target, "".join(f"{pubkey}\n" for pubkey in entries).encode("utf-8"))

    return entries


def merge_allowlist_entries(
    existing: Iterable[str],
    *,
    additions: Iterable[str] = (),
    removals: Iterable[str] = (),
) -> List[str]:
    current = set(normalize_pubkeys(existing))
    current.update(normalize_pubkeys(additions))
    current.difference_update(normalize_pubkeys(removals))
    return sorted(current)


def allowlist_snapshot(path: str) -> List[str]:
    raw = Path(path).read_text(encoding="utf-8")
    return sorted(_parse_allowed_pubkeys(raw))


def build_dry_run_message(label: str) -> bytes:
    clean = str(label or "default").strip() or "default"
    return f"PROPHET_REMOTE_SIGNER_DRY_RUN:{clean}".encode("utf-8")


def parse_message_b64(message_b64: str) -> bytes:
    return base64.b64decode(message_b64, validate=True)


def bootstrap_aws_kms_keys(
    *,
    region_name: str,
    key_ids: Sequence[str],
    endpoint_url: str,
    timeout_s: float,
    client=None,
) -> Dict[str, Any]:
    deduped_key_ids = list(dict.fromkeys([str(x).strip() for x in key_ids if str(x).strip()]))
    if not deduped_key_ids:
        raise ValueError("At least one AWS KMS key id is required.")

    kms_client = client or _make_aws_kms_client(
        region_name=region_name,
        endpoint_url=endpoint_url,
        timeout_s=timeout_s,
    )

    keys: List[Dict[str, Any]] = []
    seen_pubkeys: Dict[str, str] = {}
    for key_id in deduped_key_ids:
        try:
            response = kms_client.get_public_key(KeyId=key_id)
        except Exception as exc:
            raise RuntimeError(f"AWS KMS GetPublicKey failed for {key_id}: {exc}")
        parsed = _parse_aws_kms_public_key_response(key_id, response)
        existing = seen_pubkeys.get(parsed["pubkey"])
        if existing and existing != parsed["resolved_key_id"]:
            raise ValueError(
                "Configured AWS KMS keys map to the same Solana pubkey "
                f"{parsed['pubkey']}: {existing} vs {parsed['resolved_key_id']}"
            )
        seen_pubkeys[parsed["pubkey"]] = parsed["resolved_key_id"]
        keys.append(
            {
                "configured_key_id": key_id,
                "resolved_key_id": parsed["resolved_key_id"],
                "solana_pubkey": parsed["pubkey"],
                "key_spec": parsed["key_spec"],
                "key_usage": parsed["key_usage"],
                "signing_algorithms": parsed["signing_algorithms"],
            }
        )

    return {
        "region_name": region_name,
        "endpoint_url": endpoint_url,
        "keys": keys,
        "allowlist_pubkeys": [item["solana_pubkey"] for item in keys],
    }


def normalize_remote_signer_sign_url(url: str) -> str:
    parts = urlsplit(str(url or "").strip())
    if not parts.scheme or not parts.netloc:
        raise ValueError("Remote signer URL must include scheme and host.")

    path = parts.path or ""
    if path in {"", "/"}:
        path = "/sign"
    elif not path.endswith("/sign"):
        path = path.rstrip("/") + "/sign"

    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))


def derive_remote_signer_health_url(sign_url: str) -> str:
    normalized = normalize_remote_signer_sign_url(sign_url)
    parts = urlsplit(normalized)
    path = parts.path[:-5] + "/health"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))


def discover_pubkeys_from_signer_health(payload: Dict[str, Any]) -> List[str]:
    pubkeys: List[str] = []
    aws_loaded = payload.get("aws_loaded_key_ids")
    if isinstance(aws_loaded, dict):
        pubkeys.extend([str(key) for key in aws_loaded.keys()])

    loaded = payload.get("loaded_pubkeys")
    if isinstance(loaded, list):
        pubkeys.extend([str(item) for item in loaded])

    direct = payload.get("pubkeys")
    if isinstance(direct, list):
        pubkeys.extend([str(item) for item in direct])

    return normalize_pubkeys(pubkeys)


def fetch_remote_signer_health(sign_url: str, *, timeout_s: float, health_url: str = "") -> Dict[str, Any]:
    url = health_url or derive_remote_signer_health_url(sign_url)
    try:
        with httpx.Client(timeout=timeout_s) as client:
            response = client.get(url)
            response.raise_for_status()
    except Exception as exc:
        raise RuntimeError(f"Remote signer health request failed for {url}: {exc}")

    try:
        payload = response.json()
    except Exception as exc:
        raise RuntimeError(f"Remote signer health returned invalid JSON: {exc}")
    if not isinstance(payload, dict):
        raise RuntimeError("Remote signer health returned non-object JSON")
    return payload


def request_remote_signer_signature(
    sign_url: str,
    *,
    public_key: str,
    message: bytes,
    context: Dict[str, str],
    timeout_s: float,
    api_key: str = "",
) -> Dict[str, Any]:
    normalized_url = normalize_remote_signer_sign_url(sign_url)
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "public_key": str(Pubkey.from_string(public_key)),
        "message_b64": base64.b64encode(message).decode("ascii"),
        "context": context,
    }

    try:
        with httpx.Client(timeout=timeout_s) as client:
            response = client.post(normalized_url, json=payload, headers=headers)
    except Exception as exc:
        raise RuntimeError(f"Remote signer sign request failed for {normalized_url}: {exc}")

    if response.status_code != 200:
        detail = response.text[:200].strip()
        raise RuntimeError(
            f"Remote signer sign request failed with status {response.status_code}: {detail}"
        )

    try:
        body = response.json()
    except Exception as exc:
        raise RuntimeError(f"Remote signer sign returned invalid JSON: {exc}")
    if not isinstance(body, dict):
        raise RuntimeError("Remote signer sign returned non-object JSON")

    signature_b64 = str(body.get("signature_b64", "")).strip()
    if not signature_b64:
        raise RuntimeError("Remote signer sign response missing signature_b64")

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise RuntimeError(f"Remote signer sign returned invalid signature_b64: {exc}")
    if len(signature) != 64:
        raise RuntimeError(f"Remote signer signature length invalid: {len(signature)}")

    returned_pubkey = str(body.get("public_key", "")).strip()
    expected_pubkey = str(Pubkey.from_string(public_key))
    if returned_pubkey and returned_pubkey != expected_pubkey:
        raise RuntimeError("Remote signer sign response returned an unexpected public_key")

    return {
        "public_key": expected_pubkey,
        "signature_b64": signature_b64,
        "signature_len": len(signature),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }


def run_backend_dry_run(
    backend: SignerBackend,
    *,
    public_keys: Sequence[str],
    message: bytes,
    context: Dict[str, str],
) -> Dict[str, Any]:
    candidates = normalize_pubkeys(public_keys or backend.loaded_pubkeys())
    if not candidates:
        raise ValueError("No signer public keys provided and backend did not expose loaded keys.")

    results: List[Dict[str, Any]] = []
    for pubkey in candidates:
        signature = backend.sign(Pubkey.from_string(pubkey), message, context)
        if len(signature) != 64:
            raise RuntimeError(f"Signer backend returned invalid signature length for {pubkey}: {len(signature)}")
        results.append(
            {
                "public_key": pubkey,
                "signature_b64": base64.b64encode(signature).decode("ascii"),
                "signature_len": len(signature),
                "signature_sha256": hashlib.sha256(signature).hexdigest(),
            }
        )

    return {
        "backend": backend.name,
        "loaded_pubkeys": backend.loaded_pubkeys(),
        "message_b64": base64.b64encode(message).decode("ascii"),
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "message_len": len(message),
        "results": results,
    }


def json_dumps(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)

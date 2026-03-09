import json
import os
from typing import Any, Dict

import httpx

from .config import settings
from .resolver import ResolverDefinition, compute_resolver_hash


class ResolverRegistry:
    mode = "unknown"

    def load(self, resolver_hash: bytes) -> ResolverDefinition:
        raise NotImplementedError

    def health(self) -> Dict[str, Any]:
        return {"mode": self.mode}

    @staticmethod
    def _parse_and_verify(resolver_hash: bytes, payload: Dict[str, Any]) -> ResolverDefinition:
        if compute_resolver_hash(payload) != resolver_hash:
            raise ValueError(f"Integrity check failed for resolver {resolver_hash.hex()}")
        return ResolverDefinition(**payload)


class DirectoryResolverRegistry(ResolverRegistry):
    mode = "directory"

    def __init__(self, store_dir: str):
        self.store_dir = store_dir

    def load(self, resolver_hash: bytes) -> ResolverDefinition:
        hash_hex = resolver_hash.hex()
        path = os.path.join(self.store_dir, f"{hash_hex}.json")

        if not os.path.exists(path):
            raise ValueError(f"Resolver definition not found for hash: {hash_hex}")

        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return self._parse_and_verify(resolver_hash, payload)

    def health(self) -> Dict[str, Any]:
        return {"mode": self.mode, "store_dir": self.store_dir}


class HttpResolverRegistry(ResolverRegistry):
    mode = "http"

    def __init__(self, base_url: str, api_key: str, timeout_s: float):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_s = timeout_s

    def load(self, resolver_hash: bytes) -> ResolverDefinition:
        hash_hex = resolver_hash.hex()
        url = f"{self.base_url}/{hash_hex}.json"
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            with httpx.Client(timeout=self.timeout_s) as client:
                response = client.get(url, headers=headers)
        except Exception as exc:
            raise RuntimeError(f"Resolver registry request failed: {exc}")

        if response.status_code >= 300:
            raise ValueError(
                f"Resolver registry returned {response.status_code} for resolver {hash_hex}"
            )

        try:
            payload = response.json()
        except Exception as exc:
            raise RuntimeError(f"Resolver registry returned invalid JSON: {exc}")

        if not isinstance(payload, dict):
            raise ValueError("Resolver registry payload must be a JSON object")

        if "resolver" in payload and isinstance(payload["resolver"], dict):
            payload = payload["resolver"]

        return self._parse_and_verify(resolver_hash, payload)

    def health(self) -> Dict[str, Any]:
        return {"mode": self.mode, "base_url": self.base_url}


def make_resolver_registry() -> ResolverRegistry:
    mode = (settings.RESOLVER_REGISTRY_MODE or "directory").strip().lower()
    if mode == "http":
        return HttpResolverRegistry(
            base_url=settings.RESOLVER_REGISTRY_URL,
            api_key=settings.RESOLVER_REGISTRY_API_KEY,
            timeout_s=settings.RESOLVER_REGISTRY_TIMEOUT_S,
        )
    return DirectoryResolverRegistry(settings.RESOLVER_STORE_DIR)

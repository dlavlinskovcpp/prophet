import json
import os
import time
from collections import OrderedDict
from threading import Lock
from typing import Any, Dict

import httpx

from .config import settings
from .resolver import ResolverDefinition, compute_resolver_hash


class ResolverRegistryClientError(RuntimeError):
    """Fail-closed resolver-registry transport/response error."""


class ResolverRegistryResponseTooLarge(ResolverRegistryClientError):
    pass


class ResolverRegistryMalformedResponse(ResolverRegistryClientError):
    pass


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

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_s: float,
        response_max_bytes: int = 256_000,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_s = timeout_s
        self.response_max_bytes = int(response_max_bytes)
        if self.response_max_bytes <= 0:
            raise ValueError("resolver registry response limit must be > 0")

    def _read_bounded_response(self, response: httpx.Response) -> bytes:
        declared = response.headers.get("content-length")
        if declared is not None:
            if not declared.isdigit():
                raise ResolverRegistryMalformedResponse(
                    "resolver registry returned invalid Content-Length"
                )
            if int(declared) > self.response_max_bytes:
                raise ResolverRegistryResponseTooLarge(
                    "resolver registry response exceeds configured size limit"
                )

        raw = bytearray()
        for chunk in response.iter_bytes():
            if len(raw) + len(chunk) > self.response_max_bytes:
                raise ResolverRegistryResponseTooLarge(
                    "resolver registry response exceeds configured size limit"
                )
            raw.extend(chunk)
        return bytes(raw)

    def load(self, resolver_hash: bytes) -> ResolverDefinition:
        hash_hex = resolver_hash.hex()
        url = f"{self.base_url}/{hash_hex}.json"
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            with httpx.Client(timeout=self.timeout_s) as client:
                with client.stream("GET", url, headers=headers) as response:
                    if response.status_code >= 300:
                        raise ValueError(
                            f"Resolver registry returned {response.status_code} "
                            f"for resolver {hash_hex}"
                        )
                    raw = self._read_bounded_response(response)
        except (
            ResolverRegistryResponseTooLarge,
            ResolverRegistryMalformedResponse,
            ValueError,
        ):
            raise
        except httpx.TimeoutException as exc:
            raise ResolverRegistryClientError(
                "resolver registry request timed out"
            ) from exc
        except httpx.HTTPError as exc:
            raise ResolverRegistryClientError(
                "resolver registry request failed"
            ) from exc

        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ResolverRegistryMalformedResponse(
                "resolver registry returned invalid JSON"
            ) from None

        if not isinstance(payload, dict):
            raise ValueError("Resolver registry payload must be a JSON object")

        if "resolver" in payload and isinstance(payload["resolver"], dict):
            payload = payload["resolver"]

        return self._parse_and_verify(resolver_hash, payload)

    def health(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "base_url": self.base_url,
            "response_max_bytes": self.response_max_bytes,
        }


class CachingResolverRegistry(ResolverRegistry):
    def __init__(
        self,
        inner: ResolverRegistry,
        *,
        ttl_s: float,
        max_entries: int,
        allow_stale_on_error: bool,
    ):
        self.inner = inner
        self.mode = inner.mode
        self.ttl_s = ttl_s
        self.max_entries = max_entries
        self.allow_stale_on_error = allow_stale_on_error
        self._lock = Lock()
        self._cache: "OrderedDict[str, tuple[ResolverDefinition, float]]" = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._stale_hits = 0
        self._last_error = ""

    def _get_fresh(self, hash_hex: str) -> ResolverDefinition | None:
        item = self._cache.get(hash_hex)
        if item is None:
            return None
        resolver, loaded_at = item
        if time.monotonic() - loaded_at > self.ttl_s:
            return None
        self._cache.move_to_end(hash_hex)
        return resolver

    def _get_any(self, hash_hex: str) -> ResolverDefinition | None:
        item = self._cache.get(hash_hex)
        if item is None:
            return None
        resolver, _ = item
        self._cache.move_to_end(hash_hex)
        return resolver

    def _store(self, hash_hex: str, resolver: ResolverDefinition) -> None:
        self._cache[hash_hex] = (resolver, time.monotonic())
        self._cache.move_to_end(hash_hex)
        while len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)

    def load(self, resolver_hash: bytes) -> ResolverDefinition:
        hash_hex = resolver_hash.hex()

        with self._lock:
            fresh = self._get_fresh(hash_hex)
            if fresh is not None:
                self._hits += 1
                return fresh

        try:
            resolver = self.inner.load(resolver_hash)
        except Exception as exc:
            with self._lock:
                fallback = self._get_any(hash_hex) if self.allow_stale_on_error else None
                if fallback is not None:
                    self._stale_hits += 1
                    self._last_error = str(exc)
                    return fallback
                self._last_error = str(exc)
            raise

        with self._lock:
            self._misses += 1
            self._last_error = ""
            self._store(hash_hex, resolver)
        return resolver

    def health(self) -> Dict[str, Any]:
        payload = dict(self.inner.health())
        with self._lock:
            payload.update(
                {
                    "cache_ttl_s": self.ttl_s,
                    "cache_max_entries": self.max_entries,
                    "cache_entries": len(self._cache),
                    "cache_hits": self._hits,
                    "cache_misses": self._misses,
                    "cache_stale_hits": self._stale_hits,
                    "cache_last_error": self._last_error,
                    "cache_allow_stale_on_error": self.allow_stale_on_error,
                }
            )
        return payload


def make_resolver_registry() -> ResolverRegistry:
    mode = (settings.RESOLVER_REGISTRY_MODE or "directory").strip().lower()
    if mode == "http":
        inner: ResolverRegistry = HttpResolverRegistry(
            base_url=settings.RESOLVER_REGISTRY_URL,
            api_key=settings.RESOLVER_REGISTRY_API_KEY,
            timeout_s=settings.RESOLVER_REGISTRY_TIMEOUT_S,
            response_max_bytes=settings.RESOLVER_REGISTRY_MAX_RESPONSE_BYTES,
        )
    else:
        inner = DirectoryResolverRegistry(settings.RESOLVER_STORE_DIR)

    return CachingResolverRegistry(
        inner,
        ttl_s=settings.RESOLVER_REGISTRY_CACHE_TTL_S,
        max_entries=settings.RESOLVER_REGISTRY_CACHE_MAX_ENTRIES,
        allow_stale_on_error=settings.RESOLVER_REGISTRY_ALLOW_STALE_ON_ERROR,
    )

import base64
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

from .proof_formats import calculate_hash, normalize_public_inputs

logger = logging.getLogger(__name__)


@dataclass
class ZkProof:
    proof_bytes: bytes
    public_inputs_bytes: bytes

    @property
    def proof_b64(self) -> str:
        return base64.b64encode(self.proof_bytes).decode("utf-8")

    @property
    def public_inputs_b64(self) -> str:
        return base64.b64encode(self.public_inputs_bytes).decode("utf-8")

    @property
    def proof_hash(self) -> bytes:
        return calculate_hash(self.proof_bytes)

    @property
    def public_inputs_hash(self) -> bytes:
        return calculate_hash(self.public_inputs_bytes)


class ReclaimClient:
    def __init__(
        self,
        api_endpoint: str = "https://api.reclaimprotocol.org",
        api_key: Optional[str] = None,
        timeout_s: float = 15.0,
    ):
        self.api_endpoint = api_endpoint.rstrip("/")
        self.api_key = api_key
        self.timeout_s = timeout_s

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _extract_b64(self, data: Dict[str, Any], *keys: str) -> Optional[str]:
        for key in keys:
            value = data.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    def _parse_response(self, data: Dict[str, Any]) -> ZkProof:
        proof_blob = data.get("proof") if isinstance(data.get("proof"), dict) else {}

        proof_b64 = self._extract_b64(
            data,
            "proof_bytes_b64",
            "proof_b64",
        ) or self._extract_b64(proof_blob, "proof_bytes_b64", "proof_b64")

        public_inputs_b64 = self._extract_b64(
            data,
            "public_inputs_bytes_b64",
            "public_inputs_b64",
        ) or self._extract_b64(proof_blob, "public_inputs_bytes_b64", "public_inputs_b64")

        if not proof_b64:
            raise ValueError("proof bytes not found in provider response")

        proof_bytes = base64.b64decode(proof_b64)

        if public_inputs_b64:
            public_inputs_bytes = base64.b64decode(public_inputs_b64)
        else:
            public_inputs_obj = data.get("public_inputs", proof_blob.get("public_inputs"))
            if not isinstance(public_inputs_obj, dict):
                raise ValueError("public inputs not found in provider response")
            public_inputs_bytes = normalize_public_inputs(public_inputs_obj)

        return ZkProof(
            proof_bytes=proof_bytes,
            public_inputs_bytes=public_inputs_bytes,
        )

    def fetch_proof(self, proof_id: str) -> ZkProof:
        proof_id = (proof_id or "").strip()
        if not proof_id:
            raise ValueError("proof_id is required")

        logger.info("Fetching zkTLS proof for ID: %s", proof_id)
        urls = [
            f"{self.api_endpoint}/proofs/{proof_id}",
            f"{self.api_endpoint}/v1/proofs/{proof_id}",
        ]

        last_error: Optional[Exception] = None
        with httpx.Client(timeout=self.timeout_s) as client:
            for url in urls:
                try:
                    resp = client.get(url, headers=self._headers())
                    if resp.status_code == 404:
                        continue
                    resp.raise_for_status()
                    payload = resp.json()
                    if not isinstance(payload, dict):
                        raise ValueError("provider response must be a JSON object")
                    return self._parse_response(payload)
                except Exception as exc:
                    last_error = exc

        raise RuntimeError(
            f"Failed to fetch proof '{proof_id}' from {self.api_endpoint}: {last_error}"
        )

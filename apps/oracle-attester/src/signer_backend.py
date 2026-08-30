"""Legacy/test signer adapters; production launch surfaces use fixed-role Vault signers."""

import base64
import json
import logging
import os
import shlex
import subprocess
from typing import Any, Dict, List

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from .config import settings

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.config import Config as BotocoreConfig
except Exception:  # pragma: no cover - exercised via runtime validation/import environment
    boto3 = None
    BotocoreConfig = None


ED25519_OID_DER = b"\x2b\x65\x70"


class SignerBackend:
    name = "unknown"

    def sign(self, pubkey: Pubkey, message: bytes, context: Dict[str, str]) -> bytes:
        raise NotImplementedError

    def loaded_pubkeys(self) -> List[str]:
        return []

    def health(self) -> Dict[str, Any]:
        return {
            "backend": self.name,
            "loaded_signers": len(self.loaded_pubkeys()),
        }


def _split_env_list(raw: str) -> List[str]:
    out: List[str] = []
    for line in (raw or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        for item in line.split(","):
            item = item.strip()
            if item:
                out.append(item)
    return out


def _normalize_pubkeys(items: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        pubkey = str(Pubkey.from_string(str(item).strip()))
        if pubkey in seen:
            continue
        seen.add(pubkey)
        out.append(pubkey)
    return out


def _read_der_length(blob: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(blob):
        raise ValueError("Invalid DER length")
    first = blob[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(blob):
        raise ValueError("Invalid DER length encoding")
    length = int.from_bytes(blob[offset : offset + count], "big")
    return length, offset + count


def _read_der_tlv(blob: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(blob):
        raise ValueError("Unexpected end of DER")
    tag = blob[offset]
    length, value_offset = _read_der_length(blob, offset + 1)
    end = value_offset + length
    if end > len(blob):
        raise ValueError("DER value exceeds buffer")
    return tag, blob[value_offset:end], end


def _ed25519_pubkey_from_spki(spki_der: bytes) -> bytes:
    tag, top_value, top_end = _read_der_tlv(spki_der, 0)
    if tag != 0x30 or top_end != len(spki_der):
        raise ValueError("Invalid SPKI structure")

    inner_offset = 0
    tag, alg_value, inner_offset = _read_der_tlv(top_value, inner_offset)
    if tag != 0x30:
        raise ValueError("Invalid SPKI algorithm identifier")

    alg_offset = 0
    tag, oid_value, alg_offset = _read_der_tlv(alg_value, alg_offset)
    if tag != 0x06 or oid_value != ED25519_OID_DER:
        raise ValueError("SPKI public key is not Ed25519")
    if alg_offset != len(alg_value):
        raise ValueError("Unexpected Ed25519 algorithm parameters")

    tag, bit_string, inner_offset = _read_der_tlv(top_value, inner_offset)
    if tag != 0x03 or not bit_string:
        raise ValueError("Invalid SPKI public key bit string")
    if bit_string[0] != 0:
        raise ValueError("Unsupported SPKI bit string padding")

    raw_key = bit_string[1:]
    if len(raw_key) != 32:
        raise ValueError(f"Unexpected Ed25519 public key length: {len(raw_key)}")
    if inner_offset != len(top_value):
        raise ValueError("Trailing data in SPKI structure")
    return raw_key


def _make_aws_kms_client(*, region_name: str, endpoint_url: str, timeout_s: float):
    if boto3 is None or BotocoreConfig is None:
        raise RuntimeError("boto3 is required for REMOTE_SIGNER_BACKEND=aws_kms")

    kwargs: Dict[str, Any] = {
        "config": BotocoreConfig(
            connect_timeout=timeout_s,
            read_timeout=timeout_s,
            retries={"max_attempts": 3, "mode": "standard"},
        )
    }
    if region_name:
        kwargs["region_name"] = region_name
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    return boto3.client("kms", **kwargs)


def _parse_aws_kms_public_key_response(
    requested_key_id: str, response: Dict[str, Any]
) -> Dict[str, Any]:
    key_spec = str(response.get("KeySpec", "")).strip()
    key_usage = str(response.get("KeyUsage", "")).strip()
    algorithms = [str(x) for x in response.get("SigningAlgorithms", [])]
    if key_spec != "ECC_NIST_EDWARDS25519":
        raise ValueError(
            f"AWS KMS key {requested_key_id} has unsupported KeySpec {key_spec!r}; expected ECC_NIST_EDWARDS25519."
        )
    if key_usage != "SIGN_VERIFY":
        raise ValueError(
            f"AWS KMS key {requested_key_id} has unsupported KeyUsage {key_usage!r}; expected SIGN_VERIFY."
        )
    if "ED25519_SHA_512" not in algorithms:
        raise ValueError(
            f"AWS KMS key {requested_key_id} does not advertise ED25519_SHA_512 support."
        )

    public_key_der = response.get("PublicKey")
    if not isinstance(public_key_der, (bytes, bytearray)):
        raise ValueError(
            f"AWS KMS key {requested_key_id} returned an invalid PublicKey payload."
        )

    raw_pubkey = _ed25519_pubkey_from_spki(bytes(public_key_der))
    pubkey_str = str(Pubkey.from_bytes(raw_pubkey))
    resolved_key_id = str(response.get("KeyId", requested_key_id)).strip() or requested_key_id

    return {
        "key_spec": key_spec,
        "key_usage": key_usage,
        "signing_algorithms": algorithms,
        "pubkey": pubkey_str,
        "resolved_key_id": resolved_key_id,
    }


class LocalKeypairSignerBackend(SignerBackend):
    name = "local_keypairs"

    def __init__(self, signer_map: Dict[str, Keypair]):
        self.signer_map = signer_map

    def sign(self, pubkey: Pubkey, message: bytes, context: Dict[str, str]) -> bytes:
        del context
        kp = self.signer_map.get(str(pubkey))
        if kp is None:
            raise PermissionError(f"Signer key unavailable for {pubkey}")
        return bytes(kp.sign_message(message))

    def loaded_pubkeys(self) -> List[str]:
        return sorted(self.signer_map.keys())

    def health(self) -> Dict[str, Any]:
        payload = super().health()
        loaded = self.loaded_pubkeys()
        payload.update(
            {
                "backend_ready": bool(loaded),
                "loaded_pubkeys": loaded,
                "pubkeys": loaded,
            }
        )
        if not loaded:
            payload["backend_ready_reason"] = "No local signer keypairs loaded."
        return payload


class CommandSignerBackend(SignerBackend):
    name = "command"

    def __init__(self, command: str, timeout_s: float, *, public_keys: List[str] | None = None, child_env: Dict[str, str] | None = None):
        self.command = command
        self.timeout_s = timeout_s
        self.argv = shlex.split(command)
        self.public_keys = _normalize_pubkeys(public_keys or [])
        # Never inherit the parent process environment.  Fixed-role callers
        # provide their already-filtered role-local environment explicitly.
        self.child_env = dict(child_env or {name: os.environ[name] for name in ("PATH", "LANG", "LC_ALL") if name in os.environ})
        if not self.argv:
            raise ValueError("REMOTE_SIGNER_COMMAND is empty")

    def sign(self, pubkey: Pubkey, message: bytes, context: Dict[str, str]) -> bytes:
        payload = {
            "public_key": str(pubkey),
            "message_b64": base64.b64encode(message).decode("ascii"),
            "context": context,
        }

        try:
            proc = subprocess.run(
                self.argv,
                input=json.dumps(payload).encode("utf-8"),
                capture_output=True,
                timeout=self.timeout_s,
                check=False,
                env=self.child_env,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Command signer timed out: {exc}")
        except Exception as exc:
            raise RuntimeError(f"Command signer invocation failed: {exc}")

        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                f"Command signer exited with code {proc.returncode}: {stderr[:200]}"
            )

        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        if not stdout:
            raise RuntimeError("Command signer returned empty stdout")

        try:
            response = json.loads(stdout)
        except Exception as exc:
            raise RuntimeError(f"Command signer returned invalid JSON: {exc}")

        if not isinstance(response, dict):
            raise RuntimeError("Command signer returned non-object JSON")

        sig_b64 = str(response.get("signature_b64", "")).strip()
        if not sig_b64:
            raise RuntimeError("Command signer response missing signature_b64")

        try:
            signature = base64.b64decode(sig_b64, validate=True)
        except Exception as exc:
            raise RuntimeError(f"Command signer signature is not valid base64: {exc}")

        if len(signature) != 64:
            raise RuntimeError(f"Command signer signature length invalid: {len(signature)}")

        echoed_pk = str(response.get("public_key", "")).strip()
        if echoed_pk and echoed_pk != str(pubkey):
            raise RuntimeError("Command signer returned signature for unexpected public key")

        return signature

    def loaded_pubkeys(self) -> List[str]:
        return list(self.public_keys)

    def health(self) -> Dict[str, Any]:
        payload = super().health()
        payload.update(
            {
                "backend_ready": bool(self.public_keys),
                "command_argv": self.argv,
                "command_timeout_s": self.timeout_s,
                "loaded_pubkeys": self.loaded_pubkeys(),
                "pubkeys": self.loaded_pubkeys(),
            }
        )
        if not self.public_keys:
            payload["backend_ready_reason"] = (
                "Command signer did not expose any public keys. Configure "
                "REMOTE_SIGNER_COMMAND_PUBLIC_KEYS or NOTARY_KEYPAIR_PATHS."
            )
        return payload


class AwsKmsSignerBackend(SignerBackend):
    name = "aws_kms"

    def __init__(
        self,
        *,
        region_name: str,
        key_ids: List[str],
        endpoint_url: str,
        timeout_s: float,
    ):
        if not key_ids:
            raise ValueError("REMOTE_SIGNER_AWS_KMS_KEY_IDS is empty")

        self.region_name = region_name
        self.endpoint_url = endpoint_url
        self.timeout_s = timeout_s
        self.configured_key_ids = list(dict.fromkeys(key_ids))
        self.client = _make_aws_kms_client(
            region_name=region_name,
            endpoint_url=endpoint_url,
            timeout_s=timeout_s,
        )
        self._pubkey_to_key_id: Dict[str, str] = {}
        self._pubkey_to_arn: Dict[str, str] = {}

        for key_id in self.configured_key_ids:
            self._register_key(key_id)

    def _register_key(self, key_id: str) -> None:
        try:
            response = self.client.get_public_key(KeyId=key_id)
        except Exception as exc:
            raise RuntimeError(f"AWS KMS GetPublicKey failed for {key_id}: {exc}")
        parsed = _parse_aws_kms_public_key_response(key_id, response)
        pubkey_str = parsed["pubkey"]
        resolved_key_id = parsed["resolved_key_id"]

        existing = self._pubkey_to_key_id.get(pubkey_str)
        if existing and existing != resolved_key_id:
            raise ValueError(
                f"Configured AWS KMS keys map to the same Solana pubkey {pubkey_str}: {existing} vs {resolved_key_id}"
            )

        self._pubkey_to_key_id[pubkey_str] = resolved_key_id
        self._pubkey_to_arn[pubkey_str] = resolved_key_id

    def sign(self, pubkey: Pubkey, message: bytes, context: Dict[str, str]) -> bytes:
        del context
        key_id = self._pubkey_to_key_id.get(str(pubkey))
        if key_id is None:
            raise PermissionError(f"Signer key unavailable for {pubkey}")

        try:
            response = self.client.sign(
                KeyId=key_id,
                Message=message,
                MessageType="RAW",
                SigningAlgorithm="ED25519_SHA_512",
            )
        except Exception as exc:
            raise RuntimeError(f"AWS KMS Sign failed for {pubkey}: {exc}")

        signature = response.get("Signature")
        if not isinstance(signature, (bytes, bytearray)):
            raise RuntimeError("AWS KMS Sign returned an invalid Signature payload")
        signature_bytes = bytes(signature)
        if len(signature_bytes) != 64:
            raise RuntimeError(f"AWS KMS signature length invalid: {len(signature_bytes)}")
        return signature_bytes

    def loaded_pubkeys(self) -> List[str]:
        return sorted(self._pubkey_to_key_id.keys())

    def health(self) -> Dict[str, Any]:
        payload = super().health()
        loaded = self.loaded_pubkeys()
        payload.update(
            {
                "backend_ready": bool(loaded),
                "aws_region": self.region_name,
                "aws_endpoint_url": self.endpoint_url,
                "aws_configured_key_ids": list(self.configured_key_ids),
                "loaded_pubkeys": loaded,
                "pubkeys": loaded,
                "aws_loaded_key_ids": {
                    pubkey: self._pubkey_to_arn[pubkey] for pubkey in loaded
                },
            }
        )
        return payload


def _load_signers_from_settings() -> Dict[str, Keypair]:
    raw = (settings.NOTARY_KEYPAIR_PATHS or "").strip()
    if raw:
        sources = [x.strip() for x in raw.split(",") if x.strip()]
    else:
        sources = [settings.ORACLE_KEYPAIR_PATH]

    out: Dict[str, Keypair] = {}
    for src in sources:
        kp = settings._load_keypair(src)
        if kp is None:
            logger.warning(f"Skipping invalid keypair source: {src}")
            continue
        out[str(kp.pubkey())] = kp
    return out


def _configured_command_pubkeys() -> List[str]:
    explicit = _normalize_pubkeys(_split_env_list(settings.REMOTE_SIGNER_COMMAND_PUBLIC_KEYS))
    from_keypairs: List[str] = []
    if explicit:
        from_keypairs = []
    elif (settings.NOTARY_KEYPAIR_PATHS or "").strip():
        from_keypairs = sorted(_load_signers_from_settings().keys())
    else:
        fallback = settings._load_keypair(settings.ORACLE_KEYPAIR_PATH)
        if fallback is not None:
            from_keypairs = [str(fallback.pubkey())]
    combined: List[str] = []
    seen = set()
    for pubkey in [*explicit, *from_keypairs]:
        if pubkey in seen:
            continue
        seen.add(pubkey)
        combined.append(pubkey)
    return combined


def make_remote_signer_backend() -> SignerBackend:
    backend = (settings.REMOTE_SIGNER_BACKEND or "local_keypairs").strip().lower()
    if backend == "aws_kms":
        return AwsKmsSignerBackend(
            region_name=settings.REMOTE_SIGNER_AWS_KMS_REGION,
            key_ids=_split_env_list(settings.REMOTE_SIGNER_AWS_KMS_KEY_IDS),
            endpoint_url=settings.REMOTE_SIGNER_AWS_KMS_ENDPOINT_URL,
            timeout_s=settings.REMOTE_SIGNER_AWS_KMS_TIMEOUT_S,
        )
    if backend == "command":
        return CommandSignerBackend(
            command=settings.REMOTE_SIGNER_COMMAND,
            timeout_s=settings.REMOTE_SIGNER_COMMAND_TIMEOUT_S,
            public_keys=_configured_command_pubkeys(),
        )
    return LocalKeypairSignerBackend(_load_signers_from_settings())

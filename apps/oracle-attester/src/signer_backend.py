import base64
import json
import logging
import shlex
import subprocess
from typing import Any, Dict, List

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from .config import settings

logger = logging.getLogger(__name__)


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


class CommandSignerBackend(SignerBackend):
    name = "command"

    def __init__(self, command: str, timeout_s: float):
        self.command = command
        self.timeout_s = timeout_s
        self.argv = shlex.split(command)
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


def make_remote_signer_backend() -> SignerBackend:
    backend = (settings.REMOTE_SIGNER_BACKEND or "local_keypairs").strip().lower()
    if backend == "command":
        return CommandSignerBackend(
            command=settings.REMOTE_SIGNER_COMMAND,
            timeout_s=settings.REMOTE_SIGNER_COMMAND_TIMEOUT_S,
        )
    return LocalKeypairSignerBackend(_load_signers_from_settings())

import base64
import os
import stat
import httpx
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Optional, Dict, Any
from urllib.parse import unquote
from .config import settings

DEFAULT_PROOF_MAX_BYTES = 2_000_000
DEFAULT_PUBLIC_INPUTS_MAX_BYTES = 256_000
_READ_CHUNK_BYTES = 64 * 1024


class ProofFetchError(ValueError):
    """Fail-closed proof fetch error with a safe, non-path diagnostic."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


class ProofFetchConfigurationError(ProofFetchError):
    pass


@dataclass
class FetchedProof:
    proof_bytes: bytes
    public_inputs_bytes: bytes
    provider: str = ""
    meta: Optional[Dict[str, Any]] = None


class ProofFetcher(ABC):
    @abstractmethod
    def fetch(self, ref: str) -> FetchedProof:
        pass


class LocalFileProofFetcher(ProofFetcher):
    """Root-confined local proof fetcher.

    Local references retain the existing two-file shape:

        file:<proof-relative-path>:<public-inputs-relative-path>

    Both paths must be relative identifiers strictly below ``root``.
    """

    def __init__(
        self,
        root: str,
        *,
        proof_max_bytes: int = DEFAULT_PROOF_MAX_BYTES,
        public_inputs_max_bytes: int = DEFAULT_PUBLIC_INPUTS_MAX_BYTES,
    ):
        raw_root = "" if root is None else str(root).strip()
        if not raw_root:
            raise ProofFetchConfigurationError(
                "invalid_root",
                "local proof store root is required",
            )
        if proof_max_bytes <= 0 or public_inputs_max_bytes <= 0:
            raise ProofFetchConfigurationError(
                "invalid_size_limit",
                "local proof size limits must be positive",
            )

        try:
            resolved_root = Path(raw_root).expanduser().resolve(strict=True)
            root_stat = resolved_root.stat()
        except (OSError, RuntimeError, ValueError):
            raise ProofFetchConfigurationError(
                "invalid_root",
                "local proof store root is unavailable",
            ) from None

        if not stat.S_ISDIR(root_stat.st_mode):
            raise ProofFetchConfigurationError(
                "invalid_root",
                "local proof store root must be a directory",
            )
        if resolved_root == Path(resolved_root.anchor):
            raise ProofFetchConfigurationError(
                "invalid_root",
                "filesystem root is not a valid local proof store",
            )

        self.root = resolved_root
        self.proof_max_bytes = int(proof_max_bytes)
        self.public_inputs_max_bytes = int(public_inputs_max_bytes)

    @staticmethod
    def _relative_identifier(raw: str, label: str) -> str:
        if not isinstance(raw, str) or not raw or raw != raw.strip():
            raise ProofFetchError("invalid_ref", f"{label} path is invalid")

        # Decode repeatedly so single/double encoded traversal cannot become
        # meaningful after another normalization layer.
        value = raw
        for _ in range(3):
            try:
                decoded = unquote(value, errors="strict")
            except UnicodeDecodeError:
                raise ProofFetchError("invalid_ref", f"{label} path is invalid") from None
            if decoded == value:
                break
            value = decoded

        # Reject malformed/residual percent-encoding rather than allowing
        # ambiguous path interpretation by a later layer.
        if "%" in value:
            raise ProofFetchError("invalid_ref", f"{label} path is invalid")
        if "\x00" in value or "\\" in value or ":" in value:
            raise ProofFetchError("invalid_ref", f"{label} path is invalid")

        posix_path = PurePosixPath(value)
        windows_path = PureWindowsPath(value)
        if (
            posix_path.is_absolute()
            or windows_path.is_absolute()
            or bool(windows_path.drive)
        ):
            raise ProofFetchError(
                "invalid_ref",
                f"{label} path must be relative to the local proof store",
            )

        components = value.split("/")
        if any(component in {"", ".", ".."} for component in components):
            raise ProofFetchError(
                "invalid_ref",
                f"{label} path contains a forbidden path component",
            )

        return value

    def _parse_ref(self, ref: str) -> tuple[str, str]:
        if not isinstance(ref, str) or not ref.startswith("file:"):
            raise ProofFetchError(
                "invalid_ref",
                "local proof reference must use file:<proof>:<public-inputs>",
            )

        rest = ref[5:]
        if rest.count(":") != 1:
            raise ProofFetchError(
                "invalid_ref",
                "local proof reference is malformed",
            )

        proof_raw, public_inputs_raw = rest.split(":", 1)
        proof_relative = self._relative_identifier(proof_raw, "proof")
        public_inputs_relative = self._relative_identifier(
            public_inputs_raw,
            "public inputs",
        )
        return proof_relative, public_inputs_relative

    def _resolve_candidate(
        self,
        relative: str,
        *,
        label: str,
        max_bytes: int,
    ) -> tuple[Path, os.stat_result]:
        try:
            candidate = (self.root / relative).resolve(strict=True)
        except FileNotFoundError:
            raise ProofFetchError("not_found", f"{label} file is missing") from None
        except (OSError, RuntimeError, ValueError):
            raise ProofFetchError("unavailable", f"{label} file is unavailable") from None

        try:
            candidate.relative_to(self.root)
        except ValueError:
            raise ProofFetchError(
                "path_escape",
                f"{label} file escapes the local proof store",
            ) from None
        if candidate == self.root:
            raise ProofFetchError(
                "path_escape",
                f"{label} file is not strictly contained by the local proof store",
            )

        try:
            candidate_stat = candidate.stat()
        except OSError:
            raise ProofFetchError("unavailable", f"{label} file is unavailable") from None

        if not stat.S_ISREG(candidate_stat.st_mode):
            raise ProofFetchError(
                "not_regular",
                f"{label} target must be a regular file",
            )
        if candidate_stat.st_size > max_bytes:
            raise ProofFetchError(
                "too_large",
                f"{label} file exceeds the configured size limit",
            )

        return candidate, candidate_stat

    def _open_relative_no_follow(self, relative: str, candidate: Path) -> int:
        file_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        supports_dir_fd = os.open in getattr(os, "supports_dir_fd", set())

        if supports_dir_fd and no_follow:
            directory_flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | no_follow
            )
            current_fd = os.open(self.root, directory_flags)
            try:
                components = relative.split("/")
                for component in components[:-1]:
                    next_fd = os.open(
                        component,
                        directory_flags,
                        dir_fd=current_fd,
                    )
                    os.close(current_fd)
                    current_fd = next_fd

                return os.open(
                    components[-1],
                    file_flags | no_follow,
                    dir_fd=current_fd,
                )
            finally:
                os.close(current_fd)

        # Canonical containment and inode comparison below remain the
        # fail-closed fallback on platforms without dir_fd/O_NOFOLLOW.
        return os.open(candidate, file_flags | no_follow)

    def _read_relative_file(
        self,
        relative: str,
        *,
        label: str,
        max_bytes: int,
    ) -> bytes:
        candidate, expected_stat = self._resolve_candidate(
            relative,
            label=label,
            max_bytes=max_bytes,
        )

        try:
            fd = self._open_relative_no_follow(relative, candidate)
        except OSError:
            raise ProofFetchError(
                "unsafe_path",
                f"{label} file could not be opened safely",
            ) from None

        try:
            try:
                opened_stat = os.fstat(fd)
            except OSError:
                raise ProofFetchError("unavailable", f"{label} file is unavailable") from None

            if not stat.S_ISREG(opened_stat.st_mode):
                raise ProofFetchError(
                    "not_regular",
                    f"{label} target must be a regular file",
                )
            if opened_stat.st_size > max_bytes:
                raise ProofFetchError(
                    "too_large",
                    f"{label} file exceeds the configured size limit",
                )
            if (
                opened_stat.st_dev,
                opened_stat.st_ino,
            ) != (
                expected_stat.st_dev,
                expected_stat.st_ino,
            ):
                raise ProofFetchError(
                    "path_changed",
                    f"{label} file changed during validation",
                )

            data = bytearray()
            while len(data) <= max_bytes:
                remaining = max_bytes + 1 - len(data)
                if remaining <= 0:
                    break
                try:
                    chunk = os.read(fd, min(_READ_CHUNK_BYTES, remaining))
                except OSError:
                    raise ProofFetchError(
                        "unavailable",
                        f"{label} file could not be read safely",
                    ) from None
                if not chunk:
                    break
                data.extend(chunk)

            if len(data) > max_bytes:
                raise ProofFetchError(
                    "too_large",
                    f"{label} file exceeds the configured size limit",
                )

            return bytes(data)
        finally:
            os.close(fd)

    def fetch(self, ref: str) -> FetchedProof:
        proof_relative, public_inputs_relative = self._parse_ref(ref)
        proof = self._read_relative_file(
            proof_relative,
            label="proof",
            max_bytes=self.proof_max_bytes,
        )
        pi = self._read_relative_file(
            public_inputs_relative,
            label="public inputs",
            max_bytes=self.public_inputs_max_bytes,
        )

        return FetchedProof(
            proof_bytes=proof,
            public_inputs_bytes=pi,
            provider="local_files",
            meta={
                "proof_size": len(proof),
                "pi_size": len(pi),
            },
        )


class HttpProofFetcher(ProofFetcher):
    def fetch(self, ref: str) -> FetchedProof:
        url = settings.PROOF_FETCH_URL
        if not url:
            raise ValueError("PROOF_FETCH_URL not configured")
            
        headers = {}
        if settings.PROOF_FETCH_API_KEY:
            headers["Authorization"] = f"Bearer {settings.PROOF_FETCH_API_KEY}"
            
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.get(url, params={"ref": ref}, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                
                # Support variant keys
                p_b64 = data.get("proof_bytes_b64") or data.get("proof_b64")
                pi_b64 = data.get("public_inputs_bytes_b64") or data.get("public_inputs_b64")
                
                if not p_b64 or not pi_b64:
                    raise ValueError("Response missing required b64 fields")
                    
                proof = base64.b64decode(p_b64)
                pi = base64.b64decode(pi_b64)
                
                # Strict scrub of base64 fields from meta
                scrub_keys = {
                    "proof_bytes_b64", "public_inputs_bytes_b64",
                    "proof_b64", "public_inputs_b64"
                }
                
                meta = {}
                for k, v in data.items():
                    if k in scrub_keys or k.endswith("_b64"):
                        continue
                    meta[k] = v
                    
                meta["ref"] = ref
                meta["status_code"] = resp.status_code
                
                return FetchedProof(
                    proof_bytes=proof,
                    public_inputs_bytes=pi,
                    provider="http_fetch",
                    meta=meta
                )
                
        except Exception as e:
            raise RuntimeError(f"HTTP fetch failed: {e}")


def make_fetcher() -> ProofFetcher:
    mode = (settings.PROOF_FETCH_MODE or "").strip().lower()
    if mode == "http":
        return HttpProofFetcher()
    if mode == "local":
        return LocalFileProofFetcher(
            settings.PROOF_STORE_DIR,
            proof_max_bytes=settings.PROOF_MAX_BYTES,
            public_inputs_max_bytes=settings.PUBLIC_INPUTS_MAX_BYTES,
        )
    raise ProofFetchConfigurationError(
        "invalid_mode",
        "PROOF_FETCH_MODE must be local or http",
    )

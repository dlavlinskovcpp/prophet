import os
import time
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Set

from solders.pubkey import Pubkey

from .config import settings


def _parse_allowed_pubkeys(raw: str) -> Set[str]:
    raw = (raw or "").strip()
    if not raw:
        return set()

    out: Set[str] = set()
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        for item in line.split(","):
            item = item.strip()
            if not item:
                continue
            out.add(str(Pubkey.from_string(item)))
    return out


class SignerAllowlist:
    mode = "unknown"

    def __init__(self, *, required: bool):
        self.required = required

    def snapshot(self) -> Set[str]:
        raise NotImplementedError

    def contains(self, pubkey: str) -> bool:
        pubkey = str(Pubkey.from_string(pubkey))
        entries = self.snapshot()
        if not self.required and not entries:
            return True
        return pubkey in entries

    def health(self) -> Dict[str, Any]:
        entries = self.snapshot()
        ready = bool(entries) or not self.required
        return {
            "allowlist_mode": self.mode,
            "allowlist_required": self.required,
            "allowlist_size": len(entries),
            "allowlist_ready": ready,
        }


class EnvSignerAllowlist(SignerAllowlist):
    mode = "env"

    def __init__(self, raw_pubkeys: str, *, required: bool):
        super().__init__(required=required)
        self._entries = _parse_allowed_pubkeys(raw_pubkeys)

    def snapshot(self) -> Set[str]:
        return set(self._entries)


class FileSignerAllowlist(SignerAllowlist):
    mode = "file"

    def __init__(self, path: str, refresh_s: float, *, required: bool):
        super().__init__(required=required)
        self.path = path
        self.refresh_s = refresh_s
        self._lock = Lock()
        self._entries: Set[str] = set()
        self._last_loaded_at = 0
        self._last_checked_monotonic = 0.0
        self._last_mtime_ns = -1
        self._last_error = ""

    def _reload_unlocked(self) -> None:
        raw = Path(self.path).read_text(encoding="utf-8")
        self._entries = _parse_allowed_pubkeys(raw)
        self._last_loaded_at = int(time.time())
        self._last_error = ""

    def _maybe_refresh(self) -> None:
        now = time.monotonic()
        if self._last_checked_monotonic and now - self._last_checked_monotonic < self.refresh_s:
            return

        with self._lock:
            now = time.monotonic()
            if self._last_checked_monotonic and now - self._last_checked_monotonic < self.refresh_s:
                return
            self._last_checked_monotonic = now
            try:
                stat = os.stat(self.path)
                if stat.st_mtime_ns == self._last_mtime_ns and self._last_loaded_at:
                    return
                self._reload_unlocked()
                self._last_mtime_ns = stat.st_mtime_ns
            except Exception as exc:
                self._last_error = str(exc)

    def snapshot(self) -> Set[str]:
        self._maybe_refresh()
        return set(self._entries)

    def health(self) -> Dict[str, Any]:
        payload = super().health()
        payload.update(
            {
                "allowlist_path": self.path,
                "allowlist_refresh_s": self.refresh_s,
                "allowlist_last_loaded_at": self._last_loaded_at,
                "allowlist_last_error": self._last_error,
            }
        )
        if payload["allowlist_last_error"]:
            payload["allowlist_ready"] = False
        return payload


def make_signer_allowlist() -> SignerAllowlist:
    mode = (settings.REMOTE_SIGNER_ALLOWLIST_MODE or "env").strip().lower()
    require_allowlist = bool(settings.REMOTE_SIGNER_REQUIRE_ALLOWLIST)
    env = (settings.APP_ENV or "production").strip().lower()
    if (settings.REMOTE_SIGNER_BACKEND or "").strip().lower() == "command" and env not in {"dev", "development", "local", "test"}:
        require_allowlist = True

    if mode == "file":
        return FileSignerAllowlist(
            settings.REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH,
            settings.REMOTE_SIGNER_ALLOWLIST_REFRESH_S,
            required=require_allowlist,
        )
    return EnvSignerAllowlist(
        settings.REMOTE_SIGNER_ALLOWED_PUBKEYS,
        required=require_allowlist,
    )

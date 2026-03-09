import json
import os
import time
from pathlib import Path
from threading import Lock
from typing import Any, Dict


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


class JsonlAuditLogger:
    def __init__(self, path: str, component: str):
        self.path = path
        self.component = component
        self._lock = Lock()

    def write(self, event: str, payload: Dict[str, Any]) -> None:
        if not self.path:
            raise ValueError("Audit log path is empty")

        entry = {
            "ts": int(time.time()),
            "component": self.component,
            "event": event,
            **payload,
        }
        line = json.dumps(
            entry,
            sort_keys=True,
            separators=(",", ":"),
            default=_json_default,
        )

        path = Path(self.path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with self._lock:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())

"""Crash-safe writers for generated release and audit evidence."""
from __future__ import annotations

import errno
import os
import tempfile
from pathlib import Path


def atomic_write_text(path: str | Path, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, target)
        try:
            directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError as exc:
            if exc.errno not in (errno.EINVAL, errno.ENOTSUP, errno.ENOSYS):
                raise
        else:
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except Exception:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise

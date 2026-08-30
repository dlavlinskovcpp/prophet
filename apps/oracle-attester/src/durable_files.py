"""Crash-safe filesystem replacement helpers for security-critical artifacts."""
from __future__ import annotations

import errno
import os
import tempfile
from pathlib import Path


def fsync_parent_directory(path: str | Path) -> None:
    directory = Path(path).parent
    try:
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if exc.errno in (errno.EINVAL, errno.ENOTSUP, errno.ENOSYS):
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(path: str | Path, payload: bytes, *, mode: int | None = None) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary_path = Path(temporary)
    try:
        if mode is not None:
            os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, target)
        fsync_parent_directory(target)
    except Exception:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise

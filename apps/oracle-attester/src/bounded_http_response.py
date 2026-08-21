"""Transport-only helpers for bounded HTTP response bodies."""
from __future__ import annotations

import httpx


_READ_CHUNK_BYTES = 64 * 1024


class BoundedHttpResponseError(RuntimeError):
    """Base class for safe, classifiable bounded-response failures."""


class BoundedHttpResponseTooLarge(BoundedHttpResponseError):
    pass


class BoundedHttpResponseHeaderError(BoundedHttpResponseError):
    pass


def read_bounded_response_bytes(response: httpx.Response, *, max_bytes: int) -> bytes:
    """Read at most ``max_bytes`` application-visible response bytes.

    ``httpx.Response.iter_bytes()`` yields decoded/decompressed bytes, so this
    limit protects the exact representation buffered and passed to JSON parsing,
    not merely the compressed transport representation.
    """
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")

    declared = response.headers.get("content-length")
    if declared is not None:
        if not declared.isdigit():
            raise BoundedHttpResponseHeaderError("invalid_content_length")
        if int(declared) > max_bytes:
            raise BoundedHttpResponseTooLarge("response_too_large")

    parts: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes(chunk_size=min(_READ_CHUNK_BYTES, max_bytes + 1)):
        if not chunk:
            continue
        size += len(chunk)
        if size > max_bytes:
            raise BoundedHttpResponseTooLarge("response_too_large")
        parts.append(chunk)
    return b"".join(parts)

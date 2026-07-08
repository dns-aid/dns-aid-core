# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
URL safety validation for DNS-AID.

Prevents SSRF attacks by enforcing HTTPS-only and blocking
requests to private/loopback/link-local IP addresses.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import os
import socket

import structlog

logger = structlog.get_logger(__name__)


class UnsafeURLError(ValueError):
    """Raised when a URL fails safety validation."""


def redact_url_for_log(url: str) -> str:
    """Strip ``user:pass@`` userinfo from a URL before it goes to a log line.

    A defensive complement to :func:`validate_fetch_url` — even though that
    function rejects URLs with userinfo at the input boundary, code paths that
    log the *raw user-supplied* URL (e.g. on the validation-failure branch
    itself) must redact first to avoid leaking credentials to the log stream.
    """
    from urllib.parse import urlparse, urlunparse

    parsed = urlparse(url)
    if not (parsed.username or parsed.password):
        return url
    # netloc is what carries userinfo; rebuild it from hostname (and port if present).
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))


def validate_fetch_url(url: str) -> str:
    """
    Validate that a URL is safe to fetch.

    Enforces:
    - HTTPS scheme only (no http://, file://, etc.)
    - No userinfo (credentials in URL): rejects ``https://user:pass@host`` to prevent
      accidental credential leaks via logs and error messages
    - Resolved IP must not be private, loopback, or link-local
    - Allows override via DNS_AID_FETCH_ALLOWLIST env var

    Args:
        url: The URL to validate.

    Returns:
        The validated URL (unchanged).

    Raises:
        UnsafeURLError: If the URL fails validation.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)

    # Enforce HTTPS
    if parsed.scheme != "https":
        raise UnsafeURLError(f"Only HTTPS URLs are allowed, got scheme '{parsed.scheme}': {url}")

    # Reject ``https://user:pass@host`` — credentials must come via auth handlers,
    # not the URL string. Allowing them here would result in the credentials being
    # logged at every level (DEBUG/WARN) the URL is referenced.
    if parsed.username or parsed.password:
        raise UnsafeURLError(
            "URLs with embedded credentials (userinfo) are not allowed; "
            "use SDKConfig auth fields instead."
        )

    hostname = parsed.hostname
    if not hostname:
        raise UnsafeURLError(f"URL has no hostname: {url}")

    # Check allowlist
    allowlist = _get_allowlist()
    if allowlist and hostname in allowlist:
        logger.debug("URL hostname in allowlist, skipping IP check", hostname=hostname)
        return url

    # Resolve hostname and check IP addresses
    try:
        addrinfos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UnsafeURLError(f"Cannot resolve hostname '{hostname}': {e}") from e

    for _family, _type, _proto, _canonname, sockaddr in addrinfos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise UnsafeURLError(
                f"URL resolves to non-public IP {ip_str} (hostname '{hostname}'): {url}"
            )

    return url


# Per-URL SSRF-validation time budget for the async wrapper. ``validate_fetch_url``
# does a blocking ``socket.getaddrinfo`` with no timeout of its own; bound it so a
# slow/blackholed authoritative server for the target host can't stall a caller.
# Sized with headroom for a resolver that is slow-but-legitimate under concurrent
# load (e.g. an AF_UNSPEC A+AAAA lookup with a slow IPv6 leg).
_DEFAULT_VALIDATE_TIMEOUT = 5.0

# Dedicated thread pool for the (blocking) SSRF DNS resolution. ``asyncio.to_thread``
# shares the event loop's default executor (``min(32, cpu+4)`` workers) with every
# other offloaded call; on a low-core host a wide discovery fan-out queues
# validations behind each other, and that queue wait counts against the timeout
# above — so the last-queued URLs spuriously time out (surfacing as an SSRF block)
# even though they resolve to the same public host as their siblings. A dedicated,
# generously-sized pool removes that cross-call queueing, so the timeout bounds only
# the actual resolution. getaddrinfo is I/O-bound (the thread just waits), so a wide
# pool is cheap. Override the width with ``DNS_AID_SSRF_RESOLVER_THREADS``.
_SSRF_RESOLVER_THREADS = max(1, int(os.environ.get("DNS_AID_SSRF_RESOLVER_THREADS", "32")))
_resolver_pool: concurrent.futures.ThreadPoolExecutor | None = None


def _get_resolver_pool() -> concurrent.futures.ThreadPoolExecutor:
    """Lazily create the process-wide SSRF-resolution thread pool."""
    global _resolver_pool
    if _resolver_pool is None:
        _resolver_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=_SSRF_RESOLVER_THREADS, thread_name_prefix="dns-aid-ssrf"
        )
    return _resolver_pool


async def validate_fetch_url_async(url: str, *, timeout: float = _DEFAULT_VALIDATE_TIMEOUT) -> str:
    """Async, non-loop-blocking wrapper around :func:`validate_fetch_url`.

    ``validate_fetch_url`` performs a blocking ``socket.getaddrinfo`` (the SSRF IP
    check) with no timeout of its own. Called directly from a coroutine it freezes
    the whole event loop for the resolution's duration, serializing any concurrent
    ``asyncio.gather`` fan-out. This offloads the validation to a **dedicated** thread
    pool (not the shared default executor, which would re-serialize a wide fan-out on
    a low-core host) under a bounded timeout, so concurrent validations — to the same
    or different hosts — stay independent and none is spuriously blocked for losing a
    thread-pool slot.

    Raises:
        UnsafeURLError: the URL failed SSRF validation, or resolution exceeded
            ``timeout`` (fail-closed — a slow/blackholed host is treated as unsafe
            rather than fetched).
    """
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_get_resolver_pool(), validate_fetch_url, url), timeout
        )
    except TimeoutError as exc:
        raise UnsafeURLError(f"SSRF validation timed out after {timeout}s: {url}") from exc


class ResponseTooLargeError(ValueError):
    """Raised when a response exceeds the configured size limit."""


async def safe_fetch_bytes(
    url: str,
    *,
    max_bytes: int,
    timeout: float = 10.0,
    follow_redirects: bool = False,
    max_redirects: int = 0,
) -> bytes | None:
    """Fetch a URL with streaming size enforcement.

    Reads the response body in chunks and aborts the connection if the
    cumulative size exceeds *max_bytes*.  This prevents a malicious
    server from forcing an OOM — the oversized payload never fully
    lands in memory.

    ``Content-Length`` is checked first as a fast-path reject, but
    is not trusted (it can be spoofed or absent with chunked encoding).
    The byte-counted stream read is the authoritative guard.

    Returns the raw bytes on success, *None* on HTTP errors (non-200).

    Raises:
        ResponseTooLargeError: If the response exceeds *max_bytes*.
    """
    import httpx

    kwargs: dict = {"timeout": timeout, "follow_redirects": follow_redirects}
    if max_redirects:
        kwargs["max_redirects"] = max_redirects

    async with httpx.AsyncClient(**kwargs) as client, client.stream("GET", url) as resp:
        if resp.status_code != 200:
            return None

        # Fast-path: reject via Content-Length header if present.
        # Not authoritative (can be spoofed/absent) — stream read is.
        cl = resp.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > max_bytes:
            logger.warning(
                "Response Content-Length exceeds limit — aborting",
                url=url,
                content_length=int(cl),
                limit=max_bytes,
            )
            raise ResponseTooLargeError(
                f"Content-Length {cl} exceeds {max_bytes} byte limit: {url}"
            )

        # Stream with byte counting — the real guard.
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes(chunk_size=8192):
            total += len(chunk)
            if total > max_bytes:
                logger.warning(
                    "Response exceeded size limit mid-stream — aborting",
                    url=url,
                    bytes_read=total,
                    limit=max_bytes,
                )
                raise ResponseTooLargeError(
                    f"Response exceeded {max_bytes} byte limit at {total} bytes: {url}"
                )
            chunks.append(chunk)

        return b"".join(chunks)


def _get_allowlist() -> set[str]:
    """Get the fetch allowlist from environment variable."""
    raw = os.environ.get("DNS_AID_FETCH_ALLOWLIST", "")
    if not raw:
        return set()
    return {h.strip().lower() for h in raw.split(",") if h.strip()}

from __future__ import annotations

import ipaddress
import socket
import time
from collections import defaultdict, deque
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.config import get_settings
from app.core.exceptions import SSRFProtectionError
from app.utils.validators import normalize_domain_or_url

# In-memory sliding-window rate limiter keyed by hostname
_TARGET_REQUEST_LOG: dict[str, deque[float]] = defaultdict(deque)


def is_public_ip(ip_str: str) -> bool:
    ip_obj = ipaddress.ip_address(ip_str)
    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return False
    # Block Carrier-Grade NAT 100.64.0.0/10
    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


def resolve_and_validate_host(hostname: str) -> list[str]:
    """Resolve DNS for hostname and reject any private/internal IP (DNS rebinding & SSRF guard)."""
    settings = get_settings()
    try:
        addr_info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFProtectionError(f"DNS resolution failed for {hostname}: {exc}") from exc

    ips = sorted({entry[4][0] for entry in addr_info if entry and entry[4]})
    if not ips:
        raise SSRFProtectionError(f"No IP addresses resolved for {hostname}.")

    if not settings.ALLOW_LOCALHOST_SCANNING:
        for ip_addr in ips:
            if not is_public_ip(ip_addr):
                raise SSRFProtectionError(
                    f"Blocked non-public IP address {ip_addr} resolved for {hostname}."
                )
    return ips


def enforce_rate_limit(hostname: str) -> None:
    settings = get_settings()
    limit = settings.SCAN_RATE_LIMIT_PER_MINUTE
    now = time.monotonic()
    window = _TARGET_REQUEST_LOG[hostname]
    while window and (now - window[0]) > 60.0:
        window.popleft()
    if len(window) >= limit:
        raise SSRFProtectionError(f"Rate limit exceeded for target {hostname} ({limit} req/min).")
    window.append(now)


def validate_url_in_scope(url: str, allowed_domain: str, allowed_paths: list[str] | None = None) -> None:
    hostname, _ = normalize_domain_or_url(url)
    if hostname != allowed_domain and not hostname.endswith(f".{allowed_domain}"):
        raise SSRFProtectionError(f"Redirect/request host {hostname} leaves authorized scope {allowed_domain}.")
    if allowed_paths:
        path = urlparse(url).path or "/"
        if not any(path.startswith(p) for p in allowed_paths):
            raise SSRFProtectionError(f"Path {path} is outside authorized target paths.")
    resolve_and_validate_host(hostname)


def safe_fetch(
    url: str,
    allowed_domain: str,
    allowed_paths: list[str] | None = None,
    method: str = "GET",
    extra_headers: Optional[dict[str, str]] = None,
) -> httpx.Response:
    """Fetch a URL safely with DNS rebinding checks, manual redirect validation, and rate limits."""
    settings = get_settings()
    current_url = url
    headers = {
        "User-Agent": "WebGuardAI-SecurityScanner/1.0 (Authorized Non-Destructive Assessment)",
        **(extra_headers or {}),
    }

    with httpx.Client(
        timeout=settings.SCAN_HTTP_TIMEOUT_SECONDS,
        follow_redirects=False,
        verify=True,
    ) as client:
        for _ in range(settings.SCAN_MAX_REDIRECTS + 1):
            validate_url_in_scope(current_url, allowed_domain, allowed_paths)
            enforce_rate_limit(allowed_domain)
            resp = client.request(method, current_url, headers=headers)
            if resp.is_redirect and resp.headers.get("location"):
                next_url = urljoin(current_url, resp.headers["location"])
                validate_url_in_scope(next_url, allowed_domain, allowed_paths)
                current_url = next_url
                continue
            return resp

    raise SSRFProtectionError(f"Exceeded maximum redirects ({settings.SCAN_MAX_REDIRECTS}) for {url}.")

"""URL helpers shared by the rules and the fetcher."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def is_loopback(hostname: str | None) -> bool:
    if hostname is None:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def is_loopback_url(url: str) -> bool:
    return is_loopback(urlsplit(url).hostname)


def is_secure_url(url: str, *, allow_loopback_http: bool = True) -> bool:
    """HTTPS, or plain HTTP to a loopback development host when that is allowed."""
    parsed = urlsplit(url)
    if parsed.scheme == "https":
        return True
    return allow_loopback_http and parsed.scheme == "http" and is_loopback(parsed.hostname)

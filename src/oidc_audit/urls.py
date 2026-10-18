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


def is_secure_url(url: str) -> bool:
    """HTTPS, or plain HTTP to a loopback development host."""
    parsed = urlsplit(url)
    return parsed.scheme == "https" or (parsed.scheme == "http" and is_loopback(parsed.hostname))

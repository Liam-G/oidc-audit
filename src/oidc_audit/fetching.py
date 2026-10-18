"""Bounded, GET-only fetching for issuer metadata and public keys."""

from __future__ import annotations

import http.client
import json
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

from .loaders import ConfigurationError
from .urls import is_loopback, is_secure_url

MAX_RESPONSE_SIZE = 2 * 1024 * 1024
MAX_REDIRECTS = 3


@dataclass(frozen=True)
class IssuerDocuments:
    issuer: str
    discovery_url: str
    discovery: dict[str, Any]
    jwks_url: str | None
    jwks: dict[str, Any] | None


def _validate_url(url: str, *, issuer: bool = False) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError("URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ConfigurationError("URL must not contain credentials or a fragment")
    if issuer and parsed.query:
        raise ConfigurationError("issuer URL must not contain a query")
    if parsed.scheme == "http" and not is_loopback(parsed.hostname):
        raise ConfigurationError("plain HTTP fetching is limited to loopback issuers")
    return url


def _request_once(url: str, timeout: float) -> tuple[int, dict[str, str], bytes]:
    parsed = urlsplit(url)
    host = parsed.hostname
    assert host is not None
    port = parsed.port
    if parsed.scheme == "https":
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            host, port=port, timeout=timeout, context=ssl.create_default_context()
        )
    else:
        connection = http.client.HTTPConnection(host, port=port, timeout=timeout)
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    try:
        connection.request(
            "GET",
            target,
            headers={
                "Accept": "application/json",
                "User-Agent": "oidc-audit/0.2 (+read-only-metadata-fetch)",
            },
        )
        response = connection.getresponse()
        headers = {name.lower(): value for name, value in response.getheaders()}
        declared = headers.get("content-length")
        if declared is not None and int(declared) > MAX_RESPONSE_SIZE:
            raise ConfigurationError(f"remote response is larger than {MAX_RESPONSE_SIZE} bytes")
        body = response.read(MAX_RESPONSE_SIZE + 1)
        if len(body) > MAX_RESPONSE_SIZE:
            raise ConfigurationError(f"remote response is larger than {MAX_RESPONSE_SIZE} bytes")
        return response.status, headers, body
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise ConfigurationError(f"unable to fetch {url}: {exc}") from exc
    finally:
        connection.close()


def fetch_json(url: str, *, timeout: float = 10.0) -> tuple[str, dict[str, Any]]:
    current = _validate_url(url)
    for redirect_count in range(MAX_REDIRECTS + 1):
        status, headers, body = _request_once(current, timeout)
        if status in {301, 302, 303, 307, 308}:
            location = headers.get("location")
            if location is None:
                raise ConfigurationError(f"redirect from {current} has no Location header")
            if redirect_count == MAX_REDIRECTS:
                raise ConfigurationError(f"too many redirects while fetching {url}")
            redirected = _validate_url(urljoin(current, location))
            if urlsplit(current).scheme == "https" and urlsplit(redirected).scheme != "https":
                raise ConfigurationError("HTTPS fetch must not redirect to plain HTTP")
            current = redirected
            continue
        if status != 200:
            raise ConfigurationError(f"GET {current} returned HTTP {status}")
        try:
            document = json.loads(body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ConfigurationError(f"invalid JSON returned by {current}: {exc}") from exc
        if not isinstance(document, dict):
            raise ConfigurationError(f"top-level JSON value from {current} must be an object")
        return current, document
    raise AssertionError("redirect loop must return or raise")


def fetch_issuer(issuer: str, *, timeout: float = 10.0) -> IssuerDocuments:
    _validate_url(issuer, issuer=True)
    discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    final_discovery_url, discovery = fetch_json(discovery_url, timeout=timeout)
    raw_jwks_url = discovery.get("jwks_uri")
    if not isinstance(raw_jwks_url, str):
        return IssuerDocuments(issuer, final_discovery_url, discovery, None, None)
    if not is_secure_url(raw_jwks_url):
        return IssuerDocuments(issuer, final_discovery_url, discovery, raw_jwks_url, None)
    final_jwks_url, jwks = fetch_json(raw_jwks_url, timeout=timeout)
    return IssuerDocuments(issuer, final_discovery_url, discovery, final_jwks_url, jwks)

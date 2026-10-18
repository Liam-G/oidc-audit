"""Keycloak realm-export client checks."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from ..catalog import RULES
from ..models import Finding
from ..urls import is_loopback

KEYCLOAK_BUILTIN_CLIENT_IDS = frozenset(
    {
        "account",
        "account-console",
        "admin-cli",
        "broker",
        "realm-management",
        "security-admin-console",
    }
)


def _is_production(realm: dict[str, Any]) -> bool:
    attributes = realm.get("attributes", {})
    marker = attributes.get("environment") if isinstance(attributes, dict) else None
    return isinstance(marker, str) and marker.lower() in {"prod", "production"}


def _resolve_redirect(redirect: str, root_url: Any) -> str:
    """Keycloak resolves a relative redirect URI against the client's root URL;
    without an absolute one it stays on Keycloak's own origin."""
    parsed = urlsplit(redirect)
    if parsed.scheme or parsed.netloc or not isinstance(root_url, str):
        return redirect
    if urlsplit(root_url).scheme not in {"http", "https"}:
        return redirect
    return root_url.rstrip("/") + "/" + redirect.lstrip("/")


def _integer(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def audit_keycloak(
    realm: dict[str, Any],
    source: str,
    max_access_token_lifetime: int = 900,
    *,
    include_builtin_clients: bool = False,
) -> list[Finding]:
    clients = realm.get("clients")
    if not isinstance(clients, list):
        return []
    findings: list[Finding] = []
    production = _is_production(realm)
    realm_lifetime = _integer(realm.get("accessTokenLifespan"), 300)
    rotate_refresh = realm.get("revokeRefreshToken") is True
    for index, raw_client in enumerate(clients):
        if not isinstance(raw_client, dict):
            continue
        client: dict[str, Any] = raw_client
        if not include_builtin_clients and client.get("clientId") in KEYCLOAK_BUILTIN_CLIENT_IDS:
            continue
        path = f"$.clients[{index}]"
        raw_client_id = client.get("clientId")
        client_identity = raw_client_id if isinstance(raw_client_id, str) else f"index:{index}"
        attributes = client.get("attributes", {})
        if not isinstance(attributes, dict):
            attributes = {}
        redirects = client.get("redirectUris", [])
        if isinstance(redirects, list):
            for redirect_index, redirect in enumerate(redirects):
                if not isinstance(redirect, str):
                    continue
                redirect_path = f"{path}.redirectUris[{redirect_index}]"
                parsed = urlsplit(_resolve_redirect(redirect, client.get("rootUrl")))
                if "*" in redirect:
                    findings.append(
                        Finding(
                            RULES["OIDC-CLIENT-001"],
                            source,
                            redirect_path,
                            identity=f"{client_identity}:redirect:{redirect}",
                        )
                    )
                loopback = is_loopback(parsed.hostname)
                if parsed.scheme == "http" and not loopback:
                    findings.append(
                        Finding(
                            RULES["OIDC-CLIENT-002"],
                            source,
                            redirect_path,
                            identity=f"{client_identity}:redirect:{redirect}",
                        )
                    )
                if production and loopback:
                    findings.append(
                        Finding(
                            RULES["OIDC-CLIENT-003"],
                            source,
                            redirect_path,
                            identity=f"{client_identity}:redirect:{redirect}",
                        )
                    )
        public = client.get("publicClient") is True
        browser_flow = client.get("standardFlowEnabled", True) is True
        if public and browser_flow and attributes.get("pkce.code.challenge.method") != "S256":
            findings.append(
                Finding(
                    RULES["OIDC-CLIENT-004"],
                    source,
                    f"{path}.attributes.pkce.code.challenge.method",
                    identity=client_identity,
                )
            )
        if client.get("implicitFlowEnabled") is True:
            findings.append(
                Finding(
                    RULES["OIDC-CLIENT-005"],
                    source,
                    f"{path}.implicitFlowEnabled",
                    identity=client_identity,
                )
            )
        if client.get("directAccessGrantsEnabled") is True:
            findings.append(
                Finding(
                    RULES["OIDC-CLIENT-006"],
                    source,
                    f"{path}.directAccessGrantsEnabled",
                    identity=client_identity,
                )
            )
        lifetime = _integer(attributes.get("access.token.lifespan"), realm_lifetime)
        if lifetime > max_access_token_lifetime:
            findings.append(
                Finding(
                    RULES["OIDC-CLIENT-007"],
                    source,
                    f"{path}.attributes.access.token.lifespan",
                    f"Effective access-token lifetime is {lifetime} seconds; "
                    f"configured maximum is {max_access_token_lifetime} seconds.",
                    identity=client_identity,
                )
            )
        offline_access = client.get("defaultClientScopes", [])
        can_refresh = browser_flow or (
            isinstance(offline_access, list) and "offline_access" in offline_access
        )
        if public and can_refresh and not rotate_refresh:
            findings.append(
                Finding(RULES["OIDC-CLIENT-008"], source, path, identity=client_identity)
            )
        secret = client.get("secret")
        # Admin-console partial exports replace secrets with asterisks.
        if isinstance(secret, str) and secret.strip("*"):
            findings.append(
                Finding(
                    RULES["OIDC-CLIENT-009"],
                    source,
                    f"{path}.secret",
                    identity=client_identity,
                )
            )
    return findings

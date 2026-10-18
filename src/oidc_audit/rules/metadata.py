"""Authorization-server and OpenID Provider metadata checks."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from ..catalog import RULES
from ..models import Finding
from ..urls import is_secure_url

ENDPOINT_FIELDS = (
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "registration_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "end_session_endpoint",
    "pushed_authorization_request_endpoint",
    "device_authorization_endpoint",
)

KEYCLOAK_ISSUER_PATH = re.compile(r"/realms/[^/]+/?$")


def _is_keycloak(document: dict[str, Any]) -> bool:
    """Keycloak advertises every grant and response type it supports realm-wide,
    whatever individual clients allow, so those two rules only mean something
    once the realm export is audited."""
    issuer = document.get("issuer")
    return isinstance(issuer, str) and bool(KEYCLOAK_ISSUER_PATH.search(urlsplit(issuer).path))


def audit_metadata(
    document: dict[str, Any], source: str, expected_issuer: str | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    issuer = document.get("issuer")
    if expected_issuer is not None and issuer != expected_issuer:
        findings.append(Finding(RULES["OIDC-META-001"], source, "$.issuer"))

    for field in ENDPOINT_FIELDS:
        value = document.get(field)
        if isinstance(value, str) and not is_secure_url(value):
            findings.append(
                Finding(
                    RULES["OIDC-META-002"], source, f"$.{field}", f"{field} does not use HTTPS."
                )
            )

    keycloak = _is_keycloak(document)
    response_types = document.get("response_types_supported", [])
    if isinstance(response_types, list) and any(
        isinstance(item, str) and "token" in item.split() for item in response_types
    ):
        rule_id = "OIDC-META-010" if keycloak else "OIDC-META-003"
        findings.append(Finding(RULES[rule_id], source, "$.response_types_supported"))

    grants = document.get("grant_types_supported", [])
    if isinstance(grants, list) and "password" in grants:
        rule_id = "OIDC-META-011" if keycloak else "OIDC-META-004"
        findings.append(Finding(RULES[rule_id], source, "$.grant_types_supported"))

    pkce = document.get("code_challenge_methods_supported")
    if not isinstance(pkce, list) or "S256" not in pkce:
        findings.append(
            Finding(RULES["OIDC-META-005"], source, "$.code_challenge_methods_supported")
        )

    algorithms = document.get("id_token_signing_alg_values_supported", [])
    if isinstance(algorithms, list):
        string_algorithms = [item for item in algorithms if isinstance(item, str)]
        if "none" in string_algorithms:
            findings.append(
                Finding(RULES["OIDC-META-006"], source, "$.id_token_signing_alg_values_supported")
            )
        signed_algorithms = [item for item in string_algorithms if item != "none"]
        if signed_algorithms and all(item.startswith("HS") for item in signed_algorithms):
            findings.append(
                Finding(RULES["OIDC-META-007"], source, "$.id_token_signing_alg_values_supported")
            )

    if not document.get("pushed_authorization_request_endpoint"):
        findings.append(
            Finding(RULES["OIDC-META-008"], source, "$.pushed_authorization_request_endpoint")
        )

    jwks_uri = document.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not is_secure_url(jwks_uri):
        findings.append(Finding(RULES["OIDC-META-009"], source, "$.jwks_uri"))
    return findings

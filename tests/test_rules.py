from __future__ import annotations

import json
from pathlib import Path

import pytest

from oidc_audit.rules.clients import audit_keycloak
from oidc_audit.rules.keys import audit_jwks
from oidc_audit.rules.metadata import audit_metadata

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
EXAMPLES = ROOT / "examples"


def load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def ids(findings: object) -> set[str]:
    return {finding.rule.id for finding in findings}  # type: ignore[union-attr]


def test_bad_discovery_exercises_every_metadata_rule() -> None:
    findings = audit_metadata(
        load(FIXTURES / "bad-discovery.json"),
        "bad-discovery.json",
        "https://login.example.test/realms/bad",
    )
    assert ids(findings) == {f"OIDC-META-{number:03}" for number in range(1, 10)}
    assert sum(item.rule.id == "OIDC-META-002" for item in findings) == 1


def test_good_discovery_is_clean() -> None:
    findings = audit_metadata(
        load(FIXTURES / "good-discovery.json"),
        "good-discovery.json",
        "https://login.example.test/realms/good",
    )
    assert findings == []


def test_bad_jwks_exercises_every_key_rule() -> None:
    findings = audit_jwks(load(FIXTURES / "bad-jwks.json"), "bad-jwks.json")
    assert ids(findings) == {f"OIDC-KEY-{number:03}" for number in range(1, 9)}
    assert sum(item.rule.id == "OIDC-KEY-006" for item in findings) == 2


def test_good_jwks_is_clean() -> None:
    assert audit_jwks(load(FIXTURES / "good-jwks.json"), "good-jwks.json") == []


def test_bad_realm_exercises_every_client_rule_without_secret_values() -> None:
    realm = load(EXAMPLES / "bad-realm.json")
    findings = audit_keycloak(realm, "bad-realm.json")
    assert ids(findings) == {f"OIDC-CLIENT-{number:03}" for number in range(1, 10)}
    assert "deliberately-redacted" not in repr(findings)


def test_good_realm_is_false_positive_gate() -> None:
    assert audit_keycloak(load(EXAMPLES / "good-realm.json"), "good-realm.json") == []


def test_fresh_keycloak_export_is_clean_by_default() -> None:
    realm = load(FIXTURES / "keycloak-26-fresh.json")
    assert audit_keycloak(realm, "keycloak-26-fresh.json") == []
    assert audit_keycloak(realm, "keycloak-26-fresh.json", include_builtin_clients=True)


def confidential_client(**fields: object) -> dict[str, object]:
    return {"clientId": "custom-client", "publicClient": False, **fields}


@pytest.mark.parametrize(
    "redirect",
    [
        "*",
        "/*",
        "/realms/example/account/*",
        "//external.example.test/*",
        "https://app.example.test/*",
    ],
)
def test_every_wildcard_redirect_is_reported(redirect: str) -> None:
    realm = {
        "clients": [
            confidential_client(rootUrl="https://app.example.test", redirectUris=[redirect])
        ]
    }
    assert ids(audit_keycloak(realm, "wildcard.json")) == {"OIDC-CLIENT-001"}


def test_masked_secret_is_not_secret_material() -> None:
    realm = {"clients": [{**confidential_client(), "secret": "**********"}]}
    assert audit_keycloak(realm, "masked.json") == []
    realm = {"clients": [{**confidential_client(), "secret": "real-value"}]}
    assert ids(audit_keycloak(realm, "unmasked.json")) == {"OIDC-CLIENT-009"}


def test_pkce_applies_only_to_browser_flow_clients() -> None:
    client = {"clientId": "cli-tool", "publicClient": True, "standardFlowEnabled": False}
    realm = {"revokeRefreshToken": True, "clients": [client]}
    assert audit_keycloak(realm, "cli.json") == []
    client["standardFlowEnabled"] = True
    assert ids(audit_keycloak(realm, "browser.json")) == {"OIDC-CLIENT-004"}


def test_keycloak_metadata_reports_realm_wide_capabilities_as_info() -> None:
    document = load(FIXTURES / "good-discovery.json")
    document["response_types_supported"] = ["code", "id_token token"]
    document["grant_types_supported"] = ["authorization_code", "password"]
    findings = audit_metadata(document, "keycloak.json")
    assert ids(findings) == {"OIDC-META-010", "OIDC-META-011"}
    assert all(str(item.rule.severity) == "info" for item in findings)
    document["issuer"] = "https://login.example.test/oauth2"
    assert ids(audit_metadata(document, "generic.json")) == {"OIDC-META-003", "OIDC-META-004"}


def test_loopback_http_jwks_uri_is_accepted_like_other_endpoints() -> None:
    document = load(FIXTURES / "good-discovery.json")
    document["jwks_uri"] = "http://127.0.0.1:8080/realms/good/protocol/openid-connect/certs"
    assert audit_metadata(document, "lab.json") == []
    document["jwks_uri"] = "http://login.example.test/certs"
    assert ids(audit_metadata(document, "remote.json")) == {"OIDC-META-009"}


def test_rule_functions_ignore_unrelated_shapes() -> None:
    assert audit_jwks({}, "empty") == []
    assert audit_jwks({"keys": [None]}, "empty") == []
    assert audit_keycloak({}, "empty") == []
    assert audit_keycloak({"clients": [None]}, "empty") == []
    assert audit_metadata({"authorization_endpoint": 42}, "partial")

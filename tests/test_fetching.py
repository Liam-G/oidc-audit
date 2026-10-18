from __future__ import annotations

import json
from typing import Any

import pytest

from oidc_audit import fetching
from oidc_audit.loaders import ConfigurationError


def test_fetch_json_follows_bounded_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = iter(
        [
            (302, {"location": "/metadata"}, b""),
            (200, {"content-type": "application/json"}, b'{"issuer":"https://id.test"}'),
        ]
    )
    calls: list[tuple[str, float]] = []

    def fake_request(url: str, timeout: float) -> tuple[int, dict[str, str], bytes]:
        calls.append((url, timeout))
        return next(responses)

    monkeypatch.setattr(fetching, "_request_once", fake_request)
    final_url, document = fetching.fetch_json("https://id.test/start", timeout=4.0)
    assert final_url == "https://id.test/metadata"
    assert document == {"issuer": "https://id.test"}
    assert calls == [("https://id.test/start", 4.0), ("https://id.test/metadata", 4.0)]


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("ftp://id.test/config", "absolute HTTP"),
        ("https://user:pass@id.test/config", "credentials"),
        ("http://id.test/config", "plain HTTP"),
    ],
)
def test_fetch_json_rejects_unsafe_urls(url: str, message: str) -> None:
    with pytest.raises(ConfigurationError, match=message):
        fetching.fetch_json(url)


def test_loopback_http_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        fetching,
        "_request_once",
        lambda url, timeout: (200, {}, b"{}"),
    )
    assert fetching.fetch_json("http://127.0.0.1:8080/config")[1] == {}
    assert fetching.fetch_json("http://localhost:8080/config")[1] == {}


@pytest.mark.parametrize(
    ("response", "message"),
    [
        ((404, {}, b"{}"), "HTTP 404"),
        ((302, {}, b""), "no Location"),
        ((200, {}, b"not-json"), "invalid JSON"),
        ((200, {}, b"[]"), "must be an object"),
    ],
)
def test_fetch_json_reports_bad_responses(
    monkeypatch: pytest.MonkeyPatch,
    response: tuple[int, dict[str, str], bytes],
    message: str,
) -> None:
    monkeypatch.setattr(fetching, "_request_once", lambda url, timeout: response)
    with pytest.raises(ConfigurationError, match=message):
        fetching.fetch_json("https://id.test/config")


def test_fetch_json_rejects_too_many_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        fetching,
        "_request_once",
        lambda url, timeout: (302, {"location": "/again"}, b""),
    )
    with pytest.raises(ConfigurationError, match="too many redirects"):
        fetching.fetch_json("https://id.test/start")


def test_fetch_json_rejects_https_downgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        fetching,
        "_request_once",
        lambda url, timeout: (302, {"location": "http://localhost/config"}, b""),
    )
    with pytest.raises(ConfigurationError, match="must not redirect"):
        fetching.fetch_json("https://id.test/start")


def test_fetch_issuer_gets_discovery_then_jwks(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_fetch(url: str, *, timeout: float) -> tuple[str, dict[str, Any]]:
        calls.append(url)
        if url.endswith("openid-configuration"):
            return url, {"issuer": "https://id.test/realm", "jwks_uri": "https://keys.test/jwks"}
        return url, {"keys": []}

    monkeypatch.setattr(fetching, "fetch_json", fake_fetch)
    documents = fetching.fetch_issuer("https://id.test/realm", timeout=3.0)
    assert documents.jwks == {"keys": []}
    assert calls == [
        "https://id.test/realm/.well-known/openid-configuration",
        "https://keys.test/jwks",
    ]


def test_fetch_issuer_does_not_fetch_missing_or_insecure_jwks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    documents = [
        {"issuer": "https://id.test"},
        {"issuer": "https://id.test", "jwks_uri": "http://keys.test/jwks"},
    ]

    def fake_fetch(url: str, *, timeout: float) -> tuple[str, dict[str, Any]]:
        return url, documents.pop(0)

    monkeypatch.setattr(fetching, "fetch_json", fake_fetch)
    assert fetching.fetch_issuer("https://id.test").jwks_url is None
    insecure = fetching.fetch_issuer("https://id.test")
    assert insecure.jwks_url == "http://keys.test/jwks"
    assert insecure.jwks is None


def test_issuer_rejects_query_or_fragment() -> None:
    for issuer in ("https://id.test?tenant=x", "https://id.test#fragment"):
        with pytest.raises(ConfigurationError):
            fetching.fetch_issuer(issuer)


def test_loopback_issuer_fetches_its_http_jwks(monkeypatch: pytest.MonkeyPatch) -> None:
    issuer = "http://127.0.0.1:8080/realms/good-realm"
    jwks_uri = f"{issuer}/protocol/openid-connect/certs"
    responses = {
        f"{issuer}/.well-known/openid-configuration": {"issuer": issuer, "jwks_uri": jwks_uri},
        jwks_uri: {"keys": []},
    }
    monkeypatch.setattr(
        fetching,
        "_request_once",
        lambda url, timeout: (200, {}, json.dumps(responses[url]).encode()),
    )
    documents = fetching.fetch_issuer(issuer)
    assert documents.jwks_url == jwks_uri
    assert documents.jwks == {"keys": []}

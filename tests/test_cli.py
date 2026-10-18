from __future__ import annotations

import json
import re
from pathlib import Path

from oidc_audit import cli
from oidc_audit.fetching import IssuerDocuments

ROOT = Path(__file__).parents[1]


def test_bad_realm_end_to_end_json(capsys: object) -> None:
    result = cli.run(
        ["lint", "--keycloak", str(ROOT / "examples" / "bad-realm.json"), "--format", "json"]
    )
    assert result == 2
    output = json.loads(capsys.readouterr().out)  # type: ignore[union-attr]
    assert output["summary"]["findings"] >= 9
    assert "deliberately-redacted-by-oidc-audit" not in json.dumps(output)


def test_good_realm_end_to_end_is_clean(capsys: object) -> None:
    result = cli.run(["lint", "--keycloak", str(ROOT / "examples" / "good-realm.json")])
    assert result == 0
    assert "findings: 0" in capsys.readouterr().out  # type: ignore[union-attr]


def test_all_inputs_sarif_and_output_file(tmp_path: Path) -> None:
    output = tmp_path / "report.sarif"
    result = cli.run(
        [
            "lint",
            "--discovery",
            str(ROOT / "tests" / "fixtures" / "bad-discovery.json"),
            "--expected-issuer",
            "https://login.example.test/realms/bad",
            "--jwks",
            str(ROOT / "tests" / "fixtures" / "bad-jwks.json"),
            "--keycloak",
            str(ROOT / "examples" / "bad-realm.json"),
            "--format",
            "sarif",
            "--output",
            str(output),
        ]
    )
    document = json.loads(output.read_text(encoding="utf-8"))
    assert result == 2
    assert document["version"] == "2.1.0"
    assert len(document["runs"][0]["results"]) >= 26


def test_filter_disable_and_rules(capsys: object) -> None:
    bad_realm = str(ROOT / "examples" / "bad-realm.json")
    assert cli.run(["lint", "--keycloak", bad_realm, "--min-severity", "critical"]) == 2
    output = capsys.readouterr().out  # type: ignore[union-attr]
    assert "OIDC-CLIENT-001" in output
    assert "OIDC-CLIENT-004" not in output
    assert (
        cli.run(
            [
                "lint",
                "--keycloak",
                bad_realm,
                "--disable",
                "OIDC-CLIENT-001",
                "--min-severity",
                "critical",
            ]
        )
        == 0
    )
    capsys.readouterr()  # type: ignore[union-attr]
    assert cli.run(["rules"]) == 0
    assert "RFC9700" in capsys.readouterr().out  # type: ignore[union-attr]


def test_keycloak_builtins_can_be_included(capsys: object) -> None:
    fresh = str(ROOT / "tests" / "fixtures" / "keycloak-26-fresh.json")
    assert cli.run(["lint", "--keycloak", fresh]) == 0
    capsys.readouterr()  # type: ignore[union-attr]
    assert cli.run(["lint", "--keycloak", fresh, "--include-keycloak-builtins"]) == 2
    assert "OIDC-CLIENT" in capsys.readouterr().out  # type: ignore[union-attr]


def test_issuer_mode_audits_fetched_documents(monkeypatch: object, capsys: object) -> None:
    discovery = json.loads(
        (ROOT / "tests" / "fixtures" / "bad-discovery.json").read_text(encoding="utf-8")
    )
    jwks = json.loads((ROOT / "tests" / "fixtures" / "good-jwks.json").read_text(encoding="utf-8"))

    def fake_fetch(issuer: str, *, timeout: float) -> IssuerDocuments:
        assert issuer == "https://login.example.test/realms/bad"
        assert timeout == 1.5
        return IssuerDocuments(
            issuer,
            f"{issuer}/.well-known/openid-configuration",
            discovery,
            "https://login.example.test/jwks",
            jwks,
        )

    monkeypatch.setattr(cli, "fetch_issuer", fake_fetch)  # type: ignore[union-attr]
    assert (
        cli.run(
            [
                "lint",
                "--issuer",
                "https://login.example.test/realms/bad",
                "--timeout",
                "1.5",
                "--format",
                "json",
            ]
        )
        == 2
    )
    report = json.loads(capsys.readouterr().out)  # type: ignore[union-attr]
    assert report["mode"] == "lint"
    assert report["summary"]["inputs"] == 2


def test_configuration_errors(capsys: object, tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("[]", encoding="utf-8")
    cases = [
        ["lint"],
        ["lint", "--keycloak", str(invalid)],
        [
            "lint",
            "--issuer",
            "https://id.test",
            "--discovery",
            str(ROOT / "tests" / "fixtures" / "good-discovery.json"),
        ],
        ["lint", "--issuer", "https://id.test", "--expected-issuer", "https://id.test"],
        ["lint", "--issuer", "https://id.test", "--timeout", "0"],
        ["lint", "--keycloak", str(ROOT / "examples" / "good-realm.json"), "--disable", "NOPE"],
        [
            "lint",
            "--keycloak",
            str(ROOT / "examples" / "good-realm.json"),
            "--max-access-token-lifetime",
            "0",
        ],
    ]
    for arguments in cases:
        assert cli.run(arguments) == 1
    assert "oidc-audit: error:" in capsys.readouterr().err  # type: ignore[union-attr]


def test_fail_on_threshold_controls_exit_status(tmp_path: Path, capsys: object) -> None:
    discovery = json.loads(
        (ROOT / "tests" / "fixtures" / "good-discovery.json").read_text(encoding="utf-8")
    )
    del discovery["pushed_authorization_request_endpoint"]
    path = tmp_path / "info-only.json"
    path.write_text(json.dumps(discovery), encoding="utf-8")
    assert cli.run(["lint", "--discovery", str(path)]) == 0
    assert "OIDC-META-008" in capsys.readouterr().out  # type: ignore[union-attr]
    assert cli.run(["lint", "--discovery", str(path), "--fail-on", "info"]) == 2
    config = tmp_path / "policy.toml"
    config.write_text('[oidc-audit]\nfail-on = "info"\n', encoding="utf-8")
    assert cli.run(["lint", "--discovery", str(path), "--config", str(config)]) == 2
    config.write_text('[oidc-audit]\nfail-on = "severe"\n', encoding="utf-8")
    assert cli.run(["lint", "--discovery", str(path), "--config", str(config)]) == 1


def test_lab_import_files_match_keycloak_naming_rule() -> None:
    compose = (ROOT / "examples" / "docker-compose.yml").read_text(encoding="utf-8")
    mounts = re.findall(r"- \./(\S+\.json):/opt/keycloak/data/import/(\S+\.json):ro", compose)
    assert len(mounts) == 2
    for source, target in mounts:
        realm = json.loads((ROOT / "examples" / source).read_text(encoding="utf-8"))["realm"]
        assert target == f"{realm}-realm.json"

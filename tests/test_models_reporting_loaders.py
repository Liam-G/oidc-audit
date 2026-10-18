from __future__ import annotations

import json
from pathlib import Path

import pytest

from oidc_audit.catalog import RULES
from oidc_audit.loaders import ConfigurationError, load_json_object
from oidc_audit.models import AuditReport, Finding, Severity
from oidc_audit.reporting import SARIF_SECURITY_SEVERITY, render_report


def test_severity_and_models() -> None:
    assert Severity.parse("HIGH") is Severity.HIGH
    assert str(Severity.INFO) == "info"
    with pytest.raises(ValueError):
        Severity.parse("unknown")
    finding = Finding(RULES["OIDC-META-008"], "input.json", "$.par")
    report = AuditReport.create([finding], ["input.json"])
    assert report.as_dict()["summary"]["info"] == 1
    assert finding.rule.as_dict()["severity"] == "info"
    assert finding.as_dict()["rule_id"] == "OIDC-META-008"


def test_renderers_are_valid_and_secret_free() -> None:
    findings = [
        Finding(RULES["OIDC-KEY-001"], "keys.json", "$.keys[0]"),
        Finding(RULES["OIDC-META-008"], "metadata.json", "$.par", "Custom safe message"),
    ]
    report = AuditReport.create(findings, ["keys.json", "metadata.json"])
    text = render_report(report, "text")
    raw_json = render_report(report, "json")
    sarif = render_report(report, "sarif")
    assert "RFC7517" in text
    assert json.loads(raw_json)["summary"]["findings"] == 2
    sarif_run = json.loads(sarif)["runs"][0]
    levels = {result["level"] for result in sarif_run["results"]}
    assert levels == {"error", "note"}
    severities = {
        rule["id"]: rule["properties"]["security-severity"]
        for rule in sarif_run["tool"]["driver"]["rules"]
    }
    assert severities == {"OIDC-KEY-001": "9.1", "OIDC-META-008": "0.0"}
    assert all(float(value) >= 0 for value in severities.values())


def test_sarif_security_severity_uses_numeric_scores() -> None:
    assert SARIF_SECURITY_SEVERITY == {
        Severity.CRITICAL: "9.1",
        Severity.HIGH: "7.0",
        Severity.MEDIUM: "4.0",
        Severity.LOW: "1.0",
        Severity.INFO: "0.0",
    }


def test_loader_rejects_bad_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    valid = tmp_path / "valid.json"
    valid.write_text('{"ok": true}', encoding="utf-8")
    assert load_json_object(valid) == {"ok": True}
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_json_object(broken)
    with pytest.raises(ConfigurationError):
        load_json_object(tmp_path / "missing.json")
    monkeypatch.setattr(
        Path, "stat", lambda self: type("Stat", (), {"st_size": 11 * 1024 * 1024})()
    )
    with pytest.raises(ConfigurationError):
        load_json_object(valid)

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oidc_audit import cli
from oidc_audit.catalog import RULES
from oidc_audit.config import load_config
from oidc_audit.diffing import regressions
from oidc_audit.loaders import ConfigurationError
from oidc_audit.models import Finding

ROOT = Path(__file__).parents[1]


def test_load_config_and_cli_override(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "oidc-audit.toml"
    config.write_text(
        """
[oidc-audit]
format = "json"
min-severity = "high"
disable = ["OIDC-CLIENT-001"]
max-access-token-lifetime = 7200
include-keycloak-builtins = false
timeout = 2.5
""".strip(),
        encoding="utf-8",
    )
    loaded = load_config(config)
    assert loaded.timeout == 2.5
    bad = str(ROOT / "examples" / "bad-realm.json")
    assert cli.run(["lint", "--keycloak", bad, "--config", str(config)]) == 2
    report = json.loads(capsys.readouterr().out)
    assert "OIDC-CLIENT-001" not in {item["rule_id"] for item in report["findings"]}
    assert cli.run(["lint", "--keycloak", bad, "--config", str(config), "--format", "text"]) == 2
    assert "oidc-audit lint report" in capsys.readouterr().out


@pytest.mark.parametrize(
    "content",
    [
        "not = [toml",
        "value = 1",
        "[oidc-audit]\nunknown = true",
        "[oidc-audit]\ndisable = 'nope'",
        "[oidc-audit]\nformat = 'xml'",
        "[oidc-audit]\nmin-severity = 'urgent'",
        "[oidc-audit]\nmax-access-token-lifetime = 0",
        "[oidc-audit]\ninclude-keycloak-builtins = 'yes'",
        "[oidc-audit]\ntimeout = 0",
    ],
)
def test_invalid_configs(content: str, tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(path)


def test_regressions_use_stable_identity() -> None:
    existing = Finding(RULES["OIDC-CLIENT-001"], "old", "$.clients[0]", identity="app:a")
    reordered = Finding(RULES["OIDC-CLIENT-001"], "new", "$.clients[9]", identity="app:a")
    added = Finding(RULES["OIDC-CLIENT-001"], "new", "$.clients[10]", identity="app:b")
    assert regressions([existing], [reordered]) == []
    assert regressions([existing], [reordered, added]) == [added]


def test_diff_command_fails_only_for_regressions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    clean = json.loads((ROOT / "examples" / "good-realm.json").read_text(encoding="utf-8"))
    baseline.write_text(json.dumps(clean), encoding="utf-8")
    clean["clients"].append(
        {
            "clientId": "regression",
            "publicClient": False,
            "standardFlowEnabled": False,
            "redirectUris": ["https://app.example.test/*"],
            "attributes": {},
        }
    )
    current.write_text(json.dumps(clean), encoding="utf-8")
    args = ["diff", "--baseline", str(baseline), "--current", str(current)]
    assert cli.run(args) == 2
    output = capsys.readouterr().out
    assert "oidc-audit diff report" in output
    assert "OIDC-CLIENT-001" in output
    assert cli.run(["diff", "--baseline", str(current), "--current", str(baseline)]) == 0
    assert "findings: 0" in capsys.readouterr().out

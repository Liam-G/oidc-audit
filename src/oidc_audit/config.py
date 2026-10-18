"""Strict TOML configuration loading."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised by the Python 3.10 CI job
    import tomli as tomllib  # type: ignore[import-not-found, unused-ignore]

from .loaders import ConfigurationError

ALLOWED_KEYS = frozenset(
    {
        "disable",
        "fail-on",
        "format",
        "include-keycloak-builtins",
        "max-access-token-lifetime",
        "min-severity",
        "timeout",
    }
)


@dataclass(frozen=True)
class AuditConfig:
    output_format: str = "text"
    min_severity: str = "info"
    fail_on: str = "low"
    disabled_rules: tuple[str, ...] = ()
    max_access_token_lifetime: int = 900
    include_keycloak_builtins: bool = False
    timeout: float = 10.0


def _string_list(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigurationError(f"config {name} must be an array of strings")
    return tuple(value)


def load_config(path: Path | None) -> AuditConfig:
    if path is None:
        return AuditConfig()
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"invalid TOML in {path}: {exc}") from exc
    section = raw.get("oidc-audit")
    if not isinstance(section, dict):
        raise ConfigurationError(f"config {path} must contain an [oidc-audit] table")
    unknown = sorted(set(section).difference(ALLOWED_KEYS))
    if unknown:
        raise ConfigurationError(f"unknown config key: {', '.join(unknown)}")

    output_format = section.get("format", "text")
    min_severity = section.get("min-severity", "info")
    fail_on = section.get("fail-on", "low")
    max_lifetime = section.get("max-access-token-lifetime", 900)
    include_builtins = section.get("include-keycloak-builtins", False)
    timeout = section.get("timeout", 10.0)
    disabled = _string_list(section.get("disable", []), "disable")
    if output_format not in {"text", "json", "sarif"}:
        raise ConfigurationError("config format must be text, json, or sarif")
    if min_severity not in {"info", "low", "medium", "high", "critical"}:
        raise ConfigurationError("config min-severity is invalid")
    if fail_on not in {"info", "low", "medium", "high", "critical"}:
        raise ConfigurationError("config fail-on is invalid")
    if not isinstance(max_lifetime, int) or isinstance(max_lifetime, bool) or max_lifetime < 1:
        raise ConfigurationError("config max-access-token-lifetime must be a positive integer")
    if not isinstance(include_builtins, bool):
        raise ConfigurationError("config include-keycloak-builtins must be a boolean")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise ConfigurationError("config timeout must be greater than zero")
    return AuditConfig(
        output_format=output_format,
        min_severity=min_severity,
        fail_on=fail_on,
        disabled_rules=disabled,
        max_access_token_lifetime=max_lifetime,
        include_keycloak_builtins=include_builtins,
        timeout=float(timeout),
    )

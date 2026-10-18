"""Command-line interface for offline and read-only OIDC configuration auditing."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .catalog import RULES
from .config import AuditConfig, load_config
from .diffing import regressions
from .fetching import fetch_issuer
from .loaders import ConfigurationError, load_json_object
from .models import AuditReport, Finding, Severity
from .reporting import render_report
from .rules.clients import audit_keycloak
from .rules.keys import audit_jwks
from .rules.metadata import audit_metadata


def _add_policy_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, help="TOML policy configuration")
    parser.add_argument("--max-access-token-lifetime", type=int, metavar="SECONDS")
    parser.add_argument(
        "--include-keycloak-builtins",
        action="store_true",
        default=None,
        help="Audit Keycloak-managed clients, which are skipped by default",
    )
    parser.add_argument("--format", choices=("text", "json", "sarif"))
    parser.add_argument("--output", type=Path, help="Write the report instead of stdout")
    parser.add_argument(
        "--min-severity",
        choices=tuple(str(item) for item in Severity),
        help="Only report findings at or above this severity",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(str(item) for item in Severity),
        help="Exit with status 2 only for findings at or above this severity (default: low)",
    )
    parser.add_argument("--disable", action="append", default=None, metavar="RULE_ID")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oidc-audit",
        description="Audit OAuth 2.0 and OpenID Connect configurations.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    lint = commands.add_parser("lint", help="Audit local exports or a read-only issuer URL")
    lint.add_argument("--discovery", type=Path, help="OIDC discovery/authorization metadata JSON")
    lint.add_argument("--expected-issuer", help="Expected issuer URL for discovery validation")
    lint.add_argument("--jwks", type=Path, help="Published JWK Set JSON")
    lint.add_argument("--keycloak", type=Path, help="Keycloak realm export JSON")
    lint.add_argument(
        "--issuer",
        help="Issuer URL; fetch discovery metadata and its advertised JWKS using GET only",
    )
    lint.add_argument("--timeout", type=float, help="Network timeout in seconds")
    _add_policy_options(lint)

    diff = commands.add_parser("diff", help="Report only findings added since a baseline export")
    diff.add_argument("--baseline", type=Path, required=True, help="Baseline Keycloak realm export")
    diff.add_argument("--current", type=Path, required=True, help="Current Keycloak realm export")
    _add_policy_options(diff)

    commands.add_parser("rules", help="List rules and RFC references")
    return parser


def _resolved_config(args: argparse.Namespace) -> AuditConfig:
    stored = load_config(args.config)
    disabled = tuple(dict.fromkeys((*stored.disabled_rules, *(args.disable or ()))))
    unknown = sorted(set(disabled).difference(RULES))
    if unknown:
        raise ConfigurationError(f"unknown rule ID: {', '.join(unknown)}")
    max_lifetime = (
        stored.max_access_token_lifetime
        if args.max_access_token_lifetime is None
        else args.max_access_token_lifetime
    )
    if max_lifetime < 1:
        raise ConfigurationError("--max-access-token-lifetime must be greater than zero")
    timeout_arg = getattr(args, "timeout", None)
    timeout = stored.timeout if timeout_arg is None else timeout_arg
    if timeout <= 0:
        raise ConfigurationError("--timeout must be greater than zero")
    return AuditConfig(
        output_format=args.format or stored.output_format,
        min_severity=args.min_severity or stored.min_severity,
        fail_on=args.fail_on or stored.fail_on,
        disabled_rules=disabled,
        max_access_token_lifetime=max_lifetime,
        include_keycloak_builtins=(
            stored.include_keycloak_builtins
            if args.include_keycloak_builtins is None
            else args.include_keycloak_builtins
        ),
        timeout=timeout,
    )


def _filter_findings(findings: list[Finding], policy: AuditConfig) -> list[Finding]:
    minimum = Severity.parse(policy.min_severity)
    return [
        finding
        for finding in findings
        if finding.rule.severity >= minimum and finding.rule.id not in policy.disabled_rules
    ]


def _exit_status(findings: list[Finding], policy: AuditConfig) -> int:
    threshold = Severity.parse(policy.fail_on)
    return 2 if any(finding.rule.severity >= threshold for finding in findings) else 0


def _write_report(report: AuditReport, output_format: str, output: Path | None) -> None:
    rendered = render_report(report, output_format)
    if output is None:
        sys.stdout.write(rendered)
    else:
        output.write_text(rendered, encoding="utf-8")


def _audit_keycloak(path: Path, policy: AuditConfig) -> list[Finding]:
    return audit_keycloak(
        load_json_object(path),
        str(path),
        policy.max_access_token_lifetime,
        include_builtin_clients=policy.include_keycloak_builtins,
    )


def _lint(args: argparse.Namespace) -> int:
    policy = _resolved_config(args)
    local_paths = [path for path in (args.discovery, args.jwks, args.keycloak) if path is not None]
    if args.issuer is None and not local_paths:
        raise ConfigurationError(
            "at least one of --issuer, --discovery, --jwks, or --keycloak is required"
        )
    if args.issuer is not None and (args.discovery is not None or args.jwks is not None):
        raise ConfigurationError("--issuer cannot be combined with --discovery or --jwks")
    if args.issuer is not None and args.expected_issuer is not None:
        raise ConfigurationError("--expected-issuer is inferred when --issuer is used")

    findings: list[Finding] = []
    inputs = [str(path) for path in local_paths]
    if args.issuer is not None:
        documents = fetch_issuer(args.issuer, timeout=policy.timeout)
        inputs.append(documents.discovery_url)
        findings.extend(
            audit_metadata(
                documents.discovery, documents.discovery_url, expected_issuer=documents.issuer
            )
        )
        if documents.jwks is not None and documents.jwks_url is not None:
            inputs.append(documents.jwks_url)
            findings.extend(audit_jwks(documents.jwks, documents.jwks_url))
    if args.discovery is not None:
        findings.extend(
            audit_metadata(
                load_json_object(args.discovery), str(args.discovery), args.expected_issuer
            )
        )
    if args.jwks is not None:
        findings.extend(audit_jwks(load_json_object(args.jwks), str(args.jwks)))
    if args.keycloak is not None:
        findings.extend(_audit_keycloak(args.keycloak, policy))

    selected = _filter_findings(findings, policy)
    report = AuditReport.create(selected, inputs)
    _write_report(report, policy.output_format, args.output)
    return _exit_status(selected, policy)


def _diff(args: argparse.Namespace) -> int:
    policy = _resolved_config(args)
    baseline = _filter_findings(_audit_keycloak(args.baseline, policy), policy)
    current = _filter_findings(_audit_keycloak(args.current, policy), policy)
    added = regressions(baseline, current)
    report = AuditReport.create(added, [str(args.baseline), str(args.current)], mode="diff")
    _write_report(report, policy.output_format, args.output)
    return _exit_status(added, policy)


def _rules() -> int:
    for rule in RULES.values():
        print(f"{rule.id}\t{str(rule.severity)}\t{rule.title}\t{rule.reference}")
    return 0


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "lint":
            return _lint(args)
        if args.command == "diff":
            return _diff(args)
        return _rules()
    except (ConfigurationError, OSError, ValueError) as exc:
        print(f"oidc-audit: error: {exc}", file=sys.stderr)
        return 1


def main() -> None:
    raise SystemExit(run())

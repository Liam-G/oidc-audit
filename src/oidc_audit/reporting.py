"""Text, JSON, and SARIF renderers that never include input values."""

from __future__ import annotations

import json
from typing import Any

from .models import AuditReport, Severity

SARIF_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.1",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "4.0",
    Severity.LOW: "1.0",
    Severity.INFO: "0.0",
}


def render_text(report: AuditReport) -> str:
    lines = [
        f"oidc-audit {report.mode} report",
        f"inputs: {len(report.inputs)}",
        f"findings: {len(report.findings)}",
    ]
    for finding in report.findings:
        lines.extend(
            (
                "",
                f"[{str(finding.rule.severity).upper()}] {finding.rule.id}: {finding.rule.title}",
                f"  source: {finding.source}",
                f"  location: {finding.path}",
                f"  {finding.message or finding.rule.message}",
                f"  fix: {finding.rule.remediation}",
                f"  reference: {finding.rule.reference} ({finding.rule.reference_url})",
            )
        )
    return "\n".join(lines) + "\n"


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity >= Severity.MEDIUM:
        return "warning"
    return "note"


def render_sarif(report: AuditReport) -> str:
    used_rules = {finding.rule.id: finding.rule for finding in report.findings}
    rules: list[dict[str, Any]] = []
    for rule in used_rules.values():
        rules.append(
            {
                "id": rule.id,
                "name": rule.title,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.message},
                "helpUri": rule.reference_url,
                "help": {"text": f"{rule.remediation} Reference: {rule.reference}."},
                "properties": {
                    "security-severity": SARIF_SECURITY_SEVERITY[rule.severity],
                    "tags": ["security"],
                },
            }
        )
    results = [
        {
            "ruleId": finding.rule.id,
            "level": _sarif_level(finding.rule.severity),
            "message": {"text": finding.message or finding.rule.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.source},
                        "region": {"snippet": {"text": finding.path}},
                    }
                }
            ],
        }
        for finding in report.findings
    ]
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "oidc-audit",
                        "informationUri": "https://github.com/Liam-G/oidc-audit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def render_report(report: AuditReport, output_format: str) -> str:
    if output_format == "text":
        return render_text(report)
    if output_format == "sarif":
        return render_sarif(report)
    return json.dumps(report.as_dict(), indent=2) + "\n"

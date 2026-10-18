"""Rule, finding, and report models."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value}") from exc

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    message: str
    remediation: str
    reference: str
    reference_url: str

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["severity"] = str(self.severity)
        return result


@dataclass(frozen=True)
class Finding:
    rule: Rule
    source: str
    path: str
    message: str | None = None
    identity: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "severity": str(self.rule.severity),
            "title": self.rule.title,
            "message": self.message or self.rule.message,
            "source": self.source,
            "path": self.path,
            "remediation": self.rule.remediation,
            "reference": self.rule.reference,
            "reference_url": self.rule.reference_url,
        }


@dataclass(frozen=True)
class AuditReport:
    findings: tuple[Finding, ...]
    inputs: tuple[str, ...]
    generated_at: str
    mode: str = "lint"

    @classmethod
    def create(
        cls, findings: list[Finding], inputs: list[str], *, mode: str = "lint"
    ) -> AuditReport:
        ordered = sorted(findings, key=lambda item: (-item.rule.severity, item.rule.id, item.path))
        return cls(
            findings=tuple(ordered),
            inputs=tuple(inputs),
            generated_at=datetime.now(timezone.utc).isoformat(),
            mode=mode,
        )

    def as_dict(self) -> dict[str, Any]:
        counts = {str(severity): 0 for severity in Severity}
        for finding in self.findings:
            counts[str(finding.rule.severity)] += 1
        return {
            "schema_version": "1.0",
            "generated_at": self.generated_at,
            "mode": self.mode,
            "summary": {"inputs": len(self.inputs), "findings": len(self.findings), **counts},
            "inputs": list(self.inputs),
            "findings": [finding.as_dict() for finding in self.findings],
        }

"""Finding-level regression comparison."""

from __future__ import annotations

from collections import Counter

from .models import Finding


def finding_key(finding: Finding) -> tuple[str, str]:
    return finding.rule.id, finding.identity or finding.path


def regressions(baseline: list[Finding], current: list[Finding]) -> list[Finding]:
    remaining = Counter(finding_key(finding) for finding in baseline)
    result: list[Finding] = []
    for finding in current:
        key = finding_key(finding)
        if remaining[key] > 0:
            remaining[key] -= 1
        else:
            result.append(finding)
    return result

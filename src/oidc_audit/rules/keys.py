"""Published JWK Set checks."""

from __future__ import annotations

import base64
from typing import Any

from ..catalog import RULES
from ..models import Finding

PRIVATE_PARAMETERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})
STANDARD_CURVES = frozenset({"P-256", "P-384", "P-521"})


def _modulus_bits(value: str) -> int | None:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        return None
    return int.from_bytes(raw, "big").bit_length()


def audit_jwks(document: dict[str, Any], source: str) -> list[Finding]:
    keys = document.get("keys")
    if not isinstance(keys, list):
        return []
    findings: list[Finding] = []
    kid_indexes: dict[str, list[int]] = {}
    for index, raw_key in enumerate(keys):
        if not isinstance(raw_key, dict):
            continue
        key: dict[str, Any] = raw_key
        path = f"$.keys[{index}]"
        if PRIVATE_PARAMETERS.intersection(key):
            findings.append(Finding(RULES["OIDC-KEY-001"], source, path))
        if key.get("kty") == "oct":
            findings.append(Finding(RULES["OIDC-KEY-002"], source, path))
        if key.get("kty") == "RSA" and isinstance(key.get("n"), str):
            bits = _modulus_bits(key["n"])
            if bits is not None and bits < 2048:
                findings.append(
                    Finding(
                        RULES["OIDC-KEY-003"],
                        source,
                        f"{path}.n",
                        f"RSA modulus is {bits} bits; minimum is 2048 bits.",
                    )
                )
        if key.get("kty") == "EC" and key.get("crv") not in STANDARD_CURVES:
            findings.append(Finding(RULES["OIDC-KEY-004"], source, f"{path}.crv"))
        kid = key.get("kid")
        if not isinstance(kid, str) or not kid.strip():
            findings.append(Finding(RULES["OIDC-KEY-005"], source, f"{path}.kid"))
        else:
            kid_indexes.setdefault(kid, []).append(index)
        if not key.get("use") and not key.get("key_ops"):
            findings.append(Finding(RULES["OIDC-KEY-007"], source, f"{path}.use"))
        if not key.get("alg"):
            findings.append(Finding(RULES["OIDC-KEY-008"], source, f"{path}.alg"))
    for indexes in kid_indexes.values():
        if len(indexes) > 1:
            for index in indexes:
                findings.append(Finding(RULES["OIDC-KEY-006"], source, f"$.keys[{index}].kid"))
    return findings

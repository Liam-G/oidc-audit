"""Safe local JSON loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_INPUT_SIZE = 10 * 1024 * 1024


class ConfigurationError(ValueError):
    """Raised for invalid or unusable audit input."""


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ConfigurationError(f"cannot read {path}: {exc}") from exc
    if size > MAX_INPUT_SIZE:
        raise ConfigurationError(f"input file is larger than 10 MiB: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigurationError(f"top-level JSON value must be an object: {path}")
    return document

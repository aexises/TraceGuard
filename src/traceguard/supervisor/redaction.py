"""Configurable redaction for supervisor prompts and traces."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pydantic import Field

from traceguard.types import StrictModel

DEFAULT_SECRET_PATTERNS = [
    r"(?i)\b(?:password|secret|token|api[_-]?key)\s*[:=]\s*['\"]?[^'\"\s,&;]+",
    r"(?i)\bapi[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})",
    r"(?i)\bbearer\s+[A-Za-z0-9_\-.=]{12,}",
    r"(?i)\bpassword\s*[:=]\s*['\"]?[^'\"\s]+",
    r"(?i)\b(access|session|refresh)[_-]?token\s*[:=]\s*['\"]?[A-Za-z0-9_\-.=]{12,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    r"(?i)\bcookie\s*[:=]\s*[^;\n]+",
]
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(api[_-]?key|password|passphrase|secret|credential|"
    r"(access|session|refresh|auth)[_-]?token|authorization|cookie|private[_-]?key)"
)


class RedactionConfig(StrictModel):
    enabled: bool = True
    replacement: str = "[REDACTED_SECRET]"
    extra_patterns: list[str] = Field(default_factory=list)

    @property
    def patterns(self) -> list[re.Pattern[str]]:
        flags = re.DOTALL
        return [
            re.compile(pattern, flags)
            for pattern in [*DEFAULT_SECRET_PATTERNS, *self.extra_patterns]
        ]


def load_redaction_config(path: Path | None) -> RedactionConfig:
    if path is None:
        return RedactionConfig()
    payload = json.loads(path.read_text(encoding="utf-8"))
    return mandatory_redaction_config(RedactionConfig.model_validate(payload))


def mandatory_redaction_config(config: RedactionConfig | None = None) -> RedactionConfig:
    config = config or RedactionConfig()
    return config.model_copy(update={"enabled": True})


def redact_text(text: str, config: RedactionConfig | None = None) -> str:
    config = config or RedactionConfig()
    if not config.enabled:
        return text
    redacted = text
    for pattern in config.patterns:
        redacted = pattern.sub(config.replacement, redacted)
    return redacted


def redact_value(value: Any, config: RedactionConfig | None = None) -> Any:
    config = config or RedactionConfig()
    if isinstance(value, str):
        return redact_text(value, config)
    if isinstance(value, Mapping):
        return {
            str(key): (
                config.replacement
                if config.enabled and SENSITIVE_KEY_PATTERN.search(str(key))
                else redact_value(item, config)
            )
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact_value(item, config) for item in value]
    return value


def redact_request(value: Any, config: RedactionConfig | None = None) -> Any:
    """Use request-local opaque labels so distinct protected values do not collapse.

    No raw-to-label mapping leaves this function. Logs continue to use redact_value.
    This preserves equality for recognized values, not meaning or arbitrary secrets.
    """
    config = mandatory_redaction_config(config)
    protected: dict[str, str] = {}

    def remember(raw: str) -> None:
        if raw and raw not in protected:
            protected[raw] = f"{config.replacement}:{len(protected) + 1}"

    def collect(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if SENSITIVE_KEY_PATTERN.search(str(key)):
                    remember(child if isinstance(child, str) else json.dumps(child, sort_keys=True))
                collect(child)
        elif isinstance(item, str):
            for pattern in config.patterns:
                for match in pattern.finditer(item):
                    remember(match.group())
        elif isinstance(item, Sequence):
            for child in item:
                collect(child)

    collect(value)

    def replace(item: Any) -> Any:
        if isinstance(item, str):
            if not protected:
                return item
            # One substitution pass avoids touching an already emitted opaque label.
            pattern = re.compile(
                "|".join(re.escape(s) for s in sorted(protected, key=len, reverse=True))
            )
            return pattern.sub(lambda match: protected[match.group()], item)
        if isinstance(item, Mapping):
            return {
                str(key): (
                    protected.get(json.dumps(child, sort_keys=True), config.replacement)
                    if SENSITIVE_KEY_PATTERN.search(str(key)) and not isinstance(child, str)
                    else replace(child)
                )
                for key, child in item.items()
            }
        if isinstance(item, Sequence) and not isinstance(item, (bytes, bytearray)):
            return [replace(child) for child in item]
        return item

    return replace(value)

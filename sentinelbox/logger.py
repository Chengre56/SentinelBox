from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re
from typing import Any, Dict

from sentinelbox.models import AuditEvent

SECRET_PATTERNS = [
    re.compile(r"(sk-[a-zA-Z0-9_-]{20,})"),
    re.compile(r"(ghp_[a-zA-Z0-9]{36})"),
    re.compile(r"(password\s*[:=]\s*)([^\s,]+)", re.IGNORECASE),
    re.compile(r"(token\s*[:=]\s*)([^\s,]+)", re.IGNORECASE),
    re.compile(r"(secret\s*[:=]\s*)([^\s,]+)", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*[:=]\s*)([^\s,]+)", re.IGNORECASE),
    re.compile(r"(BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY)"),
]


def redact_secrets(text: str) -> str:
    """Redacts known API keys, tokens, and private key structures from logged text."""
    if not isinstance(text, str):
        return text
    sanitized = text
    for pattern in SECRET_PATTERNS:
        sanitized = pattern.sub(r"[REDACTED]", sanitized)
    return sanitized


def sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redacts secrets in dict structures."""
    sanitized: Dict[str, Any] = {}
    for k, v in data.items():
        if any(secret_kw in k.lower() for secret_kw in ("password", "secret", "token", "key", "auth")):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, str):
            sanitized[k] = redact_secrets(v)
        elif isinstance(v, dict):
            sanitized[k] = sanitize_dict(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_dict(item) if isinstance(item, dict) else (redact_secrets(item) if isinstance(item, str) else item)
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


class AuditLogger:
    """Structured JSON Lines audit logger with secret redaction and rotation."""

    def __init__(self, log_dir: Path, max_bytes: int = 50 * 1024 * 1024, backup_count: int = 10) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "audit.jsonl"

        self._logger = logging.getLogger("sentinelbox.audit")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

        if not self._logger.handlers:
            handler = RotatingFileHandler(
                str(self.log_file),
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    def log_event(self, transaction_id: str, event_type: str, details: Dict[str, Any]) -> AuditEvent:
        clean_details = sanitize_dict(details)
        event = AuditEvent.create(transaction_id=transaction_id, event=event_type, details=clean_details)
        self._logger.info(json.dumps(event.to_dict(), ensure_ascii=False))
        return event
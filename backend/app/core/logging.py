from __future__ import annotations

import logging
import sys
from typing import Any


def configure_logging(level: int = logging.INFO) -> None:
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def redact_sensitive(payload: dict[str, Any]) -> dict[str, Any]:
    sensitive_keys = {"password", "secret", "token", "api_key", "authorization"}
    cleaned: dict[str, Any] = {}
    for k, v in payload.items():
        if any(s in k.lower() for s in sensitive_keys):
            cleaned[k] = "***REDACTED***"
        else:
            cleaned[k] = v
    return cleaned

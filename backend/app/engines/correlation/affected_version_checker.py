from __future__ import annotations

from typing import Any
from packaging.version import InvalidVersion, Version


def evaluate_version_against_range(detected_version: str | None, product_entry: dict[str, Any]) -> str:
    """Compare a detected version against an official CVE product range.

    Returns one of:
    - 'Verified affected configuration'
    - 'Not affected'
    - 'Potentially affected'
    - 'Insufficient information'
    """
    if not detected_version:
        return "Insufficient information"

    try:
        v = Version(detected_version.strip().lstrip("v"))
    except InvalidVersion:
        return "Insufficient information"

    v_eq = product_entry.get("version_eq")
    v_start = product_entry.get("version_start")
    v_lt = product_entry.get("version_lt")
    v_le = product_entry.get("version_le")

    if not any([v_eq, v_start, v_lt, v_le]):
        return "Potentially affected"

    try:
        if v_eq and v == Version(str(v_eq).lstrip("v")):
            return "Verified affected configuration"
        if v_eq and not (v_lt or v_le):
            return "Not affected"

        in_lower = True if not v_start else v >= Version(str(v_start).lstrip("v"))
        in_upper = True
        if v_lt:
            in_upper = v < Version(str(v_lt).lstrip("v"))
        elif v_le:
            in_upper = v <= Version(str(v_le).lstrip("v"))

        if in_lower and in_upper:
            return "Verified affected configuration"
        return "Not affected"
    except InvalidVersion:
        return "Insufficient information"

from __future__ import annotations

from typing import Any


def calculate_confidence(
    evidence_items: list[dict[str, Any]],
    context: dict[str, Any],
    corroborated_by_multiple_engines: bool = False,
) -> float:
    """Compute bounded confidence score [0.0, 1.0] grounded strictly in evidence and context."""
    verifiable = [e for e in evidence_items if e.get("is_verifiable")]
    if not verifiable:
        base = 0.28
    else:
        base = max(float(e.get("weight", 0.5)) for e in verifiable)

    if corroborated_by_multiple_engines:
        base += 0.14

    if context.get("is_test_context"):
        base -= 0.35
    if context.get("is_comment_only"):
        base -= 0.45
    if context.get("uses_env_fallback"):
        base -= 0.35
    if context.get("has_parameterized_marker"):
        base -= 0.30

    return round(max(0.05, min(0.99, base)), 2)

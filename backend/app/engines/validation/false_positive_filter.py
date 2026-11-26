from __future__ import annotations

from typing import Any


def evaluate_false_positive(
    finding: dict[str, Any],
    context: dict[str, Any],
    evidence_items: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Identify likely false positives (comments, test fixtures, env fallbacks, or unsupported guesses)."""
    if context.get("is_comment_only"):
        return True, "Matched line is a comment or documentation string, not executable logic."
    if context.get("uses_env_fallback"):
        return True, "Secret/configuration loads from environment variables rather than a hardcoded literal."
    if context.get("has_parameterized_marker"):
        return True, "Query uses parameterized placeholder binding."
    if context.get("is_test_context") and finding.get("severity") in {"low", "medium", "info"}:
        return True, "Low/medium pattern inside test/fixture file; downgraded to avoid test noise."
    if not any(e.get("is_verifiable") for e in evidence_items):
        return False, "Lacks verifiable concrete evidence; cannot be auto-confirmed."
    return False, "Concrete evidence verified in active code or live target response."

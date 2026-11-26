from __future__ import annotations

from pathlib import Path
from typing import Any


TEST_PATH_MARKERS = ("/tests/", "\\tests\\", "test_", "_test.", ".spec.", ".test.", "/fixtures/", "/examples/")


def analyze_finding_context(finding: dict[str, Any]) -> dict[str, Any]:
    """Evaluate environmental and code context to surface false-positive modifiers."""
    location = (finding.get("location") or "").lower()
    snippet = (finding.get("code_snippet") or "").strip()
    source_engine = finding.get("source_engine", "")

    is_test_context = any(marker in location for marker in TEST_PATH_MARKERS)
    is_comment_only = snippet.startswith(("#", "//", "/*", "*"))
    uses_env_fallback = "os.environ" in snippet or "os.getenv" in snippet or "process.env" in snippet
    has_parameterized_marker = "?" in snippet and "%" not in snippet and "f\"" not in snippet and "f'" not in snippet

    if source_engine == "dependency_scanner":
        context_risk = "high" if finding.get("cve_id") else "medium"
    elif is_test_context:
        context_risk = "low"
    elif is_comment_only or uses_env_fallback or has_parameterized_marker:
        context_risk = "low"
    else:
        context_risk = "high"

    return {
        "is_test_context": is_test_context,
        "is_comment_only": is_comment_only,
        "uses_env_fallback": uses_env_fallback,
        "has_parameterized_marker": has_parameterized_marker,
        "context_risk": context_risk,
    }

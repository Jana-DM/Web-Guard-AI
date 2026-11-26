from __future__ import annotations

from typing import Any

from app.ai.llm_client import generate_grounded_completion


def summarize_assessment_report(metrics: dict[str, Any]) -> str:
    prompt = (
        f"Write a concise executive security summary strictly from these verified metrics: {metrics}. "
        "Do not invent vulnerabilities or numbers."
    )
    llm_reply = generate_grounded_completion(
        "You are a CISO advisor summarizing verified security assessment results.",
        prompt,
    )
    if llm_reply:
        return llm_reply

    return (
        f"Web Guard AI analyzed {metrics.get('total_scans', 0)} scan job(s) and recorded "
        f"{metrics.get('total_findings', 0)} candidate finding(s): "
        f"{metrics.get('confirmed_count', 0)} CONFIRMED, "
        f"{metrics.get('potential_count', 0)} POTENTIAL, "
        f"{metrics.get('needs_review_count', 0)} NEEDS REVIEW, and "
        f"{metrics.get('not_reproduced_count', 0)} filtered as NOT REPRODUCED. "
        f"All confirmed findings are backed by concrete verifiable evidence records."
    )

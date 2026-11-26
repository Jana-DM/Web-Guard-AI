from __future__ import annotations

from typing import Any

from app.engines.validation.confidence_engine import calculate_confidence
from app.engines.validation.context_analyzer import analyze_finding_context
from app.engines.validation.evidence_collector import collect_evidence
from app.engines.validation.false_positive_filter import evaluate_false_positive


def validate_and_classify_findings(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run the 6-stage AI & evidence validation pipeline on candidate findings.

    Stages:
    1. Detection
    2. Context Analysis
    3. Cross Validation
    4. Evidence Collection
    5. Confidence Assessment
    6. Final Classification (CONFIRMED | POTENTIAL | NEEDS REVIEW | NOT REPRODUCED)
    """
    # Group by (location, cwe_id) to detect multi-engine corroboration (e.g., AST + Bandit)
    engine_groups: dict[tuple[str, str], set[str]] = {}
    for f in raw_findings:
        key = (str(f.get("location", "")), str(f.get("cwe_id") or f.get("category") or ""))
        engine_groups.setdefault(key, set()).add(str(f.get("source_engine", "")))

    validated: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()

    for f in raw_findings:
        dedup_key = (str(f.get("location", "")), str(f.get("title", "")), str(f.get("source_engine", "")))
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        group_key = (str(f.get("location", "")), str(f.get("cwe_id") or f.get("category") or ""))
        corroborated = len(engine_groups.get(group_key, set())) > 1

        context = analyze_finding_context(f)
        evidence_items = collect_evidence(f)
        is_fp, fp_reason = evaluate_false_positive(f, context, evidence_items)
        confidence = calculate_confidence(evidence_items, context, corroborated_by_multiple_engines=corroborated)

        has_verifiable = any(e.get("is_verifiable") for e in evidence_items)

        # Strict accuracy rule: CONFIRMED requires concrete verifiable evidence AND confidence >= 0.75
        if is_fp or confidence < 0.30:
            classification = "NOT REPRODUCED"
        elif has_verifiable and confidence >= 0.75:
            classification = "CONFIRMED"
        elif has_verifiable and confidence >= 0.50:
            classification = "POTENTIAL"
        else:
            classification = "NEEDS REVIEW"

        stages = {
            "1_detection": {"engine": f.get("source_engine"), "title": f.get("title")},
            "2_context_analysis": context,
            "3_cross_validation": {
                "corroborated": corroborated,
                "supporting_engines": sorted(engine_groups.get(group_key, set())),
            },
            "4_evidence_collection": {"verifiable_count": sum(1 for e in evidence_items if e.get("is_verifiable"))},
            "5_confidence_assessment": {"score": confidence, "fp_reason": fp_reason},
            "6_final_classification": classification,
        }

        enriched = dict(f)
        enriched["classification"] = classification
        enriched["confidence_score"] = confidence
        enriched["validation_summary"] = fp_reason
        enriched["validation_stages"] = stages
        enriched["evidence_records"] = evidence_items
        validated.append(enriched)

    return validated

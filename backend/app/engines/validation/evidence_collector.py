from __future__ import annotations

from typing import Any


def collect_evidence(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """Build structured, verifiable evidence records from raw engine output."""
    raw = finding.get("evidence") or {}
    source_engine = finding.get("source_engine", "unknown")
    items: list[dict[str, Any]] = []

    if source_engine in {"ast_analyzer", "bandit", "semgrep", "custom_rules"}:
        snippet = finding.get("code_snippet") or raw.get("snippet") or raw.get("matched_line")
        has_concrete = bool(snippet and finding.get("line_number"))
        items.append({
            "evidence_type": f"{source_engine}_match",
            "source": source_engine,
            "summary": f"Static match at {finding.get('location')} (rule {raw.get('rule_id', 'N/A')}).",
            "raw_artifact": {**raw, "snippet": snippet},
            "is_verifiable": has_concrete,
            "weight": 0.78 if has_concrete else 0.35,
        })
    elif source_engine == "dependency_scanner":
        has_version = bool(raw.get("detected_version") and raw.get("cve_id"))
        items.append({
            "evidence_type": "dependency_version_range",
            "source": "dependency_scanner",
            "summary": (
                f"Manifest {raw.get('manifest')} declares {raw.get('package')}=={raw.get('detected_version')} "
                f"matching {raw.get('cve_id')}."
            ),
            "raw_artifact": raw,
            "is_verifiable": has_version,
            "weight": 0.85 if has_version else 0.4,
        })
    elif source_engine == "domain_scanner":
        has_artifact = bool(raw)
        items.append({
            "evidence_type": "http_or_dns_observation",
            "source": "domain_scanner",
            "summary": f"Observed network/HTTP configuration on {finding.get('location')}.",
            "raw_artifact": raw,
            "is_verifiable": has_artifact,
            "weight": 0.82 if has_artifact else 0.3,
        })
    elif source_engine == "cve_correlation":
        status = raw.get("correlation_status")
        is_verified = status == "Verified affected configuration"
        items.append({
            "evidence_type": "cve_version_correlation",
            "source": "cve_correlation",
            "summary": f"Technology correlation status: {status}.",
            "raw_artifact": raw,
            "is_verifiable": is_verified,
            "weight": 0.85 if is_verified else 0.4,
        })
    else:
        items.append({
            "evidence_type": "generic_observation",
            "source": source_engine,
            "summary": finding.get("description", "")[:240],
            "raw_artifact": raw,
            "is_verifiable": False,
            "weight": 0.25,
        })

    return items

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.engines.code_scanner.ast_analyzer import analyze_python_ast
from app.engines.code_scanner.bandit_engine import run_bandit_scan
from app.engines.code_scanner.custom_rules import run_custom_rules
from app.engines.code_scanner.language_detector import detect_file_kind
from app.engines.validation.finding_classifier import validate_and_classify_findings
from app.models.remediation import RemediationRecord
from app.models.vulnerability import Vulnerability


def verify_remediated_code(record: RemediationRecord, vuln: Vulnerability) -> dict[str, Any]:
    """Re-scan the patched source file and verify whether the original issue is resolved without regressions."""
    now = datetime.now(timezone.utc)
    if not record.file_path or not Path(record.file_path).exists():
        return {
            "original_finding_resolved": False,
            "new_issues_introduced": 0,
            "verification_status": "still_vulnerable",
            "details": {"reason": "Source file path missing on disk; cannot re-scan."},
            "verified_at": now,
        }

    file_path = Path(record.file_path)
    lang = detect_file_kind(file_path)
    raw_findings: list[dict[str, Any]] = []

    if lang == "python":
        raw_findings.extend(analyze_python_ast(file_path, file_path.name))
        bandit_res = run_bandit_scan(file_path.parent)
        raw_findings.extend(
            [
                f
                for f in bandit_res.get("findings", [])
                if f.get("file_path") and Path(f["file_path"]).resolve() == file_path.resolve()
            ]
        )

    raw_findings.extend(run_custom_rules(file_path, file_path.name, lang))
    validated = validate_and_classify_findings(raw_findings)
    active = [f for f in validated if f["classification"] in {"CONFIRMED", "POTENTIAL"}]

    orig_rule_id = None
    if vuln.evidence_records:
        orig_rule_id = (vuln.evidence_records[0].raw_artifact or {}).get("rule_id")
    orig_cwe = (vuln.cwe_id or "").upper()

    still_present = []
    for f in active:
        f_rule_id = (f.get("evidence") or {}).get("rule_id")
        if orig_rule_id and f_rule_id:
            if f_rule_id == orig_rule_id:
                still_present.append(f)
        elif f.get("title") == vuln.title or (
            orig_cwe and (f.get("cwe_id") or "").upper() == orig_cwe and f.get("severity") in {"critical", "high", "medium"}
        ):
            still_present.append(f)

    # Only treat medium/high/critical new findings as regressions (ignore low/info module-import notices like Bandit B404/B603)
    new_issues = [
        f
        for f in active
        if f not in still_present and f.get("severity") in {"critical", "high", "medium"}
    ]
    resolved = len(still_present) == 0

    if resolved and len(new_issues) == 0:
        status = "verified_fixed"
    elif resolved and len(new_issues) > 0:
        status = "regression_detected"
    else:
        status = "still_vulnerable"

    return {
        "original_finding_resolved": resolved,
        "new_issues_introduced": len(new_issues),
        "verification_status": status,
        "details": {
            "remaining_matching_findings": still_present,
            "new_findings": new_issues,
            "scanned_file": str(file_path),
        },
        "verified_at": now,
    }

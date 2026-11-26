from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.engines.code_scanner.ast_analyzer import analyze_python_ast
from app.engines.code_scanner.bandit_engine import run_bandit_scan
from app.engines.code_scanner.custom_rules import run_custom_rules
from app.engines.code_scanner.dependency_scanner import scan_dependencies
from app.engines.code_scanner.file_validator import list_scannable_files
from app.engines.code_scanner.language_detector import detect_file_kind, summarize_languages
from app.engines.code_scanner.semgrep_engine import run_semgrep_scan
from app.engines.correlation.technology_cve_matcher import correlate_technologies_with_cves
from app.engines.domain_scanner.safe_assessment import run_safe_domain_assessment
from app.engines.validation.finding_classifier import validate_and_classify_findings
from app.models.authorized_target import AuthorizedTarget
from app.models.evidence import EvidenceRecord
from app.models.scan_job import ScanJob
from app.models.scan_result import ScanResult, TechnologyFingerprint
from app.models.vulnerability import Vulnerability


def _persist_validated_findings(
    db: Session,
    scan_job: ScanJob,
    validated: list[dict[str, Any]],
    target_id: str | None = None,
) -> list[Vulnerability]:
    created_vulns: list[Vulnerability] = []
    for item in validated:
        vuln = Vulnerability(
            scan_job_id=scan_job.id,
            target_id=target_id,
            title=item["title"][:300],
            description=item.get("description", ""),
            category=item.get("category", "General"),
            source_engine=item.get("source_engine", "unknown"),
            severity=item.get("severity", "medium"),
            cvss_score=item.get("cvss_score"),
            cwe_id=item.get("cwe_id"),
            cve_id=item.get("cve_id"),
            classification=item["classification"],
            confidence_score=item["confidence_score"],
            validation_summary=item.get("validation_summary"),
            validation_stages=item.get("validation_stages", {}),
            location=item.get("location", scan_job.target_label)[:1024],
            file_path=item.get("file_path"),
            line_number=item.get("line_number"),
            code_snippet=item.get("code_snippet"),
            status="false_positive" if item["classification"] == "NOT REPRODUCED" else "open",
        )
        db.add(vuln)
        db.flush()

        for ev in item.get("evidence_records", []):
            db.add(
                EvidenceRecord(
                    vulnerability_id=vuln.id,
                    evidence_type=ev["evidence_type"],
                    source=ev["source"],
                    summary=ev["summary"],
                    raw_artifact=ev.get("raw_artifact", {}),
                    is_verifiable=bool(ev.get("is_verifiable", True)),
                    weight=float(ev.get("weight", 0.5)),
                )
            )
        created_vulns.append(vuln)
    return created_vulns


def execute_domain_scan_job(
    db: Session,
    scan_job: ScanJob,
    target: AuthorizedTarget,
    enable_safe_owasp_checks: bool = True,
    max_endpoints: int = 25,
) -> ScanJob:
    scan_job.status = "running"
    scan_job.started_at = datetime.now(timezone.utc)
    scan_job.progress = 15
    db.commit()

    try:
        report = run_safe_domain_assessment(
            target=target,
            enable_safe_owasp_checks=enable_safe_owasp_checks,
            max_endpoints=max_endpoints,
        )
        for mod_name in ("recon", "dns", "tls", "headers", "endpoints"):
            db.add(ScanResult(scan_job_id=scan_job.id, module_name=mod_name, status="completed", data={"payload": report[mod_name]}))

        for fp in report["fingerprints"]:
            db.add(
                TechnologyFingerprint(
                    scan_job_id=scan_job.id,
                    target_id=target.id,
                    product_name=fp["product_name"],
                    version=fp.get("version"),
                    category=fp.get("category", "framework"),
                    detection_source=fp["detection_source"],
                    confidence=fp.get("confidence", 0.7),
                    raw_evidence=fp.get("raw_evidence", {}),
                )
            )

        correlations = correlate_technologies_with_cves(db, report["fingerprints"])
        db.add(ScanResult(scan_job_id=scan_job.id, module_name="cve_correlation", status="completed", data={"items": correlations}))

        validated = validate_and_classify_findings(report["raw_findings"])
        vulns = _persist_validated_findings(db, scan_job, validated, target_id=target.id)

        scan_job.status = "completed"
        scan_job.progress = 100
        scan_job.completed_at = datetime.now(timezone.utc)
        scan_job.summary = {
            "http_status": report["http_status"],
            "final_url": report["final_url"],
            "endpoints_discovered": len(report["endpoints"]),
            "technologies_detected": len(report["fingerprints"]),
            "total_findings": len(vulns),
            "confirmed_findings": sum(1 for v in vulns if v.classification == "CONFIRMED"),
            "correlated_cves": len(correlations),
        }
        db.commit()
        db.refresh(scan_job)
        return scan_job
    except Exception as exc:
        scan_job.status = "failed"
        scan_job.error_message = str(exc)
        scan_job.completed_at = datetime.now(timezone.utc)
        db.commit()
        raise


def execute_code_scan_job(db: Session, scan_job: ScanJob, workspace: Path) -> ScanJob:
    scan_job.status = "running"
    scan_job.started_at = datetime.now(timezone.utc)
    scan_job.progress = 15
    db.commit()

    try:
        files = list_scannable_files(workspace)
        lang_summary = summarize_languages(files)
        raw_findings: list[dict[str, Any]] = []

        for f in files:
            rel = str(f.resolve().relative_to(workspace.resolve()))
            kind = detect_file_kind(f)
            if kind == "python":
                raw_findings.extend(analyze_python_ast(f, rel))
            if kind in {"python", "javascript", "typescript"}:
                raw_findings.extend(run_custom_rules(f, rel, kind))

        bandit_res = run_bandit_scan(workspace)
        raw_findings.extend(bandit_res.get("findings", []))

        semgrep_res = run_semgrep_scan(workspace)
        raw_findings.extend(semgrep_res.get("findings", []))

        dep_findings, dep_fingerprints = scan_dependencies(files, workspace, db=db)
        raw_findings.extend(dep_findings)

        for fp in dep_fingerprints:
            db.add(
                TechnologyFingerprint(
                    scan_job_id=scan_job.id,
                    product_name=fp["product_name"],
                    version=fp.get("version"),
                    category=fp.get("category", "dependency"),
                    detection_source=fp["detection_source"],
                    confidence=fp.get("confidence", 0.9),
                    raw_evidence=fp.get("raw_evidence", {}),
                )
            )

        db.add(
            ScanResult(
                scan_job_id=scan_job.id,
                module_name="code_inventory",
                status="completed",
                data={
                    "files_scanned": len(files),
                    "languages": lang_summary,
                    "bandit_available": bandit_res.get("available", False),
                    "semgrep_available": semgrep_res.get("available", False),
                },
            )
        )

        validated = validate_and_classify_findings(raw_findings)
        vulns = _persist_validated_findings(db, scan_job, validated)

        scan_job.status = "completed"
        scan_job.progress = 100
        scan_job.completed_at = datetime.now(timezone.utc)
        scan_job.summary = {
            "files_scanned": len(files),
            "languages": lang_summary,
            "total_findings": len(vulns),
            "confirmed_findings": sum(1 for v in vulns if v.classification == "CONFIRMED"),
            "potential_findings": sum(1 for v in vulns if v.classification == "POTENTIAL"),
            "filtered_false_positives": sum(1 for v in vulns if v.classification == "NOT REPRODUCED"),
        }
        db.commit()
        db.refresh(scan_job)
        return scan_job
    except Exception as exc:
        scan_job.status = "failed"
        scan_job.error_message = str(exc)
        scan_job.completed_at = datetime.now(timezone.utc)
        db.commit()
        raise

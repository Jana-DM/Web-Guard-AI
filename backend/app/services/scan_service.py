from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.engines.code_scanner.ast_analyzer import analyze_python_ast
from app.engines.code_scanner.bandit_engine import run_bandit_scan
from app.engines.code_scanner.config_scanner import scan_project_configurations
from app.engines.code_scanner.custom_rules import run_custom_rules
from app.engines.code_scanner.dependency_scanner import scan_dependencies
from app.engines.code_scanner.language_detector import detect_file_kind, summarize_languages
from app.engines.code_scanner.project_validator import build_project_inventory, validate_web_project
from app.engines.code_scanner.secret_detector import scan_project_for_sensitive_info
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
            severity=item.get("severity", "medium").lower(),
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
            remediation_advice=item.get("remediation_advice"),
        )
        db.add(vuln)
        db.flush()

        for ev in item.get("evidence_records", []):
            db.add(
                EvidenceRecord(
                    vulnerability_id=vuln.id,
                    evidence_type=ev.get("evidence_type", "static_pattern"),
                    source=ev.get("source", item.get("source_engine", "scanner")),
                    summary=ev.get("summary", item.get("title", "Evidence")),
                    raw_artifact=ev.get("raw_artifact", ev),
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


def execute_code_scan_job(
    db: Session,
    scan_job: ScanJob,
    workspace: Path,
    extra_summary: dict[str, Any] | None = None,
) -> ScanJob:
    """
    Intelligent Web Project Validation & Security Scanner Workflow:
    1. Project File Discovery & Inventory
    2. Web Technology & Language Validation (Fails if no recognized web project)
    3. Sensitive Information Detection (scans all files including .env, strictly masks values)
    4. Complete Project Security Scanning (Frontend, Backend, Configs, Dependencies)
    5. Evidence-Based Vulnerability Validation (CONFIRMED, POTENTIAL, INFORMATIONAL)
    6. Comprehensive Cybersecurity Dashboard Report Generation
    """
    scan_job.status = "running"
    scan_job.started_at = datetime.now(timezone.utc)
    scan_job.progress = 10
    db.commit()

    try:
        # STEP 1: File Discovery & Inventory
        inventory = build_project_inventory(workspace)
        scan_job.progress = 20
        db.commit()

        # STEP 2: Technology & Language Validation
        val_result = validate_web_project(workspace, inventory)
        if not val_result.is_valid:
            scan_job.status = "failed"
            error_msg = (
                "Web Project Validation Failed. No supported web development technologies or languages were detected. "
                + " ".join(val_result.failure_reasons)
            )
            scan_job.error_message = error_msg
            scan_job.completed_at = datetime.now(timezone.utc)
            scan_job.summary = {
                "validation_status": "FAILED",
                "failure_reasons": val_result.failure_reasons,
                "inventory": inventory.to_dict(),
            }
            db.commit()
            raise ValueError(error_msg)

        scan_job.progress = 30
        db.commit()

        # Record detected frameworks and backend in TechnologyFingerprint table
        for fw in val_result.detected_frameworks:
            db.add(TechnologyFingerprint(scan_job_id=scan_job.id, product_name=fw, category="frontend_framework", detection_source="project_validator", confidence=0.95))
        for be in val_result.detected_backend:
            db.add(TechnologyFingerprint(scan_job_id=scan_job.id, product_name=be, category="backend_technology", detection_source="project_validator", confidence=0.90))

        raw_findings: list[dict[str, Any]] = []

        # STEP 3: Sensitive Information Detection (Scans all files including .env; masked secrets)
        sensitive_findings = scan_project_for_sensitive_info(workspace, inventory.scannable_files)
        for s in sensitive_findings:
            raw_findings.append(s.to_vulnerability_dict())

        scan_job.progress = 45
        db.commit()

        # STEP 4: Complete Project Security Scanning (Does not stop after sensitive files)
        # 4a. Configuration Security (.gitignore, vite.config, package.json scripts)
        raw_findings.extend(scan_project_configurations(workspace))

        # 4b. Source Code Analysis (AST analyzer, Custom Web Rules, Bandit, Semgrep)
        scannable_files = inventory.scannable_files
        lang_summary = summarize_languages(scannable_files)

        for f in scannable_files:
            rel = str(f.resolve().relative_to(workspace.resolve())).replace("\\", "/")
            kind = detect_file_kind(f)
            if kind == "python":
                raw_findings.extend(analyze_python_ast(f, rel))
            if kind in {"python", "javascript", "typescript", "html", "css", "php", "vue", "svelte"}:
                raw_findings.extend(run_custom_rules(f, rel, kind))

        scan_job.progress = 65
        db.commit()

        # 4c. Bandit static analyzer
        bandit_res = run_bandit_scan(workspace)
        raw_findings.extend(bandit_res.get("findings", []))

        # 4d. Semgrep static rules
        semgrep_res = run_semgrep_scan(workspace)
        raw_findings.extend(semgrep_res.get("findings", []))

        # 4e. Dependency CVE & Advisory Scanning
        dep_findings, dep_fingerprints = scan_dependencies(scannable_files, workspace, db=db)
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

        scan_job.progress = 85
        db.commit()

        # STEP 5: Evidence-Based Vulnerability Validation (CONFIRMED, POTENTIAL, INFORMATIONAL)
        validated = validate_and_classify_findings(raw_findings)
        vulns = _persist_validated_findings(db, scan_job, validated)

        # STEP 6: Security Report Dashboard Generation
        scan_job.status = "completed"
        scan_job.progress = 100
        scan_job.completed_at = datetime.now(timezone.utc)

        active_vulns = [v for v in vulns if v.classification != "NOT REPRODUCED"]

        summary_payload: dict[str, Any] = {
            "project_name": val_result.project_name,
            "validation_status": "VALIDATED",
            "detected_technologies": sorted(list(set(val_result.detected_frameworks + val_result.detected_backend + val_result.detected_tools))),
            "detected_frameworks": val_result.detected_frameworks,
            "detected_backend": val_result.detected_backend,
            "supported_languages": val_result.detected_languages,
            "inventory": inventory.to_dict(),
            "total_files_discovered": inventory.total_discovered,
            "total_files_scanned": inventory.total_scanned,
            "files_scanned": inventory.total_scanned,
            "total_files_excluded": inventory.total_excluded,
            "excluded_details": inventory.excluded_summary,
            "sensitive_information_findings": [s.to_dict() for s in sensitive_findings],
            "sensitive_findings_count": len(sensitive_findings),
            "severity_breakdown": {
                "critical": sum(1 for v in active_vulns if v.severity == "critical"),
                "high": sum(1 for v in active_vulns if v.severity == "high"),
                "medium": sum(1 for v in active_vulns if v.severity == "medium"),
                "low": sum(1 for v in active_vulns if v.severity == "low"),
                "info": sum(1 for v in active_vulns if v.severity == "info"),
            },
            "classification_breakdown": {
                "confirmed": sum(1 for v in active_vulns if v.classification == "CONFIRMED"),
                "potential": sum(1 for v in active_vulns if v.classification == "POTENTIAL"),
                "informational": sum(1 for v in active_vulns if v.classification == "INFORMATIONAL"),
            },
            "confirmed_findings": sum(1 for v in active_vulns if v.classification == "CONFIRMED"),
            "potential_findings": sum(1 for v in active_vulns if v.classification == "POTENTIAL"),
            "informational_findings": sum(1 for v in active_vulns if v.classification == "INFORMATIONAL"),
            "total_findings": len(active_vulns),
            "filtered_false_positives": sum(1 for v in vulns if v.classification == "NOT REPRODUCED"),
            "scan_completion_status": "COMPLETED",
        }

        # Record code inventory module result
        db.add(
            ScanResult(
                scan_job_id=scan_job.id,
                module_name="project_security_summary",
                status="completed",
                data=summary_payload,
            )
        )

        scan_job.summary = summary_payload
        db.commit()
        db.refresh(scan_job)
        return scan_job
    except Exception as exc:
        scan_job.status = "failed"
        scan_job.error_message = str(exc)
        scan_job.completed_at = datetime.now(timezone.utc)
        db.commit()
        raise

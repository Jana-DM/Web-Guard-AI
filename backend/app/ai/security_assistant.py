from __future__ import annotations

from typing import Any
from sqlalchemy.orm import Session

from app.ai.llm_client import generate_grounded_completion
from app.ai.vulnerability_explainer import explain_cve, explain_vulnerability
from app.models.cve import CVEIntelligence
from app.models.scan_job import ScanJob
from app.models.vulnerability import Vulnerability


def answer_security_question(
    db: Session,
    question: str,
    vulnerability_id: str | None = None,
    scan_job_id: str | None = None,
    cve_id: str | None = None,
) -> dict[str, Any]:
    """Answer analyst queries strictly grounded in database records and evidence."""
    citations: list[dict[str, str]] = []
    context_parts: list[str] = []

    if vulnerability_id:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        if vuln:
            citations.append({"type": "vulnerability", "id": vuln.id, "label": vuln.title})
            context_parts.append(explain_vulnerability(vuln))

    if cve_id:
        cve = db.query(CVEIntelligence).filter(CVEIntelligence.cve_id == cve_id.upper()).first()
        if cve:
            citations.append({"type": "cve", "id": cve.cve_id, "label": cve.title})
            context_parts.append(explain_cve(cve))

    if scan_job_id:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if scan:
            vulns = db.query(Vulnerability).filter(Vulnerability.scan_job_id == scan.id).all()
            confirmed = [v for v in vulns if v.classification == "CONFIRMED"]
            citations.append({"type": "scan_job", "id": scan.id, "label": scan.target_label})
            context_parts.append(
                f"Scan '{scan.target_label}' ({scan.scan_type}, status={scan.status}) produced "
                f"{len(vulns)} total findings ({len(confirmed)} CONFIRMED)."
            )

    if not context_parts:
        recent_confirmed = (
            db.query(Vulnerability)
            .filter(Vulnerability.classification == "CONFIRMED")
            .order_by(Vulnerability.created_at.desc())
            .limit(5)
            .all()
        )
        kev_cves = db.query(CVEIntelligence).filter(CVEIntelligence.is_kev.is_(True)).limit(5).all()
        if recent_confirmed:
            context_parts.append(
                "Recent confirmed findings:\n"
                + "\n".join(f"- [{v.severity.upper()}] {v.title} at {v.location}" for v in recent_confirmed)
            )
            citations.extend({"type": "vulnerability", "id": v.id, "label": v.title} for v in recent_confirmed)
        if kev_cves:
            context_parts.append(
                "Tracked CISA KEV CVEs:\n" + "\n".join(f"- {c.cve_id}: {c.title}" for c in kev_cves)
            )
            citations.extend({"type": "cve", "id": c.cve_id, "label": c.title} for c in kev_cves)

    grounded_context = "\n\n".join(context_parts) if context_parts else "No matching scan or CVE records found in the database yet."

    llm_answer = generate_grounded_completion(
        "You are Web Guard AI Security Analyst. Answer strictly using the verified context provided. Never invent vulnerabilities or evidence.",
        f"Question: {question}\n\nVerified Context:\n{grounded_context}",
    )

    answer_text = llm_answer or (
        f"### Grounded Security Analysis\n\n**Query:** {question}\n\n{grounded_context}"
    )

    return {
        "answer": answer_text,
        "citations": citations,
        "grounded": True,
    }

from __future__ import annotations

import html
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, joinedload

from app.ai.report_summarizer import summarize_assessment_report
from app.config import get_settings
from app.models.scan_job import ScanJob
from app.models.vulnerability import Vulnerability


def build_report_payload(
    db: Session,
    scan_job_id: str | None = None,
    include_non_confirmed: bool = True,
) -> dict[str, Any]:
    query = db.query(Vulnerability).options(joinedload(Vulnerability.evidence_records))
    scan_info = None
    if scan_job_id:
        query = query.filter(Vulnerability.scan_job_id == scan_job_id)
        scan = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if scan:
            scan_info = {
                "id": scan.id,
                "scan_type": scan.scan_type,
                "target_label": scan.target_label,
                "status": scan.status,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            }

    vulns = query.order_by(Vulnerability.severity, Vulnerability.created_at.desc()).all()
    if not include_non_confirmed:
        vulns = [v for v in vulns if v.classification in {"CONFIRMED", "POTENTIAL"}]

    metrics = {
        "total_scans": 1 if scan_job_id else db.query(ScanJob).count(),
        "total_findings": len(vulns),
        "confirmed_count": sum(1 for v in vulns if v.classification == "CONFIRMED"),
        "potential_count": sum(1 for v in vulns if v.classification == "POTENTIAL"),
        "needs_review_count": sum(1 for v in vulns if v.classification == "NEEDS REVIEW"),
        "not_reproduced_count": sum(1 for v in vulns if v.classification == "NOT REPRODUCED"),
    }

    executive_summary = summarize_assessment_report(metrics)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": scan_info,
        "metrics": metrics,
        "executive_summary": executive_summary,
        "findings": [
            {
                "id": v.id,
                "title": v.title,
                "severity": v.severity,
                "classification": v.classification,
                "confidence_score": v.confidence_score,
                "cwe_id": v.cwe_id,
                "cve_id": v.cve_id,
                "location": v.location,
                "status": v.status,
                "description": v.description,
                "evidence": [
                    {"type": e.evidence_type, "summary": e.summary, "verifiable": e.is_verifiable}
                    for e in (v.evidence_records or [])
                ],
            }
            for v in vulns
        ],
    }


def generate_report_file(
    db: Session,
    report_format: str = "markdown",
    scan_job_id: str | None = None,
    include_non_confirmed: bool = True,
) -> dict[str, Any]:
    payload = build_report_payload(db, scan_job_id=scan_job_id, include_non_confirmed=include_non_confirmed)
    settings = get_settings()
    reports_dir = Path(settings.REPORTS_DIR).resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_id = uuid.uuid4().hex[:12]

    if report_format == "json":
        filename = f"webguard_report_{report_id}.json"
        content = json.dumps(payload, indent=2)
    elif report_format == "html":
        filename = f"webguard_report_{report_id}.html"
        rows_html = "".join(
            f"<tr><td>{html.escape(f['severity'].upper())}</td>"
            f"<td>{html.escape(f['classification'])}</td>"
            f"<td>{html.escape(f['title'])}</td>"
            f"<td><code>{html.escape(f['location'])}</code></td>"
            f"<td>{f['confidence_score']:.0%}</td></tr>"
            for f in payload["findings"]
        )
        content = (
            "<!doctype html><html><head><meta charset='utf-8'><title>Web Guard AI Security Report</title>"
            "<style>body{font-family:system-ui,sans-serif;background:#0b1120;color:#e2e8f0;padding:32px}"
            "table{width:100%;border-collapse:collapse;margin-top:20px}th,td{border:1px solid #334155;padding:10px;text-align:left}"
            "th{background:#1e293b}</style></head><body>"
            f"<h1>Web Guard AI — Security Assessment Report</h1>"
            f"<p>Generated: {html.escape(payload['generated_at'])}</p>"
            f"<h2>Executive Summary</h2><p>{html.escape(payload['executive_summary'])}</p>"
            "<h2>Validated Findings</h2>"
            "<table><thead><tr><th>Severity</th><th>Classification</th><th>Title</th><th>Location</th><th>Confidence</th></tr></thead>"
            f"<tbody>{rows_html}</tbody></table></body></html>"
        )
    else:
        filename = f"webguard_report_{report_id}.md"
        lines = [
            "# Web Guard AI — Security Assessment Report",
            f"**Generated:** {payload['generated_at']}",
            "",
            "## Executive Summary",
            payload["executive_summary"],
            "",
            "## Findings",
        ]
        for f in payload["findings"]:
            lines.append(
                f"### [{f['severity'].upper()}] {f['title']} ({f['classification']} — {f['confidence_score']:.0%})"
            )
            lines.append(f"- **Location:** `{f['location']}`")
            lines.append(f"- **CWE/CVE:** {f['cwe_id'] or 'N/A'} / {f['cve_id'] or 'N/A'}")
            lines.append(f"- **Description:** {f['description']}")
            for ev in f["evidence"]:
                lines.append(f"  - Evidence ({ev['type']}): {ev['summary']}")
            lines.append("")
        content = "\n".join(lines)

    out_path = reports_dir / filename
    out_path.write_text(content, encoding="utf-8")

    return {
        "report_id": report_id,
        "filename": filename,
        "format": report_format,
        "download_url": f"/api/v1/reports/{filename}/download",
        "metrics": payload["metrics"],
        "executive_summary": payload["executive_summary"],
        "preview": content[:4000],
    }

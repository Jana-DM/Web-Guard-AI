from __future__ import annotations

from typing import Any
from sqlalchemy.orm import Session

from app.engines.correlation.affected_version_checker import evaluate_version_against_range
from app.models.cve import CVEIntelligence


def correlate_technologies_with_cves(
    db: Session,
    technologies: list[dict[str, Any]],
    limit_per_tech: int = 15,
) -> list[dict[str, Any]]:
    """Correlate detected products/versions with stored CVE intelligence."""
    correlations: list[dict[str, Any]] = []

    for tech in technologies:
        product = (tech.get("product_name") or "").strip().lower()
        version = tech.get("version")
        if not product:
            continue

        candidates = (
            db.query(CVEIntelligence)
            .filter(CVEIntelligence.description.ilike(f"%{product}%"))
            .limit(limit_per_tech)
            .all()
        )

        for cve in candidates:
            matching_entries = [
                p for p in (cve.affected_products or [])
                if product in str(p.get("product", "")).lower() or product in str(p.get("vendor", "")).lower()
            ]
            if matching_entries:
                statuses = [evaluate_version_against_range(version, entry) for entry in matching_entries]
                if "Verified affected configuration" in statuses:
                    status = "Verified affected configuration"
                elif "Potentially affected" in statuses:
                    status = "Potentially affected"
                elif "Not affected" in statuses and "Insufficient information" not in statuses:
                    status = "Not affected"
                else:
                    status = "Insufficient information"
            else:
                status = "Insufficient information" if not version else "Potentially affected"

            correlations.append({
                "product_name": product,
                "detected_version": version,
                "cve_id": cve.cve_id,
                "severity": cve.severity,
                "cvss_score": cve.cvss_score,
                "is_kev": cve.is_kev,
                "status": status,
                "title": cve.title,
                "patch_available": cve.patch_available,
            })

    return correlations

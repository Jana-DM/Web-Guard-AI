from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.cve import CVEIntelligence


def compute_cve_hash(record: dict[str, Any]) -> str:
    canonical = {
        "cve_id": record.get("cve_id"),
        "description": record.get("description", ""),
        "cvss_score": record.get("cvss_score"),
        "is_kev": bool(record.get("is_kev")),
        "patch_available": bool(record.get("patch_available")),
        "affected_products": record.get("affected_products", []),
    }
    encoded = json.dumps(canonical, sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def upsert_cve_record(db: Session, normalized: dict[str, Any]) -> str:
    """Insert or merge a CVE record. Returns 'created', 'updated', or 'duplicate'."""
    cve_id = normalized["cve_id"]
    new_hash = compute_cve_hash(normalized)
    existing = db.query(CVEIntelligence).filter(CVEIntelligence.cve_id == cve_id).first()

    if existing is None:
        record = CVEIntelligence(
            cve_id=cve_id,
            title=normalized["title"][:500],
            description=normalized["description"],
            severity=normalized["severity"],
            cvss_score=normalized.get("cvss_score"),
            cvss_vector=normalized.get("cvss_vector"),
            cwe_ids=normalized.get("cwe_ids", []),
            affected_products=normalized.get("affected_products", []),
            is_kev=bool(normalized.get("is_kev", False)),
            kev_date_added=normalized.get("kev_date_added"),
            patch_available=bool(normalized.get("patch_available", False)),
            patch_urls=normalized.get("patch_urls", []),
            references=normalized.get("references", []),
            sources=normalized.get("sources", []),
            dedup_hash=new_hash,
            update_history=[
                {"timestamp": datetime.now(timezone.utc).isoformat(), "action": "created", "sources": normalized.get("sources", [])}
            ],
            published_at=normalized.get("published_at"),
            last_modified_at=normalized.get("last_modified_at"),
        )
        db.add(record)
        return "created"

    merged_sources = sorted(set(existing.sources or []) | set(normalized.get("sources", [])))
    is_kev_now = existing.is_kev or bool(normalized.get("is_kev"))
    patch_now = existing.patch_available or bool(normalized.get("patch_available"))

    if (
        existing.dedup_hash == new_hash
        and merged_sources == sorted(existing.sources or [])
        and is_kev_now == existing.is_kev
        and patch_now == existing.patch_available
    ):
        return "duplicate"

    existing.sources = merged_sources
    existing.is_kev = is_kev_now
    if normalized.get("kev_date_added") and not existing.kev_date_added:
        existing.kev_date_added = normalized["kev_date_added"]
    existing.patch_available = patch_now
    existing.patch_urls = sorted(set(existing.patch_urls or []) | set(normalized.get("patch_urls", [])))[:15]
    existing.references = sorted(set(existing.references or []) | set(normalized.get("references", [])))[:20]
    if normalized.get("cvss_score") is not None and existing.cvss_score is None:
        existing.cvss_score = normalized["cvss_score"]
        existing.severity = normalized["severity"]
        existing.cvss_vector = normalized.get("cvss_vector")
    if normalized.get("affected_products"):
        if not existing.affected_products:
            existing.affected_products = normalized["affected_products"]
    existing.dedup_hash = new_hash
    history = list(existing.update_history or [])
    history.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "updated",
        "sources": normalized.get("sources", []),
    })
    existing.update_history = history[-20:]
    return "updated"

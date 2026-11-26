from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.engines.intelligence.cisa_kev_collector import fetch_cisa_kev
from app.engines.intelligence.cve_collector import fetch_cve_program_records
from app.engines.intelligence.data_normalizer import (
    normalize_cve_program_item,
    normalize_github_advisory,
    normalize_kev_item,
    normalize_nvd_item,
)
from app.engines.intelligence.deduplication import upsert_cve_record
from app.engines.intelligence.github_advisory_collector import fetch_github_advisories
from app.engines.intelligence.nvd_collector import fetch_nvd_cves
from app.engines.intelligence.vendor_advisory_collector import fetch_vendor_and_owasp_advisories
from app.models.advisory import SecurityAdvisory, SyncLog
from app.utils.date_utils import parse_iso_datetime


def _upsert_advisory(db: Session, adv: dict[str, Any]) -> str:
    existing = db.query(SecurityAdvisory).filter(SecurityAdvisory.advisory_id == adv["advisory_id"]).first()
    if existing:
        return "duplicate"
    pub = adv.get("published_at")
    if isinstance(pub, str):
        pub = parse_iso_datetime(pub)
    db.add(
        SecurityAdvisory(
            advisory_id=adv["advisory_id"],
            source=adv["source"],
            title=adv["title"][:500],
            summary=adv["summary"],
            severity=adv.get("severity", "medium"),
            cve_ids=adv.get("cve_ids", []),
            affected_packages=adv.get("affected_packages", []),
            advisory_url=adv.get("advisory_url"),
            published_at=pub,
        )
    )
    return "created"


def sync_intelligence_sources(
    db: Session,
    sources: list[str] | None = None,
    days_back: int = 7,
) -> list[SyncLog]:
    """Run synchronization across specified threat intelligence feeds and log each outcome."""
    selected = sources or ["nvd", "cisa_kev", "github", "cve_program", "vendor"]
    logs: list[SyncLog] = []

    for src in selected:
        started_at = datetime.now(timezone.utc)
        fetched = created = updated = skipped = 0
        error_msg = None
        status = "completed"
        details: dict[str, Any] = {}

        if src == "nvd":
            res = fetch_nvd_cves(days_back=days_back)
            if not res["ok"]:
                status = "failed"
                error_msg = res.get("error")
            for item in res["items"]:
                norm = normalize_nvd_item(item)
                if not norm:
                    continue
                fetched += 1
                outcome = upsert_cve_record(db, norm)
                if outcome == "created":
                    created += 1
                elif outcome == "updated":
                    updated += 1
                else:
                    skipped += 1

        elif src == "cisa_kev":
            res = fetch_cisa_kev()
            if not res["ok"]:
                status = "failed"
                error_msg = res.get("error")
            for item in res["items"]:
                norm = normalize_kev_item(item)
                if not norm:
                    continue
                fetched += 1
                outcome = upsert_cve_record(db, norm)
                if outcome == "created":
                    created += 1
                elif outcome == "updated":
                    updated += 1
                else:
                    skipped += 1

        elif src == "github":
            res = fetch_github_advisories()
            if not res["ok"]:
                status = "failed"
                error_msg = res.get("error")
            for item in res["items"]:
                cve_rec, adv_rec = normalize_github_advisory(item)
                if cve_rec:
                    fetched += 1
                    outcome = upsert_cve_record(db, cve_rec)
                    if outcome == "created":
                        created += 1
                    elif outcome == "updated":
                        updated += 1
                    else:
                        skipped += 1
                if adv_rec:
                    adv_res = _upsert_advisory(db, adv_rec)
                    if adv_res == "created":
                        created += 1
                    else:
                        skipped += 1

        elif src == "cve_program":
            res = fetch_cve_program_records()
            if not res["ok"]:
                status = "failed"
                error_msg = res.get("error")
            for item in res["items"]:
                norm = normalize_cve_program_item(item)
                if not norm:
                    continue
                fetched += 1
                outcome = upsert_cve_record(db, norm)
                if outcome == "created":
                    created += 1
                elif outcome == "updated":
                    updated += 1
                else:
                    skipped += 1

        elif src in {"vendor", "owasp"}:
            res = fetch_vendor_and_owasp_advisories()
            if not res["ok"]:
                status = "partial"
                error_msg = "; ".join(res.get("errors", []))
            for adv in res["items"]:
                fetched += 1
                adv_res = _upsert_advisory(db, adv)
                if adv_res == "created":
                    created += 1
                else:
                    skipped += 1

        log = SyncLog(
            source=src,
            status=status,
            records_fetched=fetched,
            records_created=created,
            records_updated=updated,
            duplicates_skipped=skipped,
            details=details,
            error_message=error_msg,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        logs.append(log)

    return logs

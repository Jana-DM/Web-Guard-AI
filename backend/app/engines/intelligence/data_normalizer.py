from __future__ import annotations

from typing import Any

from app.utils.date_utils import parse_iso_datetime


def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def normalize_nvd_item(raw: dict[str, Any]) -> dict[str, Any] | None:
    cve = raw.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    descriptions = cve.get("descriptions") or []
    desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    if not desc and descriptions:
        desc = descriptions[0].get("value", "")

    metrics = cve.get("metrics") or {}
    cvss_score = None
    cvss_vector = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key)
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            break

    cwe_ids: list[str] = []
    for weak in cve.get("weaknesses") or []:
        for wd in weak.get("description") or []:
            val = wd.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    refs = [r.get("url") for r in (cve.get("references") or []) if r.get("url")]
    patch_urls = [
        r.get("url")
        for r in (cve.get("references") or [])
        if r.get("url") and ("Patch" in (r.get("tags") or []) or "Vendor Advisory" in (r.get("tags") or []))
    ]

    affected_products: list[dict[str, Any]] = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5:
                    affected_products.append({
                        "vendor": parts[3],
                        "product": parts[4],
                        "version_eq": parts[5] if parts[5] not in ("*", "-") else None,
                        "version_start": match.get("versionStartIncluding"),
                        "version_lt": match.get("versionEndExcluding"),
                        "version_le": match.get("versionEndIncluding"),
                    })

    return {
        "cve_id": cve_id,
        "title": f"{cve_id}: {desc[:120]}" if desc else cve_id,
        "description": desc or "No NVD description provided.",
        "severity": _cvss_to_severity(cvss_score),
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe_ids": sorted(set(cwe_ids)),
        "affected_products": affected_products[:25],
        "is_kev": False,
        "kev_date_added": None,
        "patch_available": len(patch_urls) > 0,
        "patch_urls": patch_urls[:10],
        "references": refs[:15],
        "sources": ["nvd"],
        "published_at": parse_iso_datetime(cve.get("published")),
        "last_modified_at": parse_iso_datetime(cve.get("lastModified")),
    }


def normalize_kev_item(raw: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = raw.get("cveID")
    if not cve_id:
        return None
    vendor = raw.get("vendorProject", "")
    product = raw.get("product", "")
    return {
        "cve_id": cve_id,
        "title": f"{cve_id}: {raw.get('vulnerabilityName', cve_id)}",
        "description": raw.get("shortDescription", ""),
        "severity": "critical",
        "cvss_score": None,
        "cvss_vector": None,
        "cwe_ids": raw.get("cwes", []) if isinstance(raw.get("cwes"), list) else [],
        "affected_products": [{"vendor": vendor.lower(), "product": product.lower()}] if product else [],
        "is_kev": True,
        "kev_date_added": raw.get("dateAdded"),
        "patch_available": bool(raw.get("requiredAction")),
        "patch_urls": [],
        "references": ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
        "sources": ["cisa_kev"],
        "published_at": parse_iso_datetime(raw.get("dateAdded")),
        "last_modified_at": parse_iso_datetime(raw.get("dueDate")),
    }


def normalize_github_advisory(raw: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    ghsa_id = raw.get("ghsa_id")
    cve_id = raw.get("cve_id")
    severity = (raw.get("severity") or "medium").lower()
    affected: list[dict[str, Any]] = []
    for vuln in raw.get("vulnerabilities") or []:
        pkg = vuln.get("package") or {}
        if pkg.get("name"):
            affected.append({
                "vendor": pkg.get("ecosystem", "").lower(),
                "product": pkg.get("name", "").lower(),
                "vulnerable_range": vuln.get("vulnerable_version_range"),
                "patched_versions": vuln.get("first_patched_version"),
            })

    advisory_record = None
    if ghsa_id:
        advisory_record = {
            "advisory_id": ghsa_id,
            "source": "github",
            "title": raw.get("summary") or ghsa_id,
            "summary": (raw.get("description") or raw.get("summary") or "")[:2000],
            "severity": severity,
            "cve_ids": [cve_id] if cve_id else [],
            "affected_packages": affected,
            "advisory_url": raw.get("html_url"),
            "published_at": parse_iso_datetime(raw.get("published_at")),
        }

    cve_record = None
    if cve_id:
        cvss = raw.get("cvss") or {}
        cve_record = {
            "cve_id": cve_id,
            "title": f"{cve_id}: {raw.get('summary') or cve_id}",
            "description": raw.get("description") or raw.get("summary") or "",
            "severity": severity,
            "cvss_score": cvss.get("score"),
            "cvss_vector": cvss.get("vector_string"),
            "cwe_ids": [c.get("cwe_id") for c in (raw.get("cwes") or []) if c.get("cwe_id")],
            "affected_products": affected,
            "is_kev": False,
            "kev_date_added": None,
            "patch_available": any(a.get("patched_versions") for a in affected),
            "patch_urls": [raw.get("html_url")] if raw.get("html_url") else [],
            "references": [raw.get("html_url")] if raw.get("html_url") else [],
            "sources": ["github"],
            "published_at": parse_iso_datetime(raw.get("published_at")),
            "last_modified_at": parse_iso_datetime(raw.get("updated_at")),
        }

    return cve_record, advisory_record


def normalize_cve_program_item(raw: dict[str, Any]) -> dict[str, Any] | None:
    # Supports both CVE 5.0 JSON and CIRCL CVE format
    cve_id = raw.get("id") or (raw.get("cveMetadata") or {}).get("cveId")
    if not cve_id:
        return None
    summary = raw.get("summary") or ""
    if not summary and "containers" in raw:
        descs = ((raw["containers"].get("cna") or {}).get("descriptions")) or []
        summary = descs[0].get("value", "") if descs else ""
    cvss = raw.get("cvss")
    return {
        "cve_id": cve_id,
        "title": f"{cve_id}: {summary[:120]}" if summary else cve_id,
        "description": summary or "CVE Program record.",
        "severity": _cvss_to_severity(float(cvss)) if isinstance(cvss, (int, float)) else "medium",
        "cvss_score": float(cvss) if isinstance(cvss, (int, float)) else None,
        "cvss_vector": raw.get("cvss-vector"),
        "cwe_ids": [raw["cwe"]] if raw.get("cwe") else [],
        "affected_products": [],
        "is_kev": False,
        "kev_date_added": None,
        "patch_available": False,
        "patch_urls": [],
        "references": (raw.get("references") or [])[:10],
        "sources": ["cve_program"],
        "published_at": parse_iso_datetime(raw.get("Published")),
        "last_modified_at": parse_iso_datetime(raw.get("Modified")),
    }

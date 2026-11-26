from __future__ import annotations

from typing import Any

import dns.resolver


def analyze_dns(domain: str) -> dict[str, Any]:
    """Inspect DNS records (A, AAAA, MX, NS, TXT, CAA) and email/cert security policies."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CAA"]
    records: dict[str, list[str]] = {}

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=4.0)
            records[rtype] = [r.to_text() for r in answers]
        except Exception:
            records[rtype] = []

    dmarc_records: list[str] = []
    try:
        dmarc_ans = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=4.0)
        dmarc_records = [r.to_text() for r in dmarc_ans]
    except Exception:
        pass

    txt_joined = " ".join(records.get("TXT", []))
    has_spf = "v=spf1" in txt_joined.lower()
    has_dmarc = any("v=dmarc1" in rec.lower() for rec in dmarc_records)
    has_caa = len(records.get("CAA", [])) > 0

    issues: list[dict[str, Any]] = []
    if not has_spf:
        issues.append({
            "title": "Missing SPF DNS Record",
            "severity": "low",
            "cwe_id": "CWE-290",
            "category": "DNS Configuration",
            "description": f"No SPF (v=spf1) TXT record was observed on {domain}, increasing email spoofing risk.",
            "evidence": {"checked_domain": domain, "txt_records": records.get("TXT", [])},
        })
    if not has_dmarc:
        issues.append({
            "title": "Missing DMARC Policy Record",
            "severity": "low",
            "cwe_id": "CWE-290",
            "category": "DNS Configuration",
            "description": f"No DMARC policy record was found at _dmarc.{domain}.",
            "evidence": {"checked_domain": f"_dmarc.{domain}", "dmarc_records": dmarc_records},
        })
    if not has_caa:
        issues.append({
            "title": "Missing CAA DNS Record",
            "severity": "info",
            "cwe_id": "CWE-295",
            "category": "DNS Configuration",
            "description": f"No Certification Authority Authorization (CAA) record is configured for {domain}.",
            "evidence": {"checked_domain": domain, "caa_records": []},
        })

    return {
        "domain": domain,
        "records": records,
        "dmarc_records": dmarc_records,
        "has_spf": has_spf,
        "has_dmarc": has_dmarc,
        "has_caa": has_caa,
        "issues": issues,
    }

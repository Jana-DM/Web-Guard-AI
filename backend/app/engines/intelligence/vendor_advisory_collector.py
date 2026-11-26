from __future__ import annotations

from typing import Any

import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

OWASP_CORE_REFERENCES = [
    {
        "advisory_id": "OWASP-TOP10-A01-2021",
        "source": "owasp",
        "title": "OWASP A01:2021 — Broken Access Control",
        "summary": "Enforce server-side ownership checks, deny by default, and validate authorization tokens on every endpoint.",
        "severity": "high",
        "cve_ids": [],
        "affected_packages": [],
        "advisory_url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    {
        "advisory_id": "OWASP-TOP10-A03-2021",
        "source": "owasp",
        "title": "OWASP A03:2021 — Injection",
        "summary": "Use parameterized database queries, safe AST/API bindings, and strict input validation to prevent SQL/OS injection.",
        "severity": "critical",
        "cve_ids": [],
        "affected_packages": [],
        "advisory_url": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    {
        "advisory_id": "OWASP-TOP10-A10-2021",
        "source": "owasp",
        "title": "OWASP A10:2021 — Server-Side Request Forgery (SSRF)",
        "summary": "Validate target domains, block private/reserved IPs on DNS resolution, and verify every redirect target.",
        "severity": "high",
        "cve_ids": [],
        "affected_packages": [],
        "advisory_url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    },
]


def fetch_vendor_and_owasp_advisories() -> dict[str, Any]:
    """Fetch vendor ecosystem advisories via OSV.dev and synchronize OWASP reference entries."""
    items: list[dict[str, Any]] = list(OWASP_CORE_REFERENCES)
    errors: list[str] = []

    for ecosystem, pkg in (("PyPI", "django"), ("PyPI", "fastapi"), ("npm", "express")):
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(OSV_QUERY_URL, json={"package": {"ecosystem": ecosystem, "name": pkg}})
                resp.raise_for_status()
                vulns = resp.json().get("vulns", [])[:5]
                for v in vulns:
                    aliases = v.get("aliases", [])
                    cves = [a for a in aliases if a.startswith("CVE-")]
                    items.append({
                        "advisory_id": v.get("id", f"OSV-{pkg}"),
                        "source": "vendor",
                        "title": v.get("summary") or f"{pkg} Advisory ({v.get('id')})",
                        "summary": (v.get("details") or v.get("summary") or "")[:1500],
                        "severity": "high" if cves else "medium",
                        "cve_ids": cves,
                        "affected_packages": [{"ecosystem": ecosystem.lower(), "package": pkg}],
                        "advisory_url": f"https://osv.dev/vulnerability/{v.get('id')}",
                        "published_at": v.get("published"),
                    })
        except Exception as exc:
            errors.append(f"{ecosystem}/{pkg}: {exc}")

    return {"ok": len(errors) < 3, "source": "vendor", "items": items, "errors": errors}

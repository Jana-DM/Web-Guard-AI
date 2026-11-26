from __future__ import annotations

from typing import Any

import httpx

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kev(limit: int = 40) -> dict[str, Any]:
    """Fetch CISA Known Exploited Vulnerabilities (KEV) catalog."""
    try:
        with httpx.Client(timeout=15.0, headers={"User-Agent": "WebGuardAI-IntelSync/1.0"}) as client:
            resp = client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            # Take newest additions first
            vulns_sorted = sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:limit]
            return {"ok": True, "source": "cisa_kev", "items": vulns_sorted}
    except Exception as exc:
        return {"ok": False, "source": "cisa_kev", "items": [], "error": str(exc)}

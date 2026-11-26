from __future__ import annotations

from typing import Any

import httpx

CIRCL_CVE_LAST_URL = "https://cve.circl.lu/api/last/20"


def fetch_cve_program_records(limit: int = 20) -> dict[str, Any]:
    """Fetch recent CVE Program JSON records from public CVE feed."""
    try:
        with httpx.Client(timeout=15.0, headers={"User-Agent": "WebGuardAI-IntelSync/1.0"}) as client:
            resp = client.get(CIRCL_CVE_LAST_URL)
            resp.raise_for_status()
            payload = resp.json()
            items = payload[:limit] if isinstance(payload, list) else []
            return {"ok": True, "source": "cve_program", "items": items}
    except Exception as exc:
        return {"ok": False, "source": "cve_program", "items": [], "error": str(exc)}

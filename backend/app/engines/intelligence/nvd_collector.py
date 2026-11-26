from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.config import get_settings

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_nvd_cves(days_back: int = 7, results_per_page: int = 25) -> dict[str, Any]:
    """Fetch recent CVEs from the official NVD 2.0 API."""
    settings = get_settings()
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(days=days_back)

    params = {
        "pubStartDate": start_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": results_per_page,
    }
    headers = {"User-Agent": "WebGuardAI-IntelSync/1.0"}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(NVD_API_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return {"ok": True, "source": "nvd", "items": data.get("vulnerabilities", [])}
    except Exception as exc:
        return {"ok": False, "source": "nvd", "items": [], "error": str(exc)}

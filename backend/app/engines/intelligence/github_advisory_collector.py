from __future__ import annotations

from typing import Any

import httpx

from app.config import get_settings

GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"


def fetch_github_advisories(per_page: int = 25) -> dict[str, Any]:
    """Fetch reviewed security advisories from GitHub Advisory Database."""
    settings = get_settings()
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "WebGuardAI-IntelSync/1.0",
    }
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"

    try:
        with httpx.Client(timeout=15.0, headers=headers) as client:
            resp = client.get(GITHUB_ADVISORIES_URL, params={"per_page": per_page, "type": "reviewed"})
            resp.raise_for_status()
            data = resp.json()
            items = data if isinstance(data, list) else []
            return {"ok": True, "source": "github", "items": items}
    except Exception as exc:
        return {"ok": False, "source": "github", "items": [], "error": str(exc)}

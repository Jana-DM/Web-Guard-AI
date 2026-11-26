from __future__ import annotations

from typing import Any


def build_exposure_summary(
    fingerprints: list[dict[str, Any]],
    correlations: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
) -> dict[str, Any]:
    verified_cves = [c for c in correlations if c.get("status") == "Verified affected configuration"]
    potential_cves = [c for c in correlations if c.get("status") == "Potentially affected"]
    kev_hits = [c for c in correlations if c.get("is_kev")]

    return {
        "detected_technologies": len(fingerprints),
        "discovered_endpoints": len(endpoints),
        "verified_affected_cves": len(verified_cves),
        "potentially_affected_cves": len(potential_cves),
        "kev_matched_count": len(kev_hits),
        "note": "Technology detection alone does not confirm exploitability; only verified version ranges and evidence confirm exposure.",
    }

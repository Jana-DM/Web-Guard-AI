from __future__ import annotations

from typing import Any

from app.engines.domain_scanner.target_validator import resolve_and_validate_host, safe_fetch


def run_passive_recon(domain: str, base_url: str) -> dict[str, Any]:
    """Collect non-intrusive public metadata (resolved IPs, robots.txt, security.txt, sitemap.xml)."""
    resolved_ips = resolve_and_validate_host(domain)
    artifacts: dict[str, Any] = {
        "domain": domain,
        "resolved_ips": resolved_ips,
        "robots_txt": None,
        "security_txt": None,
        "sitemap_urls": [],
    }

    for path, key in (
        ("/robots.txt", "robots_txt"),
        ("/.well-known/security.txt", "security_txt"),
    ):
        try:
            resp = safe_fetch(f"{base_url.rstrip('/')}{path}", allowed_domain=domain)
            if resp.status_code == 200 and len(resp.text) < 65536:
                artifacts[key] = resp.text[:4000]
        except Exception:
            pass

    try:
        sitemap_resp = safe_fetch(f"{base_url.rstrip('/')}/sitemap.xml", allowed_domain=domain)
        if sitemap_resp.status_code == 200 and "<loc>" in sitemap_resp.text:
            import re

            locs = re.findall(r"<loc>(.*?)</loc>", sitemap_resp.text)
            artifacts["sitemap_urls"] = locs[:50]
    except Exception:
        pass

    return artifacts

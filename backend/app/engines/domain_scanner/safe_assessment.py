from __future__ import annotations

from typing import Any

from app.engines.domain_scanner.authorization import assert_target_authorized
from app.engines.domain_scanner.dns_analysis import analyze_dns
from app.engines.domain_scanner.endpoint_discovery import discover_endpoints
from app.engines.domain_scanner.header_analysis import analyze_headers_and_cookies
from app.engines.domain_scanner.passive_recon import run_passive_recon
from app.engines.domain_scanner.target_validator import safe_fetch
from app.engines.domain_scanner.technology_detection import detect_technologies
from app.engines.domain_scanner.tls_analysis import analyze_tls
from app.models.authorized_target import AuthorizedTarget


def run_safe_domain_assessment(
    target: AuthorizedTarget,
    enable_safe_owasp_checks: bool = True,
    max_endpoints: int = 25,
) -> dict[str, Any]:
    """Execute a complete, authorized, non-destructive domain assessment."""
    assert_target_authorized(target)

    domain = target.domain
    base_url = target.normalized_url
    allowed_paths = target.allowed_paths or ["/"]

    recon = run_passive_recon(domain, base_url)
    dns_report = analyze_dns(domain)
    tls_report = analyze_tls(domain)

    # Main HTTP fetch + safe CORS reflection probe
    main_resp = safe_fetch(base_url, allowed_domain=domain, allowed_paths=allowed_paths)
    cors_resp = safe_fetch(
        base_url,
        allowed_domain=domain,
        allowed_paths=allowed_paths,
        extra_headers={"Origin": "https://evil-untrusted-origin.example"},
    )

    set_cookies = main_resp.headers.get_list("set-cookie") if hasattr(main_resp.headers, "get_list") else []
    header_report = analyze_headers_and_cookies(
        url=str(main_resp.url),
        headers=dict(main_resp.headers),
        set_cookie_headers=set_cookies,
        cors_probe_headers=dict(cors_resp.headers),
    )

    fingerprints = detect_technologies(
        headers={k.lower(): v for k, v in main_resp.headers.items()},
        html_body=main_resp.text,
        cookies=set_cookies,
    )

    endpoints = discover_endpoints(
        base_url=str(main_resp.url),
        allowed_domain=domain,
        html_body=main_resp.text,
        sitemap_urls=recon.get("sitemap_urls", []),
        allowed_paths=allowed_paths,
        max_endpoints=max_endpoints,
    )

    owasp_issues: list[dict[str, Any]] = []
    if enable_safe_owasp_checks:
        # Non-destructive checks: HTTP->HTTPS transport, directory listing, sensitive public files
        if base_url.startswith("http://"):
            owasp_issues.append({
                "title": "Unencrypted HTTP Base URL",
                "severity": "medium",
                "cwe_id": "CWE-319",
                "category": "OWASP A02 Cryptographic Failures",
                "description": f"Target {base_url} uses plaintext HTTP without TLS.",
                "evidence": {"url": base_url},
            })

        if "Index of /" in main_resp.text and "<title>Index of" in main_resp.text:
            owasp_issues.append({
                "title": "Directory Listing Enabled",
                "severity": "medium",
                "cwe_id": "CWE-548",
                "category": "OWASP A05 Security Misconfiguration",
                "description": f"Web server at {main_resp.url} exposes directory index listings.",
                "evidence": {"url": str(main_resp.url), "indicator": "Index of /"},
            })

        # Safe check for accidentally exposed .git/HEAD or .env (read-only status check)
        for sensitive_path, label in (("/.git/HEAD", ".git repository"), ("/.env", ".env configuration")):
            try:
                probe_url = f"{base_url.rstrip('/')}{sensitive_path}"
                probe = safe_fetch(probe_url, allowed_domain=domain)
                if probe.status_code == 200 and (
                    ("ref: refs/" in probe.text and sensitive_path == "/.git/HEAD")
                    or ("=" in probe.text and "SECRET" in probe.text.upper() and sensitive_path == "/.env")
                ):
                    owasp_issues.append({
                        "title": f"Exposed {label} File",
                        "severity": "critical",
                        "cwe_id": "CWE-200",
                        "category": "OWASP A05 Security Misconfiguration",
                        "description": f"Sensitive resource {probe_url} returned HTTP 200 with recognizable contents.",
                        "evidence": {"url": probe_url, "status_code": probe.status_code, "excerpt": probe.text[:160]},
                    })
            except Exception:
                pass

    raw_findings: list[dict[str, Any]] = []
    for item in dns_report["issues"] + tls_report["issues"] + header_report["issues"] + owasp_issues:
        item.setdefault("location", str(main_resp.url))
        item.setdefault("source_engine", "domain_scanner")
        raw_findings.append(item)

    return {
        "recon": recon,
        "dns": dns_report,
        "tls": tls_report,
        "headers": header_report,
        "fingerprints": fingerprints,
        "endpoints": endpoints,
        "raw_findings": raw_findings,
        "http_status": main_resp.status_code,
        "final_url": str(main_resp.url),
    }

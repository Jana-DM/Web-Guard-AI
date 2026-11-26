from __future__ import annotations

from typing import Any


REQUIRED_SECURITY_HEADERS = [
    ("strict-transport-security", "Missing Strict-Transport-Security (HSTS) Header", "medium", "CWE-319"),
    ("content-security-policy", "Missing Content-Security-Policy (CSP) Header", "medium", "CWE-693"),
    ("x-frame-options", "Missing X-Frame-Options Clickjacking Protection", "low", "CWE-1021"),
    ("x-content-type-options", "Missing X-Content-Type-Options Header", "low", "CWE-16"),
    ("referrer-policy", "Missing Referrer-Policy Header", "info", "CWE-200"),
]


def analyze_headers_and_cookies(
    url: str,
    headers: dict[str, str],
    set_cookie_headers: list[str],
    cors_probe_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    lower_headers = {k.lower(): v for k, v in headers.items()}
    issues: list[dict[str, Any]] = []

    for h_name, title, severity, cwe in REQUIRED_SECURITY_HEADERS:
        if h_name == "strict-transport-security" and not url.startswith("https://"):
            continue
        if h_name not in lower_headers:
            issues.append({
                "title": title,
                "severity": severity,
                "cwe_id": cwe,
                "category": "HTTP Security Headers",
                "description": f"Response from {url} is missing the '{h_name}' security header.",
                "evidence": {"url": url, "missing_header": h_name, "observed_headers": list(lower_headers.keys())},
            })

    if lower_headers.get("x-content-type-options", "").lower() not in ("", "nosniff"):
        issues.append({
            "title": "Weak X-Content-Type-Options Configuration",
            "severity": "low",
            "cwe_id": "CWE-16",
            "category": "HTTP Security Headers",
            "description": "X-Content-Type-Options should be set strictly to 'nosniff'.",
            "evidence": {"url": url, "header_value": lower_headers["x-content-type-options"]},
        })

    # Cookie security checks
    cookie_findings: list[dict[str, Any]] = []
    for raw_cookie in set_cookie_headers:
        cookie_name = raw_cookie.split("=", 1)[0].strip()
        lower_cookie = raw_cookie.lower()
        missing_flags = []
        if url.startswith("https://") and "secure" not in lower_cookie:
            missing_flags.append("Secure")
        if "httponly" not in lower_cookie:
            missing_flags.append("HttpOnly")
        if "samesite" not in lower_cookie:
            missing_flags.append("SameSite")

        cookie_findings.append({"name": cookie_name, "missing_flags": missing_flags})
        if missing_flags:
            issues.append({
                "title": f"Insecure Cookie Flags on '{cookie_name}'",
                "severity": "medium" if "HttpOnly" in missing_flags or "Secure" in missing_flags else "low",
                "cwe_id": "CWE-614",
                "category": "Cookie Security",
                "description": f"Cookie '{cookie_name}' lacks security attributes: {', '.join(missing_flags)}.",
                "evidence": {"url": url, "cookie_name": cookie_name, "missing_flags": missing_flags},
            })

    # CORS evaluation
    cors_headers = {k.lower(): v for k, v in (cors_probe_headers or lower_headers).items()}
    acao = cors_headers.get("access-control-allow-origin", "")
    acac = cors_headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        issues.append({
            "title": "Insecure Wildcard CORS With Credentials",
            "severity": "high",
            "cwe_id": "CWE-942",
            "category": "CORS Misconfiguration",
            "description": "Server returns Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.",
            "evidence": {"url": url, "acao": acao, "acac": acac},
        })
    elif "https://evil-untrusted-origin.example" in acao and acac == "true":
        issues.append({
            "title": "Arbitrary Origin Reflection in CORS With Credentials",
            "severity": "high",
            "cwe_id": "CWE-942",
            "category": "CORS Misconfiguration",
            "description": "Server reflects arbitrary untrusted Origin header while allowing credentials.",
            "evidence": {"url": url, "reflected_origin": acao, "acac": acac},
        })

    return {
        "headers": lower_headers,
        "cookies": cookie_findings,
        "cors": {"acao": acao, "acac": acac},
        "issues": issues,
    }

from __future__ import annotations

import re
from typing import Any


HEADER_PRODUCT_PATTERNS = [
    (re.compile(r"nginx(?:/([\d.]+))?", re.I), "nginx", "web_server"),
    (re.compile(r"apache(?:/([\d.]+))?", re.I), "apache", "web_server"),
    (re.compile(r"cloudflare", re.I), "cloudflare", "cdn"),
    (re.compile(r"express", re.I), "express", "framework"),
    (re.compile(r"php(?:/([\d.]+))?", re.I), "php", "runtime"),
    (re.compile(r"asp\.net", re.I), "aspnet", "framework"),
    (re.compile(r"uvicorn", re.I), "uvicorn", "asgi_server"),
    (re.compile(r"gunicorn(?:/([\d.]+))?", re.I), "gunicorn", "wsgi_server"),
]

HTML_PRODUCT_PATTERNS = [
    (re.compile(r"wp-content|WordPress\s*([\d.]+)?", re.I), "wordpress", "cms"),
    (re.compile(r"jquery[.-]([\d.]+)(?:\.min)?\.js", re.I), "jquery", "js_library"),
    (re.compile(r"react(?:\.production\.min\.js|@([\d.]+))", re.I), "react", "frontend_framework"),
    (re.compile(r"next(?:/|data|_next/static)", re.I), "nextjs", "frontend_framework"),
    (re.compile(r"bootstrap[.-]([\d.]+)", re.I), "bootstrap", "ui_framework"),
    (re.compile(r"django|csrfmiddlewaretoken", re.I), "django", "framework"),
]


def detect_technologies(headers: dict[str, str], html_body: str, cookies: list[str]) -> list[dict[str, Any]]:
    """Fingerprint technologies and extract observed versions without fabricating unverified numbers."""
    detected: dict[str, dict[str, Any]] = {}

    for header_name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        val = headers.get(header_name)
        if not val:
            continue
        for pattern, product, category in HEADER_PRODUCT_PATTERNS:
            m = pattern.search(val)
            if m:
                version = m.group(1) if m.lastindex else None
                detected[product] = {
                    "product_name": product,
                    "version": version,
                    "category": category,
                    "detection_source": f"header:{header_name}",
                    "confidence": 0.9 if version else 0.75,
                    "raw_evidence": {"header": header_name, "value": val},
                }

    for pattern, product, category in HTML_PRODUCT_PATTERNS:
        m = pattern.search(html_body[:200000])
        if m and product not in detected:
            version = m.group(1) if m.lastindex else None
            detected[product] = {
                "product_name": product,
                "version": version,
                "category": category,
                "detection_source": "html_body",
                "confidence": 0.85 if version else 0.7,
                "raw_evidence": {"matched_snippet": m.group(0)[:120]},
            }

    cookie_joined = " ".join(cookies).lower()
    if "phpsessid" in cookie_joined and "php" not in detected:
        detected["php"] = {
            "product_name": "php",
            "version": None,
            "category": "runtime",
            "detection_source": "cookie:PHPSESSID",
            "confidence": 0.8,
            "raw_evidence": {"cookie": "PHPSESSID"},
        }
    if "csrftoken" in cookie_joined and "django" not in detected:
        detected["django"] = {
            "product_name": "django",
            "version": None,
            "category": "framework",
            "detection_source": "cookie:csrftoken",
            "confidence": 0.65,
            "raw_evidence": {"cookie": "csrftoken"},
        }

    return list(detected.values())

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from app.engines.domain_scanner.target_validator import resolve_and_validate_host


def analyze_tls(domain: str, port: int = 443) -> dict[str, Any]:
    """Perform safe TLS handshake inspection after SSRF validation."""
    resolved_ips = resolve_and_validate_host(domain)
    connect_host = resolved_ips[0]
    context = ssl.create_default_context()
    issues: list[dict[str, Any]] = []

    try:
        with socket.create_connection((connect_host, port), timeout=5.0) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                protocol = tls_sock.version()

        not_after_raw = cert.get("notAfter") if cert else None
        days_remaining = None
        if not_after_raw:
            expiry = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_remaining = (expiry - datetime.now(timezone.utc)).days
            if days_remaining < 0:
                issues.append({
                    "title": "Expired TLS Certificate",
                    "severity": "high",
                    "cwe_id": "CWE-295",
                    "category": "TLS Security",
                    "description": f"The TLS certificate for {domain} expired {-days_remaining} days ago.",
                    "evidence": {"not_after": not_after_raw, "days_remaining": days_remaining},
                })
            elif days_remaining < 21:
                issues.append({
                    "title": "TLS Certificate Expiring Soon",
                    "severity": "medium",
                    "cwe_id": "CWE-295",
                    "category": "TLS Security",
                    "description": f"The TLS certificate for {domain} expires in {days_remaining} days.",
                    "evidence": {"not_after": not_after_raw, "days_remaining": days_remaining},
                })

        if protocol in {"TLSv1", "TLSv1.1", "SSLv3"}:
            issues.append({
                "title": f"Deprecated TLS Protocol Negotiated ({protocol})",
                "severity": "high",
                "cwe_id": "CWE-326",
                "category": "TLS Security",
                "description": f"{domain} negotiated deprecated protocol {protocol}. Upgrade to TLS 1.2+ / TLS 1.3.",
                "evidence": {"negotiated_protocol": protocol, "cipher": cipher},
            })

        return {
            "tls_enabled": True,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher and len(cipher) >= 3 else None,
            "subject": dict(x[0] for x in cert.get("subject", ())) if cert else {},
            "issuer": dict(x[0] for x in cert.get("issuer", ())) if cert else {},
            "not_after": not_after_raw,
            "days_remaining": days_remaining,
            "issues": issues,
        }
    except ssl.SSLCertVerificationError as exc:
        issues.append({
            "title": "Untrusted or Invalid TLS Certificate",
            "severity": "high",
            "cwe_id": "CWE-295",
            "category": "TLS Security",
            "description": f"TLS certificate verification failed for {domain}: {exc}",
            "evidence": {"ssl_error": str(exc)},
        })
        return {"tls_enabled": True, "error": str(exc), "issues": issues}
    except Exception as exc:
        return {"tls_enabled": False, "error": str(exc), "issues": issues}

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import dns.resolver

from app.core.exceptions import UnauthorizedTargetError
from app.engines.domain_scanner.target_validator import safe_fetch
from app.models.authorized_target import AuthorizedTarget


def generate_verification_token() -> str:
    return f"webguard-verify-{secrets.token_hex(16)}"


def verification_expiry(days: int = 7) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)


def verify_dns_txt(domain: str, expected_token: str) -> tuple[bool, dict[str, Any]]:
    records_checked: list[str] = []
    for candidate in (f"_webguard-verify.{domain}", domain):
        try:
            answers = dns.resolver.resolve(candidate, "TXT", lifetime=5.0)
            for rdata in answers:
                txt_value = "".join(
                    part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                    for part in getattr(rdata, "strings", [rdata.to_text().strip('"')])
                )
                records_checked.append(f"{candidate}: {txt_value}")
                if expected_token in txt_value:
                    return True, {"matched_record": candidate, "txt_values": records_checked}
        except Exception as exc:
            records_checked.append(f"{candidate}: lookup error ({exc})")
    return False, {"checked": records_checked, "reason": "Expected TXT verification token not found."}


def verify_http_well_known(domain: str, normalized_url: str, expected_token: str) -> tuple[bool, dict[str, Any]]:
    well_known_url = f"{normalized_url.rstrip('/')}/.well-known/webguard-verify.txt"
    try:
        resp = safe_fetch(well_known_url, allowed_domain=domain)
        if resp.status_code == 200 and expected_token in resp.text:
            return True, {"url": well_known_url, "status_code": resp.status_code}
        return False, {
            "url": well_known_url,
            "status_code": resp.status_code,
            "reason": "Verification token missing from /.well-known/webguard-verify.txt",
        }
    except Exception as exc:
        return False, {"url": well_known_url, "reason": f"HTTP verification failed: {exc}"}


def verify_explicit_authorization(
    domain: str,
    signed_statement: str | None,
    expected_token: str,
) -> tuple[bool, dict[str, Any]]:
    if not signed_statement or len(signed_statement.strip()) < 15:
        return False, {"reason": "Explicit authorization requires a written authorization statement (>= 15 chars)."}
    return True, {
        "method": "explicit_authorization",
        "domain": domain,
        "token_ref": expected_token,
        "statement_excerpt": signed_statement.strip()[:300],
    }


def assert_target_authorized(target: AuthorizedTarget | None) -> AuthorizedTarget:
    if target is None:
        raise UnauthorizedTargetError("Target record does not exist.")
    if not target.is_authorized:
        raise UnauthorizedTargetError(
            f"Active scanning blocked: domain '{target.domain}' has not passed ownership verification or explicit authorization."
        )
    return target

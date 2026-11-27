from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def mask_secret(secret: str) -> str:
    """
    Safely mask a secret value so it is never exposed in logs, findings, or UI.
    Preserves at most first 4 and last 2 characters (if length >= 10), masking the rest with '*'.
    For shorter secrets, replaces everything except first 2 chars with '*'.
    """
    clean = secret.strip().strip("'\"`")
    if not clean:
        return "********"
    length = len(clean)
    if length <= 4:
        return "****"
    if length <= 8:
        return clean[:2] + "*" * (length - 2)
    prefix_len = min(4, length // 4)
    suffix_len = min(2, length // 6)
    masked_len = max(6, length - prefix_len - suffix_len)
    return clean[:prefix_len] + "*" * masked_len + clean[-suffix_len:]


@dataclass
class SensitiveFinding:
    file_name: str
    file_path: str
    line_number: int
    secret_type: str
    severity: str
    detection_reason: str
    recommended_remediation: str
    masked_value: str
    rule_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_name": self.file_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "type": self.secret_type,
            "severity": self.severity,
            "detection_reason": self.detection_reason,
            "recommended_remediation": self.recommended_remediation,
            "masked_value": self.masked_value,
            "rule_id": self.rule_id,
        }

    def to_vulnerability_dict(self) -> dict[str, Any]:
        """Convert to Web Guard standard finding dictionary for pipeline classification."""
        return {
            "title": f"Sensitive Information Detected: {self.secret_type} in {self.file_name}",
            "severity": self.severity.lower(),
            "category": "Sensitive Information Exposure",
            "cwe_id": "CWE-798",
            "source_engine": "secret_detector",
            "location": f"{self.file_path}:{self.line_number}",
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": f"[{self.secret_type}] Value: {self.masked_value}",
            "description": (
                f"[SENSITIVE INFORMATION DETECTED]\n"
                f"File: {self.file_path}\n"
                f"Line: {self.line_number}\n"
                f"Type: {self.secret_type}\n"
                f"Severity: {self.severity}\n"
                f"Reason: {self.detection_reason}\n"
                f"Remediation: {self.recommended_remediation}"
            ),
            "remediation_advice": self.recommended_remediation,
            "evidence": {
                "rule_id": self.rule_id,
                "type": self.secret_type,
                "file": self.file_path,
                "line": self.line_number,
                "masked_value": self.masked_value,
                "verifiable": True,
            },
        }


# High-precision regular expressions for sensitive data patterns
SECRET_PATTERNS: list[tuple[str, str, str, re.Pattern, str, str]] = [
    # (rule_id, type, severity, regex, reason, remediation)
    (
        "SEC-AWS-KEY-001",
        "AWS Access Key ID",
        "CRITICAL",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "Standard Amazon Web Services 20-character Access Key ID detected.",
        "Revoke AWS IAM key immediately; move credentials to AWS Secrets Manager or IAM Roles.",
    ),
    (
        "SEC-AWS-SEC-001",
        "AWS Secret Access Key",
        "CRITICAL",
        re.compile(r"(?i)\baws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "High-entropy 40-character AWS Secret Access Key assignment found.",
        "Rotate the associated AWS IAM credential immediately and use environment variables injected via secret store.",
    ),
    (
        "SEC-PRIV-KEY-001",
        "Private Key / Certificate",
        "CRITICAL",
        re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----"),
        "Unencrypted private key block detected directly inside source code or configuration.",
        "Remove private key from source control; deploy keys securely through system keystore or vault.",
    ),
    (
        "SEC-CONN-STR-001",
        "Database Connection String with Credentials",
        "CRITICAL",
        re.compile(r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql)://[^:\s]+:([^@\s]+)@[^/\s]+/\S+)\b", re.I),
        "Database URI containing plaintext username and password embedded directly.",
        "Store connection parameters as separate environment variables (DB_HOST, DB_USER, DB_PASS) in a secret manager.",
    ),
    (
        "SEC-JWT-SEC-001",
        "Hardcoded JWT Secret",
        "HIGH",
        re.compile(r"(?i)\b(?:jwt[_\-\s]?secret|jwt[_\-\s]?private[_\-\s]?key|jwt[_\-\s]?token_secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
        "Hardcoded symmetric key used for signing JSON Web Tokens.",
        "Inject JWT signing secrets through runtime environment variables; rotate the compromised secret key.",
    ),
    (
        "SEC-API-OPENAI-001",
        "OpenAI API Key",
        "CRITICAL",
        re.compile(r"\b(sk-[A-Za-z0-9_-]{20,})\b"),
        "Hardcoded OpenAI secret API key detected.",
        "Revoke the API key from the OpenAI dashboard and set OPENAI_API_KEY in your hosting environment.",
    ),
    (
        "SEC-API-GITHUB-001",
        "GitHub Personal Access Token",
        "CRITICAL",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"),
        "Active GitHub Personal Access Token or fine-grained token found in source code.",
        "Revoke this token immediately via GitHub Settings -> Developer settings -> Personal access tokens.",
    ),
    (
        "SEC-API-STRIPE-001",
        "Stripe Secret Key",
        "CRITICAL",
        re.compile(r"\b(sk_(?:live|test)_[0-9a-zA-Z]{24,})\b"),
        "Live or test Stripe payment processing secret key detected.",
        "Roll this API key in the Stripe Dashboard to prevent unauthorized merchant operations.",
    ),
    (
        "SEC-API-SLACK-001",
        "Slack Bot / User Token or Webhook",
        "HIGH",
        re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48}|https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)\b"),
        "Slack token or incoming webhook URL exposed in source code.",
        "Revoke the Slack app token and store the webhook URL in secure configuration.",
    ),
    (
        "SEC-API-SENDGRID-001",
        "SendGrid API Key",
        "HIGH",
        re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"),
        "SendGrid email delivery API key detected.",
        "Delete compromised API key in SendGrid and regenerate with restricted permissions.",
    ),
    (
        "SEC-SMTP-CRED-001",
        "SMTP Email Credentials",
        "HIGH",
        re.compile(r"(?i)\b(?:smtp[_\-\s]?pass(?:word)?|email[_\-\s]?host[_\-\s]?password|mail[_\-\s]?password)\s*[:=]\s*['\"]([^'\"]{4,})['\"]"),
        "Plaintext password for SMTP outgoing mail server found.",
        "Pass SMTP passwords via environment variables; do not commit them to version control.",
    ),
    (
        "SEC-OAUTH-SEC-001",
        "OAuth Client Secret",
        "HIGH",
        re.compile(r"(?i)\b(?:client[_\-\s]?secret|oauth[_\-\s]?secret|google[_\-\s]?client[_\-\s]?secret)\s*[:=]\s*['\"]([A-Za-z0-9_-]{20,})['\"]"),
        "OAuth 2.0 client secret assigned directly in code.",
        "Store OAuth client secret in server environment; ensure client secrets never reach frontend bundles.",
    ),
    (
        "SEC-DB-PASS-001",
        "Hardcoded Database Password",
        "HIGH",
        re.compile(r"(?i)\b(?:db[_\-\s]?pass(?:word)?|database[_\-\s]?password|mysql[_\-\s]?password|postgres[_\-\s]?password)\s*[:=]\s*['\"]([^'\"]{4,})['\"]"),
        "Database access password assigned in cleartext.",
        "Store database passwords in .env (and ensure .env is gitignored) or inject via Docker/K8s secrets.",
    ),
    (
        "SEC-AUTH-PASS-001",
        "Hardcoded Admin / Master Password",
        "HIGH",
        re.compile(r"(?i)\b(?:admin[_\-\s]?pass(?:word)?|master[_\-\s]?password|root[_\-\s]?password)\s*[:=]\s*['\"]([^'\"]{4,})['\"]"),
        "Administrative account password hardcoded directly in file.",
        "Use bcrypt or argon2 hashed passwords stored in database; never hardcode credentials.",
    ),
    (
        "SEC-INTERNAL-URL-001",
        "Internal Infrastructure URL / Host",
        "MEDIUM",
        re.compile(r"\b(https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9_\-]+\.internal|[a-zA-Z0-9_\-]+\.corp|localhost:[0-9]{4,5})\S*)\b"),
        "Internal network IP or intranet domain embedded in configuration.",
        "Extract internal hostnames into deployment-specific environment variables.",
    ),
]


def scan_file_for_sensitive_info(file_path: Path, relative_name: str) -> list[SensitiveFinding]:
    """
    Scan a single file for sensitive secrets, credentials, API keys, and connection strings.
    Never exposes raw secret values - all findings strictly contain masked values.
    """
    # Skip binary files or files over 5 MB
    try:
        size = file_path.stat().st_size
        if size > 5 * 1024 * 1024:
            return []
    except OSError:
        return []

    findings: list[SensitiveFinding] = []
    is_env_file = file_path.name.lower() == ".env" or file_path.name.lower().startswith(".env.")
    is_example_file = file_path.name.lower().endswith((".example", ".sample", ".template"))

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") and not is_env_file:
            # Allow checking .env commented lines if they contain live keys, but ignore standard comments elsewhere
            continue

        for rule_id, sec_type, severity, pattern, reason, remediation in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                raw_val = match.group(1) if match.groups() else match.group(0)
                # Skip example/placeholder values
                val_lower = raw_val.lower()
                if any(p in val_lower for p in ["your_", "example", "placeholder", "xxx", "change_me", "my-secret", "1234567890"]):
                    if not is_env_file:
                        continue

                # In .env files, even example keys shouldn't be checked if it's explicitly a .env.example
                if is_example_file and "your_" in val_lower:
                    continue

                masked = mask_secret(raw_val)
                findings.append(
                    SensitiveFinding(
                        file_name=file_path.name,
                        file_path=relative_name,
                        line_number=idx,
                        secret_type=sec_type,
                        severity=severity,
                        detection_reason=reason,
                        recommended_remediation=remediation,
                        masked_value=masked,
                        rule_id=rule_id,
                    )
                )

    # Special check for .env files without specific matches: check for any active SECRET/KEY=value
    if is_env_file and not is_example_file:
        for idx, line in enumerate(lines, start=1):
            s = line.strip()
            if s and not s.startswith("#") and "=" in s:
                k, _, v = s.partition("=")
                key_upper = k.strip().upper()
                val_clean = v.strip().strip("'\"`")
                if val_clean and len(val_clean) >= 6:
                    if any(term in key_upper for term in ["SECRET", "TOKEN", "KEY", "PASSWORD", "PASS", "AUTH", "CREDENTIAL"]):
                        # Check if already recorded on this line
                        if not any(f.line_number == idx for f in findings):
                            findings.append(
                                SensitiveFinding(
                                    file_name=file_path.name,
                                    file_path=relative_name,
                                    line_number=idx,
                                    secret_type="Environment Secret / Key",
                                    severity="CRITICAL",
                                    detection_reason=f"Environment variable '{k.strip()}' in .env contains active credential value.",
                                    recommended_remediation="Add .env to .gitignore and inject credentials via production secret manager.",
                                    masked_value=mask_secret(val_clean),
                                    rule_id="SEC-ENV-VAR-001",
                                )
                            )

    return findings


def scan_project_for_sensitive_info(workspace: Path, scannable_files: list[Path]) -> list[SensitiveFinding]:
    """
    Scan all supported project files (including hidden .env files) for sensitive info.
    Does not stop after finding the first secret; continues across the entire project.
    """
    root = workspace.resolve()
    all_findings: list[SensitiveFinding] = []

    for fpath in scannable_files:
        try:
            rel = fpath.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = fpath.name
        findings = scan_file_for_sensitive_info(fpath, rel)
        all_findings.extend(findings)

    return all_findings

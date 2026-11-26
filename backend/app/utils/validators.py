import ipaddress
import re
from urllib.parse import urlparse

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)
GITHUB_REPO_REGEX = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?/?$")


def normalize_domain_or_url(raw_input: str) -> tuple[str, str]:
    """Return (domain_hostname, normalized_https_or_http_url) or raise ValueError."""
    raw = raw_input.strip()
    if not raw:
        raise ValueError("Target domain or URL cannot be empty.")

    if "://" not in raw:
        raw = f"https://{raw}"

    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported.")

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValueError("Invalid domain hostname.")

    # Reject raw IP addresses by default unless valid public domain/host check runs downstream
    try:
        ipaddress.ip_address(hostname)
        raise ValueError("Direct IP address scanning is disallowed; supply a domain name.")
    except ValueError as exc:
        if "Direct IP address" in str(exc):
            raise

    if hostname == "localhost" or hostname.endswith(".local") or hostname.endswith(".internal"):
        raise ValueError("Localhost and internal domain suffixes are prohibited.")

    if not DOMAIN_REGEX.match(hostname):
        raise ValueError(f"Invalid domain name format: {hostname}")

    port_part = f":{parsed.port}" if parsed.port else ""
    normalized_url = f"{parsed.scheme}://{hostname}{port_part}"
    return hostname, normalized_url


def validate_github_url(url: str) -> str:
    cleaned = url.strip()
    if not GITHUB_REPO_REGEX.match(cleaned):
        raise ValueError("Only public https://github.com/<owner>/<repo> URLs are permitted.")
    return cleaned.rstrip("/")

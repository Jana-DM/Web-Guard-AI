from __future__ import annotations

from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from app.utils.validators import normalize_domain_or_url


def discover_endpoints(
    base_url: str,
    allowed_domain: str,
    html_body: str,
    sitemap_urls: list[str] | None = None,
    allowed_paths: list[str] | None = None,
    max_endpoints: int = 30,
) -> list[dict[str, str]]:
    """Extract in-scope URLs and forms passively from HTML and sitemap."""
    soup = BeautifulSoup(html_body or "", "html.parser")
    found: dict[str, dict[str, str]] = {}

    def _add(raw_link: str, source: str) -> None:
        if len(found) >= max_endpoints:
            return
        full = urljoin(base_url, raw_link)
        parsed = urlparse(full)
        if parsed.scheme not in {"http", "https"}:
            return
        try:
            host, _ = normalize_domain_or_url(full)
        except ValueError:
            return
        if host != allowed_domain and not host.endswith(f".{allowed_domain}"):
            return
        path = parsed.path or "/"
        if allowed_paths and not any(path.startswith(p) for p in allowed_paths):
            return
        clean = f"{parsed.scheme}://{parsed.netloc}{path}"
        if clean not in found:
            found[clean] = {"url": clean, "path": path, "source": source}

    _add(base_url, "root")
    for tag in soup.find_all(["a", "form", "script"]):
        attr = "action" if tag.name == "form" else ("src" if tag.name == "script" else "href")
        val = tag.get(attr)
        if val and not str(val).startswith(("mailto:", "javascript:", "tel:", "#")):
            _add(str(val), f"html:{tag.name}")

    for s_url in sitemap_urls or []:
        _add(s_url, "sitemap.xml")

    return list(found.values())

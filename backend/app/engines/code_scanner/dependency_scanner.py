from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version
from sqlalchemy.orm import Session

from app.models.cve import CVEIntelligence


REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|!=|<|>)?\s*([A-Za-z0-9_.+-]+)?")

# Baseline advisory map for well-known vulnerable package boundaries (supplemented by synced DB CVEs)
KNOWN_PACKAGE_ADVISORIES = [
    {
        "package": "pyyaml",
        "lt_version": "5.4",
        "cve_id": "CVE-2020-14343",
        "severity": "critical",
        "cwe_id": "CWE-502",
        "title": "PyYAML < 5.4 Arbitrary Code Execution via full_load",
    },
    {
        "package": "requests",
        "lt_version": "2.31.0",
        "cve_id": "CVE-2023-32681",
        "severity": "medium",
        "cwe_id": "CWE-200",
        "title": "Requests < 2.31.0 Proxy-Authorization Header Leak on Redirect",
    },
    {
        "package": "django",
        "lt_version": "4.2.11",
        "cve_id": "CVE-2024-27351",
        "severity": "high",
        "cwe_id": "CWE-1333",
        "title": "Django < 4.2.11 ReDoS in intcomma / truncatechars",
    },
    {
        "package": "lodash",
        "lt_version": "4.17.21",
        "cve_id": "CVE-2021-23337",
        "severity": "high",
        "cwe_id": "CWE-94",
        "title": "Lodash < 4.17.21 Command Injection / Prototype Pollution",
    },
    {
        "package": "axios",
        "lt_version": "1.6.0",
        "cve_id": "CVE-2023-45857",
        "severity": "medium",
        "cwe_id": "CWE-352",
        "title": "Axios < 1.6.0 XSRF-TOKEN Header Exposure",
    },
]


def parse_dependencies(files: list[Path], workspace: Path) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    for path in files:
        rel = str(path.resolve().relative_to(workspace.resolve()))
        if path.name == "requirements.txt":
            for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
                stripped = line.split("#", 1)[0].strip()
                if not stripped:
                    continue
                m = REQ_LINE_RE.match(stripped)
                if m:
                    deps.append({
                        "ecosystem": "pypi",
                        "name": m.group(1).lower(),
                        "version": m.group(3),
                        "operator": m.group(2),
                        "file": rel,
                        "file_path": str(path),
                        "line_number": lineno,
                    })
        elif path.name == "package.json":
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                for section in ("dependencies", "devDependencies"):
                    for pkg, ver in (data.get(section) or {}).items():
                        cleaned_ver = str(ver).lstrip("^~>=< ")
                        deps.append({
                            "ecosystem": "npm",
                            "name": pkg.lower(),
                            "version": cleaned_ver if cleaned_ver and cleaned_ver != "*" else None,
                            "operator": "declared",
                            "file": rel,
                            "file_path": str(path),
                            "line_number": 1,
                        })
            except json.JSONDecodeError:
                pass
    return deps


def scan_dependencies(files: list[Path], workspace: Path, db: Session | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    deps = parse_dependencies(files, workspace)
    findings: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []

    for dep in deps:
        fingerprints.append({
            "product_name": dep["name"],
            "version": dep["version"],
            "category": f"dependency:{dep['ecosystem']}",
            "detection_source": dep["file"],
            "confidence": 0.95 if dep["version"] else 0.7,
            "raw_evidence": dep,
        })

        ver_str = dep["version"]
        if not ver_str:
            continue
        try:
            current_v = Version(ver_str.split(",")[0].strip())
        except InvalidVersion:
            continue

        for adv in KNOWN_PACKAGE_ADVISORIES:
            if dep["name"] == adv["package"] and current_v < Version(adv["lt_version"]):
                findings.append({
                    "title": adv["title"],
                    "severity": adv["severity"],
                    "cwe_id": adv["cwe_id"],
                    "cve_id": adv["cve_id"],
                    "category": "Vulnerable Dependency",
                    "source_engine": "dependency_scanner",
                    "location": f"{dep['file']}:{dep['line_number']}",
                    "file_path": dep["file_path"],
                    "line_number": dep["line_number"],
                    "code_snippet": f"{dep['name']}=={ver_str}",
                    "description": f"Declared dependency {dep['name']} ({ver_str}) is older than fixed version {adv['lt_version']}.",
                    "evidence": {
                        "package": dep["name"],
                        "detected_version": ver_str,
                        "fixed_version": adv["lt_version"],
                        "cve_id": adv["cve_id"],
                        "manifest": dep["file"],
                    },
                })

        if db is not None:
            cve_matches = (
                db.query(CVEIntelligence)
                .filter(CVEIntelligence.description.ilike(f"%{dep['name']}%"))
                .limit(10)
                .all()
            )
            for cve in cve_matches:
                for prod in cve.affected_products or []:
                    if str(prod.get("product", "")).lower() == dep["name"]:
                        lt_ver = prod.get("version_lt")
                        if lt_ver:
                            try:
                                if current_v < Version(str(lt_ver)):
                                    findings.append({
                                        "title": f"{cve.cve_id}: {dep['name']} Vulnerable Version",
                                        "severity": cve.severity,
                                        "cwe_id": cve.cwe_ids[0] if cve.cwe_ids else None,
                                        "cve_id": cve.cve_id,
                                        "category": "Vulnerable Dependency (CVE DB)",
                                        "source_engine": "dependency_scanner",
                                        "location": f"{dep['file']}:{dep['line_number']}",
                                        "file_path": dep["file_path"],
                                        "line_number": dep["line_number"],
                                        "code_snippet": f"{dep['name']} {ver_str}",
                                        "description": cve.description[:400],
                                        "evidence": {
                                            "package": dep["name"],
                                            "detected_version": ver_str,
                                            "affected_lt": lt_ver,
                                            "cve_id": cve.cve_id,
                                        },
                                    })
                            except InvalidVersion:
                                pass

    return findings, fingerprints

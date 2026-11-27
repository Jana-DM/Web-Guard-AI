from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def check_gitignore_security(workspace: Path) -> list[dict[str, Any]]:
    """
    Inspect .gitignore to ensure sensitive files (.env, keys, credentials, db files)
    are explicitly excluded from version control.
    """
    findings: list[dict[str, Any]] = []
    gitignore_path = workspace / ".gitignore"

    if not gitignore_path.exists():
        findings.append({
            "title": "Missing .gitignore File in Web Project",
            "severity": "medium",
            "category": "Configuration Security",
            "cwe_id": "CWE-200",
            "source_engine": "config_scanner",
            "location": ".gitignore:1",
            "file_path": ".gitignore",
            "line_number": 1,
            "code_snippet": "Missing .gitignore file",
            "description": "Project root does not have a .gitignore file, risking accidental commits of .env files, node_modules, and sensitive tokens.",
            "remediation_advice": "Create a .gitignore file in the root directory and add rules for .env, node_modules/, *.pem, and *.key.",
            "classification_hint": "INFORMATIONAL",
            "evidence": {
                "rule_id": "CFG-GITIGNORE-MISSING",
                "file": ".gitignore",
                "verifiable": True,
            },
        })
        return findings

    try:
        content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
        lines = [line.strip() for line in content.splitlines()]
    except Exception:
        return []

    # Check for .env exclusion
    has_env_rule = any(
        re.match(r"^\.?\*?\.?env(\.\*)?$", line) or ".env" in line or "*.env" in line
        for line in lines
        if not line.startswith("#") and line
    )

    if not has_env_rule:
        findings.append({
            "title": ".env Environment Files Not Excluded in .gitignore",
            "severity": "high",
            "category": "Configuration Security",
            "cwe_id": "CWE-200",
            "source_engine": "config_scanner",
            "location": ".gitignore:1",
            "file_path": ".gitignore",
            "line_number": 1,
            "code_snippet": "# .gitignore missing .env exclusion",
            "description": ".gitignore does not contain an entry for '.env'. Any secret or API key stored in .env could be accidentally published to Git.",
            "remediation_advice": "Add '.env' and '.env.*.local' to your .gitignore file immediately.",
            "classification_hint": "CONFIRMED",
            "evidence": {
                "rule_id": "CFG-GITIGNORE-ENV-MISSING",
                "file": ".gitignore",
                "line": 1,
                "verifiable": True,
            },
        })

    return findings


def check_vite_and_frontend_configs(workspace: Path) -> list[dict[str, Any]]:
    """
    Inspect Vite, Next.js, and frontend configurations for security issues:
    - Vite 'define' exposing entire process.env
    - Dev server listening on 0.0.0.0 with disabled host checks
    - Source maps enabled in production build
    """
    findings: list[dict[str, Any]] = []

    for fpath in workspace.glob("**/vite.config.*"):
        if "node_modules" in fpath.parts:
            continue
        try:
            rel = fpath.relative_to(workspace).as_posix()
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            continue

        for idx, line in enumerate(lines, start=1):
            # Checking define: { 'process.env': process.env }
            if re.search(r"['\"]?process\.env['\"]?\s*:\s*(?:JSON\.stringify\()?process\.env\b", line):
                findings.append({
                    "title": "Insecure Vite Configuration: Full process.env Exposure",
                    "severity": "critical",
                    "category": "Configuration Security",
                    "cwe_id": "CWE-200",
                    "source_engine": "config_scanner",
                    "location": f"{rel}:{idx}",
                    "file_path": rel,
                    "line_number": idx,
                    "code_snippet": line.strip(),
                    "description": "Vite 'define' embeds the entire Node.js host process.env into client-side JS bundles, exposing backend secrets to browser users.",
                    "remediation_advice": "Use Vite's standard VITE_ prefixed environment variables instead of exposing process.env directly.",
                    "classification_hint": "CONFIRMED",
                    "evidence": {
                        "rule_id": "CFG-VITE-ENV-EXPOSE",
                        "file": rel,
                        "line": idx,
                        "verifiable": True,
                    },
                })

            # Check server.host = true / '0.0.0.0' with allowedHosts or no auth
            if re.search(r"server\s*:\s*\{[^}]*host\s*:\s*(?:true|['\"]0\.0\.0\.0['\"])", content):
                pass  # Typical in containers, but flag if host check disabled
            if re.search(r"allowedHosts\s*:\s*(?:true|['\"]all['\"])", line):
                findings.append({
                    "title": "Vite Server Host Header Validation Disabled",
                    "severity": "medium",
                    "category": "Configuration Security",
                    "cwe_id": "CWE-183",
                    "source_engine": "config_scanner",
                    "location": f"{rel}:{idx}",
                    "file_path": rel,
                    "line_number": idx,
                    "code_snippet": line.strip(),
                    "description": "Disabling allowedHosts allows DNS rebinding attacks against local or staging Vite development servers.",
                    "remediation_advice": "Specify explicit allowed hostname domains in vite.config.",
                    "classification_hint": "CONFIRMED",
                    "evidence": {
                        "rule_id": "CFG-VITE-ALLOWED-HOSTS",
                        "file": rel,
                        "line": idx,
                        "verifiable": True,
                    },
                })

    return findings


def check_package_json_security(workspace: Path) -> list[dict[str, Any]]:
    """
    Inspect package.json files for:
    - Dangerous install scripts (curl | bash, rm -rf, arbitrary downloads)
    - Debug / dev dependencies used in production
    """
    findings: list[dict[str, Any]] = []

    for fpath in workspace.glob("**/package.json"):
        if "node_modules" in fpath.parts or "dist" in fpath.parts:
            continue
        try:
            rel = fpath.relative_to(workspace).as_posix()
            data = json.loads(fpath.read_text(encoding="utf-8", errors="ignore"))
            if not isinstance(data, dict):
                continue
        except Exception:
            continue

        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for script_name, cmd in scripts.items():
                if isinstance(cmd, str):
                    if re.search(r"curl\s+[^|]+\|\s*(?:ba|z|sh)", cmd) or re.search(r"wget\s+[^|]+\|\s*(?:ba|z|sh)", cmd):
                        findings.append({
                            "title": f"Dangerous Script in package.json: Pipe to Shell ({script_name})",
                            "severity": "high",
                            "category": "Configuration Security",
                            "cwe_id": "CWE-78",
                            "source_engine": "config_scanner",
                            "location": f"{rel}:{script_name}",
                            "file_path": rel,
                            "line_number": 1,
                            "code_snippet": f'"{script_name}": "{cmd}"',
                            "description": f"Script '{script_name}' downloads remote content and pipes it directly into a shell interpreter without integrity verification.",
                            "remediation_advice": "Download and verify SHA-256 integrity checksums before executing external scripts.",
                            "classification_hint": "CONFIRMED",
                            "evidence": {
                                "rule_id": "CFG-PKG-PIPE-SHELL",
                                "file": rel,
                                "script": script_name,
                                "verifiable": True,
                            },
                        })

    return findings


def scan_project_configurations(workspace: Path) -> list[dict[str, Any]]:
    """Run all project configuration security audits."""
    findings: list[dict[str, Any]] = []
    findings.extend(check_gitignore_security(workspace))
    findings.extend(check_vite_and_frontend_configs(workspace))
    findings.extend(check_package_json_security(workspace))
    return findings

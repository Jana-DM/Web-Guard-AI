from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def run_semgrep_scan(workspace: Path) -> dict[str, Any]:
    """Execute Semgrep static rules if Semgrep CLI is installed in the environment."""
    semgrep_exe = shutil.which("semgrep")
    if not semgrep_exe:
        return {
            "available": False,
            "findings": [],
            "reason": "Semgrep CLI not installed; AST, Bandit, and custom static rules executed.",
        }

    cmd = [semgrep_exe, "scan", "--config", "auto", "--json", "--quiet", str(workspace)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if not proc.stdout.strip():
            return {"available": True, "findings": []}
        data = json.loads(proc.stdout)
    except Exception as exc:
        return {"available": True, "findings": [], "error": str(exc)}

    findings: list[dict[str, Any]] = []
    for res in data.get("results", []):
        extra = res.get("extra", {})
        meta = extra.get("metadata", {})
        cwe_list = meta.get("cwe", [])
        cwe = cwe_list[0].split(":")[0] if isinstance(cwe_list, list) and cwe_list else None
        path_str = res.get("path", "unknown")
        start_line = res.get("start", {}).get("line")
        findings.append({
            "title": f"Semgrep: {res.get('check_id', 'Rule Match')}",
            "severity": SEMGREP_SEVERITY.get(extra.get("severity", "WARNING").upper(), "medium"),
            "cwe_id": cwe,
            "category": "SAST (Semgrep)",
            "source_engine": "semgrep",
            "location": f"{path_str}:{start_line}",
            "file_path": path_str,
            "line_number": start_line,
            "code_snippet": extra.get("lines", ""),
            "description": extra.get("message", "Semgrep pattern match"),
            "evidence": {
                "rule_id": res.get("check_id"),
                "file": path_str,
                "line": start_line,
                "lines": extra.get("lines", ""),
            },
        })

    return {"available": True, "findings": findings}

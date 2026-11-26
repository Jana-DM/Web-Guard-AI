from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def run_bandit_scan(workspace: Path) -> dict[str, Any]:
    """Run Bandit static analyzer on Python files without executing target code."""
    bandit_exe = shutil.which("bandit")
    if not bandit_exe:
        candidate = Path(sys.executable).parent / ("bandit.exe" if sys.platform == "win32" else "bandit")
        if candidate.exists():
            bandit_exe = str(candidate)

    if not bandit_exe:
        return {"available": False, "findings": [], "reason": "Bandit binary not found in environment."}

    cmd = [bandit_exe, "-r", str(workspace), "-f", "json", "-q"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        raw = proc.stdout.strip()
        if not raw:
            return {"available": True, "findings": []}
        parsed = json.loads(raw)
    except Exception as exc:
        return {"available": True, "findings": [], "error": str(exc)}

    findings: list[dict[str, Any]] = []
    for item in parsed.get("results", []):
        rel = str(Path(item["filename"]).resolve().relative_to(workspace.resolve())) if item.get("filename") else "unknown"
        cwe_obj = item.get("issue_cwe") or {}
        cwe_id = f"CWE-{cwe_obj['id']}" if cwe_obj.get("id") else None
        findings.append({
            "title": f"Bandit {item.get('test_id')}: {item.get('test_name', 'Security Issue')}",
            "severity": SEVERITY_MAP.get(item.get("issue_severity", "MEDIUM").upper(), "medium"),
            "cwe_id": cwe_id,
            "category": "Python SAST (Bandit)",
            "source_engine": "bandit",
            "location": f"{rel}:{item.get('line_number')}",
            "file_path": item.get("filename"),
            "line_number": item.get("line_number"),
            "code_snippet": item.get("code", ""),
            "description": item.get("issue_text", ""),
            "evidence": {
                "rule_id": item.get("test_id"),
                "confidence": item.get("issue_confidence"),
                "severity": item.get("issue_severity"),
                "file": rel,
                "line": item.get("line_number"),
                "more_info": item.get("more_info"),
            },
        })

    return {"available": True, "findings": findings}

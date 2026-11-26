from __future__ import annotations

import re
from pathlib import Path
from typing import Any


JS_TS_RULES = [
    (
        "RULE-JS-XSS-001",
        "Potential DOM XSS via dangerouslySetInnerHTML",
        "high",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:"),
        "Using dangerouslySetInnerHTML with unsanitized input exposes the DOM to XSS.",
    ),
    (
        "RULE-JS-XSS-002",
        "Direct innerHTML Assignment",
        "high",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"\.innerHTML\s*=\s*(?!['\"]\s*['\"])"),
        "Assigning dynamic content to innerHTML can trigger DOM-based XSS; prefer textContent or sanitization.",
    ),
    (
        "RULE-JS-EVAL-001",
        "Dynamic JavaScript Evaluation (eval / new Function)",
        "high",
        "CWE-95",
        "Code Injection",
        re.compile(r"\b(eval\s*\(|new\s+Function\s*\()"),
        "eval() and new Function() compile and run arbitrary code strings.",
    ),
    (
        "RULE-JS-CMD-001",
        "Shell Command Execution via child_process.exec",
        "high",
        "CWE-78",
        "Command Injection",
        re.compile(r"child_process['\"]?\)\s*\.\s*exec\(|require\(['\"]child_process['\"]\)|execSync\("),
        "child_process.exec/execSync invokes a shell; use execFile with explicit argument arrays instead.",
    ),
    (
        "RULE-JS-SQLI-001",
        "Template Literal Interpolation in SQL Query",
        "critical",
        "CWE-89",
        "SQL Injection",
        re.compile(r"\.(query|execute)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`"),
        "SQL template string interpolation allows SQL injection; use parameterized placeholders.",
    ),
    (
        "RULE-JS-JWT-001",
        "Insecure JWT Algorithm 'none' Permitted",
        "critical",
        "CWE-347",
        "Authentication Bypass",
        re.compile(r"algorithms\s*:\s*\[[^\]]*['\"]none['\"]", re.I),
        "Allowing JWT algorithm 'none' lets attackers forge unsigned tokens.",
    ),
    (
        "RULE-ANY-SEC-001",
        "Potential Hardcoded API Token or Private Key",
        "high",
        "CWE-798",
        "Hardcoded Secrets",
        re.compile(r"(AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|ghp_[A-Za-z0-9]{30,})"),
        "High-confidence credential or private key pattern detected in source file.",
    ),
]


def run_custom_rules(file_path: Path, relative_name: str, language: str) -> list[dict[str, Any]]:
    if language not in {"javascript", "typescript", "python"}:
        return []

    text = file_path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    findings: list[dict[str, Any]] = []

    for rule_id, title, severity, cwe, category, pattern, description in JS_TS_RULES:
        if rule_id.startswith("RULE-JS-") and language == "python":
            continue
        for idx, line in enumerate(lines, start=1):
            if pattern.search(line):
                findings.append({
                    "title": title,
                    "severity": severity,
                    "cwe_id": cwe,
                    "category": category,
                    "source_engine": "custom_rules",
                    "location": f"{relative_name}:{idx}",
                    "file_path": str(file_path),
                    "line_number": idx,
                    "code_snippet": line.strip(),
                    "description": description,
                    "evidence": {
                        "rule_id": rule_id,
                        "file": relative_name,
                        "line": idx,
                        "matched_line": line.strip()[:300],
                    },
                })
    return findings

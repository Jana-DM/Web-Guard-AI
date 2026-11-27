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
]

HTML_RULES = [
    (
        "RULE-HTML-XSS-001",
        "Inline JavaScript Event Handler in HTML",
        "medium",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"<\w+[^>]*\son(?:click|load|error|mouseover|focus|submit)\s*=", re.I),
        "Inline DOM event handlers bypass Content Security Policy (CSP) script-src protections and increase XSS exposure.",
    ),
    (
        "RULE-HTML-XSS-002",
        "Dangerous javascript: URI in HTML Attribute",
        "high",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"(?:href|src|action)\s*=\s*['\"]\s*javascript:", re.I),
        "javascript: URIs execute arbitrary script in the page origin when triggered.",
    ),
    (
        "RULE-HTML-TLS-001",
        "Insecure HTTP External Script or Form Target",
        "medium",
        "CWE-319",
        "Cleartext Transmission",
        re.compile(r"<(?:script|iframe|form)\b[^>]*(?:src|action)\s*=\s*['\"]http://(?!localhost|127\.0\.0\.1)", re.I),
        "Loading scripts or submitting forms over unencrypted HTTP permits active MitM tampering.",
    ),
    (
        "RULE-HTML-TAB-001",
        "External Link With target=_blank Missing rel=noopener",
        "low",
        "CWE-1022",
        "Reverse Tabnabbing",
        re.compile(r"<a\b(?=[^>]*target\s*=\s*['\"]_blank['\"])(?![^>]*\bnoopener\b)[^>]*>", re.I),
        "Opening external tabs without rel='noopener noreferrer' lets the opened page inspect window.opener.",
    ),
]

CSS_RULES = [
    (
        "RULE-CSS-XSS-001",
        "Legacy CSS expression() Script Execution Sink",
        "high",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"\bexpression\s*\(", re.I),
        "CSS expression() evaluates JavaScript expressions inside stylesheets in legacy contexts.",
    ),
    (
        "RULE-CSS-TLS-001",
        "Unencrypted HTTP Asset or @import in Stylesheet",
        "medium",
        "CWE-319",
        "Cleartext Transmission",
        re.compile(r"(?:url\(|@import\s+['\"])http://(?!localhost|127\.0\.0\.1)", re.I),
        "Loading stylesheet imports or assets over plain HTTP triggers mixed-content downgrade risks.",
    ),
]

PHP_RULES = [
    (
        "RULE-PHP-CMD-001",
        "Unsafe PHP Command or Code Execution Call",
        "critical",
        "CWE-78",
        "Command / Code Injection",
        re.compile(r"\b(?:shell_exec|exec|system|passthru|eval)\s*\("),
        "Direct shell/code execution in PHP risks remote code execution if tainted input reaches arguments.",
    ),
    (
        "RULE-PHP-XSS-001",
        "Unescaped PHP Superglobal Output",
        "high",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"\becho\b[^;]*\$_(?:GET|POST|REQUEST)\b"),
        "Echoing HTTP request superglobals without htmlspecialchars() allows reflected XSS.",
    ),
]

SHARED_RULES = [
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

LANGUAGE_RULE_MAP = {
    "javascript": JS_TS_RULES + SHARED_RULES,
    "typescript": JS_TS_RULES + SHARED_RULES,
    "python": SHARED_RULES,
    "html": HTML_RULES + SHARED_RULES,
    "css": CSS_RULES + SHARED_RULES,
    "php": PHP_RULES + SHARED_RULES,
}


def run_custom_rules(file_path: Path, relative_name: str, language: str) -> list[dict[str, Any]]:
    rules = LANGUAGE_RULE_MAP.get(language)
    if not rules:
        return []

    text = file_path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    findings: list[dict[str, Any]] = []

    for rule_id, title, severity, cwe, category, pattern, description in rules:
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

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


WEB_SECURITY_RULES = [
    # --- CROSS-SITE SCRIPTING (XSS) ---
    (
        "RULE-JS-XSS-001",
        "Potential DOM XSS via dangerouslySetInnerHTML",
        "high",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:"),
        "Using dangerouslySetInnerHTML with dynamic input exposes the DOM to Cross-Site Scripting (XSS).",
        "CONFIRMED",
        "Use DOMPurify to sanitize HTML or render plain text children instead of raw HTML.",
    ),
    (
        "RULE-JS-XSS-002",
        "Direct innerHTML / outerHTML Assignment",
        "high",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"\.(innerHTML|outerHTML)\s*=\s*(?!['\"]\s*['\"])"),
        "Assigning dynamic content to innerHTML allows script execution; prefer textContent or a sanitizer.",
        "POTENTIAL",
        "Replace .innerHTML with .textContent or sanitize dynamic markup with DOMPurify.",
    ),
    (
        "RULE-JS-XSS-003",
        "DOM Injection via document.write()",
        "high",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"\bdocument\.(write|writeln)\s*\("),
        "document.write() writes directly to the document stream and is a common sink for reflected/DOM XSS.",
        "CONFIRMED",
        "Use standard DOM methods (appendChild, textContent) instead of document.write.",
    ),
    (
        "RULE-VUE-XSS-001",
        "Raw HTML Injection via Vue v-html Directive",
        "high",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"\bv-html\s*=\s*['\"][^'\"]+['\"]"),
        "The v-html directive renders unescaped raw HTML. If bound to user input, it allows XSS.",
        "POTENTIAL",
        "Ensure data rendered with v-html is sanitized with sanitize-html or DOMPurify.",
    ),

    # --- CODE INJECTION / EVAL ---
    (
        "RULE-JS-EVAL-001",
        "Dynamic JavaScript Execution (eval / new Function)",
        "critical",
        "CWE-95",
        "Code Injection",
        re.compile(r"\b(eval\s*\(|new\s+Function\s*\()"),
        "eval() and new Function() compile and run arbitrary code strings, leading to Remote Code Execution if input is tainted.",
        "CONFIRMED",
        "Avoid dynamic evaluation; use structured parsers like JSON.parse() or function lookup tables.",
    ),

    # --- COMMAND INJECTION ---
    (
        "RULE-JS-CMD-001",
        "Shell Command Execution via child_process.exec",
        "critical",
        "CWE-78",
        "Command Injection",
        re.compile(r"child_process['\"]?\)\s*\.\s*(exec|execSync)\(|require\(['\"]child_process['\"]\)\.(exec|execSync)\("),
        "child_process.exec invokes a system shell, permitting shell metacharacter injection.",
        "CONFIRMED",
        "Use execFile or spawn with shell: false and pass arguments as an explicit array.",
    ),

    # --- SQL INJECTION ---
    (
        "RULE-JS-SQLI-001",
        "Template Literal Interpolation in SQL Query",
        "critical",
        "CWE-89",
        "SQL Injection",
        re.compile(r"\.(query|execute|raw)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`"),
        "Template string interpolation inside a SQL query bypasses query parameterization and allows SQL Injection.",
        "CONFIRMED",
        "Use parameterized placeholders ($1, ?, :param) and pass variables via parameter bindings.",
    ),
    (
        "RULE-JS-SQLI-002",
        "String Concatenation in Database Query",
        "high",
        "CWE-89",
        "SQL Injection",
        re.compile(r"\.(query|execute)\s*\(\s*(['\"][^'\"]*SELECT|['\"][^'\"]*UPDATE|['\"][^'\"]*DELETE|['\"][^'\"]*INSERT)[^'\"]*['\"]\s*\+"),
        "Building SQL statements using string concatenation allows untrusted input to modify query syntax.",
        "CONFIRMED",
        "Bind dynamic parameters with prepared statements instead of string concatenation.",
    ),

    # --- PATH TRAVERSAL ---
    (
        "RULE-JS-TRAV-001",
        "Potential Path Traversal in File System Call",
        "high",
        "CWE-22",
        "Path Traversal",
        re.compile(r"(?:fs\.(?:readFile|readFileSync|createReadStream|unlink|writeFile)|res\.sendFile)\s*\(\s*(?:req\.(?:query|params|body)|path\.join\([^)]*req\.)"),
        "Directly passing request parameters into file system operations allows ../ traversal to read unauthorized files.",
        "CONFIRMED",
        "Validate paths against an allowlist and verify resolved path starts with the intended base directory.",
    ),

    # --- SERVER-SIDE REQUEST FORGERY (SSRF) ---
    (
        "RULE-JS-SSRF-001",
        "Server-Side Request Forgery via Dynamic HTTP Client URL",
        "high",
        "CWE-918",
        "Server-Side Request Forgery",
        re.compile(r"(?:axios|fetch|got|http\.get|https\.get|needle)\s*\(\s*(?:req\.(?:query|body|params)\.[a-zA-Z0-9_]+|[a-zA-Z0-9_]*url[a-zA-Z0-9_]*\b)"),
        "Server makes outgoing HTTP requests to a URL derived directly from client request parameters.",
        "POTENTIAL",
        "Validate target URLs against an explicit domain allowlist and block private/link-local IP addresses.",
    ),

    # --- OPEN REDIRECT ---
    (
        "RULE-JS-REDIR-001",
        "Unvalidated Open Redirect",
        "medium",
        "CWE-601",
        "Open Redirect",
        re.compile(r"res\.redirect\s*\(\s*req\.(?:query|params|body)\.[a-zA-Z0-9_]+"),
        "Redirecting to an arbitrary user-supplied URL allows attackers to redirect users to phishing sites.",
        "CONFIRMED",
        "Use relative paths for redirects or validate target URL against an allowed domains allowlist.",
    ),

    # --- CORS MISCONFIGURATION ---
    (
        "RULE-JS-CORS-001",
        "Insecure CORS: Wildcard Origin with Credentials",
        "high",
        "CWE-942",
        "Insecure CORS Configuration",
        re.compile(r"(?i)cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|['\"]\s*\*?\s*['\"])[^}]*credentials\s*:\s*true"),
        "Configuring CORS with origin: '*' or dynamic reflection alongside credentials: true exposes authenticated data cross-origin.",
        "CONFIRMED",
        "Specify an explicit list of trusted origin domains when credentials: true is enabled.",
    ),

    # --- INSECURE AUTHENTICATION & TOKENS ---
    (
        "RULE-JS-JWT-001",
        "Insecure JWT Algorithm 'none' Allowed",
        "critical",
        "CWE-347",
        "Authentication Bypass",
        re.compile(r"algorithms\s*:\s*\[[^\]]*['\"]none['\"]", re.I),
        "Allowing JWT algorithm 'none' permits attackers to forge arbitrary tokens without a signature.",
        "CONFIRMED",
        "Explicitly allow only strong algorithms like RS256 or HS256.",
    ),
    (
        "RULE-JS-HASH-001",
        "Weak Cryptographic Hash Algorithm (MD5 / SHA1)",
        "medium",
        "CWE-328",
        "Weak Cryptography",
        re.compile(r"crypto\.createHash\s*\(\s*['\"](md5|sha1)['\"]", re.I),
        "MD5 and SHA-1 are cryptographically broken and prone to collision attacks.",
        "INFORMATIONAL",
        "Upgrade to SHA-256 for integrity checks, or bcrypt/argon2 for password hashing.",
    ),

    # --- HTML SPECIFIC RULES ---
    (
        "RULE-HTML-XSS-001",
        "Inline JavaScript Event Handler in HTML",
        "medium",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"<\w+[^>]*\son(?:click|load|error|mouseover|focus|submit)\s*=", re.I),
        "Inline event handlers bypass Content Security Policy (CSP) protections and increase XSS risk.",
        "INFORMATIONAL",
        "Attach event listeners via external JavaScript using addEventListener.",
    ),
    (
        "RULE-HTML-XSS-002",
        "Dangerous javascript: URI in HTML Attribute",
        "high",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"(?:href|src|action)\s*=\s*['\"]\s*javascript:", re.I),
        "javascript: URIs execute script in the page origin when triggered.",
        "CONFIRMED",
        "Replace javascript: URIs with event listeners and standard anchor navigation.",
    ),
    (
        "RULE-HTML-TLS-001",
        "Insecure HTTP External Script or Form Target",
        "medium",
        "CWE-319",
        "Cleartext Transmission",
        re.compile(r"<(?:script|iframe|form)\b[^>]*(?:src|action)\s*=\s*['\"]http://(?!localhost|127\.0\.0\.1)", re.I),
        "Loading scripts or submitting forms over plain HTTP permits active Man-in-the-Middle tampering.",
        "CONFIRMED",
        "Enforce HTTPS for all external resource URLs and form endpoints.",
    ),
    (
        "RULE-HTML-TAB-001",
        "External Link With target=_blank Missing rel=noopener",
        "low",
        "CWE-1022",
        "Reverse Tabnabbing",
        re.compile(r"<a\b(?=[^>]*target\s*=\s*['\"]_blank['\"])(?![^>]*\bnoopener\b)[^>]*>", re.I),
        "Opening external links with target='_blank' without rel='noopener noreferrer' lets external page manipulate window.opener.",
        "INFORMATIONAL",
        "Add rel='noopener noreferrer' to all target='_blank' anchor tags.",
    ),

    # --- CSS SPECIFIC RULES ---
    (
        "RULE-CSS-XSS-001",
        "Legacy CSS expression() Script Sink",
        "high",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"\bexpression\s*\(", re.I),
        "CSS expression() allows arbitrary JavaScript evaluation in legacy browsers.",
        "CONFIRMED",
        "Remove expression() calls and use standard CSS properties or media queries.",
    ),

    # --- PHP SPECIFIC RULES ---
    (
        "RULE-PHP-CMD-001",
        "Unsafe PHP Shell Execution Function",
        "critical",
        "CWE-78",
        "Command Injection",
        re.compile(r"\b(?:shell_exec|exec|system|passthru|popen)\s*\("),
        "Executing system commands in PHP risks command injection if user input reaches the argument.",
        "CONFIRMED",
        "Avoid system execution; use PHP native functions or escapeshellarg().",
    ),
    (
        "RULE-PHP-XSS-001",
        "Unescaped HTTP Superglobal Output in PHP",
        "high",
        "CWE-79",
        "Cross-Site Scripting",
        re.compile(r"\becho\b[^;]*\$_(?:GET|POST|REQUEST)\b"),
        "Echoing request superglobals without htmlspecialchars() leads directly to reflected XSS.",
        "CONFIRMED",
        "Wrap output with htmlspecialchars($val, ENT_QUOTES, 'UTF-8').",
    ),
    (
        "RULE-PHP-SQLI-001",
        "Unparameterized MySQL Query in PHP",
        "critical",
        "CWE-89",
        "SQL Injection",
        re.compile(r"\b(?:mysql_query|mysqli_query)\s*\([^,]+,\s*(?:['\"][^'\"]*SELECT|['\"][^'\"]*UPDATE|['\"][^'\"]*INSERT)[^'\"]*['\"]\s*\."),
        "Constructing SQL queries via string concatenation in PHP permits SQL Injection.",
        "CONFIRMED",
        "Use PDO or MySQLi prepared statements with parameter binding.",
    ),
]


def run_custom_rules(file_path: Path, relative_name: str, language: str) -> list[dict[str, Any]]:
    """Execute static rules across JavaScript, TypeScript, Python, HTML, CSS, and PHP files."""
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    lines = text.splitlines()
    findings: list[dict[str, Any]] = []

    for rule_id, title, severity, cwe, category, pattern, description, classification_hint, remediation in WEB_SECURITY_RULES:
        # Check if rule applies to language
        if rule_id.startswith("RULE-JS-") and language not in {"javascript", "typescript"}:
            continue
        if rule_id.startswith("RULE-VUE-") and language not in {"javascript", "typescript", "vue"}:
            continue
        if rule_id.startswith("RULE-HTML-") and language not in {"html", "javascript", "typescript"}:
            continue
        if rule_id.startswith("RULE-CSS-") and language not in {"css", "html"}:
            continue
        if rule_id.startswith("RULE-PHP-") and language != "php":
            continue

        for idx, line in enumerate(lines, start=1):
            s = line.strip()
            if not s or s.startswith(("//", "/*", "*", "#", "<!--")):
                continue

            if pattern.search(line):
                findings.append({
                    "title": title,
                    "severity": severity,
                    "cwe_id": cwe,
                    "category": category,
                    "source_engine": "custom_rules",
                    "location": f"{relative_name}:{idx}",
                    "file_path": relative_name,
                    "line_number": idx,
                    "code_snippet": s[:300],
                    "description": description,
                    "remediation_advice": remediation,
                    "classification_hint": classification_hint,
                    "evidence": {
                        "rule_id": rule_id,
                        "file": relative_name,
                        "line": idx,
                        "matched_line": s[:300],
                        "verifiable": True,
                    },
                })

    return findings

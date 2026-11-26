from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any

from app.models.vulnerability import Vulnerability


def generate_code_fix(vuln: Vulnerability) -> dict[str, Any]:
    """Generate a grounded code fix proposal with original vs. proposed diff."""
    file_path = vuln.file_path
    if file_path and Path(file_path).exists():
        original_code = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    else:
        original_code = vuln.code_snippet or "# Source snippet unavailable"

    proposed_code = original_code
    rationale = "Apply secure coding pattern aligned with OWASP and CWE guidance."
    cwe = (vuln.cwe_id or "").upper()
    title_low = vuln.title.lower()

    if cwe == "CWE-78" or "shell=true" in title_low or "os.system" in title_low:
        proposed_code = re.sub(r"shell\s*=\s*True", "shell=False", proposed_code)
        proposed_code = re.sub(
            r"os\.system\((.+?)\)",
            r"subprocess.run(\1, shell=False, check=True)  # WebGuard: replaced os.system",
            proposed_code,
        )
        rationale = "Disable shell interpolation (shell=False) and pass explicit argument lists to prevent command injection."

    elif cwe == "CWE-89" or "sql injection" in title_low:
        # Replace simple f-string execute(f"SELECT ... {var}") safely when recognizable
        proposed_code = re.sub(
            r'(\.execute\(\s*)f(["\'])([^"\']*?)\{([A-Za-z0-9_]+)\}([^"\']*?)\2(\s*\))',
            r'\1\2\3?\5\2, (\4,)\6',
            proposed_code,
        )
        rationale = "Use parameterized SQL bindings (?) instead of dynamic string interpolation."

    elif cwe == "CWE-502" or "yaml.load" in title_low:
        proposed_code = re.sub(
            r"yaml\.load\(([^,\)]+)\)",
            r"yaml.safe_load(\1)",
            proposed_code,
        )
        rationale = "Replace unsafe yaml.load() with yaml.safe_load() to block arbitrary object deserialization."

    elif cwe == "CWE-798" or "hardcoded" in title_low:
        def _env_replace(match: re.Match[str]) -> str:
            var_name = match.group(1)
            return f'{var_name} = os.environ.get("{var_name.upper()}", "")'

        proposed_code = re.sub(
            r'([A-Za-z0-9_]*(?:secret|password|api_key|token)[A-Za-z0-9_]*)\s*=\s*["\'][^"\']+["\']',
            _env_replace,
            proposed_code,
            flags=re.IGNORECASE,
        )
        if "os.environ.get" in proposed_code and "import os" not in proposed_code:
            proposed_code = "import os\n" + proposed_code
        rationale = "Externalize hardcoded credentials to environment variables instead of storing literals in source."

    elif cwe == "CWE-295" or "verify=false" in title_low:
        proposed_code = re.sub(r"verify\s*=\s*False", "verify=True", proposed_code)
        rationale = "Enforce TLS certificate verification (verify=True) to prevent MITM attacks."

    elif cwe == "CWE-328" or "md5" in title_low or "sha1" in title_low:
        proposed_code = re.sub(r"hashlib\.(md5|sha1)\(", "hashlib.sha256(", proposed_code)
        rationale = "Upgrade weak MD5/SHA1 digest to SHA-256 (or bcrypt/argon2 for passwords)."

    elif cwe == "CWE-79" or "innerhtml" in title_low:
        proposed_code = re.sub(r"\.innerHTML\s*=", ".textContent =", proposed_code)
        rationale = "Use textContent instead of innerHTML to prevent DOM-based XSS."

    elif cwe == "CWE-95" or "eval" in title_low:
        proposed_code = re.sub(r"\beval\(", "ast.literal_eval(", proposed_code)
        if "ast.literal_eval" in proposed_code and "import ast" not in proposed_code:
            proposed_code = "import ast\n" + proposed_code
        rationale = "Replace arbitrary eval() with ast.literal_eval() for safe literal parsing."

    if proposed_code == original_code:
        # Provide targeted secure guidance comment block on the exact line if automated AST transform isn't unambiguous
        proposed_code = (
            f"# TODO(WebGuard Security Fix - {cwe or 'Review'}): {rationale}\n"
            + original_code
        )

    diff_lines = difflib.unified_diff(
        original_code.splitlines(keepends=True),
        proposed_code.splitlines(keepends=True),
        fromfile=f"a/{Path(file_path).name if file_path else 'snippet'}",
        tofile=f"b/{Path(file_path).name if file_path else 'snippet'}",
    )
    diff_preview = "".join(diff_lines)

    return {
        "file_path": file_path,
        "original_code": original_code,
        "proposed_code": proposed_code,
        "diff_preview": diff_preview or "No line diff generated.",
        "rationale": rationale,
    }

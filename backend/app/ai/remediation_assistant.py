from __future__ import annotations

from app.ai.llm_client import generate_grounded_completion
from app.models.remediation import RemediationRecord
from app.models.vulnerability import Vulnerability


def explain_remediation(vuln: Vulnerability, record: RemediationRecord) -> str:
    prompt = (
        f"Explain the proposed fix for {vuln.title} ({vuln.cwe_id}) at {record.file_path}.\n"
        f"Rationale: {record.rationale}\n"
        f"Diff:\n{record.diff_preview[:1500]}"
    )
    llm_reply = generate_grounded_completion(
        "You are an AppSec remediation engineer. Explain the patch concisely and accurately.",
        prompt,
    )
    if llm_reply:
        return llm_reply

    return (
        f"**Remediation Guidance for {vuln.title}:** {record.rationale}\n\n"
        f"Review the unified diff before approving. A timestamped backup will be created automatically prior to applying changes."
    )

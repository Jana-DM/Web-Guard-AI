from app.engines.validation.finding_classifier import validate_and_classify_findings


def test_confirmed_requires_verifiable_evidence():
    raw = [
        {
            "title": "Potential SQL Injection via Unparameterized Query",
            "severity": "critical",
            "cwe_id": "CWE-89",
            "category": "SQL Injection",
            "source_engine": "ast_analyzer",
            "location": "app/db.py:12",
            "line_number": 12,
            "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
            "description": "Dynamic SQL string.",
            "evidence": {"rule_id": "AST-PY-SQLI-001", "line": 12, "snippet": 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")'},
        },
        {
            "title": "Unverified Heuristic Guess",
            "severity": "high",
            "cwe_id": "CWE-79",
            "category": "XSS",
            "source_engine": "ai_guess",
            "location": "unknown",
            "description": "Guess without evidence",
            "evidence": {},
        },
    ]

    results = validate_and_classify_findings(raw)
    assert len(results) == 2
    assert results[0]["classification"] == "CONFIRMED"
    assert results[0]["confidence_score"] >= 0.75
    assert results[1]["classification"] != "CONFIRMED"
    assert results[1]["classification"] == "NOT REPRODUCED"


def test_false_positive_filtered_for_comments_and_env_vars():
    raw = [
        {
            "title": "Hardcoded Secret",
            "severity": "high",
            "cwe_id": "CWE-798",
            "source_engine": "custom_rules",
            "location": "app/config.py:4",
            "line_number": 4,
            "code_snippet": "# API_KEY = 'demo'",
            "evidence": {"rule_id": "RULE-ANY-SEC-001", "line": 4},
        },
        {
            "title": "Hardcoded Secret",
            "severity": "high",
            "cwe_id": "CWE-798",
            "source_engine": "custom_rules",
            "location": "app/config.py:8",
            "line_number": 8,
            "code_snippet": "SECRET_KEY = os.environ.get('SECRET_KEY')",
            "evidence": {"rule_id": "RULE-ANY-SEC-001", "line": 8},
        },
    ]
    results = validate_and_classify_findings(raw)
    assert all(r["classification"] == "NOT REPRODUCED" for r in results)

from app.engines.correlation.affected_version_checker import evaluate_version_against_range
from app.engines.correlation.technology_cve_matcher import correlate_technologies_with_cves
from app.engines.intelligence.deduplication import upsert_cve_record


def test_version_range_evaluation():
    bounds = {"product": "nginx", "version_start": "1.20.0", "version_lt": "1.24.1"}
    assert evaluate_version_against_range("1.22.0", bounds) == "Verified affected configuration"
    assert evaluate_version_against_range("1.24.1", bounds) == "Not affected"
    assert evaluate_version_against_range(None, bounds) == "Insufficient information"


def test_cve_correlation_with_db(db_session):
    upsert_cve_record(
        db_session,
        {
            "cve_id": "CVE-2024-9999",
            "title": "CVE-2024-9999: nginx buffer issue",
            "description": "Vulnerability affecting nginx HTTP server before 1.24.1.",
            "severity": "high",
            "cvss_score": 7.5,
            "affected_products": [{"vendor": "f5", "product": "nginx", "version_lt": "1.24.1"}],
            "sources": ["nvd"],
        },
    )
    db_session.commit()

    matches = correlate_technologies_with_cves(db_session, [{"product_name": "nginx", "version": "1.22.0"}])
    assert len(matches) == 1
    assert matches[0]["cve_id"] == "CVE-2024-9999"
    assert matches[0]["status"] == "Verified affected configuration"

    safe_matches = correlate_technologies_with_cves(db_session, [{"product_name": "nginx", "version": "1.26.0"}])
    assert safe_matches[0]["status"] == "Not affected"

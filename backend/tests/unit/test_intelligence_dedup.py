from app.engines.intelligence.data_normalizer import normalize_kev_item, normalize_nvd_item
from app.engines.intelligence.deduplication import upsert_cve_record
from app.models.cve import CVEIntelligence


def test_intelligence_normalization_and_deduplication(db_session):
    nvd_raw = {
        "cve": {
            "id": "CVE-2025-1001",
            "descriptions": [{"lang": "en", "value": "Critical flaw in example-web."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L"}}]},
            "weaknesses": [{"description": [{"value": "CWE-89"}]}],
            "references": [{"url": "https://vendor.example/patch", "tags": ["Patch"]}],
            "published": "2025-01-10T00:00:00Z",
        }
    }
    norm = normalize_nvd_item(nvd_raw)
    assert norm is not None
    assert norm["severity"] == "critical"
    assert norm["patch_available"] is True

    assert upsert_cve_record(db_session, norm) == "created"
    db_session.commit()
    # Second identical ingest is detected as duplicate
    assert upsert_cve_record(db_session, norm) == "duplicate"

    # Merge KEV feed info for same CVE
    kev_norm = normalize_kev_item({
        "cveID": "CVE-2025-1001",
        "vulnerabilityName": "Example Web RCE",
        "shortDescription": "Actively exploited.",
        "dateAdded": "2025-01-12",
        "requiredAction": "Apply patch",
    })
    assert upsert_cve_record(db_session, kev_norm) == "updated"
    db_session.commit()

    stored = db_session.query(CVEIntelligence).filter_by(cve_id="CVE-2025-1001").first()
    assert stored is not None
    assert stored.is_kev is True
    assert set(stored.sources) == {"nvd", "cisa_kev"}

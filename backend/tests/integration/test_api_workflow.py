import io
from pathlib import Path
from unittest.mock import patch


def _register_and_login(client):
    reg = client.post(
        "/api/v1/auth/register",
        json={
            "email": "lead@webguard.io",
            "username": "sec_lead",
            "password": "StrongPassword123!",
            "full_name": "Security Lead",
        },
    )
    assert reg.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": "sec_lead", "password": "StrongPassword123!"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_end_to_end_code_scan_remediation_verification_and_report(client):
    headers = _register_and_login(client)

    # 1. Dashboard initially reports zero real findings (no hardcoded stats)
    dash = client.get("/api/v1/dashboard/summary", headers=headers)
    assert dash.status_code == 200
    assert dash.json()["metrics"]["total_scans"] == 0

    # 2. Upload vulnerable Python file for static scan (never executed)
    vulnerable_py = (
        "import subprocess\n"
        "def run_cmd(user_arg):\n"
        "    return subprocess.run(user_arg, shell=True)\n"
    ).encode("utf-8")

    scan_resp = client.post(
        "/api/v1/code-scans/upload",
        headers=headers,
        files=[("files", ("app_runner.py", io.BytesIO(vulnerable_py), "text/x-python"))],
    )
    assert scan_resp.status_code == 201
    scan_data = scan_resp.json()
    assert scan_data["status"] == "completed"
    assert scan_data["summary"]["confirmed_findings"] >= 1

    # 3. Inspect vulnerabilities and evidence
    vulns_resp = client.get("/api/v1/vulnerabilities", headers=headers)
    assert vulns_resp.status_code == 200
    items = vulns_resp.json()["items"]
    assert len(items) >= 1
    target_vuln = next(v for v in items if v["classification"] == "CONFIRMED")
    assert len(target_vuln["evidence_records"]) >= 1

    # 4. Generate remediation proposal (requires explicit approval before modifying file)
    rem_resp = client.post(f"/api/v1/remediation/generate/{target_vuln['id']}", headers=headers)
    assert rem_resp.status_code == 201
    rem_id = rem_resp.json()["remediation"]["id"]
    assert rem_resp.json()["remediation"]["status"] == "pending_approval"
    assert "shell=False" in rem_resp.json()["remediation"]["proposed_code"]

    # 5. Explicitly approve and apply remediation (creates backup)
    approve_resp = client.post(
        f"/api/v1/remediation/{rem_id}/approve",
        headers=headers,
        json={"approved": True, "review_comment": "Verified fix"},
    )
    assert approve_resp.status_code == 200
    approved_data = approve_resp.json()
    assert approved_data["status"] == "approved_applied"
    assert Path(approved_data["backup_path"]).exists()

    # 6. Run post-remediation verification re-scan
    verify_resp = client.post(f"/api/v1/verification/run/{rem_id}", headers=headers)
    assert verify_resp.status_code == 200
    assert verify_resp.json()["original_finding_resolved"] is True
    assert verify_resp.json()["verification_status"] == "verified_fixed"

    # 7. Generate and download report
    rep_resp = client.post(
        "/api/v1/reports/generate",
        headers=headers,
        json={"format": "markdown", "scan_job_id": scan_data["id"]},
    )
    assert rep_resp.status_code == 200
    filename = rep_resp.json()["filename"]
    dl = client.get(f"/api/v1/reports/{filename}/download", headers=headers)
    assert dl.status_code == 200
    assert "Web Guard AI" in dl.text


def test_domain_authorization_enforced_before_scan(client):
    headers = _register_and_login(client)

    with patch("app.api.v1.endpoints.domain_scans.resolve_and_validate_host", return_value=["93.184.216.34"]):
        target_resp = client.post(
            "/api/v1/domain-scans/targets",
            headers=headers,
            json={"domain_or_url": "https://example.com", "scope_notes": "Authorized staging"},
        )
    assert target_resp.status_code == 201
    target_id = target_resp.json()["id"]
    assert target_resp.json()["is_authorized"] is False

    # Scanning before verification must be rejected (403)
    blocked_scan = client.post("/api/v1/domain-scans", headers=headers, json={"target_id": target_id})
    assert blocked_scan.status_code == 403

    # Explicit authorization verification unlocks target
    verify_resp = client.post(
        f"/api/v1/domain-scans/targets/{target_id}/verify",
        headers=headers,
        json={
            "method": "explicit_authorization",
            "signed_statement": "I am the authorized domain administrator approving non-destructive testing.",
        },
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["is_authorized"] is True


def test_intelligence_sync_endpoint_with_mocked_feeds(client):
    headers = _register_and_login(client)

    mock_kev = {
        "ok": True,
        "source": "cisa_kev",
        "items": [
            {
                "cveID": "CVE-2025-7777",
                "vulnerabilityName": "Test KEV Vuln",
                "shortDescription": "Exploited in the wild.",
                "dateAdded": "2025-02-01",
                "requiredAction": "Patch immediately",
            }
        ],
    }
    with patch("app.engines.intelligence.sync_manager.fetch_cisa_kev", return_value=mock_kev):
        sync_resp = client.post(
            "/api/v1/intelligence/sync",
            headers=headers,
            json={"sources": ["cisa_kev"], "days_back": 7},
        )
    assert sync_resp.status_code == 200
    assert sync_resp.json()[0]["records_created"] == 1

    cve_list = client.get("/api/v1/cve?kev_only=true", headers=headers)
    assert cve_list.status_code == 200
    assert cve_list.json()["items"][0]["cve_id"] == "CVE-2025-7777"


def test_chunked_folder_code_upload_workflow(client):
    headers = _register_and_login(client)

    init_resp = client.post(
        "/api/v1/code-scans/upload/init",
        headers=headers,
        json={"target_label": "large_project (2 files)", "total_files": 2},
    )
    assert init_resp.status_code == 201
    scan_id = init_resp.json()["id"]

    c1 = client.post(
        f"/api/v1/code-scans/upload/{scan_id}/chunk",
        headers=headers,
        files=[("files", ("large_project/sub/safe.py", io.BytesIO(b"def ok():\n    return 1\n"), "text/x-python"))],
    )
    assert c1.status_code == 200
    assert c1.json()["uploaded_files"] == 1

    c2 = client.post(
        f"/api/v1/code-scans/upload/{scan_id}/chunk",
        headers=headers,
        files=[("files", ("large_project/app.py", io.BytesIO(b"import os\ndef run(x):\n    os.system(x)\n"), "text/x-python"))],
    )
    assert c2.status_code == 200
    assert c2.json()["uploaded_files"] == 2

    exec_resp = client.post(f"/api/v1/code-scans/upload/{scan_id}/execute", headers=headers)
    assert exec_resp.status_code == 200
    data = exec_resp.json()
    assert data["status"] == "completed"
    assert data["summary"]["files_scanned"] == 2
    assert data["summary"]["confirmed_findings"] >= 1

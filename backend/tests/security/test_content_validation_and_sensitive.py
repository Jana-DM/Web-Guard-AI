import io
import zipfile
from pathlib import Path
from unittest.mock import patch

from app.engines.code_scanner.project_validator import build_project_inventory, validate_web_project
from app.engines.code_scanner.secret_detector import mask_secret, scan_file_for_sensitive_info
from app.models.scan_job import ScanJob


def _auth_headers(client):
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "scanner_lead@webguard.io",
            "username": "scanner_lead",
            "password": "StrongPassword123!",
            "full_name": "Scanner Lead",
        },
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": "scanner_lead", "password": "StrongPassword123!"},
    )
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_validation_fails_for_non_web_media_only_project(client):
    headers = _auth_headers(client)
    resp = client.post(
        "/api/v1/code-scans/upload",
        headers=headers,
        files=[
            ("files", ("media_only/pic1.png", io.BytesIO(b"\x89PNG\r\n\x1a\n"), "image/png")),
            ("files", ("media_only/clip.mp4", io.BytesIO(b"\x00\x00\x00\x18ftyp"), "video/mp4")),
        ],
    )
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert "Web Project Validation Failed" in detail


def test_validation_succeeds_and_scans_react_vite_project_with_masked_secrets(client, db_session):
    headers = _auth_headers(client)
    secret_key = "sk_live_51M0123456789ABCDEF012345"
    jwt_secret = "my_super_secret_jwt_signing_key_999"

    package_json = b'{"name": "my-vite-app", "dependencies": {"react": "^18.2.0", "vite": "^5.0.0"}}'
    vite_config = b"import { defineConfig } from 'vite'; export default defineConfig({});"
    app_jsx = b"""
    import React from 'react';
    export function App() {
        const rawHtml = '<img src=x onerror=alert(1)>';
        return <div dangerouslySetInnerHTML={{ __html: rawHtml }} />;
    }
    """
    env_content = f"VITE_STRIPE_KEY={secret_key}\nJWT_SECRET={jwt_secret}\n".encode()

    resp = client.post(
        "/api/v1/code-scans/upload",
        headers=headers,
        files=[
            ("files", ("my-website/package.json", io.BytesIO(package_json), "application/json")),
            ("files", ("my-website/vite.config.js", io.BytesIO(vite_config), "application/javascript")),
            ("files", ("my-website/src/App.jsx", io.BytesIO(app_jsx), "text/javascript")),
            ("files", ("my-website/.env", io.BytesIO(env_content), "text/plain")),
            ("files", ("my-website/public/logo.png", io.BytesIO(b"\x89PNG"), "image/png")),
        ],
    )
    assert resp.status_code == 201
    data = resp.json()
    summary = data["summary"]

    # 1. Project Technology Validation
    assert summary["validation_status"] == "VALIDATED"
    assert "React" in summary["detected_technologies"]
    assert "Vite" in summary["detected_technologies"]

    # 2. File Inventory
    assert summary["total_files_discovered"] >= 5
    assert summary["total_files_scanned"] >= 4  # package.json, vite.config.js, App.jsx, .env
    assert summary["total_files_excluded"] >= 1  # logo.png binary

    # 3. Sensitive Information Detection with strict masking
    assert summary["sensitive_findings_count"] >= 2
    sensitive_items = summary["sensitive_information_findings"]
    assert any(s["type"] == "Stripe Secret Key" or "Secret" in s["type"] for s in sensitive_items)

    # Verify secret value is masked and never exposed in full plaintext
    for s in sensitive_items:
        assert secret_key not in s["masked_value"]
        assert jwt_secret not in s["masked_value"]
        assert "*" in s["masked_value"]

    # 4. Web Security Vulnerabilities (dangerouslySetInnerHTML XSS + .gitignore missing .env)
    assert summary["classification_breakdown"]["confirmed"] >= 1


def test_secret_masking_utility():
    assert mask_secret("sk-1234567890abcdef") != "sk-1234567890abcdef"
    assert "*" in mask_secret("sk-1234567890abcdef")
    assert mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA**************LE"

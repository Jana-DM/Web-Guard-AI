import io
import zipfile
from pathlib import Path
from unittest.mock import patch

from app.engines.code_scanner.content_validator import sanitize_workspace_sensitive_items, validate_workspace_content
from app.models.scan_job import ScanJob


def _auth_headers(client):
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "guard@webguard.io",
            "username": "guard_lead",
            "password": "StrongPassword123!",
            "full_name": "Guard Lead",
        },
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": "guard_lead", "password": "StrongPassword123!"},
    )
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_rejects_images_videos_only_folder(client):
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
    detail = resp.json()["detail"].lower()
    assert "no valid web or source code files" in detail
    assert "image" in detail
    assert "video" in detail


def test_rejects_plain_text_only_upload(client):
    headers = _auth_headers(client)
    resp = client.post(
        "/api/v1/code-scans/upload",
        headers=headers,
        files=[
            ("files", ("notes.txt", io.BytesIO(b"Meeting notes: buy coffee and check schedule."), "text/plain")),
        ],
    )
    assert resp.status_code == 400
    assert "plain text" in resp.json()["detail"].lower()


def test_scans_html_css_mixed_with_images_and_excludes_sensitive_without_saving(client, db_session):
    headers = _auth_headers(client)
    secret_marker = "SUPER_SECRET_NEVER_INSPECT_OR_SAVE_TOKEN_999"
    html_bytes = b"<html><body><button onclick='alert(1)'>Go</button></body></html>"
    css_bytes = b"@import 'http://cdn.insecure.example/style.css'; body { color: #fff; }"

    resp = client.post(
        "/api/v1/code-scans/upload",
        headers=headers,
        files=[
            ("files", ("webapp/index.html", io.BytesIO(html_bytes), "text/html")),
            ("files", ("webapp/styles.css", io.BytesIO(css_bytes), "text/css")),
            ("files", ("webapp/banner.jpg", io.BytesIO(b"\xff\xd8\xff\xe0"), "image/jpeg")),
            ("files", ("webapp/.env", io.BytesIO(f"API_SECRET={secret_marker}\n".encode()), "text/plain")),
            ("files", ("webapp/secrets/private.key", io.BytesIO(secret_marker.encode()), "application/octet-stream")),
        ],
    )
    assert resp.status_code == 201
    data = resp.json()
    summary = data["summary"]
    assert summary["files_scanned"] == 2
    assert summary["languages"]["html"] == 1
    assert summary["languages"]["css"] == 1
    assert summary["skipped_non_web"]["images"] == 1
    assert "webapp/.env" in summary["sensitive_detected"]
    assert any(s.startswith("webapp/secrets") for s in summary["sensitive_detected"])

    # Verify sensitive contents were NEVER saved to workspace on disk or into DB findings
    job = db_session.query(ScanJob).filter(ScanJob.id == data["id"]).first()
    workspace = Path(job.source_path)
    assert not (workspace / "webapp" / ".env").exists()
    assert not (workspace / "webapp" / "secrets").exists()
    assert not (workspace / "webapp" / "banner.jpg").exists()

    vulns_resp = client.get(f"/api/v1/vulnerabilities?scan_job_id={data['id']}", headers=headers)
    assert secret_marker not in vulns_resp.text


def test_zip_archive_skips_sensitive_entries_without_extracting(client, db_session):
    headers = _auth_headers(client)
    secret_marker = "ZIP_SECRET_SHOULD_NEVER_HIT_DISK_12345"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("site/.env", f"DB_PASS={secret_marker}\n")
        zf.writestr("site/secrets/key.pem", secret_marker)
        zf.writestr("site/app.html", "<a href='javascript:alert(1)'>click</a>")

    resp = client.post(
        "/api/v1/code-scans/upload",
        headers=headers,
        files=[("files", ("bundle.zip", io.BytesIO(buf.getvalue()), "application/zip"))],
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "site/.env" in data["summary"]["sensitive_detected"]
    assert any("secrets" in s for s in data["summary"]["sensitive_detected"])

    job = db_session.query(ScanJob).filter(ScanJob.id == data["id"]).first()
    workspace = Path(job.source_path)
    for p in workspace.rglob("*"):
        if p.is_file():
            assert secret_marker not in p.read_text(encoding="utf-8", errors="ignore")


def test_github_workspace_sanitization_and_media_only_rejection(tmp_path):
    # Repo with only images + sensitive dir must be rejected and cleaned up
    media_repo = tmp_path / "media_repo"
    (media_repo / "certs").mkdir(parents=True)
    (media_repo / "certs" / "tls.key").write_text("PRIVATE_KEY_DATA", encoding="utf-8")
    (media_repo / "logo.png").write_bytes(b"\x89PNG")

    removed = sanitize_workspace_sensitive_items(media_repo)
    assert "certs/" in removed
    assert not (media_repo / "certs").exists()

    try:
        validate_workspace_content(media_repo, pre_sensitive=removed)
        assert False, "Expected ValueError for media-only GitHub workspace"
    except ValueError as exc:
        msg = str(exc).lower()
        assert "no valid web or source code files" in msg
        assert "certs/" in msg
    assert not media_repo.exists()

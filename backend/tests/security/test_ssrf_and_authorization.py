import io
import zipfile
import pytest

from app.core.exceptions import SSRFProtectionError, UnauthorizedTargetError
from app.engines.domain_scanner.authorization import assert_target_authorized
from app.engines.domain_scanner.target_validator import is_public_ip, validate_url_in_scope
from app.models.authorized_target import AuthorizedTarget
from app.utils.file_utils import safe_extract_zip
from app.utils.validators import normalize_domain_or_url


def test_private_and_metadata_ips_blocked():
    for blocked in ("127.0.0.1", "10.0.0.1", "172.16.0.5", "192.168.1.1", "169.254.169.254", "::1"):
        assert is_public_ip(blocked) is False
    assert is_public_ip("93.184.216.34") is True


def test_localhost_and_direct_ip_rejected():
    for bad in ("http://localhost:8000", "http://127.0.0.1", "http://internal.local"):
        with pytest.raises(ValueError):
            normalize_domain_or_url(bad)


def test_redirect_out_of_scope_blocked():
    with pytest.raises(SSRFProtectionError):
        validate_url_in_scope("https://evil.com/admin", allowed_domain="example.com")


def test_unauthorized_target_blocked():
    target = AuthorizedTarget(
        created_by="user-1",
        domain="example.com",
        normalized_url="https://example.com",
        is_authorized=False,
    )
    with pytest.raises(UnauthorizedTargetError):
        assert_target_authorized(target)


def test_zip_slip_traversal_blocked(tmp_path):
    zip_path = tmp_path / "malicious.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../outside.py", "print('pwn')")
    zip_path.write_bytes(buf.getvalue())

    with pytest.raises(ValueError, match="Unsafe path traversal"):
        safe_extract_zip(zip_path, tmp_path / "extract")

import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


def _get_fernet() -> Fernet:
    settings = get_settings()
    if settings.ENCRYPTION_KEY:
        try:
            return Fernet(settings.ENCRYPTION_KEY.encode("utf-8"))
        except Exception:
            pass
    derived = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(derived)
    return Fernet(key)


def encrypt_value(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_value(ciphertext: str) -> str:
    try:
        return _get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Failed to decrypt value.") from exc

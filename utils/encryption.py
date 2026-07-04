# Symmetric encryption for user API keys using Fernet (AES-128-CBC + HMAC-SHA256)
# The encryption key is stored in .env as GROQ_ENCRYPTION_KEY and MUST be kept safe.
# If the key is lost, all stored user API keys become permanently undecryptable.

import logging
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

# Lazy-loaded cipher — initialized on first use so settings are fully resolved.
_cipher = None


def _get_cipher() -> Fernet:
    """Return a cached Fernet cipher seeded from GROQ_ENCRYPTION_KEY."""
    global _cipher
    if _cipher is not None:
        return _cipher

    from config.settings import get_settings
    settings = get_settings()
    key = settings.groq_encryption_key
    if not key:
        raise RuntimeError(
            "GROQ_ENCRYPTION_KEY is not set in the environment. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    _cipher = Fernet(key.encode() if isinstance(key, str) else key)
    return _cipher


def encrypt_api_key(raw_key: str) -> str:
    """Encrypt a plaintext API key and return a URL-safe base64-encoded string."""
    if not raw_key:
        raise ValueError("Cannot encrypt an empty API key")
    cipher = _get_cipher()
    return cipher.encrypt(raw_key.encode("utf-8")).decode("utf-8")


def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt a previously encrypted API key back to plaintext."""
    if not encrypted_key:
        raise ValueError("Cannot decrypt an empty value")
    cipher = _get_cipher()
    try:
        return cipher.decrypt(encrypted_key.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.error("Failed to decrypt API key — the encryption key may have changed")
        raise ValueError(
            "API key decryption failed. The encryption key may have been rotated. "
            "Please re-enter your Groq API key in Settings."
        )

"""Server-side secret handling (stdlib + cryptography). Secrets are passed in explicitly so this stays testable."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken


def _fernet(secret_key: str) -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(("sentinelx-secrets-v1|" + secret_key).encode()).digest())
    return Fernet(key)


def encrypt(secret_key: str, plaintext: str) -> str:
    return _fernet(secret_key).encrypt(plaintext.encode()).decode()


def decrypt(secret_key: str, token: str) -> str:
    try:
        return _fernet(secret_key).decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("stored secret cannot be decrypted (was SECRET_KEY changed?)") from exc


def key_hint(plaintext: str) -> str:
    """Only the last 4 characters, for display ('****abcd')."""
    return "****" + plaintext[-4:] if len(plaintext) >= 8 else "****"


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(secret_key: str, raw: str) -> str:
    return hmac.new(secret_key.encode(), b"token|" + raw.encode(), hashlib.sha256).hexdigest()

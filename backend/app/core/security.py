"""Password hashing (Argon2id), JWT tokens and collector API keys."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import get_settings

_ph = PasswordHasher()  # argon2-cffi defaults to Argon2id
_DUMMY_HASH = _ph.hash("sentinelx-timing-equalizer")
MIN_PASSWORD_LEN = 12


def validate_password_strength(pw: str) -> None:
    if len(pw) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    if len(pw) > 256:
        raise ValueError("password too long")


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, hashed: str | None) -> bool:
    """Constant-ish time: verifies against a dummy hash when the user is unknown."""
    try:
        _ph.verify(hashed or _DUMMY_HASH, pw)
        return hashed is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    return _ph.check_needs_rehash(hashed)


# ------------------------------------------------------------------------ JWT
def _encode(claims: dict, expires: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {**claims, "iat": now, "exp": now + expires, "iss": "sentinelx"}
    return jwt.encode(payload, get_settings().secret_key, algorithm="HS256")


def create_access_token(user_id: uuid.UUID) -> str:
    return _encode({"sub": str(user_id), "typ": "access"}, timedelta(minutes=get_settings().access_token_minutes))


def create_refresh_token(user_id: uuid.UUID) -> tuple[str, str, datetime]:
    jti = secrets.token_urlsafe(24)
    expires = timedelta(days=get_settings().refresh_token_days)
    token = _encode({"sub": str(user_id), "typ": "refresh", "jti": jti}, expires)
    return token, jti, datetime.now(timezone.utc) + expires


def decode_token(token: str, expected_type: str) -> dict:
    payload = jwt.decode(token, get_settings().secret_key, algorithms=["HS256"], issuer="sentinelx",
                         options={"require": ["exp", "iat", "sub", "typ"]})
    if payload.get("typ") != expected_type:
        raise jwt.InvalidTokenError("wrong token type")
    return payload


# ----------------------------------------------------------- collector API keys
def _pepper() -> bytes:
    return get_settings().secret_key.encode()


def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix, hash). Full key is shown once and never stored."""
    prefix = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    full = f"sxk_{prefix}_{secret}"
    return full, prefix, hash_api_key(full)


def hash_api_key(full_key: str) -> str:
    return hmac.new(_pepper(), full_key.encode(), hashlib.sha256).hexdigest()


def parse_api_key_prefix(full_key: str) -> str | None:
    parts = full_key.split("_", 2)
    if len(parts) != 3 or parts[0] != "sxk" or len(parts[1]) != 8:
        return None
    return parts[1]


def verify_api_key(full_key: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_api_key(full_key), stored_hash)

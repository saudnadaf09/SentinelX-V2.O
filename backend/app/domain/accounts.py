"""Pure validation/normalization for registration and profile data."""
from __future__ import annotations

import re
import unicodedata

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")
RESERVED_USERNAMES = {"admin", "root", "system", "support", "sentinelx", "administrator", "null", "undefined"}
ACCOUNT_TYPES = ("individual", "organization")


class ValidationFailed(ValueError):
    """Carries field-level messages: {field: message}."""

    def __init__(self, errors: dict[str, str]):
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


def normalize_email(email: str) -> str:
    return unicodedata.normalize("NFKC", email).strip().lower()


def valid_email(email: str) -> bool:
    return len(email) <= 254 and bool(EMAIL_RE.match(email))


def password_problems(pw: str, *, email: str = "", username: str = "") -> list[str]:
    out = []
    if len(pw) < 12:
        out.append("must be at least 12 characters")
    if len(pw) > 256:
        out.append("must be at most 256 characters")
    classes = sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        out.append("must mix at least 3 of: lowercase, uppercase, digits, symbols")
    low = pw.lower()
    for ident in (email.split("@")[0] if email else "", username):
        if ident and len(ident) >= 4 and ident.lower() in low:
            out.append("must not contain your email name or username")
            break
    return out


def validate_registration(d: dict) -> dict:
    """Return a cleaned copy of the registration payload or raise ValidationFailed."""
    e: dict[str, str] = {}
    full_name = " ".join(str(d.get("full_name", "")).split())
    if not 2 <= len(full_name) <= 120:
        e["full_name"] = "required (2-120 characters)"
    email = normalize_email(str(d.get("email", "")))
    if not valid_email(email):
        e["email"] = "enter a valid email address"
    username = str(d.get("username", "")).strip()
    if not USERNAME_RE.match(username):
        e["username"] = "3-32 characters: letters, digits, dot, dash, underscore; must start with a letter or digit"
    elif username.lower() in RESERVED_USERNAMES:
        e["username"] = "this username is reserved"
    pw, confirm = str(d.get("password", "")), str(d.get("confirm_password", ""))
    problems = password_problems(pw, email=email, username=username)
    if problems:
        e["password"] = "; ".join(problems)
    if pw != confirm:
        e["confirm_password"] = "passwords do not match"
    atype = d.get("account_type")
    if atype not in ACCOUNT_TYPES:
        e["account_type"] = "choose Individual or Organization"
    org_name = " ".join(str(d.get("organization_name") or "").split())
    org_email = normalize_email(str(d.get("organization_email") or ""))
    org_details = str(d.get("organization_details") or "").strip()
    if atype == "organization":
        if not 2 <= len(org_name) <= 120:
            e["organization_name"] = "required for organization accounts (2-120 characters)"
        if not valid_email(org_email):
            e["organization_email"] = "enter a valid organization email"
        if not 10 <= len(org_details) <= 2000:
            e["organization_details"] = "required for organization accounts (10-2000 characters)"
    if e:
        raise ValidationFailed(e)
    return {"full_name": full_name, "email": email, "username": username, "password": pw, "account_type": atype,
            "organization_name": org_name or None, "organization_email": org_email or None,
            "organization_details": org_details or None}


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower()).strip("-")
    return (s or "workspace")[:40]

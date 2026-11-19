import os
import tempfile
import unittest

from app.core.permissions import PERMISSIONS, has_permission
from app.domain import accounts, mailer, secrets_util as su

GOOD = {"full_name": "  Saud   Nadaf ", "email": "Saud@Example.COM ", "username": "saud_n", "password": "Zx9!kLm2#qWe",
        "confirm_password": "Zx9!kLm2#qWe", "account_type": "individual"}


class RegistrationValidation(unittest.TestCase):
    def test_valid_individual_is_normalized(self):
        c = accounts.validate_registration(GOOD)
        self.assertEqual((c["full_name"], c["email"]), ("Saud Nadaf", "saud@example.com"))

    def test_each_field_is_checked(self):
        cases = {
            "email": {**GOOD, "email": "not-an-email"},
            "username": {**GOOD, "username": "a b"},
            "password": {**GOOD, "password": "short1A!", "confirm_password": "short1A!"},
            "confirm_password": {**GOOD, "confirm_password": "different-Pass1!"},
            "account_type": {**GOOD, "account_type": "alien"},
            "full_name": {**GOOD, "full_name": ""},
        }
        for field, payload in cases.items():
            with self.assertRaises(accounts.ValidationFailed, msg=field) as cm:
                accounts.validate_registration(payload)
            self.assertIn(field, cm.exception.errors)

    def test_reserved_username_and_password_containing_username(self):
        with self.assertRaises(accounts.ValidationFailed) as cm:
            accounts.validate_registration({**GOOD, "username": "admin"})
        self.assertIn("username", cm.exception.errors)
        self.assertTrue(accounts.password_problems("Saud_n-Passw0rd!x", username="saud_n"))

    def test_organization_requires_extra_fields(self):
        with self.assertRaises(accounts.ValidationFailed) as cm:
            accounts.validate_registration({**GOOD, "account_type": "organization"})
        self.assertEqual({"organization_name", "organization_email", "organization_details"}, set(cm.exception.errors))
        ok = accounts.validate_registration({**GOOD, "account_type": "organization", "organization_name": "Acme Labs",
                                             "organization_email": "SEC@acme.io", "organization_details": "Security team of ten"})
        self.assertEqual(ok["organization_email"], "sec@acme.io")


class Secrets(unittest.TestCase):
    def test_encrypt_roundtrip_and_no_plaintext(self):
        key = "k" * 40
        tok = su.encrypt(key, "sk-super-secret-1234")
        self.assertNotIn("super-secret", tok)
        self.assertEqual(su.decrypt(key, tok), "sk-super-secret-1234")
        with self.assertRaises(ValueError):
            su.decrypt("other-secret-" + "z" * 30, tok)  # wrong SECRET_KEY cannot read it
        self.assertEqual(su.key_hint("sk-super-secret-1234"), "****1234")

    def test_tokens_are_random_and_hashed(self):
        a, b = su.new_token(), su.new_token()
        self.assertNotEqual(a, b)
        self.assertEqual(su.hash_token("s" * 40, a), su.hash_token("s" * 40, a))
        self.assertNotEqual(su.hash_token("s" * 40, a), su.hash_token("t" * 40, a))
        self.assertNotIn(a, su.hash_token("s" * 40, a))


class Mail(unittest.TestCase):
    def test_console_mode_never_claims_delivery(self):
        d = tempfile.mkdtemp()
        r = mailer.send_mail(mode="console", to="a@b.co", subject="Hi", body="link", sender="x@y.z", outbox_dir=d)
        self.assertFalse(r["delivered"])
        text = open(r["outbox_file"]).read()
        self.assertIn("no real email was sent", text)

    def test_smtp_without_host_reports_failure(self):
        r = mailer.send_mail(mode="smtp", to="a@b.co", subject="s", body="b", sender="x@y.z", outbox_dir=tempfile.mkdtemp())
        self.assertFalse(r["delivered"])
        r2 = mailer.send_mail(mode="smtp", to="a@b.co", subject="s", body="b", sender="x@y.z", outbox_dir=".",
                              smtp_host="127.0.0.1", smtp_port=1)  # nothing listens here
        self.assertFalse(r2["delivered"])


class RoleMatrix(unittest.TestCase):
    def test_role_boundaries(self):
        p = lambda r, perm: has_permission(r, perm)  # noqa: E731
        self.assertFalse(p("viewer", "alerts:write"))
        self.assertTrue(p("analyst", "incidents:write") and not p("analyst", "rules:override") and not p("analyst", "assets:write"))
        self.assertTrue(p("engineer", "rules:override") and p("engineer", "keys:manage") and not p("engineer", "incidents:write"))
        self.assertTrue(p("org_admin", "users:manage") and p("org_admin", "ai:configure") and not p("org_admin", "platform:manage"))
        self.assertFalse(p("org_admin", "rules:write"))
        self.assertTrue(p("super_admin", "platform:manage") and p("super_admin", "rules:write"))
        for role in ("viewer", "analyst", "engineer", "org_admin"):
            self.assertFalse(has_permission(role, "platform:manage"))
        self.assertFalse(has_permission("nonsense", "events:read"))


if __name__ == "__main__":
    unittest.main()

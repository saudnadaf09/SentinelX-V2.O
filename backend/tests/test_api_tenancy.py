"""Registration, roles, tenant isolation, AI settings, invitations, resets. REQUIRES the full dependency set
(pip install -r requirements-dev.txt); written but NOT executed in the authoring sandbox."""
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.db.session import get_session_factory
from app.main import create_app
from app.models import AiSetting, Alert, User
from sqlalchemy import select

API = "/api/v1"
PW = "Zx9!kLm2#qWe"


def reg(client, n, kind="individual", **extra):
    body = {"full_name": f"User {n}", "email": f"user{n}@example.com", "username": f"user_{n}x", "password": PW,
            "confirm_password": PW, "account_type": kind, **extra}
    if kind == "organization":
        body.update(organization_name=f"Org {n} Ltd", organization_email=f"sec{n}@org{n}.io", organization_details="A security team of ten people")
    return client.post(f"{API}/auth/register", json=body)


def login(client, ident, pw=PW):
    r = client.post(f"{API}/auth/login", json={"email": ident, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def mk_org(client, n):
    assert reg(client, n, "organization").status_code == 201
    return login(client, f"user{n}@example.com")


def outbox_token(purpose_word):
    d = Path(os.environ["OUTBOX_DIR"])
    for f in sorted(d.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True):
        t = f.read_text()
        if purpose_word in t:
            return re.search(r"token=([A-Za-z0-9_-]+)", t).group(1)
    raise AssertionError("no mail found")


def fail_events(prefix, ip, n, host="WEB-1"):
    now = datetime.now(timezone.utc)
    return [{"event_id": f"{prefix}{i}", "timestamp": (now - timedelta(seconds=30 - i)).isoformat(), "source_type": "linux_auth",
             "host": {"name": host}, "raw": {"program": "sshd", "message": f"Failed password for root from {ip} port 22 ssh2"}}
            for i in range(n)]


def endpoint(client, h, host="WEB-1"):
    a = client.post(f"{API}/assets/register", headers=h, json={"hostname": host, "platform": "linux", "authorized": True}).json()
    key = client.post(f"{API}/assets/{a['id']}/keys", headers=h, json={"name": "k"}).json()["api_key"]
    return a, key


def ingest(client, key, events):
    r = client.post(f"{API}/ingest/events/batch", headers={"X-API-Key": key}, json={"events": events})
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------------- registration & login
def test_registration_login_duplicates_and_validation(client):
    r = reg(client, 1)
    assert r.status_code == 201 and r.json()["user"]["role"] == "org_admin" and r.json()["user"]["organization"]["kind"] == "individual"
    assert "password_hash" not in r.text
    assert client.post(f"{API}/auth/login", json={"email": "user_1x", "password": PW}).status_code == 200  # by username
    assert client.post(f"{API}/auth/login", json={"email": "user1@example.com", "password": "wrong-Pass-1!"}).status_code == 401
    assert reg(client, 1).status_code == 409                                   # duplicate email AND username
    dup_user = reg(client, 2); assert dup_user.status_code == 201
    r = client.post(f"{API}/auth/register", json={"full_name": "X Y", "email": "other@example.com", "username": "USER_1X", "password": PW,
                                                  "confirm_password": PW, "account_type": "individual"})
    assert r.status_code == 409                                                # username unique case-insensitively
    bad = client.post(f"{API}/auth/register", json={"full_name": "A", "email": "nope", "username": "a b", "password": "short",
                                                    "confirm_password": "x", "account_type": "organization"})
    assert bad.status_code == 400
    fields = {d["field"] for d in bad.json()["error"]["details"]}
    assert {"full_name", "email", "username", "password", "confirm_password", "organization_name"} <= fields
    sneaky = client.post(f"{API}/auth/register", json={"full_name": "Evil One", "email": "e@example.com", "username": "evil_x", "password": PW,
                                                       "confirm_password": PW, "account_type": "individual", "role": "super_admin"})
    assert sneaky.status_code == 400                                           # public registration can never choose a role


def test_registered_account_survives_restart_and_password_is_hashed(client):
    reg(client, 3)
    with get_session_factory()() as db:
        u = db.scalar(select(User).where(User.email == "user3@example.com"))
        assert u.password_hash.startswith("$argon2id$") and PW not in u.password_hash
    with TestClient(create_app()) as fresh:                                    # simulated restart: new app, same database
        assert fresh.post(f"{API}/auth/login", json={"email": "user3@example.com", "password": PW}).status_code == 200


def test_logout_refresh_rotation_and_sessions(client):
    reg(client, 4)
    t = client.post(f"{API}/auth/login", json={"email": "user4@example.com", "password": PW}).json()
    h = {"Authorization": f"Bearer {t['access_token']}"}
    assert len(client.get(f"{API}/auth/sessions", headers=h).json()["items"]) == 1
    new = client.post(f"{API}/auth/refresh", json={"refresh_token": t["refresh_token"]})
    assert new.status_code == 200
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": t["refresh_token"]}).status_code == 401  # rotated token is dead
    client.post(f"{API}/auth/logout", headers=h, json={"refresh_token": new.json()["refresh_token"]})
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": new.json()["refresh_token"]}).status_code == 401


def test_email_verification_and_password_reset_are_real_single_use_flows(client):
    reg(client, 5)
    h = login(client, "user5@example.com")
    assert client.get(f"{API}/auth/me", headers=h).json()["email_verified"] is False   # not claimed until it really happens
    tok = outbox_token("Confirm your email")
    assert client.post(f"{API}/auth/verify-email", json={"token": tok}).status_code == 200
    assert client.get(f"{API}/auth/me", headers=h).json()["email_verified"] is True
    assert client.post(f"{API}/auth/verify-email", json={"token": tok}).status_code == 400   # single use
    assert client.post(f"{API}/auth/verify-email", json={"token": "x" * 30}).status_code == 400
    r = client.post(f"{API}/auth/forgot-password", json={"email": "ghost@example.com"})
    assert r.status_code == 200                                                 # identical answer for unknown accounts
    client.post(f"{API}/auth/forgot-password", json={"email": "user5@example.com"})
    rt = outbox_token("Reset link")
    new_pw = "Qw3#rTy8!uIoP"
    assert client.post(f"{API}/auth/reset-password", json={"token": rt, "new_password": new_pw}).status_code == 200
    assert client.post(f"{API}/auth/reset-password", json={"token": rt, "new_password": new_pw}).status_code == 400
    assert client.post(f"{API}/auth/login", json={"email": "user5@example.com", "password": PW}).status_code == 401
    assert client.post(f"{API}/auth/login", json={"email": "user5@example.com", "password": new_pw}).status_code == 200


# --------------------------------------------------------------------------- tenant isolation
def test_cross_tenant_access_is_denied_everywhere(client):
    a, b = mk_org(client, 10), mk_org(client, 11)
    asset_a, key_a = endpoint(client, a)
    ingest(client, key_a, fail_events("a", "203.0.113.9", 6))
    alerts_a = client.get(f"{API}/alerts", headers=a).json()["items"]
    assert alerts_a and alerts_a[0]["rule_key"] == "SX-AUTH-001"
    alert_id = alerts_a[0]["id"]
    ev_id = client.get(f"{API}/events", headers=a).json()["items"][0]["event"]["id"]
    inc = client.post(f"{API}/alerts/{alert_id}/incident", headers=a).json()
    key_id = client.get(f"{API}/assets/{asset_a['id']}/keys", headers=a).json()["items"][0]["id"]

    assert client.get(f"{API}/alerts", headers=b).json()["total"] == 0
    assert client.get(f"{API}/events", headers=b).json()["total"] == 0
    assert client.get(f"{API}/assets", headers=b).json()["items"] == []
    assert client.get(f"{API}/incidents", headers=b).json()["total"] == 0
    for method, url, body in [("get", f"/alerts/{alert_id}", None), ("patch", f"/alerts/{alert_id}", {"status": "resolved"}),
                              ("post", f"/alerts/{alert_id}/incident", None), ("get", f"/events/{ev_id}", None),
                              ("get", f"/incidents/{inc['id']}", None), ("get", f"/incidents/{inc['id']}/timeline", None),
                              ("post", f"/incidents/{inc['id']}/notes", {"note": "x"}), ("get", f"/assets/{asset_a['id']}/keys", None),
                              ("post", f"/assets/{asset_a['id']}/keys", {"name": "steal"}), ("post", f"/assets/keys/{key_id}/revoke", None),
                              ("delete", f"/assets/{asset_a['id']}", None), ("post", f"/ai/rule-summary/{alert_id}", None),
                              ("post", f"/ai/investigate/{alert_id}", None), ("get", f"/reports/incidents/{inc['id']}", None)]:
        r = getattr(client, method)(f"{API}{url}", headers=b, **({"json": body} if body else {}))
        assert r.status_code in (404, 403, 503), f"{method} {url} -> {r.status_code}"
        assert r.status_code != 200
    assert client.post(f"{API}/incidents", headers=b, json={"title": "grab", "alert_ids": [alert_id]}).status_code == 404
    hunt = client.post(f"{API}/hunt/search", headers=b, json={"start": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
                                                                "end": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(), "text": "203.0.113.9"})
    assert hunt.json()["total"] == 0
    assert "203.0.113.9" not in client.get(f"{API}/audit-logs/export.csv", headers=b).text
    assert client.get(f"{API}/alerts/{alert_id}", headers=a).status_code == 200      # owner still has access
    assert client.get(f"{API}/dashboard/overview", headers=b).json()["alerts"]["total"] == 0


def test_same_ip_and_hostname_in_two_orgs_never_merge(client):
    a, b = mk_org(client, 20), mk_org(client, 21)
    _, ka = endpoint(client, a); _, kb = endpoint(client, b)           # identical hostname allowed per organization
    ingest(client, ka, fail_events("a", "203.0.113.50", 3)); ingest(client, kb, fail_events("b", "203.0.113.50", 3))
    assert client.get(f"{API}/alerts", headers=a).json()["total"] == 0 and client.get(f"{API}/alerts", headers=b).json()["total"] == 0
    ingest(client, ka, fail_events("a2-", "203.0.113.50", 3)); ingest(client, kb, fail_events("b2-", "203.0.113.50", 3))
    ra, rb = (client.get(f"{API}/alerts", headers=h).json() for h in (a, b))
    assert ra["total"] == 1 and rb["total"] == 1 and ra["items"][0]["id"] != rb["items"][0]["id"]
    with get_session_factory()() as db:
        assert len({al.org_id for al in db.scalars(select(Alert))}) == 2


def test_org_rule_override_and_custom_rules_are_per_org(client):
    a, b = mk_org(client, 30), mk_org(client, 31)
    _, ka = endpoint(client, a); _, kb = endpoint(client, b)
    rule = next(r for r in client.get(f"{API}/rules", headers=a).json()["items"] if r["rule_key"] == "SX-AUTH-001")
    assert client.patch(f"{API}/rules/{rule['id']}", headers=a, json={"enabled": False}).status_code == 200   # org A switches it off
    ingest(client, ka, fail_events("a", "203.0.113.7", 6)); ingest(client, kb, fail_events("b", "203.0.113.7", 6))
    assert client.get(f"{API}/alerts", headers=a).json()["total"] == 0          # A: disabled for A only
    assert client.get(f"{API}/alerts", headers=b).json()["total"] == 1          # B unaffected
    prefix = client.get(f"{API}/rules", headers=a).json()["org_rule_prefix"]
    y = f"id: {prefix}X1\ntitle: Custom\nseverity: low\ntype: match\nmatch:\n  - {{field: event.action, op: eq, value: ssh_login_failed}}\n"
    assert client.post(f"{API}/rules", headers=a, json={"yaml": y}).status_code == 201
    assert all(not r["rule_key"].startswith("ORG-") for r in client.get(f"{API}/rules", headers=b).json()["items"])
    assert client.post(f"{API}/rules", headers=b, json={"yaml": y}).status_code == 400    # wrong prefix for org B


# ---------------------------------------------------------------------- roles & organizations
def test_invitations_roles_and_member_management(client):
    admin = mk_org(client, 40)
    r = client.post(f"{API}/org/invitations", headers=admin, json={"email": "new@team.io", "role": "analyst"})
    assert r.status_code == 201
    link = r.json()["delivery"]["invite_link"]
    token = re.search(r"token=([A-Za-z0-9_-]+)", link).group(1)
    acc = {"token": token, "full_name": "New Member", "username": "new_member", "password": PW, "confirm_password": PW}
    assert client.post(f"{API}/auth/accept-invite", json=acc).status_code == 201
    assert client.post(f"{API}/auth/accept-invite", json=acc).status_code == 400          # single use
    member = login(client, "new@team.io")
    me = client.get(f"{API}/auth/me", headers=member).json()
    assert me["role"] == "analyst" and me["organization"]["name"] == "Org 40 Ltd"
    assert client.get(f"{API}/org/members", headers=member).status_code == 403              # analyst cannot manage members
    assert client.post(f"{API}/org/invitations", headers=member, json={"email": "x@y.io", "role": "viewer"}).status_code == 403
    members = client.get(f"{API}/org/members", headers=admin).json()["items"]
    mid = next(m["id"] for m in members if m["email"] == "new@team.io")
    assert client.patch(f"{API}/org/members/{mid}", headers=admin, json={"role": "viewer"}).json()["role"] == "viewer"
    assert client.get(f"{API}/alerts", headers=member).status_code == 200                    # viewer can read
    assert client.patch(f"{API}/alerts/00000000-0000-0000-0000-0000000000aa", headers=member, json={"status": "resolved"}).status_code == 403
    own = next(m["id"] for m in members if m["email"] == "user40@example.com")
    assert client.patch(f"{API}/org/members/{own}", headers=admin, json={"role": "viewer"}).status_code == 409   # last admin
    assert client.patch(f"{API}/org/members/{mid}", headers=admin, json={"is_active": False}).status_code == 200
    assert client.get(f"{API}/auth/me", headers=member).status_code == 401      # existing access token is rejected immediately
    assert client.post(f"{API}/auth/login", json={"email": "new@team.io", "password": PW}).status_code == 401  # access revoked
    assert client.post(f"{API}/org/invitations", headers=admin, json={"email": "user40@example.com", "role": "viewer"}).status_code == 409


def test_individual_workspace_cannot_invite_and_member_isolation(client):
    reg(client, 41); h = login(client, "user41@example.com")
    assert client.post(f"{API}/org/invitations", headers=h, json={"email": "a@b.io", "role": "viewer"}).status_code == 409
    other = mk_org(client, 42)
    mid = client.get(f"{API}/org/members", headers=other).json()["items"][0]["id"]
    assert client.patch(f"{API}/org/members/{mid}", headers=h, json={"role": "viewer"}).status_code == 404   # not even visible


def test_platform_admin_boundaries(client, login):
    mk = mk_org(client, 50)
    assert client.get(f"{API}/platform/orgs", headers=mk).status_code == 403
    sa = login("admin")
    orgs = client.get(f"{API}/platform/orgs", headers=sa).json()["items"]
    assert any(o["name"] == "Org 50 Ltd" for o in orgs)
    assert "alerts" not in orgs[0] and "evidence" not in str(orgs)              # aggregate counts only, no tenant data
    oid = next(o["id"] for o in orgs if o["name"] == "Org 50 Ltd")
    assert client.patch(f"{API}/platform/orgs/{oid}", headers=sa, json={"is_active": False}).status_code == 200
    assert client.get(f"{API}/alerts", headers=mk).status_code == 403            # suspended tenant is locked out
    assert client.patch(f"{API}/platform/orgs/{oid}", headers=sa, json={"is_active": True}).status_code == 200
    assert client.get(f"{API}/alerts", headers=mk).status_code == 200
    assert client.get(f"{API}/dashboard/overview", headers=mk).json()["pipeline"] is None   # global counters hidden from tenants


# -------------------------------------------------------------------------------- AI settings
def test_ai_key_is_encrypted_never_returned_and_unavailable_is_honest(client):
    a, b = mk_org(client, 60), mk_org(client, 61)
    assert client.get(f"{API}/ai/status", headers=a).json()["state"] == "unavailable"
    secret = "sk-test-SUPERSECRET-9999"
    r = client.put(f"{API}/ai/settings", headers=a, json={"provider": "openai", "model": "gpt-4o-mini", "api_key": secret})
    assert r.status_code == 200 and secret not in r.text
    got = client.get(f"{API}/ai/settings", headers=a)
    assert secret not in got.text and got.json()["organization"]["key_hint"] == "****9999" and got.json()["organization"]["key_set"]
    assert client.get(f"{API}/ai/status", headers=a).json()["state"] == "untested"       # configured != connected
    with get_session_factory()() as db:
        row = db.scalar(select(AiSetting))
        assert secret not in row.api_key_enc and row.api_key_enc
    assert client.get(f"{API}/ai/status", headers=b).json()["state"] == "unavailable"    # other tenants never see it
    assert client.get(f"{API}/ai/settings", headers=b).json()["organization"] is None
    viewer_like = client.put(f"{API}/ai/settings", headers=login_member(client, a, "viewer", 62), json={"provider": "openai", "model": "x", "api_key": "k" * 20})
    assert viewer_like.status_code == 403
    t = client.post(f"{API}/ai/settings/test", headers=a, json={}).json()                # a REAL call with a fake key: must fail
    assert t["ok"] is False and t["error_kind"] in ("auth", "network", "rate_limit", "bad_request", "model", "server")
    assert secret not in str(t)
    st = client.get(f"{API}/ai/status", headers=a).json()
    assert st["state"] == "error"                                                       # never "connected" after a failed test


def login_member(client, admin_headers, role, n):
    r = client.post(f"{API}/org/invitations", headers=admin_headers, json={"email": f"m{n}@team.io", "role": role})
    token = re.search(r"token=([A-Za-z0-9_-]+)", r.json()["delivery"]["invite_link"]).group(1)
    client.post(f"{API}/auth/accept-invite", json={"token": token, "full_name": "M Member", "username": f"m_{n}_x", "password": PW, "confirm_password": PW})
    return login(client, f"m{n}@team.io")


# --------------------------------------------------------------------- endpoints, export, delete
def test_deregistered_endpoint_is_rejected_and_data_class_flows_to_alerts(client):
    a = mk_org(client, 70)
    asset, key = endpoint(client, a)
    ingest(client, key, fail_events("t", "203.0.113.80", 6))
    assert client.get(f"{API}/alerts", headers=a).json()["items"][0]["data_class"] == "live"
    hb = client.post(f"{API}/agent/heartbeat", headers={"X-API-Key": key}, json={"agent_version": "1.0.0", "sources": {"auth.log": {"status": "ok"}}})
    assert hb.status_code == 200 and hb.json()["endpoint_id"] == asset["id"]
    assert [x for x in client.get(f"{API}/assets", headers=a).json()["items"]][0]["status"] == "online"
    assert client.delete(f"{API}/assets/{asset['id']}", headers=a).status_code == 200
    assert client.post(f"{API}/ingest/events/batch", headers={"X-API-Key": key}, json={"events": fail_events("z", "203.0.113.80", 1)}).status_code == 401
    assert client.post(f"{API}/agent/heartbeat", headers={"X-API-Key": key}, json={"agent_version": "1"}).status_code == 401


def test_export_has_no_secrets_and_workspace_deletion_is_complete(client):
    a = mk_org(client, 80)
    _, key = endpoint(client, a)
    ingest(client, key, fail_events("d", "203.0.113.90", 6))
    exp = client.get(f"{API}/org/export", headers=a)
    assert exp.status_code == 200 and "argon2" not in exp.text and "sxk_" not in exp.text and "password_hash" not in exp.text
    assert client.post(f"{API}/org/delete", headers=a, json={"password": "wrong", "confirm_name": "Org 80 Ltd"}).status_code == 403
    assert client.post(f"{API}/org/delete", headers=a, json={"password": PW, "confirm_name": "wrong name"}).status_code == 400
    d = client.post(f"{API}/org/delete", headers=a, json={"password": PW, "confirm_name": "Org 80 Ltd"})
    assert d.status_code == 200 and d.json()["removed"]["alerts"] == 1
    assert client.post(f"{API}/auth/login", json={"email": "user80@example.com", "password": PW}).status_code == 401
    with get_session_factory()() as db:
        assert db.scalar(select(Alert)) is None


def test_failed_logins_and_admin_actions_are_audited_per_tenant(client):
    a = mk_org(client, 90)
    client.post(f"{API}/auth/login", json={"email": "user90@example.com", "password": "bad-Pass-12!"})
    actions = {(e["action"], e["outcome"]) for e in client.get(f"{API}/audit-logs?size=100", headers=a).json()["items"]}
    assert ("user.registered", "success") in actions and ("auth.login", "failure") in actions

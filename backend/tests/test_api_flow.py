from datetime import datetime, timezone

from app.samples import LNX, WIN, build_scenario

API = "/api/v1"


def register_asset(client, h, hostname=WIN, platform="windows"):
    r = client.post(f"{API}/assets/register", headers=h, json={"hostname": hostname, "platform": platform, "authorized": True})
    assert r.status_code == 201, r.text
    return r.json()


def new_key(client, h, asset_id):
    r = client.post(f"{API}/assets/{asset_id}/keys", headers=h, json={"name": "t"})
    assert r.status_code == 201, r.text
    return r.json()


def replay(client, h):
    scenario = build_scenario(datetime.now(timezone.utc), prefix="t")
    results = {}
    for host, platform in ((WIN, "windows"), (LNX, "linux")):
        asset = register_asset(client, h, host, platform)
        key = new_key(client, h, asset["id"])["api_key"]
        r = client.post(f"{API}/ingest/events/batch", headers={"X-API-Key": key}, json={"events": scenario[host]})
        assert r.status_code == 200, r.text
        results[host] = (r.json(), key, asset)
    return scenario, results


def test_auth_basics(client, login):
    assert client.get(f"{API}/alerts").status_code == 401
    assert client.post(f"{API}/auth/login", json={"email": "admin@test.local", "password": "wrong"}).status_code == 401
    me = client.get(f"{API}/auth/me", headers=login("analyst")).json()
    assert me["role"] == "analyst" and "alerts:write" in me["permissions"] and "password_hash" not in me


def test_refresh_token_rotates(client):
    r = client.post(f"{API}/auth/login", json={"email": "admin@test.local", "password": "correct-horse-battery-1"}).json()
    ok = client.post(f"{API}/auth/refresh", json={"refresh_token": r["refresh_token"]})
    assert ok.status_code == 200
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": r["refresh_token"]}).status_code == 401  # reuse blocked


def test_rbac_enforced_server_side(client, login):
    prefix = client.get(f"{API}/rules", headers=login("engineer")).json()["org_rule_prefix"]
    yaml_rule = f"id: {prefix}T1\ntitle: t\nseverity: low\ntype: match\nmatch:\n  - {{field: a, op: eq, value: b}}\n"
    assert client.post(f"{API}/rules", headers=login("viewer"), json={"yaml": yaml_rule}).status_code == 403
    assert client.post(f"{API}/rules", headers=login("analyst"), json={"yaml": yaml_rule}).status_code == 403
    assert client.post(f"{API}/rules", headers=login("engineer"), json={"yaml": yaml_rule}).status_code == 201
    assert client.post(f"{API}/rules", headers=login("engineer"), json={"yaml": yaml_rule, "scope": "global"}).status_code == 403
    assert client.get(f"{API}/audit-logs", headers=login("analyst")).status_code == 403
    assert client.get(f"{API}/audit-logs", headers=login("admin")).status_code == 200
    assert client.get(f"{API}/users", headers=login("engineer")).status_code == 403


def test_end_to_end_ingest_detect_correlate(client, login):
    admin = login("admin")
    scenario, results = replay(client, admin)
    assert results[WIN][0]["accepted"] == len(scenario[WIN])
    alerts = client.get(f"{API}/alerts?size=100", headers=admin).json()["items"]
    keys = {a["rule_key"] for a in alerts}
    assert {"SX-AUTH-001", "SX-AUTH-003", "SX-EXEC-001", "SX-NET-001", "SX-NET-002"} <= keys
    detail = client.get(f"{API}/alerts/{alerts[0]['id']}", headers=admin).json()
    assert detail["rule_version"] >= 1 and detail["event_ids"] and detail["mitre"]
    incidents = client.get(f"{API}/incidents", headers=admin).json()["items"]
    assert incidents and incidents[0]["auto_created"]
    tl = client.get(f"{API}/incidents/{incidents[0]['id']}/timeline", headers=admin).json()["items"]
    assert any(t["kind"] == "alert" and t["detail"] for t in tl)
    ev = client.get(f"{API}/events?size=5", headers=admin).json()
    assert ev["total"] >= len(scenario[WIN])


def test_duplicate_events_do_not_duplicate_alerts(client, login):
    admin = login("admin")
    scenario, results = replay(client, admin)
    before = client.get(f"{API}/alerts?size=100", headers=admin).json()
    _, key, _ = results[LNX]
    r = client.post(f"{API}/ingest/events/batch", headers={"X-API-Key": key}, json={"events": scenario[LNX]})
    assert r.status_code == 200
    after = client.get(f"{API}/alerts?size=100", headers=admin).json()
    assert after["total"] == before["total"]
    assert [a["event_count"] for a in after["items"]] == [a["event_count"] for a in before["items"]]


def test_malformed_events_rejected_with_reason_and_keys_revocable(client, login):
    admin = login("admin")
    asset = register_asset(client, admin)
    k = new_key(client, admin, asset["id"])
    good = {"event_id": "g1", "timestamp": "2026-11-14T10:00:00Z", "source_type": "sysmon", "raw": {"EventID": 1, "Image": "a.exe"}}
    r = client.post(f"{API}/ingest/events/batch", headers={"X-API-Key": k["api_key"]},
                    json={"events": [good, {"event_id": "b1", "source_type": "nope"}]})
    body = r.json()
    assert (body["accepted"], body["rejected"]) == (1, 1) and body["errors"][0]["index"] == 1
    assert client.post(f"{API}/ingest/events/batch", headers={"X-API-Key": "sxk_deadbeef_bad"}, json={"events": [good]}).status_code == 401
    client.post(f"{API}/assets/keys/{k['id']}/revoke", headers=admin)
    assert client.post(f"{API}/ingest/events/batch", headers={"X-API-Key": k["api_key"]}, json={"events": [good]}).status_code == 401
    keys = client.get(f"{API}/assets/{asset['id']}/keys", headers=admin).json()["items"]
    assert "api_key" not in keys[0] and "key_hash" not in keys[0]


def test_response_requires_approval_by_a_different_authorized_user(client, login):
    admin, analyst, engineer = login("admin"), login("analyst"), login("engineer")
    asset = register_asset(client, admin)
    body = {"asset_id": asset["id"], "action_type": "isolate_lab_host", "parameters": {}, "rationale": "contain lab host"}
    bad = client.post(f"{API}/response/actions", headers=analyst, json={**body, "action_type": "run_shell"})
    assert bad.status_code == 409
    act = client.post(f"{API}/response/actions", headers=analyst, json=body).json()
    assert act["status"] == "pending_approval" and act["dry_run_result"]["changes_made"] is False
    assert client.post(f"{API}/response/actions/{act['id']}/approve", headers=analyst, json={}).status_code == 403
    done = client.post(f"{API}/response/actions/{act['id']}/approve", headers=engineer, json={})
    assert done.status_code == 200 and done.json()["status"] == "executed"
    assert done.json()["result"]["simulated"] is True
    assert client.post(f"{API}/response/actions/{act['id']}/approve", headers=engineer, json={}).status_code == 409
    assets = client.get(f"{API}/assets", headers=admin).json()["items"]
    assert assets[0]["isolation_state"] == "isolated-simulated"
    rb = client.post(f"{API}/response/actions/{act['id']}/rollback", headers=engineer)
    assert rb.json()["status"] == "rolled_back"


def test_requester_cannot_self_approve(client, login):
    admin = login("admin")
    asset = register_asset(client, admin)
    act = client.post(f"{API}/response/actions", headers=admin, json={
        "asset_id": asset["id"], "action_type": "collect_evidence", "parameters": {"script": "process_list"},
        "rationale": "gather evidence"}).json()
    assert client.post(f"{API}/response/actions/{act['id']}/approve", headers=admin, json={}).status_code == 403


def test_audit_trail_and_ai_fallback_and_reports(client, login):
    admin, analyst = login("admin"), login("analyst")
    replay(client, admin)
    alert = client.get(f"{API}/alerts?size=1", headers=analyst).json()["items"][0]
    inc = client.post(f"{API}/alerts/{alert['id']}/incident", headers=analyst)
    iid = inc.json()["id"] if inc.status_code == 201 else alert["incident_id"]
    assert client.patch(f"{API}/incidents/{iid}", headers=analyst, json={"status": "investigating"}).status_code == 200
    assert client.post(f"{API}/incidents/{iid}/notes", headers=analyst, json={"note": "checked source"}).status_code == 201
    refused = client.post(f"{API}/ai/investigate/{alert['id']}", headers=analyst)
    assert refused.status_code == 503 and refused.json()["error"]["code"] == "ai_unavailable"  # no provider -> no fake AI
    assert client.get(f"{API}/ai/status", headers=analyst).json()["state"] == "unavailable"
    inv = client.post(f"{API}/ai/rule-summary/{alert['id']}", headers=analyst).json()
    assert inv["mode"] == "rule_based" and inv["output"]["ai_generated"] is False and inv["output"]["summary"]
    actions = {e["action"] for e in client.get(f"{API}/audit-logs?size=200", headers=admin).json()["items"]}
    assert {"incident.updated", "alert.rule_summary", "alert.created", "auth.login"} <= actions
    rpt = client.get(f"{API}/reports/incidents/{iid}?format=md", headers=analyst)
    assert rpt.status_code == 200 and "Limitations" in rpt.text
    assert client.get(f"{API}/reports/alerts.csv", headers=analyst).text.startswith("id,title")


def test_oversized_request_rejected(client, login):
    r = client.post(f"{API}/ingest/events/batch", headers={"X-API-Key": "x", "Content-Length": "5000000"}, content=b"{}")
    assert r.status_code == 413

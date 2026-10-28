#!/usr/bin/env python3
"""
Test the AI security layer through the Flask web API.

Exercises injection rejection, risk reporting, anomaly blocking, brute-force
blocking, HMAC-mismatch signalling and the /api/ai_security/* endpoints.

Run directly:  python tests/test_web_ai_security.py
Or via pytest: pytest tests/test_web_ai_security.py -v
"""

import hashlib
import hmac
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import web_app  # noqa: E402
from ai_security import LLMSecurityAnalyst  # noqa: E402
from ai_security import config as ai_cfg  # noqa: E402
from server.server import SplitSmartServer  # noqa: E402

# Never sleep in tests when a client is throttled.
ai_cfg.THROTTLE_DELAY_SECONDS = 0

PASSWORD = "correct-horse-9"


def make_client():
    """Fresh app client bound to a brand-new server/database."""
    db_path = os.path.join(tempfile.mkdtemp(prefix="splitsmart-web-"), "web.db")
    server = SplitSmartServer(db_path=db_path)
    server.ai_security.analyst = LLMSecurityAnalyst(enabled=False)
    with web_app._server_lock:
        web_app._server_instance = server
    web_app._rate_limit_store.clear()
    web_app._replay_protection_store.clear()
    web_app.clients.clear()
    web_app.app.config["TESTING"] = True
    return web_app.app.test_client()


def register_and_login(client, username, ip):
    env = {"REMOTE_ADDR": ip}
    response = client.post("/api/register", json={"username": username, "password": PASSWORD}, environ_base=env)
    assert response.status_code == 200, response.get_json()
    response = client.post("/api/login", json={"username": username, "password": PASSWORD}, environ_base=env)
    data = response.get_json()
    assert response.status_code == 200 and data["success"], data
    return data["integrity_key"]


def post_expense(client, key, ip, payer, amount, description, tamper=False):
    body = json.dumps({"payer": payer, "amount": amount, "description": description})
    mac = hmac.new(key.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
    if tamper:
        body = json.dumps({"payer": payer, "amount": amount * 10, "description": description})
    return client.post("/api/add_expense", data=body, content_type="application/json",
                       headers={"X-Request-HMAC": mac}, environ_base={"REMOTE_ADDR": ip})


def test_web_rejects_injection_payload():
    print("\n[1] Web API rejects an injection payload...")
    client = make_client()
    key = register_and_login(client, "web_alice", "203.0.113.10")
    response = post_expense(client, key, "203.0.113.10", "web_alice", 20.0, "'; DROP TABLE ledger; --")
    data = response.get_json()
    assert response.status_code == 400, data
    assert "AI Security" in data["error"] and data["security"]["threat"]["malicious"]
    assert data["security"]["threat"]["label"] == "sql_injection"
    ledger = client.get("/api/ledger", environ_base={"REMOTE_ADDR": "203.0.113.10"}).get_json()
    assert ledger["success"] and ledger["entries"] == []
    print(f"  ✓ {data['error']}")


def test_web_accepts_clean_expense_with_risk_report():
    print("\n[2] Web API accepts a clean expense and reports its risk...")
    client = make_client()
    key = register_and_login(client, "web_bob", "203.0.113.11")
    response = post_expense(client, key, "203.0.113.11", "web_bob", 32.5, "Groceries")
    data = response.get_json()
    assert response.status_code == 200 and data["success"], data
    assert data["security"]["action"] == "allow" and data["security"]["risk_level"] == "LOW"
    assert "warning" not in data
    print(f"  ✓ risk {data['security']['risk_level']} score {data['security']['risk_score']}")


def test_web_blocks_critical_anomaly():
    print("\n[3] Web API blocks a CRITICAL anomaly once a baseline exists...")
    client = make_client()
    ip = "203.0.113.12"
    key = register_and_login(client, "web_carol", ip)
    for i in range(ai_cfg.ANOMALY_MIN_HISTORY):
        response = post_expense(client, key, ip, "web_carol", 25.0 + i, f"Lunch {i}")
        assert response.status_code == 200, response.get_json()
    response = post_expense(client, key, ip, "web_carol", 90000.0, "Yacht")
    data = response.get_json()
    assert response.status_code == 403, data
    assert data["security"]["risk_level"] == "CRITICAL" and data["security"]["action"] == "block"
    assert "anomaly" in data["security"] and data["security"]["anomaly"]["signals"]
    entries = client.get("/api/ledger", environ_base={"REMOTE_ADDR": ip}).get_json()["entries"]
    assert len(entries) == ai_cfg.ANOMALY_MIN_HISTORY
    print(f"  ✓ {data['error']}")


def test_web_brute_force_is_blocked():
    print("\n[4] Web API blocks a brute-forcing client...")
    client = make_client()
    attacker_ip = "198.51.100.77"
    register_and_login(client, "web_victim", "203.0.113.13")
    client.post("/api/logout", environ_base={"REMOTE_ADDR": "203.0.113.13"})

    statuses = []
    notices = 0
    for _ in range(4):
        response = client.post("/api/login", json={"username": "web_victim", "password": "wrong-guess"},
                               environ_base={"REMOTE_ADDR": attacker_ip})
        statuses.append(response.status_code)
        notices += 1 if response.get_json().get("security_notice") else 0
    assert statuses == [401, 401, 401, 401], statuses
    assert notices >= 1, "escalating failures should warn the client"

    # Fifth attempt: even the correct password is refused while blocked.
    response = client.post("/api/login", json={"username": "web_victim", "password": PASSWORD},
                           environ_base={"REMOTE_ADDR": attacker_ip})
    data = response.get_json()
    assert response.status_code == 403 and data["client_action"] == "block", data
    assert data["retry_after"] > 0 and response.headers.get("Retry-After")

    # Another client is unaffected and can see the attacker on the dashboard.
    register_and_login(client, "web_admin", "203.0.113.14")
    dashboard = client.get("/api/ai_security/status",
                           environ_base={"REMOTE_ADDR": "203.0.113.14"}).get_json()["dashboard"]
    blocked = [c for c in dashboard["clients"] if c["client_id"] == attacker_ip]
    assert blocked and blocked[0]["action"] == "block"
    assert dashboard["stats"]["clients_blocked"] >= 1
    assert dashboard["threat_level"]["level"] in ("HIGH", "ELEVATED")
    print(f"  ✓ blocked after {len(statuses)} failures; threat level {dashboard['threat_level']['level']}")


def test_web_hmac_mismatch_is_recorded():
    print("\n[5] Web API records tampered requests as security events...")
    client = make_client()
    ip = "203.0.113.15"
    key = register_and_login(client, "web_dave", ip)
    response = post_expense(client, key, ip, "web_dave", 10.0, "Coffee", tamper=True)
    assert response.status_code == 400 and "Modification attack" in response.get_json()["error"]
    events = client.get("/api/ai_security/events?limit=5", environ_base={"REMOTE_ADDR": ip}).get_json()
    assert events["success"] and events["events"][0]["event_type"] == "hmac_mismatch"
    assert events["events"][0]["severity"] == "high"
    print("  ✓ hmac_mismatch event recorded")


def test_web_ai_security_endpoints():
    print("\n[6] /api/ai_security endpoints...")
    client = make_client()
    ip = "203.0.113.16"
    assert client.get("/api/ai_security/status", environ_base={"REMOTE_ADDR": ip}).status_code == 401
    key = register_and_login(client, "web_erin", ip)

    status = client.get("/api/ai_security/status", environ_base={"REMOTE_ADDR": ip}).get_json()
    dashboard = status["dashboard"]
    for section in ("engine", "threat_level", "stats", "models", "clients", "user_profiles", "recent_events", "client"):
        assert section in dashboard, section
    assert dashboard["models"]["threat_classifier"]["signature_rules"] > 0
    assert dashboard["models"]["llm_analyst"]["available"] is False
    assert dashboard["client"]["action"] == "allow"

    dry = client.post("/api/ai_security/analyze",
                      json={"payer": "web_erin", "amount": 20, "description": "<img src=x onerror=alert(1)>"},
                      environ_base={"REMOTE_ADDR": ip}).get_json()
    assert dry["success"] and dry["analysis"]["would_block"] and dry["analysis"]["threat"]["label"] == "xss"
    ledger = client.get("/api/ledger", environ_base={"REMOTE_ADDR": ip}).get_json()
    assert ledger["entries"] == [], "dry runs must not touch the ledger"

    text_only = client.post("/api/ai_security/analyze", json={"text": "Dinner with friends"},
                            environ_base={"REMOTE_ADDR": ip}).get_json()
    assert text_only["analysis"]["threat"]["label"] == "benign"

    bad = client.post("/api/ai_security/analyze", json={"description": "x", "amount": "lots"},
                      environ_base={"REMOTE_ADDR": ip})
    assert bad.status_code == 400

    # Create a real event, then explain it (rule-based because the LLM is disabled).
    post_expense(client, key, ip, "web_erin", 20.0, "$(cat /etc/passwd)")
    events = client.get("/api/ai_security/events?min_severity=critical",
                        environ_base={"REMOTE_ADDR": ip}).get_json()["events"]
    assert events and events[0]["event_type"] == "injection_detected"
    explanation = client.get(f"/api/ai_security/explain/{events[0]['id']}",
                             environ_base={"REMOTE_ADDR": ip}).get_json()
    assert explanation["success"] and explanation["source"] == "rules"
    assert explanation["explanation"]["likely_attack"] is True
    assert client.get("/api/ai_security/explain/987654321", environ_base={"REMOTE_ADDR": ip}).status_code == 404
    print("  ✓ status, analyze (dry run), events, explain all behave")


def test_web_replay_is_rejected_and_recorded():
    print("\n[7] Web API still rejects replays and records them as intrusion signals...")
    client = make_client()
    ip = "203.0.113.17"
    key = register_and_login(client, "web_frank", ip)
    first = post_expense(client, key, ip, "web_frank", 15.0, "Bagels")
    assert first.status_code == 200 and first.get_json()["success"]
    replay = post_expense(client, key, ip, "web_frank", 15.0, "Bagels")
    data = replay.get_json()
    assert replay.status_code == 409 and "Replay attack" in data["error"], data
    events = client.get("/api/ai_security/events?limit=3", environ_base={"REMOTE_ADDR": ip}).get_json()["events"]
    assert events[0]["event_type"] == "replay_detected" and events[0]["client_id"] == ip
    entries = client.get("/api/ledger", environ_base={"REMOTE_ADDR": ip}).get_json()["entries"]
    assert len(entries) == 1
    print("  ✓ replay rejected with 409 and logged")


ALL_TESTS = [
    test_web_rejects_injection_payload,
    test_web_accepts_clean_expense_with_risk_report,
    test_web_blocks_critical_anomaly,
    test_web_brute_force_is_blocked,
    test_web_hmac_mismatch_is_recorded,
    test_web_ai_security_endpoints,
    test_web_replay_is_rejected_and_recorded,
]


if __name__ == "__main__":
    print("=" * 80)
    print("Testing SplitSmart AI Security via the Web API")
    print("=" * 80)
    failures = 0
    for test in ALL_TESTS:
        try:
            test()
        except AssertionError as exc:
            failures += 1
            print(f"  ✗ {test.__name__} failed: {exc}")
    print("\n" + "=" * 80)
    print("✓ All web AI security tests passed!" if not failures else f"✗ {failures} test(s) failed")
    print("=" * 80)
    sys.exit(1 if failures else 0)

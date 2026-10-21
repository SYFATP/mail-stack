"""Durable webhook/outbox integration against the isolated compose stack."""
import json
from pathlib import Path
import uuid

from integration_inbound import api, client, docker, login, ready, submit, wait_for


RESULTS = []


def record(name, **extra):
    RESULTS.append({"test": name, "status": "passed", **extra})
    print("PASS:", name)


def fixture(method, path, body=None):
    script = "import urllib.request,json; "
    if body is None:
        script += "r=urllib.request.urlopen('http://127.0.0.1:19123" + path + "'); print(r.read().decode())"
    else:
        script += (
            "r=urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:19123" + path +
            "',data=" + repr(json.dumps(body).encode()) +
            ",headers={'Content-Type':'application/json'},method=" + repr(method) +
            ")); print(r.read().decode())"
        )
    return json.loads(docker("exec", "-T", "api", "python", "-c", script))


def run():
    docker("restart", "api")
    wait_for(login)
    docker("exec", "-d", "api", "python", "/fixtures/domain_provider_fixture.py")
    wait_for(lambda: fixture("GET", "/fixture/health").get("ok"))
    if not any(row["domain"] == "example.test" for row in api("GET", "/mail-domains")):
        api("POST", "/mail-domains", json={"domain": "example.test"})
    api("PATCH", "/mail-domains/example.test",
        json={"enabled": True, "receive_mode": "catch_all", "receive_enabled": True,
              "receive_subdomains": True, "users": []})
    wait_for(ready)
    secret = "integration-webhook-secret-" + uuid.uuid4().hex[:8]
    hook = api("POST", "/webhooks", json={
        "url": "http://127.0.0.1:19123/fixture/webhook", "secret": secret})
    subject = "durable-webhook-" + uuid.uuid4().hex[:12]
    submit(["outbox@" + "example.test"], subject)

    def delivered():
        rows = fixture("GET", "/fixture/metrics").get("received_webhooks", [])
        return next((row for row in rows if row["body"].get("subject") == subject), None)

    received = wait_for(delivered, seconds=45)
    assert received["body"]["schema_version"] == "1"
    assert received["body"]["event_id"].startswith("evt_")
    assert received["body"]["data"]["event_id"] == received["body"]["event_id"]
    assert received["signature"].startswith("sha256=")
    check = (
        "import sqlite3; c=sqlite3.connect('/app-data/mail.db'); "
        "r=c.execute(\"select status,attempts from webhook_outbox where webhook_id=? "
        "order by id desc limit 1\",(" + str(hook["id"]) + ",)).fetchone(); "
        "assert r[0]=='delivered' and r[1]>=1, r; print(r)"
    )
    assert "delivered" in docker("exec", "-T", "api", "python", "-c", check)
    record("durable outbox commits with Maildir ingest and delivers signed v1 event",
           event_id=received["body"]["event_id"])


if __name__ == "__main__":
    path = Path(__file__).resolve().parents[1] / "reports/evidence/p3/webhook-results.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        run()
        outcome = {"status": "passed", "scope": "isolated compose + loopback webhook fixture", "results": RESULTS}
    except Exception as exc:
        outcome = {"status": "failed", "error": str(exc), "results": RESULTS}
        raise
    finally:
        path.write_text(json.dumps(outcome, indent=2, ensure_ascii=False), encoding="utf-8")
        client.close()

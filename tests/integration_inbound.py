"""Live local SMTP/Maildir/API regression. Requires tests/compose.integration.yml.
This never connects to production DNS/providers or an external SMTP host.
"""
import argparse
from email.message import EmailMessage
import json
from pathlib import Path
import smtplib
import subprocess
import time
import uuid
import httpx

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "tests/compose.integration.yml")]
BASE = "http://127.0.0.1:18091/api/v1"
RESULTS = []


def docker(*args):
    result = subprocess.run(COMPOSE + list(args), cwd=ROOT, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stderr[-2000:])
    return result.stdout


def wait_for(call, seconds=35):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = call()
            if result:
                return result
        except httpx.HTTPStatusError as error:
            if error.response.status_code not in (502, 503, 504):
                raise
        except (httpx.TransportError, ConnectionError, TimeoutError, smtplib.SMTPServerDisconnected, json.JSONDecodeError):
            pass
        time.sleep(0.5)
    raise AssertionError("timed out waiting for isolated stack")


client = httpx.Client(base_url=BASE, timeout=20)


def api(method, path, **kwargs):
    response = client.request(method, path, **kwargs)
    response.raise_for_status()
    return response.json()


def login():
    result = api("POST", "/auth/login", json={"password": "integration-only-password"})
    client.headers["x-api-key"] = result["token"]
    return True


def ready():
    if api("GET", "/health").get("routing", {}).get("status") != "applied":
        return False
    if not all(row["routing_status"] == "applied" for row in api("GET", "/mail-domains")):
        return False
    # A recent ACK can outlive the prior container for a few seconds.
    # Always confirm the replacement MTA is actually accepting connections.
    with smtplib.SMTP("127.0.0.1", 25260, timeout=2) as smtp:
        return smtp.noop()[0] == 250


def patch(name, **fields):
    result = api("PATCH", "/mail-domains/" + name, json=fields)
    wait_for(ready)
    return result


def submit(recipients, subject, raw=None):
    if raw is None:
        msg = EmailMessage()
        msg["From"] = "Sender <sender@outside.test>"
        msg["To"] = "display-only@elsewhere.test"
        msg["Subject"] = subject
        # Deliberately reused/untrusted MIME Message-ID must not deduplicate delivery.
        msg["Message-ID"] = "<same-id@outside.test>"
        msg.set_content("中文 SMTP integration body")
        msg.add_attachment(b"\x00\xffattachment\r\n", maintype="application", subtype="octet-stream", filename="测试.bin")
        raw = msg.as_bytes()
    with smtplib.SMTP("127.0.0.1", 25260, timeout=15) as smtp:
        refused = smtp.sendmail("sender@outside.test", recipients, raw)
        assert not refused, refused
    return raw


def indexed(subject, count):
    def match():
        result = api("GET", "/messages", params={"q": subject, "meta": "true"})
        assert result["total"] <= count, (subject, "unexpected duplicate", result["total"])
        return result["items"] if result["total"] == count else None
    return wait_for(match)


def rejected(recipient):
    with smtplib.SMTP("127.0.0.1", 25260, timeout=15) as smtp:
        smtp.ehlo()
        smtp.mail("sender@outside.test")
        code, message = smtp.rcpt(recipient)
        assert 500 <= code < 600, (recipient, code, message)
        return code


def record(name, **extra):
    RESULTS.append({"test": name, "status": "passed", **extra})
    print("PASS:", name)


def run():
    wait_for(login)
    run_id = uuid.uuid4().hex[:12]
    if not any(row["domain"] == "example.test" for row in api("GET", "/mail-domains")):
        api("POST", "/mail-domains", json={"domain": "example.test"})
    patch("example.test", enabled=True, receive_mode="catch_all", receive_enabled=True,
          receive_subdomains=True, max_subdomain_depth=3, users=[])
    # Remove baseline probe fixtures so release/all-delete checks are deterministic.
    for row in api("GET", "/mail-domains"):
        if row["domain"] != "example.test":
            api("DELETE", "/mail-domains/" + row["domain"])
    wait_for(ready)
    recipients = ["user+tag" + str(i) + "@" + "a." * i + "example.test" for i in range(4)]
    subject = "matrix-" + run_id
    submit(recipients, subject)
    rows = indexed(subject, 4)
    assert {row["envelope_recipient"] for row in rows} == set(recipients)
    assert {row["managed_domain"] for row in rows} == {"example.test"}
    assert all(row["to_header"] == "display-only@elsewhere.test" for row in rows)
    record("base + 1/2/3-level catch-all, plus-tag, Bcc/multi-RCPT", deliveries=len(rows))
    row = rows[0]
    response = client.get(f"/messages/{row['id']}/raw", params={"download": "true"})
    response.raise_for_status()
    assert b"Subject: " + subject.encode() in response.content
    info = api("GET", f"/messages/{row['id']}/attachments")[0]
    response = client.get(f"/messages/{row['id']}/attachments/{info['part_id']}")
    response.raise_for_status()
    assert response.content == b"\x00\xffattachment\r\n"
    assert api("GET", "/messages", params={"meta": "true", "recipient": recipients[0]})["total"] >= 1
    record("authenticated EML/attachment download and precise recipient filter")
    for address in ("u@a.b.c.d.example.test", "u@unmanaged.test", "a..b@example.test", "u@bad_.example.test"):
        record("RCPT rejected: " + address, smtp_code=rejected(address))
    patch("example.test", receive_mode="fixed", users=["listed"], receive_subdomains=False)
    record("fixed users reject random prefix", smtp_code=rejected("random@example.test"))
    subject_fixed = "fixed-" + run_id
    submit(["listed@example.test"], subject_fixed)
    indexed(subject_fixed, 1)
    record("fixed users accepted and indexed")
    patch("example.test", receive_mode="catch_all", receive_subdomains=True, users=[])
    api("POST", "/mail-domains", json={"domain": "blocked.example.test", "enabled": False})
    wait_for(ready)
    for address in ("u@blocked.example.test", "u@a.blocked.example.test"):
        record("disabled child masks parent: " + address, smtp_code=rejected(address))
    patch("example.test", enabled=False)
    record("disabled parent rejected", smtp_code=rejected("u@example.test"))
    assert api("GET", "/domains/available")["total"] == 0
    patch("example.test", enabled=True)
    assert api("GET", "/domains/available")["total"] == 0
    record("available remains empty without validated DNS; route ACK alone is insufficient")
    # Stop the API: generation-bound routing must continue without its process.
    docker("stop", "api")
    recovery = "recovery-" + run_id
    submit(["recover@example.test"], recovery)
    docker("start", "api")
    wait_for(login)
    indexed(recovery, 1)
    docker("restart", "api")
    wait_for(login)
    indexed(recovery, 1)
    record("API offline reception, restart backfill, no duplicate delivery")
    # Queue must survive container RECREATE, not only a stop/start.
    docker("exec", "-T", "postfix", "sh", "-c", "postconf -e 'defer_transports=virtual'; postfix reload")
    time.sleep(1)
    pending = "persistent-queue-" + run_id
    submit(["queued@example.test"], pending)
    queue_before = docker("exec", "-T", "postfix", "postqueue", "-j")
    assert "queued@example.test" in queue_before
    docker("up", "-d", "--no-deps", "--force-recreate", "--pull", "never", "postfix")
    wait_for(ready)
    docker("exec", "-T", "postfix", "postqueue", "-f")
    indexed(pending, 1)
    record("named Postfix spool survives container recreate and delivers held queue")
    # Move a real Linux Maildir entry new -> cur with flags. Must update, not reinsert.
    source = api("GET", f"/messages/{rows[0]['id']}")["source_path"]
    script = "import os,pathlib; p=pathlib.Path(" + repr(source) + "); q=p.parent.parent/'cur'/(p.name+':2,S'); q.parent.mkdir(exist_ok=True); p.rename(q)"
    docker("exec", "-T", "api", "python", "-c", script)
    time.sleep(12)
    rows_after = indexed(subject, 4)
    record("real Maildir new-to-cur flag rename remains idempotent", deliveries=len(rows_after))
    for row in api("GET", "/mail-domains"):
        api("DELETE", "/mail-domains/" + row["domain"])
    docker("restart", "api")
    wait_for(login)
    assert api("GET", "/mail-domains") == []
    wait_for(ready)
    record("delete all domains + restart does not reseed", smtp_code=rejected("u@example.test"))
    assert api("GET", "/domains") == []
    docker("exec", "-T", "opendkim", "nc", "-z", "127.0.0.1", "8891")
    record("OpenDKIM remains running with empty domain/key maps")
    # Leave a predictable local fixture for follow-up work; still no receive_ready.
    api("POST", "/mail-domains", json={"domain": "example.test", "receive_subdomains": True, "users": []})
    wait_for(ready)
    print("Integration checks:", len(RESULTS))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "reports/evidence/p0-p1/inbound-results.json")
    args = parser.parse_args()
    try:
        run()
        status = "passed"
    except Exception as error:
        RESULTS.append({"test": "suite", "status": "failed", "error": repr(error)})
        status = "failed"
        raise
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({"status": status, "scope": "localhost SMTP/Maildir/API with isolated DNS; not public provider validation", "results": RESULTS}, ensure_ascii=False, indent=2), encoding="utf-8")
        client.close()

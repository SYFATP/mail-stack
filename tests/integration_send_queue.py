"""Durable outbound queue integration against the isolated compose stack."""
import json
from pathlib import Path
import uuid

from integration_inbound import api, client, docker, login, ready, wait_for

RESULTS = []


def record(name, **extra):
    RESULTS.append({"test": name, "status": "passed", **extra})
    print("PASS:", name)


def run():
    docker("restart", "api")
    wait_for(login)
    wait_for(ready)
    request_id = "send_integration_" + uuid.uuid4().hex[:12]
    response = client.post(
        "/send/queue",
        headers={"x-idempotency-key": request_id},
        json={
            "sender": "sender@example.test",
            "recipients": ["test@example.test"],
            "subject": "durable-send-" + uuid.uuid4().hex[:8],
            "text": "isolated outbound queue fixture",
        },
    )
    assert response.status_code == 202, response.text
    queued = response.json()
    assert queued["request_id"] == request_id
    assert queued["status"] == "queued"

    def delivered():
        result = api("GET", "/send/" + request_id)
        return result if result["status"] in {"submitted_to_mta", "partial", "failed", "submission_unknown"} else None

    result = wait_for(delivered, seconds=45)
    assert result["status"] == "submitted_to_mta", result
    assert result["accepted"] == ["test@example.test"], result
    assert result["attempts"] >= 1
    record("durable outbound queue signs, submits and exposes delivery status",
           request_id=request_id, attempts=result["attempts"])


if __name__ == "__main__":
    path = Path(__file__).resolve().parents[1] / "reports/evidence/p4/send-queue-results.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        run()
        outcome = {"status": "passed", "scope": "isolated compose + local Postfix fixture", "results": RESULTS}
    except Exception as exc:
        outcome = {"status": "failed", "error": str(exc), "results": RESULTS}
        raise
    finally:
        path.write_text(json.dumps(outcome, indent=2, ensure_ascii=False), encoding="utf-8")
        client.close()

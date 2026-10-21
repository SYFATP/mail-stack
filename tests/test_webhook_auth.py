import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

APP_PATH = Path(__file__).resolve().parents[1] / "api" / "app.py"
spec = importlib.util.spec_from_file_location("mail_app_under_test", APP_PATH)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class WebhookAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.db_path = Path(self.temp.name) / "test.db"
        self.db_patch = patch.object(app, "DB", self.db_path)
        self.db_patch.start()
        app._schema_initialized = False
        c = app.db()
        c.execute(
            "insert into webhooks(id,url,secret,enabled) values(1,?,?,1)",
            ("https://receiver.invalid/api/webhook/email", "test-only-secret"),
        )
        digest = hashlib.sha256(("fixture" + app.os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
        c.execute("insert into api_keys(name,key_hash,scopes,created_at,global_access) values(?,?,?,?,1)",
                  ("fixture", digest, "webhook.manage", time.time()))
        c.commit()
        c.close()

    def tearDown(self):
        self.db_patch.stop()
        app._schema_initialized = False
        self.temp.cleanup()

    @staticmethod
    def success_response():
        return 200

    def test_both_receiver_headers_and_original_signature(self):
        with patch.object(app, "send_webhook_request", return_value=self.success_response()) as send:
            app.dispatch_webhooks(
                10, {"message_id": "<test@example.test>", "to": "test@example.test"},
                b"Subject: test\r\n\r\nbody",
            )
        request = send.call_args.args[0]
        headers = {k.lower(): v for k, v in request.header_items()}
        self.assertEqual(headers["x-email-webhook-secret"], "test-only-secret")
        self.assertEqual(headers["x-webhook-secret"], "test-only-secret")
        expected = hmac.new(
            b"test-only-secret",
            headers["x-webhook-timestamp"].encode() + b"." + request.data,
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(headers["x-webhook-signature"], "sha256=" + expected)
        self.assertEqual(json.loads(request.data)["raw_content"], "Subject: test\r\n\r\nbody")

    def test_retry_success_clears_previous_error(self):
        with patch.object(app, "send_webhook_request",
                          side_effect=[TimeoutError("temporary timeout"), self.success_response()]), \
             patch.object(app.time, "sleep"):
            app.dispatch_webhooks(11, {"message_id": "<retry@example.test>"})
        c = sqlite3.connect(self.db_path)
        row = c.execute(
            "select status,attempts,last_error from webhook_deliveries where message_id=11"
        ).fetchone()
        c.close()
        self.assertEqual(row, ("delivered", 2, ""))

    def test_failed_delivery_remains_failed(self):
        with patch.object(app, "send_webhook_request", side_effect=TimeoutError("timeout")), \
             patch.object(app.time, "sleep"):
            app.dispatch_webhooks(12, {"message_id": "<failure@example.test>"})
        c = sqlite3.connect(self.db_path)
        row = c.execute(
            "select status,attempts,last_error from webhook_deliveries where message_id=12"
        ).fetchone()
        c.close()
        self.assertEqual(row, ("failed", 3, "webhook_transport_failed"))

    def _queue_outbox(self, event_id="evt_fixture", message_id=20):
        c = sqlite3.connect(self.db_path)
        now = time.time()
        c.execute("insert or ignore into messages(id,received_at,raw_path) values(?,?,'fixture.eml')",
                  (message_id, now))
        c.execute("""insert or ignore into message_deliveries(
                     delivery_key,message_id,envelope_recipient,recipient_domain,received_at)
                     values(?,?,'user@example.test','example.test',?)""", (str(message_id), message_id, now))
        c.execute("""insert into webhook_outbox(
            event_id,webhook_id,message_id,payload_json,raw_path,status,attempts,
            next_attempt_at,last_error,created_at,updated_at)
            values(?,?,?,?,?,'queued',0,?,'',?,?)""",
                  (event_id, 1, message_id, json.dumps({
                      "schema_version": "1", "event_id": event_id,
                      "event": "message.received", "message_id": message_id,
                      "data": {"message_id": message_id}}), None, now, now, now))
        c.commit()
        c.close()

    def test_durable_outbox_claim_and_delivery(self):
        self._queue_outbox()
        with patch.object(app, "send_webhook_request", return_value=self.success_response()) as send:
            row = app._claim_webhook_outbox()
            self.assertEqual(row["status"], "running")
            app._deliver_webhook_outbox(row)
        request = send.call_args.args[0]
        self.assertIn("evt_fixture", request.data.decode())
        c = sqlite3.connect(self.db_path)
        self.assertEqual(c.execute("select status from webhook_outbox where event_id='evt_fixture'").fetchone()[0], "delivered")
        self.assertEqual(c.execute("select status,attempts from webhook_deliveries where message_id=20").fetchone(), ("delivered", 1))
        c.close()

    def test_durable_outbox_retry_survives_next_poll(self):
        self._queue_outbox("evt_retry", 21)
        with patch.object(app, "send_webhook_request", side_effect=TimeoutError("temporary timeout")), \
             patch.object(app.time, "sleep"):
            row = app._claim_webhook_outbox()
            app._deliver_webhook_outbox(row)
        c = sqlite3.connect(self.db_path)
        c.execute("update webhook_outbox set next_attempt_at=? where event_id='evt_retry'", (time.time() - 1,))
        c.commit(); c.close()
        with patch.object(app, "send_webhook_request", return_value=self.success_response()):
            row = app._claim_webhook_outbox()
            app._deliver_webhook_outbox(row)
        c = sqlite3.connect(self.db_path)
        self.assertEqual(c.execute("select status,attempts,last_error from webhook_outbox where event_id='evt_retry'").fetchone(),
                         ("delivered", 2, ""))
        c.close()

    def test_running_outbox_is_reclaimed_after_lease(self):
        self._queue_outbox("evt_lease", 22)
        row = app._claim_webhook_outbox()
        self.assertEqual(row["status"], "running")
        c = sqlite3.connect(self.db_path)
        c.execute("update webhook_outbox set updated_at=? where event_id='evt_lease'", (time.time() - app.WEBHOOK_LEASE_SECONDS - 1,))
        c.commit(); c.close()
        reclaimed = app._claim_webhook_outbox()
        self.assertEqual(reclaimed["id"], row["id"])
        self.assertEqual(reclaimed["attempts"], 2)

    def test_delivery_listing_redacts_payload_and_replay_is_idempotent(self):
        self._queue_outbox("evt_replay", 23)
        c = sqlite3.connect(self.db_path)
        c.execute("update webhook_outbox set status='failed',attempts=3,last_error='timeout' where event_id='evt_replay'")
        c.commit()
        delivery_id = c.execute("select id from webhook_outbox where event_id='evt_replay'").fetchone()[0]
        c.close()
        with patch.object(app, "key_scopes", return_value=frozenset({"webhook.manage"})):
            listing = app.list_webhook_deliveries(1, limit=100, offset=0, x_api_key="fixture")
            self.assertEqual(listing["total"], 1)
            self.assertNotIn("payload_json", json.dumps(listing))
            replay = app.replay_webhook_delivery(1, delivery_id, x_api_key="fixture")
            self.assertEqual(replay["status"], "queued")
            self.assertEqual(app.replay_webhook_delivery(1, delivery_id, x_api_key="fixture")["status"], "queued")
        c = sqlite3.connect(self.db_path)
        self.assertEqual(c.execute("select status,attempts,last_error from webhook_outbox where id=?", (delivery_id,)).fetchone(),
                         ("queued", 0, ""))
        c.close()

    def test_dead_letter_listing_returns_failed_only(self):
        self._queue_outbox("evt_dead", 24)
        self._queue_outbox("evt_live", 25)
        c = sqlite3.connect(self.db_path)
        c.execute(
            "update webhook_outbox set status='failed',attempts=3,last_error='timeout' where event_id='evt_dead'"
        )
        c.commit()
        c.close()
        with patch.object(app, "key_scopes", return_value=frozenset({"webhook.manage"})):
            result = app.list_webhook_dead_letters(1, limit=100, offset=0, x_api_key="fixture")
        self.assertEqual(result["total"], 1)
        self.assertEqual([item["event_id"] for item in result["items"]], ["evt_dead"])
        self.assertNotIn("payload_json", json.dumps(result))

    def test_event_query_redacts_payload_and_webhook_secret(self):
        self._queue_outbox("evt_lookup", 26)
        with patch.object(app, "key_scopes", return_value=frozenset({"webhook.manage"})):
            result = app.get_webhook_event("evt_lookup", x_api_key="fixture")
        self.assertEqual(result["event_id"], "evt_lookup")
        self.assertEqual(result["webhook_id"], 1)
        self.assertNotIn("payload_json", result)
        self.assertNotIn("secret", result)
        self.assertNotIn("project_id", result)

    def test_event_replay_only_failed_or_cancelled(self):
        self._queue_outbox("evt_failed_replay", 27)
        self._queue_outbox("evt_delivered", 28)
        c = sqlite3.connect(self.db_path)
        c.execute(
            "update webhook_outbox set status='failed',attempts=3,last_error='timeout' where event_id='evt_failed_replay'"
        )
        c.execute(
            "update webhook_outbox set status='delivered',attempts=1 where event_id='evt_delivered'"
        )
        c.commit()
        c.close()
        with patch.object(app, "key_scopes", return_value=frozenset({"webhook.manage"})):
            queued = app.replay_webhook_event("evt_failed_replay", x_api_key="fixture")
            unchanged = app.replay_webhook_event("evt_delivered", x_api_key="fixture")
        self.assertEqual(queued["status"], "queued")
        self.assertEqual(queued["attempts"], 0)
        self.assertEqual(unchanged["status"], "delivered")
        self.assertEqual(unchanged["attempts"], 1)
        c = sqlite3.connect(self.db_path)
        self.assertEqual(
            c.execute(
                "select status,attempts,last_error from webhook_outbox where event_id='evt_failed_replay'"
            ).fetchone(),
            ("queued", 0, ""),
        )
        c.close()

    def test_project_grant_is_required_for_event_dead_letter_access(self):
        project_a = "prj_fixture_a01"
        project_b = "prj_fixture_b01"
        raw = "project-isolation-key"
        digest = hashlib.sha256((raw + app.os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
        c = sqlite3.connect(self.db_path)
        c.execute("insert into projects(id,name,created_at) values(?,?,?)",
                  (project_a, "project-a", time.time()))
        c.execute("insert into projects(id,name,created_at) values(?,?,?)",
                  (project_b, "project-b", time.time()))
        c.execute("insert into api_keys(name,key_hash,scopes,created_at) values(?,?,?,?)",
                  ("project-isolation", digest, "webhook.manage", time.time()))
        key_id = c.execute("select id from api_keys where key_hash=?", (digest,)).fetchone()[0]
        c.execute(
            "insert into webhooks(id,url,secret,enabled,project_id,created_at) values(2,?,?,?,?,?)",
            ("https://receiver.invalid/project-b", "project-secret", 1, project_b, time.time()),
        )
        c.commit()
        c.close()
        self._queue_outbox("evt_project_b", 29)
        c = sqlite3.connect(self.db_path)
        c.execute("update webhook_outbox set webhook_id=2,status='failed' where event_id='evt_project_b'")
        c.execute(
            "insert into api_key_grants(key_id,project_id,scopes,created_at) values(?,?,?,?)",
            (key_id, project_a, "webhook.manage", time.time()),
        )
        c.commit()
        c.close()
        with self.assertRaises(app.HTTPException) as exc:
            app.list_webhook_dead_letters(2, limit=100, offset=0, x_api_key=raw)
        self.assertEqual(exc.exception.status_code, 403)
        c = sqlite3.connect(self.db_path)
        c.execute(
            "insert into api_key_grants(key_id,project_id,scopes,created_at) values(?,?,?,?)",
            (key_id, project_b, "webhook.manage", time.time()),
        )
        c.commit()
        c.close()
        result = app.list_webhook_dead_letters(2, limit=100, offset=0, x_api_key=raw)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["event_id"], "evt_project_b")

    def test_api_key_scopes_gate_webhook_management(self):
        raw = "ms_scope_fixture"
        digest = hashlib.sha256((raw + app.os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
        c = sqlite3.connect(self.db_path)
        c.execute("insert into api_keys(name,key_hash,scopes,created_at) values(?,?,?,?)",
                  ("read-only", digest, "mail.read", time.time()))
        c.commit(); c.close()
        self.assertEqual(app.key_scopes(raw), frozenset({"mail.read"}))
        self.assertFalse(app.key_has_scope(raw, "webhook.manage"))
        with patch.object(app, "key_scopes", return_value=frozenset({"mail.read"})):
            with self.assertRaises(app.HTTPException) as exc:
                app.create_webhook(app.Webhook(url="https://receiver.invalid/hook", secret="secret"), raw)
            self.assertEqual(exc.exception.status_code, 403)

    def test_admin_api_key_creation_validates_and_persists_scopes(self):
        with patch.object(app, "admin_ok", return_value=True):
            created = app.create_key(name="send-only", scopes="mail.send",
                                     x_api_key="admin", x_admin_password=None)
        self.assertEqual(created["scopes"], ["mail.send"])
        digest = hashlib.sha256((created["key"] + app.os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
        c = sqlite3.connect(self.db_path)
        self.assertEqual(c.execute("select scopes from api_keys where key_hash=?", (digest,)).fetchone()[0], "mail.send")
        c.close()
        with patch.object(app, "admin_ok", return_value=True):
            with self.assertRaises(app.HTTPException) as exc:
                app.create_key(name="bad", scopes="unknown", x_api_key="admin", x_admin_password=None)
            self.assertEqual(exc.exception.status_code, 400)

    def test_project_grant_is_required_for_project_bound_webhook(self):
        raw = "ms_project_fixture"
        digest = hashlib.sha256((raw + app.os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
        project_id = "prj_fixture_001"
        c = sqlite3.connect(self.db_path)
        c.execute("insert into projects(id,name,created_at) values(?,?,?)", (project_id, "fixture-project", time.time()))
        c.execute("insert into api_keys(name,key_hash,scopes,created_at) values(?,?,?,?)",
                  ("project-key", digest, "webhook.manage", time.time()))
        key_id = c.execute("select id from api_keys where key_hash=?", (digest,)).fetchone()[0]
        c.commit(); c.close()
        self.assertFalse(app.key_has_project_scope(raw, "webhook.manage", project_id))
        c = sqlite3.connect(self.db_path)
        c.execute("insert into api_key_grants(key_id,project_id,scopes,created_at) values(?,?,?,?)",
                  (key_id, project_id, "webhook.manage", time.time()))
        c.commit(); c.close()
        self.assertTrue(app.key_has_project_scope(raw, "webhook.manage", project_id))
        created = app.create_webhook(
            app.Webhook(url="https://receiver.invalid/project-hook", secret="secret", project_id=project_id),
            raw,
        )
        self.assertEqual(created["project_id"], project_id)


if __name__ == "__main__":
    unittest.main()

import base64
from email.message import EmailMessage
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch
from email import policy
from email.parser import BytesParser

APP_PATH = Path(__file__).resolve().parents[1] / "api" / "app.py"
spec = importlib.util.spec_from_file_location("mail_app_send_queue", APP_PATH)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class SendQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.db_path = Path(self.temp.name) / "test.db"
        self.db_patch = patch.object(app, "DB", self.db_path)
        self.db_patch.start()
        app._schema_initialized = False
        app.db().close()

    def tearDown(self):
        self.db_patch.stop()
        app._schema_initialized = False
        self.temp.cleanup()

    @staticmethod
    def item(project_id=None):
        return app.OutboundMessage(
            sender="sender@example.test",
            recipients=["one@outside.test", "two@outside.test"],
            subject="queued",
            text="body",
            project_id=project_id,
        )

    def test_queue_is_idempotent_and_durable(self):
        raw = b"From: sender@example.test\r\n\r\nbody"
        with patch.object(app, "key_has_project_scope", return_value=True), \
             patch.object(app, "_prepare_outbound", return_value=(
                 "sender@example.test", ["one@outside.test"], raw,
             )):
            first = app.queue_send(self.item(), "fixture", "send_fixture_1")
            second = app.queue_send(self.item(), "fixture", "send_fixture_1")
        self.assertEqual(first["request_id"], "send_fixture_1")
        self.assertEqual(first["status"], "queued")
        self.assertEqual(second, first)
        c = sqlite3.connect(self.db_path)
        self.assertEqual(c.execute("select count(*) from outbound_outbox").fetchone()[0], 1)
        self.assertEqual(c.execute(
            "select status,attempts from outbound_outbox where request_id='send_fixture_1'"
        ).fetchone(), ("queued", 0))
        c.close()

    def test_worker_delivers_signed_raw_and_records_result(self):
        raw = b"DKIM-Signature: fixture\r\n\r\nbody"
        with patch.object(app, "key_has_project_scope", return_value=True), \
             patch.object(app, "_prepare_outbound", return_value=(
                 "sender@example.test", ["one@outside.test", "two@outside.test"], raw,
             )):
            app.queue_send(self.item(), "fixture", "send_fixture_2")
        row = app._claim_outbound()
        self.assertEqual(row["status"], "running")
        smtp = MagicMock()
        smtp.__enter__.return_value.sendmail.return_value = {
            "two@outside.test": (550, b"rejected"),
        }
        with patch.object(app.smtplib, "SMTP", return_value=smtp):
            app._deliver_outbound(row)
        c = sqlite3.connect(self.db_path)
        status, accepted, rejected = c.execute(
            "select status,accepted_json,rejected_json from outbound_outbox where request_id='send_fixture_2'"
        ).fetchone()
        c.close()
        self.assertEqual(status, "partial")
        self.assertEqual(json.loads(accepted), ["one@outside.test"])
        self.assertEqual(json.loads(rejected)["two@outside.test"]["code"], 550)
        smtp.__enter__.return_value.sendmail.assert_called_once_with(
            "sender@example.test", ["one@outside.test", "two@outside.test"], raw,
        )

    def test_failed_delivery_is_retryable_and_replay_resets_terminal_state(self):
        raw = b"raw"
        with patch.object(app, "key_has_project_scope", return_value=True), \
             patch.object(app, "_prepare_outbound", return_value=(
                 "sender@example.test", ["one@outside.test"], raw,
             )):
            app.queue_send(self.item(), "fixture", "send_fixture_3")
        with patch.object(app.smtplib, "SMTP", side_effect=TimeoutError("smtp timeout")):
            row = app._claim_outbound()
            app._deliver_outbound(row)
        c = sqlite3.connect(self.db_path)
        c.execute(
            "update outbound_outbox set next_attempt_at=?,status='failed',attempts=3 where request_id=?",
            (time.time() - 1, "send_fixture_3"),
        )
        c.commit()
        c.close()
        with patch.object(app, "key_has_project_scope", return_value=True):
            replayed = app.replay_queued_send("send_fixture_3", "fixture")
            current = app.get_queued_send("send_fixture_3", "fixture")
        self.assertEqual(replayed["status"], "queued")
        self.assertEqual(replayed["attempts"], 0)
        self.assertEqual(current["status"], "queued")
        self.assertEqual(current["last_error"], "")

    def test_smtp_connect_failure_uses_brevo_api_fallback_once(self):
        raw = b"From: sender@example.test\r\n\r\nbody"
        with patch.object(app, "key_has_project_scope", return_value=True), \
             patch.object(app, "_prepare_outbound", return_value=(
                 "sender@example.test", ["one@outside.test"], raw,
             )):
            app.queue_send(self.item(), "fixture", "send_fixture_fallback")
        row = app._claim_outbound()
        with patch.object(app.smtplib, "SMTP",
                          side_effect=app.smtplib.SMTPConnectError(421, "relay unavailable")), \
             patch.object(app, "_brevo_api_fallback", return_value=True) as fallback:
            app._deliver_outbound(row)
        c = sqlite3.connect(self.db_path)
        status, transport, attempts, accepted = c.execute(
            "select status,transport,fallback_attempts,accepted_json "
            "from outbound_outbox where request_id='send_fixture_fallback'"
        ).fetchone()
        c.close()
        self.assertEqual((status, transport, attempts), ("submitted_to_mta", "brevo_api", 1))
        self.assertEqual(json.loads(accepted), ["one@outside.test"])
        fallback.assert_called_once()

    def test_queue_requires_mail_send_scope(self):
        with patch.object(app, "key_has_project_scope", return_value=False):
            with self.assertRaises(app.HTTPException) as exc:
                app.queue_send(self.item(), "read-only", "send_fixture_4")
        self.assertEqual(exc.exception.status_code, 403)

    def test_prepare_outbound_preserves_reply_headers_and_attachment(self):
        item = app.OutboundMessage(
            sender="sender@example.test",
            recipients=["one@outside.test"],
            subject="Re: original",
            text="reply body",
            in_reply_to="<original@example.test>",
            references=["<thread@example.test>", "<original@example.test>"],
            attachments=[app.OutboundAttachment(
                filename="../fixture.txt",
                content_type="text/plain",
                data_base64=base64.b64encode("attachment body".encode()).decode(),
            )],
        )
        key = MagicMock()
        key.exists.return_value = True
        key.read_bytes.return_value = b"test-only-key"
        key.__truediv__.return_value = key
        with patch.object(app, "configured_domains", return_value=["example.test"]), \
             patch.object(app, "_domain_rows", return_value=[{"domain": "example.test"}]), \
             patch.object(app, "Path", return_value=key), \
             patch.object(app.dkim, "sign", return_value=b"DKIM-Signature: fixture\r\n"):
            sender, recipients, raw = app._prepare_outbound(item)
        self.assertEqual(sender, "sender@example.test")
        self.assertEqual(recipients, ["one@outside.test"])
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertEqual(msg["In-Reply-To"], "<original@example.test>")
        self.assertEqual(msg["References"], "<thread@example.test> <original@example.test>")
        parts = [part for part in msg.walk() if part.get_filename()]
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0].get_filename(), "fixture.txt")
        self.assertEqual(parts[0].get_payload(decode=True), b"attachment body")

    def test_prepare_outbound_adds_plain_text_fallback_for_html(self):
        item = app.OutboundMessage(
            sender="sender@example.test",
            recipients=["one@outside.test"],
            subject="html",
            text="plain fallback",
            html="<p>rich body</p>",
        )
        key = MagicMock()
        key.exists.return_value = True
        key.read_bytes.return_value = b"test-only-key"
        key.__truediv__.return_value = key
        with patch.object(app, "configured_domains", return_value=["example.test"]), \
             patch.object(app, "_domain_rows", return_value=[{"domain": "example.test"}]), \
             patch.object(app, "Path", return_value=key), \
             patch.object(app.dkim, "sign", return_value=b"DKIM-Signature: fixture\r\n"):
            sender, recipients, raw = app._prepare_outbound(item)
        self.assertEqual(sender, "sender@example.test")
        self.assertEqual(recipients, ["one@outside.test"])
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertTrue(msg.is_multipart())
        self.assertEqual(msg.get_body(preferencelist=("plain",)).get_content().strip(), "plain fallback")
        self.assertIn("rich body", msg.get_body(preferencelist=("html",)).get_content())

    def test_reply_endpoint_derives_recipient_subject_and_thread_headers(self):
        original = EmailMessage()
        original["From"] = "Original Sender <sender@outside.test>"
        original["Reply-To"] = "reply@outside.test"
        original["Subject"] = "Question"
        original["Message-ID"] = "<message-001@outside.test>"
        original["References"] = "<thread-001@outside.test>"
        original.set_content("original body")
        raw_path = Path(self.temp.name) / "original.eml"
        raw_path.write_bytes(original.as_bytes())
        c = sqlite3.connect(self.db_path)
        c.execute("insert into messages(received_at,raw_path) values(?,?)", (time.time(), str(raw_path)))
        message_id = c.execute("select last_insert_rowid()").fetchone()[0]
        digest = app.hashlib.sha256(("fixture" + app.os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
        c.execute("insert into api_keys(name,key_hash,scopes,created_at,global_access) values('reply',?,'mail.read,mail.send',?,1)",
                  (digest, time.time()))
        c.commit()
        c.close()
        with patch.object(app, "key_has_project_scope", return_value=True), \
             patch.object(app, "queue_send", return_value={"status": "queued"}) as enqueue:
            result = app.reply_message(
                message_id,
                app.ReplyRequest(sender="sender@example.test", text="answer"),
                "fixture",
                "reply_fixture_1",
            )
        self.assertEqual(result["status"], "queued")
        outbound, api_key, idem = enqueue.call_args.args
        self.assertEqual(api_key, "fixture")
        self.assertEqual(idem, "reply_fixture_1")
        self.assertEqual(outbound.recipients, ["reply@outside.test"])
        self.assertEqual(outbound.subject, "Re: Question")
        self.assertEqual(outbound.in_reply_to, "<message-001@outside.test>")
        self.assertEqual(
            outbound.references,
            ["<thread-001@outside.test>", "<message-001@outside.test>"],
        )

    def test_prepare_outbound_allows_configured_multilevel_subdomain(self):
        item = app.OutboundMessage(
            sender="sender@a.b.example.test",
            recipients=["one@outside.test"],
            subject="subdomain",
            text="body",
        )
        key = MagicMock()
        key.exists.return_value = True
        key.read_bytes.return_value = b"test-only-key"
        key.__truediv__.return_value = key
        with patch.object(app, "_domain_rows", return_value=[{
            "domain": "example.test",
            "enabled": 1,
            "send_enabled": 1,
            "source_status": "imported",
            "receive_subdomains": 1,
            "max_subdomain_depth": 3,
            "dkim_selector": "default",
        }]), \
             patch.object(app, "Path", return_value=key), \
             patch.object(app.dkim, "sign", return_value=b"DKIM-Signature: fixture\r\n") as sign:
            sender, recipients, raw = app._prepare_outbound(item)
        self.assertEqual(sender, "sender@a.b.example.test")
        self.assertEqual(recipients, ["one@outside.test"])
        self.assertEqual(sign.call_args.kwargs["domain"], b"example.test")
        self.assertIn(b"sender@a.b.example.test", raw)

    def test_prepare_outbound_can_skip_local_dkim_for_authenticated_relay(self):
        item = app.OutboundMessage(
            sender="sender@example.test",
            recipients=["one@outside.test"],
            subject="relay",
            text="body",
        )
        key = MagicMock()
        key.exists.return_value = True
        key.read_bytes.return_value = b"test-only-key"
        key.__truediv__.return_value = key
        with patch.object(app, "_domain_rows", return_value=[{
            "domain": "example.test",
            "enabled": 1,
            "send_enabled": 1,
            "source_status": "imported",
            "receive_subdomains": 1,
            "max_subdomain_depth": 3,
            "dkim_selector": "default",
        }]), \
             patch.object(app, "Path", return_value=key), \
             patch.object(app.dkim, "sign", return_value=b"DKIM-Signature: fixture\r\n") as sign:
            with patch.object(app, "OUTBOUND_DKIM_ENABLED", False):
                sender, recipients, raw = app._prepare_outbound(item)
        self.assertEqual(sender, "sender@example.test")
        self.assertEqual(recipients, ["one@outside.test"])
        self.assertNotIn(b"DKIM-Signature:", raw)
        sign.assert_not_called()


if __name__ == "__main__":
    unittest.main()

import importlib.util
from email import policy
from email.parser import BytesParser
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from api.services.delivery_reports import parse_delivery_report

APP_PATH = Path(__file__).resolve().parents[1] / "api" / "app.py"
spec = importlib.util.spec_from_file_location("mail_app_delivery_report", APP_PATH)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


REPORT = b"""Content-Type: multipart/report; report-type=delivery-status; boundary="dsn"
MIME-Version: 1.0
From: MAILER-DAEMON@example.test
To: sender@example.test
Subject: failure

--dsn
Content-Type: text/plain

delivery failed
--dsn
Content-Type: message/delivery-status

Reporting-MTA: dns; mx.example.test

Final-Recipient: rfc822; one@outside.test
Original-Recipient: rfc822; one@outside.test
Action: failed
Status: 5.1.1
Diagnostic-Code: smtp; 550 5.1.1 user unknown
--dsn
Content-Type: message/rfc822

Message-ID: <outbound-001@example.test>
From: sender@example.test
To: one@outside.test
Subject: original

body
--dsn--
"""


class DeliveryReportTests(unittest.TestCase):
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

    def test_parser_extracts_bounded_failed_recipient(self):
        result = parse_delivery_report(BytesParser(policy=policy.default).parsebytes(REPORT))
        self.assertEqual(result["rfc_message_id"], "<outbound-001@example.test>")
        self.assertEqual(result["reports"][0]["recipient"], "one@outside.test")
        self.assertEqual(result["reports"][0]["status_code"], "5.1.1")
        self.assertEqual(result["reports"][0]["action"], "failed")

    def test_report_is_correlated_once_and_emits_project_scoped_webhook_event(self):
        c = app.db()
        c.execute(
            "insert into messages(id,received_at,raw_path) values(?,?,?)",
            (99, time.time(), str(Path(self.temp.name) / "dsn.eml")),
        )
        c.execute(
            "insert into webhooks(id,url,secret,enabled,created_at) values(1,?,?,1,?)",
            ("https://receiver.invalid/dsn", "secret", time.time()),
        )
        c.execute(
            """insert into outbound_outbox(
                request_id,sender,recipients_json,raw_message,status,attempts,next_attempt_at,
                last_error,accepted_json,rejected_json,created_at,updated_at,request_hash,rfc_message_id)
                values(?,?,?,?,?,1,?,'','[]','{}',?,?,?,?)""",
            ("send_dsn_001", "sender@example.test", '["one@outside.test"]', b"raw",
             "submitted_to_mta", time.time(), time.time(), time.time(), "hash", "<outbound-001@example.test>"),
        )
        c.commit()
        message = BytesParser(policy=policy.default).parsebytes(REPORT)
        self.assertEqual(app._record_delivery_report(c, message, 99, "sender@example.test", "digest"), 1)
        self.assertEqual(app._record_delivery_report(c, message, 99, "sender@example.test", "digest"), 0)
        c.commit()
        self.assertEqual(c.execute("select count(*) from outbound_delivery_reports").fetchone()[0], 1)
        self.assertEqual(c.execute("select count(*) from webhook_outbox").fetchone()[0], 1)
        self.assertEqual(tuple(c.execute(
            "select status,last_error from outbound_outbox where request_id='send_dsn_001'"
        ).fetchone()), ("failed", "remote_dsn_failed=1/1"))
        c.close()

    def test_parser_rejects_non_dsn_and_invalid_status(self):
        normal = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: text/plain\r\n\r\nhello\r\n"
        )
        self.assertIsNone(parse_delivery_report(normal))
        invalid = REPORT.replace(b"Status: 5.1.1", b"Status: 2.1.1")
        self.assertIsNone(parse_delivery_report(BytesParser(policy=policy.default).parsebytes(invalid)))


if __name__ == "__main__":
    unittest.main()

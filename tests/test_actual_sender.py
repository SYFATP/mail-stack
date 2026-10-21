"""Header-only sender inference and cached API pipeline regression tests."""
import importlib.util
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

APP_PATH = Path(__file__).resolve().parents[1] / "api" / "app.py"
spec = importlib.util.spec_from_file_location("sender_app_under_test", APP_PATH)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def message(hme="p=alias@icloud.com; f=inbox@example.test; s=noreply@email.openai.com"):
    msg = EmailMessage()
    msg["From"] = "ChatGPT <noreply_at_email_openai_com_token@icloud.com>"
    msg["To"] = "alias@icloud.com"
    if hme is not None:
        msg["X-ICLOUD-HME"] = hme
    msg.set_content("Body")
    return msg


class SenderParserTests(unittest.TestCase):
    def assertResolved(self, msg, address, source):
        self.assertEqual(app._resolve_actual_sender(msg), {
            "actual_sender": address, "actual_sender_source": source,
        })

    def test_hme_examples(self):
        self.assertResolved(message(), "noreply@email.openai.com", "hme_header")
        self.assertResolved(message("p=sample.alias2@icloud.com; d=; r=to; s=noreply@tm.openai.com"),
                            "noreply@tm.openai.com", "hme_header")

    def test_folded_case_insensitive_header_and_plus_preserved(self):
        raw = (b"From: Relay <relay@icloud.com>\r\n"
               b"x-icloud-hme: p=alias@icloud.com;\r\n\t S=Support+Ticket@EXAMPLE.TEST\r\n\r\nbody")
        self.assertResolved(BytesParser(policy=policy.default).parsebytes(raw),
                            "Support+Ticket@example.test", "hme_header")

    def test_from_fallback_and_not_reply_to_or_return_path(self):
        for hme in (None, "p=alias@icloud.com; s=", "p=alias@icloud.com; s=not-an-email"):
            with self.subTest(hme=hme):
                msg = message(hme)
                msg.replace_header("From", "Support <support@example.test>")
                msg["Reply-To"] = "different@example.test"
                msg["Return-Path"] = "<bounce@example.test>"
                self.assertResolved(msg, "support@example.test", "from_header")

    def test_duplicate_same_mapping_is_unambiguous(self):
        msg = message()
        msg["X-ICLOUD-HME"] = "s=noreply@email.openai.com"
        self.assertResolved(msg, "noreply@email.openai.com", "hme_header")

    def test_conflicting_mappings_use_from(self):
        for value in ("s=other@example.test", "s=a@example.test; s=b@example.test"):
            msg = message()
            msg["X-ICLOUD-HME"] = value
            self.assertResolved(msg, "noreply_at_email_openai_com_token@icloud.com", "from_header")

    def test_multiple_from_addresses_preserved(self):
        msg = message(None)
        msg.replace_header("From", "A <a@example.test>, B <b@example.test>")
        self.assertResolved(msg, "a@example.test, b@example.test", "from_header")

    def test_missing_and_invalid_from_are_unresolved(self):
        msg = message(None)
        del msg["From"]
        self.assertResolved(msg, None, "unresolved")
        msg["From"] = "invalid"
        self.assertResolved(msg, None, "unresolved")

    def test_no_body_scan_or_rewrite_guessing(self):
        msg = message("p=alias@icloud.com")
        msg.set_content("X-ICLOUD-HME: s=forged@example.test")
        with patch.object(app, "_hme_body_texts", side_effect=AssertionError("No body scan")):
            self.assertResolved(msg, "noreply_at_email_openai_com_token@icloud.com", "from_header")

    def test_oversize_header_does_not_select_partial_mapping(self):
        msg = message("s=first@example.test; padding=" + "x" * app.SENDER_HEADER_SCAN_LIMIT)
        self.assertResolved(msg, "noreply_at_email_openai_com_token@icloud.com", "from_header")


class SenderPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)
        self.db_patch = patch.object(app, "DB", self.root / "mail.db")
        self.db_patch.start()
        app._schema_initialized = False

    def tearDown(self):
        self.db_patch.stop()
        app._schema_initialized = False
        self.temp.cleanup()

    def save(self, msg, name="legacy", recipient_version=1):
        path = self.root / f"{name}.eml"
        path.write_bytes(msg.as_bytes())
        c = app.db()
        digest = app.hashlib.sha256(("test" + app.os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
        c.execute("insert or ignore into api_keys(name,key_hash,scopes,created_at,global_access) values('test',?,'mail.read',1,1)", (digest,))
        row_id = c.execute(
            "insert into messages(received_at,sender,to_header,raw_path,recipient_parse_version,actual_recipient) "
            "values(?,?,?,?,?,?)",
            (1, str(msg["From"]), str(msg["To"]), str(path), recipient_version, "alias@icloud.com"),
        ).lastrowid
        c.commit()
        c.close()
        return row_id, path

    def test_schema_migration_preserves_existing_data(self):
        c = sqlite3.connect(app.DB)
        c.execute("create table messages(id integer primary key,received_at real not null,"
                  "envelope_recipient text,to_header text,delivered_to text,original_to text,"
                  "message_id text,subject text,sender text,raw_path text not null,"
                  "actual_recipient text,actual_recipient_source text,recipient_parse_version integer default 0)")
        c.execute("insert into messages(received_at,raw_path,actual_recipient,recipient_parse_version) "
                  "values(1,'old.eml','alias+tag@icloud.com',1)")
        c.commit()
        c.close()
        c = app.db()
        row = dict(c.execute("select * from messages").fetchone())
        c.close()
        self.assertEqual(row["actual_recipient"], "alias+tag@icloud.com")
        self.assertEqual(row["recipient_parse_version"], 1)
        self.assertEqual(row["sender_parse_version"], 0)
        self.assertIsNone(row["actual_sender"])

    def test_backfill_cached_list_search_and_detail(self):
        row_id, path = self.save(message())
        original = path.read_bytes()
        self.assertEqual(app.backfill_actual_senders(pause_seconds=0), 1)
        with patch.object(app, "_read_sender_headers", side_effect=AssertionError("Cached")), \
             patch.object(app, "key_ok", return_value=True):
            self.assertEqual(app.backfill_actual_senders(pause_seconds=0), 0)
            listing = app.messages(x_api_key="test", q="noreply@email.openai.com", limit=20, offset=0, meta=True)
            self.assertEqual(listing["total"], 1)
            row = listing["items"][0]
            self.assertEqual(row["actual_sender"], "noreply@email.openai.com")
            self.assertEqual(row["actual_sender_source"], "hme_header")
            self.assertEqual(row["sender_parse_version"], app.SENDER_PARSE_VERSION)
            self.assertEqual(app.messages(x_api_key="test", q="absent@test.invalid", limit=20, offset=0, meta=True)["total"], 0)
            detail = app.message_detail(row_id, x_api_key="test")
            self.assertEqual(detail["actual_sender"], row["actual_sender"])
            self.assertEqual(detail["sender"], str(message()["From"]))
            self.assertEqual(detail["actual_recipient"], "alias@icloud.com")
        self.assertEqual(path.read_bytes(), original)

    def test_batched_missing_raw_fallback_and_no_webhook(self):
        self.save(message(), "a")
        self.save(message(), "b")
        _, path = self.save(message(), "missing")
        path.unlink()
        with patch.object(app.time, "sleep") as sleep, patch.object(app, "webhook_queue") as webhook:
            self.assertEqual(app.backfill_actual_senders(batch_size=2), 3)
        self.assertEqual(sleep.call_count, 2)
        webhook.put.assert_not_called()
        c = app.db()
        row = dict(c.execute("select * from messages order by id desc limit 1").fetchone())
        c.close()
        self.assertEqual(row["actual_sender_source"], "from_header")
        self.assertEqual(row["sender_parse_version"], 1)
        self.assertEqual(app.backfill_actual_senders(pause_seconds=0), 0)

    def test_header_read_skips_large_body_and_rejects_large_headers(self):
        path = self.root / "big.eml"
        path.write_bytes(b"From: sender@example.test\r\nX-ICLOUD-HME: s=original@example.test\r\n\r\n" + b"x" * (2 * 1024 * 1024))
        parsed = app._read_sender_headers(path)
        self.assertEqual(parsed.get_payload(), "")
        self.assertEqual(app._resolve_actual_sender(parsed)["actual_sender"], "original@example.test")
        path.write_bytes(b"X-Long: " + b"x" * app.SENDER_HEADER_SCAN_LIMIT + b"\r\n\r\n")
        with self.assertRaises(ValueError):
            app._read_sender_headers(path)


if __name__ == "__main__":
    unittest.main()

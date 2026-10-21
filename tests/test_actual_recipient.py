import importlib.util
import json
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
import queue
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch


APP_PATH = Path(__file__).resolve().parents[1] / "api" / "app.py"
spec = importlib.util.spec_from_file_location("recipient_app_under_test", APP_PATH)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

ALIAS = "sample.alias@icloud.com"
TAGGED = "sample.alias+fixturetag@icloud.com"
FORWARDED = "icloud0@example.com"
HME = f"p={ALIAS}; d=; f={FORWARDED}; s=noreply@email.openai.com"
BOUNCE = "bounces+100000000-0000-sample.alias+fixturetag=icloud.com@em0000.email.openai.com"


def message(hme=HME):
    msg = EmailMessage()
    msg["From"] = "ChatGPT <relay@icloud.com>"
    msg["To"] = f"Hide My Email <{ALIAS}>"
    msg["Subject"] = "Got a question? Start here"
    if hme is not None:
        msg["X-ICLOUD-HME"] = hme
    msg.set_content("Example body")
    return msg


class RecipientParserTests(unittest.TestCase):
    def assertResolved(self, msg, address, source):
        self.assertEqual(
            app._resolve_actual_recipient(msg, FORWARDED),
            {"actual_recipient": address, "actual_recipient_source": source},
        )

    def test_header_only_exact_example_and_folded_headers(self):
        raw = (
            f"To: Hide My Email <{ALIAS}>\r\n"
            f"Received-SPF: pass\r\n\tenvelope-from={BOUNCE}\r\n"
            f"Authentication-Results: spf.icloud.com; spf=pass smtp.mailfrom={BOUNCE}\r\n"
            f"X-ICLOUD-HME: {HME}\r\n\r\nBody"
        ).encode()
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        with patch.object(app, "_hme_body_texts", side_effect=AssertionError("Body must not be scanned")):
            self.assertResolved(msg, TAGGED, "hme_header")

    def test_icloud_rewritten_return_path(self):
        msg = message()
        msg["Return-Path"] = f"<{BOUNCE.replace('@em0000.email.openai.com', '_at_em0000_email_openai_com_fixture_sender_c@icloud.com')}>"
        self.assertResolved(msg, TAGGED, "hme_header")

    def test_tagged_hme_p_is_preserved(self):
        self.assertResolved(message(HME.replace(ALIAS, TAGGED)), TAGGED, "hme_header")

    def test_quoted_printable_html_login_hint(self):
        msg = message()
        msg.set_content(
            '<a href="https://example.test/?x=1&amp;login_hint=sample.alias%2Bfixturetag%40icloud.com">Example</a>',
            subtype="html", cte="quoted-printable",
        )
        reparsed = BytesParser(policy=policy.default).parsebytes(msg.as_bytes())
        self.assertResolved(reparsed, TAGGED, "hme_login_hint")

    def test_base64_literal_plus_and_double_encoding(self):
        for value in (TAGGED, "sample.alias%252Bfixturetag%2540icloud.com"):
            with self.subTest(value=value):
                msg = message()
                msg.set_content(f"login_hint={value}", cte="base64")
                self.assertResolved(msg, TAGGED, "hme_login_hint")

    def test_header_wins_over_body_hint(self):
        msg = message()
        msg["Received-SPF"] = f"pass envelope-from={BOUNCE}"
        msg.set_content(f"login_hint=sample.alias%2Bdifferent%40icloud.com")
        self.assertResolved(msg, TAGGED, "hme_header")

    def test_unrelated_header_or_body_address_is_not_used(self):
        msg = message()
        msg["Received-SPF"] = "pass envelope-from=bounces+1-2-other+tag=icloud.com@example.test"
        msg.set_content("login_hint=other%2Btag%40icloud.com")
        self.assertResolved(msg, ALIAS, "hme_alias")

    def test_unrelated_domain_and_substring_are_not_used(self):
        for value in (
            "bounces+1-2-sample.alias+tag=icloud.com.evil.test@example.test",
            "bounces+1-2-notsample.alias+tag=icloud.com@example.test",
        ):
            with self.subTest(value=value):
                msg = message()
                msg["Received-SPF"] = f"pass envelope-from={value}"
                self.assertResolved(msg, ALIAS, "hme_alias")

    def test_conflicting_candidates_return_alias_instead_of_guessing(self):
        msg = message()
        msg["Received-SPF"] = f"pass envelope-from={BOUNCE}"
        msg["Authentication-Results"] = f"spf=pass smtp.mailfrom={BOUNCE.replace('fixturetag', 'different')}"
        self.assertResolved(msg, ALIAS, "hme_alias")
        msg = message()
        msg.set_content(f"login_hint={TAGGED}\nlogin_hint=sample.alias+different@icloud.com")
        self.assertResolved(msg, ALIAS, "hme_alias")

    def test_no_hme_does_not_scan_arbitrary_login_hint(self):
        msg = message(hme=None)
        msg.set_content(f"login_hint={TAGGED}")
        self.assertResolved(msg, ALIAS, "to_header")

    def test_normal_to_preserves_plus_tag_and_fallback_to_envelope(self):
        msg = message(hme=None)
        msg.replace_header("To", "Person <person+signup@example.test>")
        self.assertResolved(msg, "person+signup@example.test", "to_header")
        del msg["To"]
        self.assertResolved(msg, FORWARDED, "envelope_recipient")

    def test_inline_body_only_attachments_and_nested_emails_excluded(self):
        msg = message()
        msg.add_attachment(f"login_hint={TAGGED}".encode(), maintype="text", subtype="plain", filename="note.txt")
        attached = EmailMessage()
        attached.set_content(f"login_hint={TAGGED}")
        msg.add_attachment(attached)
        self.assertResolved(msg, ALIAS, "hme_alias")
        alternative = message()
        alternative.add_alternative(f"<a href='?login_hint={TAGGED}'>Example</a>", subtype="html", cte="base64")
        self.assertResolved(alternative, TAGGED, "hme_login_hint")

    def test_scan_is_bounded(self):
        msg = message()
        msg.set_content("x" * (app.HME_BODY_SCAN_LIMIT * 2 + 1) + f"\nlogin_hint={TAGGED}")
        self.assertResolved(msg, ALIAS, "hme_alias")


class RecipientPipelineTests(unittest.TestCase):
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

    def save_legacy(self, msg, name="legacy"):
        raw_path = self.root / f"{name}.eml"
        raw_path.write_bytes(msg.as_bytes())
        c = app.db()
        digest = app.hashlib.sha256(("test" + app.os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
        c.execute("insert or ignore into api_keys(name,key_hash,scopes,created_at,global_access) values('test',?,'mail.read',1,1)", (digest,))
        row_id = c.execute(
            "insert into messages(received_at,envelope_recipient,to_header,subject,sender,raw_path) "
            "values(?,?,?,?,?,?)", (1, FORWARDED, str(msg["To"]), str(msg["Subject"]), str(msg["From"]), str(raw_path)),
        ).lastrowid
        c.commit()
        c.close()
        return row_id, raw_path

    def test_schema_migration_old_database(self):
        c = sqlite3.connect(app.DB)
        c.execute("create table messages(id integer primary key,received_at real not null,"
                  "envelope_recipient text,to_header text,delivered_to text,original_to text,"
                  "message_id text,subject text,sender text,raw_path text not null)")
        c.execute("insert into messages(received_at,raw_path) values(1,'legacy.eml')")
        c.commit()
        c.close()
        c = app.db()
        row = dict(c.execute("select * from messages").fetchone())
        c.close()
        self.assertEqual(row["raw_path"], "legacy.eml")
        self.assertEqual(row["recipient_parse_version"], 0)
        self.assertIsNone(row["actual_recipient"])

    def test_history_backfill_cache_search_and_detail(self):
        msg = message()
        msg["Received-SPF"] = f"pass envelope-from={BOUNCE}"
        row_id, _ = self.save_legacy(msg)
        self.assertEqual(app.backfill_actual_recipients(pause_seconds=0), 1)
        with patch.object(app, "BytesParser", side_effect=AssertionError("History must not be reparsed")):
            self.assertEqual(app.backfill_actual_recipients(pause_seconds=0), 0)
            with patch.object(app, "key_ok", return_value=True):
                listing = app.messages(x_api_key="test", q="fixturetag", limit=20, offset=0, meta=True)
                self.assertEqual(listing["total"], 1)
                self.assertEqual(listing["items"][0]["actual_recipient"], TAGGED)
                empty = app.messages(x_api_key="test", q="no-match", limit=20, offset=0, meta=True)
                self.assertEqual(empty["items"], [])
        with patch.object(app, "key_ok", return_value=True):
            detail = app.message_detail(row_id, x_api_key="test")
            self.assertEqual(detail["actual_recipient"], TAGGED)
            self.assertEqual(detail["envelope_recipient"], FORWARDED)

    def test_batched_history_and_missing_raw_is_not_retried(self):
        for i in range(3):
            self.save_legacy(message(), str(i))
        _, path = self.save_legacy(message(), "missing")
        path.unlink()
        with patch.object(app.time, "sleep") as sleep, patch.object(app.logger, "exception"):
            self.assertEqual(app.backfill_actual_recipients(batch_size=2), 4)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(app.backfill_actual_recipients(pause_seconds=0), 0)

    def test_ingest_and_webhook_preserve_envelope_and_raw(self):
        mail_root = self.root / "maildata"
        source = mail_root / "example.com" / "icloud0" / "Maildir" / "new" / "sample.eml"
        source.parent.mkdir(parents=True)
        msg = message()
        msg["Received-SPF"] = f"pass envelope-from={BOUNCE}"
        raw_bytes = msg.as_bytes()
        source.write_bytes(raw_bytes)
        real_path = Path
        def mapped_path(value):
            if value == "/maildata":
                return mail_root
            if value == "/app-data/raw":
                return self.root / "raw"
            return real_path(value)
        with patch.object(app, "Path", side_effect=mapped_path), \
             patch.object(app.shutil, "disk_usage", return_value=MagicMock(free=3 * 1024**3)), \
             patch.object(app, "webhook_queue", queue.SimpleQueue()):
            self.assertEqual(app.ingest_once(), 1)
            self.assertEqual(app.ingest_once(), 0)
            row_id, payload, raw_path = app.webhook_queue.get_nowait()
        self.assertEqual(payload["actual_recipient"], TAGGED)
        self.assertEqual(payload["actual_sender"], "noreply@email.openai.com")
        self.assertEqual(payload["actual_sender_source"], "hme_header")
        self.assertEqual(payload["from"], str(msg["From"]))
        self.assertEqual(payload["actual_recipient_source"], "hme_header")
        self.assertEqual(payload["envelope_recipient"], FORWARDED)
        c = app.db()
        row = dict(c.execute("select * from messages where id=?", (row_id,)).fetchone())
        c.execute("insert into webhooks(url,secret,enabled) values('https://receiver.invalid/','test',1)")
        c.commit()
        c.close()
        self.assertEqual(row["actual_recipient"], TAGGED)
        self.assertEqual(row["actual_sender"], "noreply@email.openai.com")
        self.assertEqual(row["sender_parse_version"], app.SENDER_PARSE_VERSION)
        self.assertEqual(row["recipient_parse_version"], app.RECIPIENT_PARSE_VERSION)
        response = MagicMock()
        response.__enter__.return_value.status = 200
        with patch.object(app, "send_webhook_request", return_value=200) as send:
            app.dispatch_webhooks(row_id, payload, raw_path=raw_path)
        sent = json.loads(send.call_args.args[0].data)
        self.assertEqual(sent["to_addr"], FORWARDED)
        self.assertEqual(sent["actual_recipient"], TAGGED)
        self.assertEqual(sent["actual_sender"], "noreply@email.openai.com")
        self.assertEqual(sent["actual_sender_source"], "hme_header")
        self.assertEqual(sent["from"], str(msg["From"]))
        self.assertEqual(sent["raw_content"], raw_bytes.decode())


if __name__ == "__main__":
    unittest.main()

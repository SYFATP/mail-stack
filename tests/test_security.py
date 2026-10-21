"""Security regressions use real authorization, synthetic SQLite and mocked I/O."""
import hashlib
import importlib.util
import json
import socket
import ssl
import sqlite3
import tempfile
import time
import unittest
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from api.services import webhook_transport as transport
from api.services.auth_throttle import AuthenticationRateLimit
from api.repositories.credentials import CredentialError
from api.services.global_credentials import load_cloudflare_secret
import api.migrations.schema as schema

spec = importlib.util.spec_from_file_location("security_app", Path(__file__).parents[1] / "api/app.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class SecurityTests(unittest.TestCase):
    A = "prj_security_a"
    B = "prj_security_b"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [patch.object(app, "DB", self.root / "mail.db"),
                        patch.object(app, "RUNTIME_DIR", self.root),
                        patch.dict(app.os.environ, {"API_KEY_PEPPER": "fixture-pepper",
                            "MAIL_CREDENTIAL_KEYS": json.dumps({"test": Fernet.generate_key().decode()}),
                            "MAIL_CREDENTIAL_ACTIVE_KEY": "test", "CF_API_TOKEN": "",
                            "CF_API_KEY": "", "CF_API_EMAIL": ""})]
        for p in self.patches:
            p.start()
        app._schema_initialized = False
        c = app.db()
        for project in (self.A, self.B):
            c.execute("insert into projects(id,name,created_at) values(?,?,?)", (project, project, time.time()))
        c.execute("insert into settings values('admin_password_hash',?)", (app.password_hash("fixture-password"),))
        c.commit()
        c.close()
        self.admin = self.session("administrator")
        self.project = self.key("project-a", "mail.read,mail.send,webhook.manage", project=self.A)
        self.global_read = self.key("global-read", "mail.read", global_access=True)
        self.hook_only = self.key("hook-only", "webhook.manage", global_access=True)
        self.domain("a.example.test", self.A)
        self.domain("b.example.test", self.B)
        self.domain("unassigned.example.test", None)
        self.msg_a = self.message("a.example.test", self.A)
        self.msg_b = self.message("b.example.test", self.B)
        self.msg_global = self.message("unassigned.example.test", None)
        self.client = TestClient(app.app)

    def tearDown(self):
        self.client.close()
        app._schema_initialized = False
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def query(self, sql, params=()):
        c = app.db()
        try:
            rows = [dict(r) for r in c.execute(sql, params)]
            c.commit()
            return rows
        finally:
            c.close()

    @staticmethod
    def digest(value):
        return hashlib.sha256((value + app.os.environ["API_KEY_PEPPER"]).encode()).hexdigest()

    def session(self, token):
        self.query("insert into sessions values(?,?)", (self.digest(token), time.time() + 3600))
        return {"X-API-Key": token}

    def key(self, token, scopes, global_access=False, project=None):
        self.query("insert into api_keys(name,key_hash,scopes,created_at,global_access) values(?,?,?,?,?)",
                   (token, self.digest(token), scopes, time.time(), int(global_access)))
        if project:
            key_id = self.query("select id from api_keys where key_hash=?", (self.digest(token),))[0]["id"]
            self.query("insert into api_key_grants values(?,?,?,?)", (key_id, project, scopes, time.time()))
        return {"X-API-Key": token}

    def domain(self, name, project):
        self.query("""insert into mail_domains(domain,users,spf,dmarc,mx,created_at,updated_at,project_id)
                   values(?,'["user"]','v=spf1 -all','v=DMARC1; p=reject','mail.example.test',?,?,?)""",
                   (name, time.time(), time.time(), project))

    def message(self, domain, project):
        message = EmailMessage()
        message["From"] = "sender@outside.test"
        message["To"] = "user@" + domain
        message["Subject"] = domain
        message.set_content("confidential fixture: " + domain)
        message.add_attachment(b"attachment fixture", maintype="application", subtype="octet-stream", filename="sample.bin")
        raw = self.root / (domain + ".eml")
        raw.write_bytes(message.as_bytes())
        self.query("insert into messages(received_at,raw_path,envelope_recipient,subject) values(?,?,?,?)",
                   (time.time(), str(raw), "user@" + domain, domain))
        message_id = self.query("select max(id) as id from messages")[0]["id"]
        self.query("""insert into message_deliveries(delivery_key,message_id,envelope_recipient,
                     managed_domain,recipient_domain,received_at,project_id) values(?,?,?,?,?,?,?)""",
                   (domain, message_id, "user@" + domain, domain, domain, time.time(), project))
        return message_id

    def hook(self, project):
        self.query("insert into webhooks(url,secret,project_id,created_at) values(?,?,?,?)",
                   ("https://receiver.invalid/webhook", "fixture-secret", project, time.time()))
        return self.query("select max(id) as id from webhooks")[0]["id"]

    def outbox(self, hook, message):
        self.query("""insert into webhook_outbox(event_id,webhook_id,message_id,payload_json,status,
                     attempts,next_attempt_at,created_at,updated_at) values(?,?,?,?,'queued',0,?,?,?)""",
                   (f"evt_{hook}_{message}", hook, message, json.dumps({"event": "message.received"}),
                    time.time(), time.time(), time.time()))

    def test_read_scope_required_for_every_mail_route(self):
        for headers in (self.hook_only, self.key("send-only", "mail.send", global_access=True)):
            for suffix in ("", "/raw", "/content", "/attachments", "/attachments/2"):
                with self.subTest(suffix=suffix, key=headers):
                    response = self.client.get(f"/api/v1/messages/{self.msg_a}" + suffix, headers=headers)
                    self.assertEqual(response.status_code, 403)
            self.assertEqual(self.client.get("/api/v1/messages", headers=headers).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/raw").status_code, 401)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/raw", headers=self.global_read).status_code, 200)

    def test_project_reads_list_details_attachments_and_domain_inventory(self):
        self.assertEqual(self.client.get("/api/v1/messages", headers=self.project).status_code, 403)
        own = self.client.get("/api/v1/messages", params={"project_id": self.A}, headers=self.project)
        self.assertEqual(own.status_code, 200)
        self.assertEqual([r["id"] for r in own.json()], [self.msg_a])
        self.assertEqual(self.client.get("/api/v1/messages", params={"project_id": self.B}, headers=self.project).status_code, 403)
        for message in (self.msg_b, self.msg_global):
            for suffix in ("", "/raw", "/content", "/attachments", "/attachments/2"):
                self.assertEqual(self.client.get(f"/api/v1/messages/{message}" + suffix, headers=self.project).status_code, 403)
        own_attachments = self.client.get(f"/api/v1/messages/{self.msg_a}/attachments", headers=self.project).json()
        self.assertEqual(len(own_attachments), 1)
        download = self.client.get(own_attachments[0]["path"], headers=self.project)
        self.assertEqual(download.content, b"attachment fixture")
        domains = self.client.get("/api/v1/domains", headers=self.project).json()
        self.assertEqual([r["domain"] for r in domains], ["a.example.test"])
        self.query("update projects set enabled=0 where id=?", (self.A,))
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/raw", headers=self.project).status_code, 403)

    def test_project_snapshot_does_not_follow_domain_reassignment(self):
        self.query("update mail_domains set project_id=? where domain='a.example.test'", (self.B,))
        key_b = self.key("project-b", "mail.read", project=self.B)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/raw", headers=key_b).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/raw", headers=self.project).status_code, 200)

    def test_domain_project_assignment_survives_updates_and_can_be_explicitly_cleared(self):
        with patch.object(app, "_write_runtime_files"):
            response = self.client.patch("/api/v1/mail-domains/a.example.test", headers=self.admin,
                                         json={"send_enabled": False})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["project_id"], self.A)
            # Internal save callers that omit project metadata preserve it.
            row = dict(response.json())
            row.pop("project_id")
            saved = app._save_domain(row)
            self.assertEqual(saved["project_id"], self.A)
            self.query("update projects set enabled=0 where id=?", (self.A,))
            kept = self.client.patch("/api/v1/mail-domains/a.example.test", headers=self.admin,
                                     json={"send_enabled": True})
            self.assertEqual(kept.status_code, 200, kept.text)
            wrong = self.client.patch("/api/v1/mail-domains/unassigned.example.test", headers=self.admin,
                                      json={"project_id": self.A})
            self.assertEqual(wrong.status_code, 400)
            cleared = self.client.patch("/api/v1/mail-domains/a.example.test", headers=self.admin,
                                        json={"project_id": None})
            self.assertEqual(cleared.status_code, 200, cleared.text)
            self.assertIsNone(cleared.json()["project_id"])

    def test_project_send_cannot_omit_project_or_use_another_sender_domain(self):
        item = {"sender": "user@a.example.test", "recipients": ["audit@outside.test"], "text": "fixture"}
        self.assertEqual(self.client.post("/api/v1/send/queue", headers=self.project, json=item).status_code, 403)
        self.assertEqual(self.client.post("/api/v1/send", headers=self.project, json=item).status_code, 403)
        for path in ("/api/v1/send/queue", "/api/v1/send"):
            wrong = self.client.post(path, headers=self.project,
                json={**item, "sender": "user@b.example.test", "project_id": self.A})
            self.assertEqual(wrong.status_code, 403)
        with patch.object(app, "OUTBOUND_DKIM_ENABLED", False):
            good = self.client.post("/api/v1/send/queue", headers=self.project, json={**item, "project_id": self.A})
        self.assertEqual(good.status_code, 202, good.text)

    def test_scoped_webhooks_and_listing(self):
        mine, foreign, global_hook = self.hook(self.A), self.hook(self.B), self.hook(None)
        body = {"url": "https://receiver.invalid/new", "secret": "fixture-secret"}
        self.assertEqual(self.client.post("/api/v1/webhooks", headers=self.project, json=body).status_code, 403)
        own = self.client.post("/api/v1/webhooks", headers=self.project, json={**body, "project_id": self.A})
        self.assertEqual(own.status_code, 200, own.text)
        listing = self.client.get("/api/v1/webhooks", headers=self.project).json()
        self.assertEqual({r["id"] for r in listing}, {mine, own.json()["id"]})
        for hook in (foreign, global_hook):
            self.assertEqual(self.client.patch(f"/api/v1/webhooks/{hook}", headers=self.project,
                                              json={"enabled": False}).status_code, 403)
            self.assertEqual(self.client.delete(f"/api/v1/webhooks/{hook}", headers=self.project).status_code, 403)

    def test_ingest_enqueues_only_own_project_and_snapshots_owner(self):
        mine = self.hook(self.A)
        self.hook(self.B)
        global_hook = self.hook(None)
        maildata = self.root / "maildata"
        source = maildata / "a.example.test/user/Maildir/new/new-message"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"From: sender@outside.test\r\nTo: user@a.example.test\r\nSubject: new\r\n\r\nfixture")
        real_path, real_disk = Path, app.shutil.disk_usage
        def mapped(value, *parts):
            text = str(value)
            if text.startswith("/app-data"):
                value = self.root / text.removeprefix("/app-data").lstrip("/")
            elif text.startswith("/maildata"):
                value = maildata / text.removeprefix("/maildata").lstrip("/")
            return real_path(value, *parts)
        with patch.object(app, "Path", side_effect=mapped), patch.object(app.shutil, "disk_usage", side_effect=lambda p: real_disk(mapped(p))):
            self.assertEqual(app.ingest_once(), 1)
        rows = self.query("select webhook_id,message_id from webhook_outbox")
        self.assertEqual({r["webhook_id"] for r in rows}, {mine, global_hook})
        delivery = self.query("select project_id from message_deliveries where message_id=?", (rows[0]["message_id"],))
        self.assertEqual(delivery[0]["project_id"], self.A)

    def test_old_cross_project_jobs_cancel_before_any_delivery(self):
        foreign = self.hook(self.B)
        self.outbox(foreign, self.msg_a)
        self.assertIsNone(app._claim_webhook_outbox())
        self.assertTrue(all(r["status"] == "cancelled" for r in self.query("select status from webhook_outbox")))
        own = self.hook(self.A)
        self.outbox(own, self.msg_a)
        row = app._claim_webhook_outbox()
        self.assertIsNotNone(row)
        self.query("update webhooks set project_id=? where id=?", (self.B, own))
        with patch.object(app, "send_webhook_request") as send:
            app._deliver_webhook_outbox(row)
            send.assert_not_called()
        self.assertEqual(self.query("select status from webhook_outbox where id=?", (row["id"],))[0]["status"], "cancelled")

    def test_new_keys_default_normal_and_admin_grants_preserve_global_access(self):
        new = self.client.post("/api/v1/api-keys", headers=self.admin, params={"name": "new", "scopes": "mail.read"})
        self.assertEqual(new.status_code, 200)
        self.assertFalse(new.json()["global_access"])
        self.assertEqual(new.json()["key_type"], "normal")
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_global}/raw", headers={"X-API-Key": new.json()["key"]}).status_code, 403)
        scoped = self.client.post("/api/v1/api-keys", headers=self.admin,
            params={"name": "scoped", "scopes": "mail.read", "project_id": self.A})
        self.assertEqual(scoped.status_code, 200, scoped.text)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/raw", headers={"X-API-Key": scoped.json()["key"]}).status_code, 200)
        global_id = self.query("select id from api_keys where name='global-read'")[0]["id"]
        grant = self.client.post(f"/api/v1/api-keys/{global_id}/grants", headers=self.admin,
                                 params={"project_id": self.A, "scopes": "mail.read"})
        self.assertEqual(grant.status_code, 200)
        self.assertTrue(app.key_has_global_scope(self.global_read["X-API-Key"], "mail.read"))
        self.assertEqual(self.client.delete(f"/api/v1/api-keys/{global_id}", headers=self.admin).status_code, 200)

    def test_admin_key_reads_all_projects_and_history_and_remains_global_with_grants(self):
        response = self.client.post("/api/v1/api-keys", headers=self.admin,
            params={"name": "modern-admin-fixture", "key_type": "admin", "project_id": self.A})
        self.assertEqual(response.status_code, 200, response.text)
        created = response.json()
        self.assertEqual(created["key_type"], "admin")
        self.assertTrue(created["global_access"])
        headers = {"X-API-Key": created["key"]}
        self.assertEqual(len(self.client.get("/api/v1/messages", headers=headers).json()), 3)
        scoped = self.client.get("/api/v1/messages", headers=headers, params={"project_id": self.B})
        self.assertEqual(scoped.status_code, 200, scoped.text)
        self.assertEqual([r["id"] for r in scoped.json()], [self.msg_b])
        for message in (self.msg_a, self.msg_b, self.msg_global):
            for suffix in ("", "/raw", "/content", "/attachments"):
                self.assertEqual(self.client.get(f"/api/v1/messages/{message}{suffix}", headers=headers).status_code, 200)
        self.assertEqual(len(self.client.get("/api/v1/mail-domains", headers=headers).json()), 3)
        grant = self.client.post(f"/api/v1/api-keys/{created['id']}/grants", headers=self.admin,
                                params={"project_id": self.B, "scopes": "mail.read"})
        self.assertEqual(grant.status_code, 200, grant.text)
        self.assertEqual(len(self.client.get("/api/v1/messages", headers=headers).json()), 3)
        listed = self.client.get("/api/v1/api-keys", headers=self.admin).json()
        self.assertEqual(next(k for k in listed if k["id"] == created["id"])["key_type"], "admin")
        item = {"sender": "user@unassigned.example.test", "recipients": ["audit@outside.test"],
                "text": "fixture", "project_id": self.A}
        with patch.object(app, "OUTBOUND_DKIM_ENABLED", False):
            queued = self.client.post("/api/v1/send/queue", headers=headers, json=item)
        self.assertEqual(queued.status_code, 202, queued.text)

    def test_key_type_validation_cannot_be_used_by_normal_keys_to_escalate(self):
        for key_type in ("normal", "admin"):
            self.assertEqual(self.client.post("/api/v1/api-keys", headers=self.project,
                params={"key_type": key_type}).status_code, 401)
        self.assertEqual(self.client.post("/api/v1/api-keys", headers=self.admin,
            params={"key_type": "unknown"}).status_code, 422)
        self.assertEqual(self.client.post("/api/v1/api-keys", headers=self.admin,
            params={"key_type": "normal", "global_access": "true"}).status_code, 400)
        alias = self.client.post("/api/v1/api-keys", headers=self.admin,
            params={"name": "legacy-global", "global_access": "true"})
        self.assertEqual(alias.status_code, 200, alias.text)
        self.assertEqual(alias.json()["key_type"], "admin")

    def test_key_edit_requires_console_admin_and_never_reveals_key_material(self):
        key_id = self.query("select id from api_keys where name='project-a'")[0]["id"]
        path = f"/api/v1/api-keys/{key_id}"
        for headers in ({}, self.project, self.global_read):
            self.assertEqual(self.client.get(path, headers=headers).status_code, 401)
            self.assertEqual(self.client.patch(path, headers=headers, json={"key_type": "admin"}).status_code, 401)
        before = self.query("select * from api_keys where id=?", (key_id,))[0]
        response = self.client.patch(path, headers=self.admin, json={"name": " Renamed "})
        self.assertEqual(response.status_code, 200, response.text)
        after = self.query("select * from api_keys where id=?", (key_id,))[0]
        self.assertEqual(after["name"], "Renamed")
        self.assertEqual(after["key_hash"], before["key_hash"])
        self.assertEqual(after["created_at"], before["created_at"])
        self.assertEqual(response.json()["grants"][0]["project_id"], self.A)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/raw", headers=self.project).status_code, 200)
        for data in (response.json(), self.client.get(path, headers=self.admin).json()):
            self.assertNotIn("key", data)
            self.assertNotIn("key_hash", data)
        for method in ("get", "patch"):
            args = {"headers": self.admin}
            if method == "patch":
                args["json"] = {"name": "missing"}
            self.assertEqual(getattr(self.client, method)("/api/v1/api-keys/99999", **args).status_code, 404)

    def test_editing_key_scopes_takes_effect_on_body_and_attachments_with_original_key(self):
        key_id = self.query("select id from api_keys where name='project-a'")[0]["id"]
        path = f"/api/v1/api-keys/{key_id}"
        changed = self.client.patch(path, headers=self.admin, json={"scopes": ["mail.send"]})
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual(changed.json()["grants"][0]["scopes"], ["mail.read", "mail.send", "webhook.manage"])
        for suffix in ("", "/raw", "/content", "/attachments", "/attachments/2"):
            self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}" + suffix, headers=self.project).status_code, 403)
        self.assertEqual(self.client.get("/api/v1/messages", headers=self.project, params={"project_id": self.A}).status_code, 403)
        restored = self.client.patch(path, headers=self.admin, json={"scopes": ["mail.read"]})
        self.assertEqual(restored.status_code, 200, restored.text)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/content", headers=self.project).status_code, 200)

    def test_editing_key_type_keeps_grants_and_admin_global_access(self):
        key_id = self.query("select id from api_keys where name='project-a'")[0]["id"]
        path = f"/api/v1/api-keys/{key_id}"
        promoted = self.client.patch(path, headers=self.admin, json={"key_type": "admin"})
        self.assertEqual(promoted.status_code, 200, promoted.text)
        self.assertEqual(promoted.json()["key_type"], "admin")
        self.assertEqual(len(self.client.get("/api/v1/messages", headers=self.project).json()), 3)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_global}/raw", headers=self.project).status_code, 200)
        kept_global = self.client.patch(path, headers=self.admin,
            json={"grants": [{"project_id": self.A, "scopes": ["mail.read"]}]})
        self.assertEqual(kept_global.status_code, 200, kept_global.text)
        self.assertTrue(kept_global.json()["global_access"])
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_b}/raw", headers=self.project).status_code, 200)
        demoted = self.client.patch(path, headers=self.admin, json={"key_type": "normal"})
        self.assertEqual(demoted.status_code, 200, demoted.text)
        self.assertFalse(demoted.json()["global_access"])
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/raw", headers=self.project).status_code, 200)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_b}/raw", headers=self.project).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_global}/raw", headers=self.project).status_code, 403)

    def test_replacing_project_grants_revokes_old_project_and_limits_each_scope(self):
        key_id = self.query("select id from api_keys where name='project-a'")[0]["id"]
        path = f"/api/v1/api-keys/{key_id}"
        replaced = self.client.patch(path, headers=self.admin,
            json={"grants": [{"project_id": self.B, "scopes": ["mail.read"]}]})
        self.assertEqual(replaced.status_code, 200, replaced.text)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/content", headers=self.project).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_b}/content", headers=self.project).status_code, 200)
        send = {"sender": "user@b.example.test", "recipients": ["audit@outside.test"], "text": "fixture", "project_id": self.B}
        self.assertEqual(self.client.post("/api/v1/send/queue", headers=self.project, json=send).status_code, 403)
        cleared = self.client.patch(path, headers=self.admin, json={"grants": []})
        self.assertEqual(cleared.status_code, 200, cleared.text)
        self.assertEqual(cleared.json()["grants"], [])
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_b}/content", headers=self.project).status_code, 403)

    def test_key_edit_invalid_grants_roll_back_every_field(self):
        key_id = self.query("select id from api_keys where name='project-a'")[0]["id"]
        path = f"/api/v1/api-keys/{key_id}"
        before = self.client.get(path, headers=self.admin).json()
        self.query("update projects set enabled=0 where id=?", (self.B,))
        for grants in ([{"project_id": "prj_missing_fixture", "scopes": ["mail.read"]}],
                       [{"project_id": self.B, "scopes": ["mail.read"]}],
                       [{"project_id": self.A, "scopes": ["mail.read"]}] * 2,
                       [{"project_id": "invalid", "scopes": ["mail.read"]}]):
            response = self.client.patch(path, headers=self.admin,
                json={"name": "should-rollback", "key_type": "admin", "scopes": ["mail.send"], "grants": grants})
            self.assertEqual(response.status_code, 400, response.text)
            self.assertEqual(self.client.get(path, headers=self.admin).json(), before)

    def test_key_edit_preserves_existing_disabled_project_grant(self):
        key_id = self.query("select id from api_keys where name='project-a'")[0]["id"]
        path = f"/api/v1/api-keys/{key_id}"
        self.query("update projects set enabled=0 where id=?", (self.A,))
        response = self.client.patch(path, headers=self.admin,
            json={"name": "keep disabled", "grants": [{"project_id": self.A, "scopes": ["mail.read"]}]})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["grants"][0]["project_id"], self.A)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/raw", headers=self.project).status_code, 403)

    def test_key_edit_rejects_empty_scopes_unknown_fields_and_nulls_without_mutation(self):
        key_id = self.query("select id from api_keys where name='project-a'")[0]["id"]
        path = f"/api/v1/api-keys/{key_id}"
        before = self.client.get(path, headers=self.admin).json()
        invalid = [{"scopes": []}, {"scopes": ["unrecognized"]}, {"key_type": "unknown"},
                   {"key": "replacement"}, {"global_access": True}, {"name": " "},
                   {"name": "x" * 81}, {"grants": [{"project_id": self.A, "scopes": []}]}]
        invalid += [{field: None} for field in ("name", "scopes", "key_type", "grants")]
        for body in invalid:
            response = self.client.patch(path, headers=self.admin, json=body)
            self.assertIn(response.status_code, (400, 422), response.text)
            self.assertEqual(self.client.get(path, headers=self.admin).json(), before)

    def test_project_management_requires_console_admin_and_reports_scoped_counts(self):
        for headers in ({}, self.project, self.global_read):
            self.assertEqual(self.client.get("/api/v1/projects", headers=headers).status_code, 401)
            self.assertEqual(self.client.post("/api/v1/projects", headers=headers, params={"name": "unauthorized"}).status_code, 401)
            self.assertEqual(self.client.patch("/api/v1/projects/" + self.A, headers=headers, json={"enabled": False}).status_code, 401)
        self.hook(self.A)
        self.hook(None)
        response = self.client.get("/api/v1/projects", headers=self.admin)
        self.assertEqual(response.status_code, 200, response.text)
        project = next(row for row in response.json() if row["id"] == self.A)
        self.assertEqual({k: project[k] for k in ("domain_count", "message_count", "key_count", "webhook_count")},
                         {"domain_count": 1, "message_count": 1, "key_count": 1, "webhook_count": 1})
        self.assertIs(project["enabled"], True)
        self.assertNotIn("key", project)
        self.assertNotIn("secret", project)

    def test_project_creation_normalizes_names_and_rejects_duplicates_and_blanks(self):
        result = self.client.post("/api/v1/projects", headers=self.admin, params={"name": "  New project  "})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["name"], "New project")
        self.assertTrue(result.json()["enabled"])
        self.assertEqual(result.json()["domain_count"], 0)
        self.assertEqual(self.client.post("/api/v1/projects", headers=self.admin, params={"name": "New project"}).status_code, 409)
        self.assertEqual(self.client.post("/api/v1/projects", headers=self.admin, params={"name": "   "}).status_code, 400)

    def test_project_rename_keeps_id_grants_and_mail_ownership_and_conflicts_roll_back(self):
        path = "/api/v1/projects/" + self.A
        original = self.query("select * from projects where id=?", (self.A,))[0]
        invalid = self.client.patch(path, headers=self.admin, json={"name": self.B, "enabled": False})
        self.assertEqual(invalid.status_code, 409, invalid.text)
        self.assertEqual(self.query("select * from projects where id=?", (self.A,))[0], original)
        response = self.client.patch(path, headers=self.admin, json={"name": " Renamed project "})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["id"], self.A)
        self.assertEqual(response.json()["name"], "Renamed project")
        self.assertEqual(response.json()["created_at"], original["created_at"])
        self.assertEqual(response.json()["message_count"], 1)
        self.assertEqual(response.json()["key_count"], 1)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/content", headers=self.project).status_code, 200)

    def test_disabling_and_reenabling_project_controls_keys_and_hooks_without_deleting_data(self):
        path = "/api/v1/projects/" + self.A
        mine, global_hook = self.hook(self.A), self.hook(None)
        before = {table: self.query("select count(*) as n from " + table)[0]["n"]
                  for table in ("messages", "message_deliveries", "mail_domains", "api_keys", "api_key_grants", "webhooks")}
        disabled = self.client.patch(path, headers=self.admin, json={"enabled": False})
        self.assertEqual(disabled.status_code, 200, disabled.text)
        self.assertFalse(disabled.json()["enabled"])
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/content", headers=self.project).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/content", headers=self.global_read).status_code, 200)
        self.assertEqual(self.client.get("/api/v1/domains", headers=self.project).json(), [])
        c = app.db()
        try:
            self.assertEqual({row["id"] for row in app._inbound_webhooks(c, self.A)}, {global_hook})
        finally:
            c.close()
        self.assertEqual(before, {table: self.query("select count(*) as n from " + table)[0]["n"] for table in before})
        enabled = self.client.patch(path, headers=self.admin, json={"enabled": True})
        self.assertEqual(enabled.status_code, 200, enabled.text)
        self.assertEqual(self.client.get(f"/api/v1/messages/{self.msg_a}/content", headers=self.project).status_code, 200)
        c = app.db()
        try:
            self.assertEqual({row["id"] for row in app._inbound_webhooks(c, self.A)}, {mine, global_hook})
        finally:
            c.close()

    def test_project_management_counts_preserve_historical_message_snapshot(self):
        with patch.object(app, "_write_runtime_files"):
            result = self.client.patch("/api/v1/mail-domains/a.example.test", headers=self.admin, json={"project_id": self.B})
        self.assertEqual(result.status_code, 200, result.text)
        projects = {row["id"]: row for row in self.client.get("/api/v1/projects", headers=self.admin).json()}
        self.assertEqual(projects[self.A]["domain_count"], 0)
        self.assertEqual(projects[self.A]["message_count"], 1)
        self.assertEqual(projects[self.B]["domain_count"], 2)
        self.assertEqual(projects[self.B]["message_count"], 1)

    def test_invalid_project_edits_leave_existing_settings_unchanged(self):
        path = "/api/v1/projects/" + self.A
        before = self.query("select * from projects where id=?", (self.A,))[0]
        for payload in ({"name": " "}, {"name": None}, {"enabled": None}, {"enabled": 0},
                        {"enabled": "false"}, {"name": "x" * 81}, {"id": self.B}, {"domain_count": 0}):
            response = self.client.patch(path, headers=self.admin, json=payload)
            self.assertIn(response.status_code, (400, 422), response.text)
            self.assertEqual(self.query("select * from projects where id=?", (self.A,))[0], before)
        self.assertEqual(self.client.patch("/api/v1/projects/prj_missing_fixture", headers=self.admin, json={"enabled": False}).status_code, 404)

    def test_global_webhook_jobs_accept_project_and_unassigned_mail(self):
        global_hook = self.hook(None)
        for message in (self.msg_a, self.msg_b, self.msg_global):
            self.outbox(global_hook, message)
            row = app._claim_webhook_outbox()
            self.assertIsNotNone(row)
            self.assertEqual(row["message_id"], message)
            self.query("update webhook_outbox set status='delivered' where id=?", (row["id"],))

    def test_range_rejected_and_normal_eml_download_works(self):
        url = f"/api/v1/messages/{self.msg_a}/raw?download=true"
        for value in ("bytes=0-1,4-5", "bytes=" + "0" * 5000 + "a-"):
            r = self.client.get(url, headers={**self.global_read, "Range": value})
            self.assertEqual(r.status_code, 400)
        response = self.client.get(url, headers=self.global_read)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["accept-ranges"], "none")
        self.assertIn(b"confidential fixture", response.content)

    def test_login_and_header_auth_are_limited_without_trusting_forwarded_headers(self):
        for i in range(10):
            r = self.client.post("/api/v1/auth/login", json={"password": "wrong"}, headers={"X-Forwarded-For": f"1.2.3.{i}"})
            self.assertEqual(r.status_code, 401)
        limited = self.client.post("/api/v1/auth/login", json={"password": "fixture-password"})
        self.assertEqual(limited.status_code, 429)
        self.assertGreater(int(limited.headers["retry-after"]), 0)
        self.assertEqual(self.client.get("/api/v1/api-keys", headers={"X-Admin-Password": "wrong"}).status_code, 429)
        # Session-authenticated use is not charged against the password budget.
        self.assertEqual(self.client.get("/api/v1/api-keys", headers=self.admin).status_code, 200)
        self.query("update auth_attempts set expires_at=0")
        self.assertEqual(self.client.post("/api/v1/auth/login", json={"password": "fixture-password"}).status_code, 200)

    def test_global_authentication_budget_bounds_distributed_attempts(self):
        limiter = AuthenticationRateLimit(None, app.db)
        for i in range(120):
            self.assertEqual(limiter.reserve("fixture-client-" + str(i)), 0)
        self.assertGreater(limiter.reserve("another-client"), 0)

    def test_cloudflare_ciphertext_migration_and_no_keyring_fail_closed(self):
        secret = "fixture-cloudflare-token"
        saved = self.client.put("/api/v1/dns/cloudflare", headers=self.admin, json={"api_token": secret})
        self.assertEqual(saved.status_code, 200, saved.text)
        self.assertEqual(self.query("select value from settings where key='cf_api_token'"), [])
        ciphertext = self.query("select ciphertext from dns_credentials")[0]["ciphertext"]
        self.assertNotIn(secret, ciphertext)
        self.assertEqual(app._global_cloudflare_secret(), {"api_token": secret})
        self.query("delete from settings where key='global_cloudflare_credential_ref'")
        self.query("insert into settings values('cf_api_token',?)", ("legacy-fixture-token",))
        self.assertEqual(load_cloudflare_secret(app.db), {"api_token": "legacy-fixture-token"})
        self.assertEqual(self.query("select value from settings where key='cf_api_token'"), [])
        with patch.dict(app.os.environ, {"MAIL_CREDENTIAL_KEYS": "{}", "MAIL_CREDENTIAL_ACTIVE_KEY": ""}):
            failed = self.client.put("/api/v1/dns/cloudflare", headers=self.admin, json={"api_token": "new-secret"})
            self.assertEqual(failed.status_code, 409)
            self.assertEqual(self.query("select value from settings where key='cf_api_token'"), [])
            self.assertEqual(self.client.get("/api/v1/dns/cloudflare", headers=self.admin).status_code, 409)

    def test_legacy_secret_never_falls_back_to_plaintext_without_keyring(self):
        self.query("insert into settings values('cf_api_token','legacy-secret')")
        with patch.dict(app.os.environ, {"MAIL_CREDENTIAL_KEYS": "{}", "MAIL_CREDENTIAL_ACTIVE_KEY": ""}):
            with self.assertRaises(CredentialError):
                load_cloudflare_secret(app.db)
            with patch.object(app, "_seed_domains") as seed:
                with self.assertRaises(CredentialError):
                    app.startup()
                seed.assert_not_called()

    def test_encrypted_credential_reads_do_not_require_a_writer_lock(self):
        saved = self.client.put("/api/v1/dns/cloudflare", headers=self.admin,
                                json={"api_token": "fixture-secret"})
        self.assertEqual(saved.status_code, 200, saved.text)
        writer = app.db()
        try:
            writer.execute("BEGIN IMMEDIATE")
            writer.execute("insert into settings values('concurrent-job','busy')")
            self.assertEqual(load_cloudflare_secret(app.db), {"api_token": "fixture-secret"})
        finally:
            writer.rollback()
            writer.close()

    def test_logout_revokes_only_current_session_and_is_idempotent(self):
        another = self.session("another-session")
        for _ in range(2):
            self.assertEqual(self.client.post("/api/v1/auth/logout", headers=self.admin).status_code, 200)
        self.assertEqual(self.client.get("/api/v1/api-keys", headers=self.admin).status_code, 401)
        self.assertEqual(self.client.get("/api/v1/api-keys", headers=another).status_code, 200)

    def test_password_change_requires_current_password_even_with_session(self):
        wrong = self.client.post("/api/v1/auth/password", headers=self.admin,
                                 json={"current_password": "wrong", "new_password": "new-fixture-password"})
        self.assertEqual(wrong.status_code, 401)
        right = self.client.post("/api/v1/auth/password", headers=self.admin,
                                 json={"current_password": "fixture-password", "new_password": "new-fixture-password"})
        self.assertEqual(right.status_code, 200)
        self.assertFalse(app.session_ok(self.admin["X-API-Key"]))

    def test_v14_migration_preserves_only_ungranted_legacy_global_keys(self):
        with patch.object(app, "DB", self.root / "legacy.db"), patch.object(schema, "_migrate_v14"):
            app._schema_initialized = False
            c = app.db()
            c.execute("insert into projects(id,name,created_at) values(?,?,?)", (self.A, "legacy-project", time.time()))
            for name in ("global", "scoped"):
                c.execute("insert into api_keys(name,key_hash,scopes,created_at) values(?,?,?,?)", (name, name, "mail.read", time.time()))
            key_id = c.execute("select id from api_keys where name='scoped'").fetchone()[0]
            c.execute("insert into api_key_grants values(?,?,?,?)", (key_id, self.A, "mail.read", time.time()))
            c.commit()
        try:
            schema.migrate(c)
            c.commit()
            self.assertEqual({r["name"]: r["global_access"] for r in c.execute("select name,global_access from api_keys")}, {"global": 1, "scoped": 0})
            schema.migrate(c)
            c.commit()
        finally:
            c.close()
            app._schema_initialized = False


class WebhookTransportTests(unittest.TestCase):
    def test_rejects_plaintext_private_and_credential_urls(self):
        for url in ("http://receiver.example/hook", "https://127.0.0.1/", "https://[::1]/",
                    "https://[::ffff:127.0.0.1]/", "https://10.1.2.3/", "https://169.254.169.254/",
                    "https://localhost/", "https://foo.localhost/", "https://user:pass@receiver.example/",
                    "https://receiver.example/#fragment", "https://receiver.example/\nsecret"):
            with self.subTest(url=url), self.assertRaises(transport.WebhookDeliveryError):
                transport.validate_webhook_url(url)

    def test_allowlist_is_exact(self):
        with patch.dict(transport.os.environ, {"WEBHOOK_ALLOWED_HOSTS": "receiver.example"}):
            transport.validate_webhook_url("https://receiver.example/webhook")
            with self.assertRaises(transport.WebhookDeliveryError):
                transport.validate_webhook_url("https://receiver.example.evil.test/webhook")

    def test_dns_mixed_private_answers_blocked_before_connect(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ("8.8.8.8", "127.0.0.1")]
        with patch.object(transport.socket, "getaddrinfo", return_value=answers), patch.object(transport.http.client, "HTTPSConnection") as connection:
            with self.assertRaises(transport.WebhookDeliveryError):
                transport.send_webhook_request(urllib.request.Request("https://receiver.example/hook", data=b"fixture"), timeout=3)
            connection.assert_not_called()

    def test_dns_is_pinned_tls_verified_and_redirect_not_followed(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        connection = MagicMock()
        connection.getresponse.return_value.status = 302
        with patch.object(transport.socket, "getaddrinfo", return_value=answers) as resolve, \
             patch.object(transport.socket, "socket") as stream, \
             patch.object(transport.http.client, "HTTPSConnection", return_value=connection) as factory:
            with self.assertRaisesRegex(transport.WebhookDeliveryError, "webhook_http_302"):
                transport.send_webhook_request(urllib.request.Request("https://receiver.example/hook", data=b"fixture"), timeout=3)
            resolve.assert_called_once()
            self.assertEqual(factory.call_args.args[:2], ("receiver.example", 443))
            context = factory.call_args.kwargs["context"]
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            connection.request.assert_called_once()
            connection._create_connection(("receiver.example", 443), 3)
            stream.return_value.connect.assert_called_once_with(("8.8.8.8", 443))
            resolve.assert_called_once()
            connection.close.assert_called_once()

    def test_transport_errors_do_not_echo_secret_or_url(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        connection = MagicMock()
        connection.request.side_effect = OSError("fixture-secret https://receiver.example")
        with patch.object(transport.socket, "getaddrinfo", return_value=answers), \
             patch.object(transport.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(transport.WebhookDeliveryError, "^webhook_transport_failed$"):
                transport.send_webhook_request(urllib.request.Request("https://receiver.example/hook", data=b"fixture"), timeout=3)


if __name__ == "__main__":
    unittest.main()

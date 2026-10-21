import importlib.util
import json
import os
from pathlib import Path
import queue
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock
from email.message import EmailMessage
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from api.services.routing import normalize_address, compile_maps, recipient_policy, publish, applied_state, config_hash, mailbox_query

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("domain_app_under_test", ROOT / "api/app.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def domain(name="example.test", **options):
    return {"domain": name, "users": ["test"], "enabled": True, "receive_mode": "catch_all",
            "receive_subdomains": True, "max_subdomain_depth": 3, **options}


class RoutingTests(unittest.TestCase):
    def test_policy_depth_and_safe_paths(self):
        for n in range(4):
            address = "user+tag@" + "a." * n + "example.test"
            result = recipient_policy(address, [domain()])
            self.assertTrue(result["ok"])
            self.assertEqual(result["maildir"], address.split("@")[1] + "/user+tag/Maildir/")
        for address in ("x@a.b.c.d.example.test", "a..b@example.test", "../x@example.test",
                        "x@notexample.test", "a" * 65 + "@example.test", "x@a_.example.test"):
            self.assertFalse(recipient_policy(address, [domain()])["ok"])
        self.assertEqual(normalize_address("USER@EXAMPLE.TEST"), "user@example.test")
        self.assertTrue(normalize_address("x@渚嬪瓙.娴嬭瘯").isascii())

    def test_specific_child_masks_parent(self):
        rows = [domain(), domain("blocked.example.test", enabled=False)]
        for address in ("u@blocked.example.test", "u@a.blocked.example.test"):
            self.assertFalse(recipient_policy(address, rows)["ok"])
        self.assertIn("blocked", compile_maps(rows)["vdomains.pcre"])
        self.assertTrue(recipient_policy("u@other.example.test", rows)["ok"])

    def test_fixed_and_empty_modes(self):
        self.assertFalse(recipient_policy("random@example.test", [domain(receive_mode="fixed")])["ok"])
        self.assertTrue(recipient_policy("test@example.test", [domain(receive_mode="fixed")])["ok"])
        self.assertFalse(recipient_policy("test@example.test", [domain(receive_mode="fixed", users=[])])["ok"])
        self.assertNotIn("example", compile_maps([])["vdomains.pcre"])

    def test_sqlite_query_matches_python_policy_and_rejects_injection(self):
        rows = [domain(), domain("blocked.example.test", enabled=False),
                domain("fixed.example.test", receive_mode="fixed", users=["listed"])]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generation = publish(rows, root)
            c = sqlite3.connect(root / 'generations' / generation / 'recipients.sqlite')
            addresses = ["user+tag@" + "a." * n + "example.test" for n in range(6)]
            addresses += ["x@blocked.example.test", "x@a.blocked.example.test", "x@fixed.example.test",
                          "listed@fixed.example.test", "listed@a.fixed.example.test", "a..b@example.test",
                          "x@bad_.example.test", "x@-bad.example.test", "x@bad-.example.test",
                          "x@" + "a"*64 + ".example.test", "x@.example.test", "../x@example.test",
                          "x' OR 1=1 --@example.test", "x@elsewhere.test", "a"*65 + "@example.test", "U@EXAMPLE.TEST"]
            for address in addresses:
                with self.subTest(address=address):
                    result = c.execute(mailbox_query(address)).fetchone()
                    expected = recipient_policy(address, rows)
                    self.assertEqual(bool(result), expected['ok'])
                    if result:
                        self.assertEqual(result[0], expected['maildir'])
            self.assertEqual(c.execute('select count(*) from domains').fetchone()[0], 3)
            self.assertEqual(c.execute('select count(*) from users').fetchone()[0], 3)
            c.close()

    def test_immutable_generations_and_stale_ack(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = publish([domain()], root)
            content = (root / "generations" / first / "manifest.json").read_bytes()
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda i: publish([domain(enabled=bool(i % 2))], root), range(20)))
            self.assertEqual(content, (root / "generations" / first / "manifest.json").read_bytes())
            second = publish([], root)
            (root / "postfix-applied.json").write_text(json.dumps({"generation": first, "status": "applied", "applied_at": time.time()}))
            self.assertEqual(applied_state(root)["status"], "pending")
            (root / "postfix-applied.json").write_text(json.dumps({"generation": second, "status": "applied", "applied_at": time.time()}))
            self.assertEqual(applied_state(root)["status"], "applied")

    def test_unrelated_claims_preserve_acknowledged_domain_routing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            existing = domain()
            first = publish([existing], root)
            (root / "postfix-applied.json").write_text(json.dumps({
                "generation": first, "status": "applied", "applied_at": time.time()}))
            rows = [existing]
            for i in range(3):
                claimed = domain(f"claimed-{i}.test", enabled=False)
                rows.append(claimed)
                desired = publish(rows, root)
                self.assertEqual(applied_state(root)["status"], "pending")
                state = applied_state(root, row=existing)
                self.assertEqual(state["status"], "applied")
                self.assertEqual(state["generation"], first, "Keep the actual Postfix ACK generation")
                self.assertEqual(state["desired_generation"], desired)
                self.assertEqual(applied_state(root, row=claimed)["status"], "pending")

    def test_pending_routing_checks_own_and_descendant_policy(self):
        existing, child = domain(), domain("child.example.test", enabled=False)
        cases = [
            ("own policy changed", [domain(receive_mode="fixed"), child], False),
            ("own policy removed", [child], False),
            ("descendant added", [existing, child, domain("new.example.test", enabled=False)], False),
            ("descendant removed", [existing], False),
            ("descendant changed", [existing, domain("child.example.test", enabled=True)], False),
            ("unrelated domain added", [existing, child, domain("other.test")], True),
            ("unrelated suffix added", [existing, child, domain("test.example")], True),
        ]
        for label, desired, ready in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                first = publish([existing, child], root)
                (root / "postfix-applied.json").write_text(json.dumps({
                    "generation": first, "status": "applied", "applied_at": time.time()}))
                publish(desired, root)
                row = next((r for r in desired if r["domain"] == existing["domain"]), existing)
                self.assertEqual(applied_state(root, row=row)["status"], "applied" if ready else "pending")
                self.assertEqual(applied_state(root)["status"], "pending")

    def test_domain_routing_requires_fresh_successful_ack_and_intact_manifests(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            existing = domain()
            first = publish([existing], root)
            desired = publish([existing, domain("claimed.test", enabled=False)], root)
            ack_path = root / "postfix-applied.json"
            for change in ({"status": "failed"}, {"status": "starting"},
                           {"applied_at": time.time() - 30}, {"applied_at": time.time() + 30},
                           {"generation": "../invalid"}, {"generation": "0" * 64}):
                with self.subTest(change=change):
                    ack_path.write_text(json.dumps({
                        "generation": first, "status": "applied", "applied_at": time.time(), **change}))
                    self.assertEqual(applied_state(root, row=existing)["status"], "pending")
            ack_path.write_text(json.dumps({
                "generation": first, "status": "applied", "applied_at": time.time()}))
            for generation in (first, desired):
                manifest_path = root / "generations" / generation / "manifest.json"
                original = manifest_path.read_text()
                for content in ("{broken", "{}", original.replace('"enabled": true', '"enabled": false')):
                    with self.subTest(generation=generation, content=content[:12]):
                        manifest_path.write_text(content)
                        self.assertEqual(applied_state(root, row=existing)["status"], "pending")
                manifest_path.write_text(original)
                manifest_path.unlink()
                self.assertEqual(applied_state(root, row=existing)["status"], "pending")
                manifest_path.write_text(original)
            self.assertEqual(applied_state(root, row=existing)["status"], "applied")


class DomainAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [patch.object(app, "DB", self.root / "mail.db"),
                        patch.object(app, "RUNTIME_DIR", self.root / "runtime"),
                        patch.object(app, "_schema_initialized", False),
                        patch.object(app, "key_ok", side_effect=lambda key: key == "test-key"),
                        patch.object(app, "admin_ok", side_effect=lambda key: key == "test-key"),
                        patch.dict(os.environ, {"MAIL_DOMAIN": "example.test", "MAILBOX_USERS": "test"})]
        for p in self.patches: p.start()
        app._seed_domains()
        c = app.db()
        digest = app.hashlib.sha256(("test-key" + os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
        c.execute("insert into api_keys(name,key_hash,scopes,created_at,global_access) values(?,?,?,0,1)",
                  ("routing fixture", digest, "mail.read"))
        c.commit(); c.close()
        self.client = TestClient(app.app)
        self.headers = {"x-api-key": "test-key"}

    def tearDown(self):
        self.client.close()
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def request(self, method, path, **kwargs):
        return self.client.request(method, "/api/v1" + path, headers=self.headers, **kwargs)

    def test_migration_defaults_fixed_and_delete_no_reseed(self):
        self.assertEqual(app._domain_rows()[0]["receive_mode"], "fixed")
        self.assertEqual(self.request("DELETE", "/mail-domains/example.test").status_code, 200)
        app._seed_domains()
        self.assertEqual(app._domain_rows(), [])
        self.assertEqual(app.configured_domains(), [])

    def test_legacy_migration_and_sqlite_backup_restore_preserve_history(self):
        legacy = self.root / 'legacy.db'
        c = sqlite3.connect(legacy)
        c.executescript("""
          CREATE TABLE mail_domains(domain TEXT PRIMARY KEY,enabled INTEGER,users TEXT,dkim_selector TEXT,spf TEXT,dmarc TEXT,mx TEXT,cf_zone_id TEXT,cf_status TEXT,created_at REAL,updated_at REAL);
          INSERT INTO mail_domains VALUES('example.test',1,'["listed"]','oldselector','v=spf1 -all','v=DMARC1; p=none','mail.example.test','zone-old','listed',1,1);
          CREATE TABLE messages(id INTEGER PRIMARY KEY,received_at REAL NOT NULL,envelope_recipient TEXT,to_header TEXT,delivered_to TEXT,original_to TEXT,message_id TEXT,subject TEXT,sender TEXT,raw_path TEXT NOT NULL,source_path TEXT);
          INSERT INTO messages(id,received_at,envelope_recipient,subject,raw_path,source_path) VALUES(77,1,'listed@a.example.test','historic','/raw/history.eml','/maildata/a.example.test/listed/Maildir/new/stable');
          CREATE TABLE api_keys(id INTEGER PRIMARY KEY,name TEXT,key_hash TEXT UNIQUE,created_at REAL);
          INSERT INTO api_keys VALUES(8,'old','old-digest',1);
        """)
        c.commit()
        baseline = self.root / 'legacy-backup.db'
        backup = sqlite3.connect(baseline)
        c.backup(backup)
        backup.close(); c.close()
        with patch.object(app, 'DB', legacy), patch.object(app, '_schema_initialized', False):
            c = app.db()
            self.assertEqual(c.execute('select subject from messages where id=77').fetchone()[0], 'historic')
            row = c.execute('select * from mail_domains').fetchone()
            self.assertEqual(row['receive_mode'], 'fixed')
            self.assertEqual(row['dkim_selector'], 'oldselector')
            self.assertEqual(c.execute('select key_hash from api_keys where id=8').fetchone()[0], 'old-digest')
            delivery = c.execute('select * from message_deliveries where message_id=77').fetchone()
            self.assertEqual(delivery['managed_domain'], 'example.test')
            self.assertEqual(delivery['envelope_recipient'], 'listed@a.example.test')
            c.close()
        restored = sqlite3.connect(baseline)
        self.assertEqual(restored.execute('select subject from messages where id=77').fetchone()[0], 'historic')
        self.assertNotIn('receive_mode', {row[1] for row in restored.execute('pragma table_info(mail_domains)')})
        restored.close()

    def test_concurrent_partial_patches_preserve_unrelated_fields(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda fields: app.patch_mail_domain('example.test', app.MailDomainPatch(**fields), 'test-key'),
                                    [{'receive_enabled': False}, {'send_enabled': False}]))
        row = app._domain_rows()[0]
        self.assertFalse(row['receive_enabled'])
        self.assertFalse(row['send_enabled'])
        self.assertEqual(row['users'], '["test"]')

    def test_disabled_never_falls_back(self):
        self.request("PATCH", "/mail-domains/example.test", json={"enabled": False})
        self.assertEqual(app.configured_domains(), [])
        self.assertEqual(self.request("GET", "/domains/available").json()["total"], 0)

    def test_ready_only_hides_claimed_domains_until_readiness_passes(self):
        app._save_domain({
            "domain": "claimed.test", "users": [], "enabled": True,
            "receive_mode": "catch_all", "receive_subdomains": True,
            "max_subdomain_depth": 3, "source_type": "sfreg_mx",
            "source_status": "claimed", "claim_id": "claim-fixture",
            "dns_provider": "digitalplat", "dns_credential_ref": "dns-fixture",
        })
        all_domains = self.request("GET", "/mail-domains").json()
        ready_domains = self.request("GET", "/mail-domains?ready_only=true").json()
        self.assertIn("claimed.test", {row["domain"] for row in all_domains})
        self.assertNotIn("claimed.test", {row["domain"] for row in ready_domains})
        self.assertIn("example.test", {row["domain"] for row in ready_domains})

    def test_available_requires_current_generation_and_dns(self):
        self.assertEqual(self.request("GET", "/domains/available").json()["total"], 0)
        generation = (app.RUNTIME_DIR / "routing.current").read_text().strip()
        (app.RUNTIME_DIR / "postfix-applied.json").write_text(json.dumps({"generation": generation, "status": "applied", "applied_at": time.time()}))
        self.assertEqual(self.request("GET", "/domains/available").json()["total"], 0)
        c = app.db()
        c.execute("insert into domain_checks(domain,check_name,status,config_hash,checked_at) values(?,?,?,?,?)",
                  ("example.test", "mx", "passed", config_hash(app._domain_rows()[0]), time.time()))
        c.commit(); c.close()
        self.assertEqual(self.request("GET", "/domains/available").json()["total"], 1)
        self.request("PATCH", "/mail-domains/example.test", json={"receive_subdomains": True})
        self.assertEqual(self.request("GET", "/domains/available").json()["total"], 0)

    def test_create_defaults_catch_all_and_validation(self):
        response = self.request("POST", "/mail-domains", json={"domain": "new.test", "users": []})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["receive_mode"], "catch_all")
        self.assertEqual(response.json()["users"], [])
        self.assertEqual(self.request("POST", "/mail-domains", json={"domain": "new.test"}).status_code, 409)
        self.assertEqual(self.request("POST", "/mail-domains", json={"domain": "../../evil"}).status_code, 400)
        self.assertEqual(self.request("PATCH", "/mail-domains/new.test", json={"max_subdomain_depth": 8}).status_code, 422)

    def test_non_cloudflare_provider_never_uses_cloudflare_credentials(self):
        self.request('PATCH', '/mail-domains/example.test', json={'dns_provider':'manual'})
        with patch.object(app, '_cf_request') as upstream:
            self.assertEqual(self.request('POST', '/mail-domains/example.test/dns/provision').status_code, 409)
            response = self.request('GET', '/mail-domains/example.test/dns')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['provider'], 'manual')
            self.assertEqual(response.json()['records'], [])
            upstream.assert_not_called()

    def test_digitalplat_inventory_is_provider_aware(self):
        self.request('PATCH', '/mail-domains/example.test', json={'dns_provider': 'digitalplat'})
        c = app.db()
        c.execute("update mail_domains set dns_credential_ref=? where domain=?",
                  ('cred-digitalplat', 'example.test'))
        c.commit(); c.close()
        inventory = {
            'zone_id': 'example.test',
            'complete': True,
            'records': [
                {'id': 'mx-1', 'type': 'MX', 'name': '@', 'value': '10 mail.example.test', 'ttl': 300},
                {'rrset_id': 'txt-1', 'type': 'TXT', 'name': '@', 'values': ['v=spf1 -all'], 'ttl': 300},
            ],
        }
        adapter = MagicMock()
        adapter.inventory.return_value = inventory
        with patch.object(app.domain_manager, 'dns_adapter', return_value=adapter):
            response = self.request('GET', '/mail-domains/example.test/dns')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['provider'], 'digitalplat')
        self.assertEqual(response.json()['records'][0]['name'], 'example.test')
        self.assertEqual(response.json()['records'][1]['content'], 'v=spf1 -all')

    def test_empty_dns_inventory_is_listed_not_ready(self):
        with patch.object(app, '_cloudflare_headers', return_value=({},None)), patch.object(app, '_cf_request', side_effect=[
            (200, {'success':True,'result':[{'id':'fixture-zone'}]}),
            (200, {'success':True,'result':[]})]):
            response = self.request('GET', '/mail-domains/example.test/dns')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['records'], [])
        row = self.request('GET', '/mail-domains').json()[0]
        self.assertEqual(row['cf_status'], 'listed')
        self.assertFalse(row['receive_ready'])
        self.assertFalse(row['send_ready'])

    def add_message(self, raw, recipient="u@example.test", age=0):
        c = app.db()
        file = self.root / "shared.eml"
        file.write_bytes(raw)
        cur = c.execute("insert into messages(received_at,envelope_recipient,raw_path) values(?,?,?)", (time.time()-age, recipient, str(file)))
        identifier = cur.lastrowid
        c.commit(); c.close()
        return identifier, file

    def test_raw_and_attachment_download_are_byte_exact_and_authenticated(self):
        msg = EmailMessage()
        msg.set_content("姝ｆ枃")
        blob = b"\x00\xff\r\nbytes"
        msg.add_attachment(blob, maintype="application", subtype="octet-stream", filename="鏂囦欢.bin")
        raw = msg.as_bytes()
        identifier, _ = self.add_message(raw)
        self.assertEqual(self.request("GET", f"/messages/{identifier}/raw?download=true").content, raw)
        self.assertIn("raw", self.request("GET", f"/messages/{identifier}/raw").json())
        info = self.request("GET", f"/messages/{identifier}/attachments").json()[0]
        path = f"/messages/{identifier}/attachments/{info['part_id']}"
        response = self.request("GET", path)
        self.assertEqual(response.content, blob)
        self.assertIn("filename*=UTF-8", response.headers["content-disposition"])
        self.assertEqual(self.client.get("/api/v1" + path).status_code, 401)
        self.assertEqual(self.request("GET", f"/messages/{identifier}/attachments/999").status_code, 404)

    def test_shared_raw_retention_keeps_live_reference_then_removes_last(self):
        first, file = self.add_message(b"Subject: test\n\nBody", age=4*86400)
        second, _ = self.add_message(file.read_bytes())
        with patch.object(app, "_email_storage_bytes", return_value=0):
            app.cleanup_expired_messages(days=3)
        self.assertTrue(file.exists())
        c = app.db(); c.execute("update messages set received_at=0"); c.commit(); c.close()
        with patch.object(app, "_email_storage_bytes", return_value=0):
            app.cleanup_expired_messages(days=3)
        self.assertFalse(file.exists())

    def test_identical_raw_multi_recipient_and_new_to_cur(self):
        mail_root = self.root / "maildata"
        raw = b"From: sender@outside.test\nTo: display@outside.test\nSubject: one\n\nBody"
        sources=[]
        for local in ("one", "two"):
            source = mail_root / "example.test" / local / "Maildir" / "new" / "stable-id"
            source.parent.mkdir(parents=True)
            source.write_bytes(raw)
            sources.append(source)
        real_path = Path
        def mapped(value):
            return mail_root if value == "/maildata" else self.root / "raw" if value == "/app-data/raw" else real_path(value)
        with patch.object(app, "Path", side_effect=mapped), patch.object(app.shutil, "disk_usage", return_value=MagicMock(free=3*1024**3)), patch.object(app, "webhook_queue", queue.SimpleQueue()):
            self.assertEqual(app.ingest_once(), 2)
            self.assertEqual(app.ingest_once(), 0)
            moved = sources[0].parent.parent / "cur" / ("stable-id" if os.name == "nt" else "stable-id:2,S")
            moved.parent.mkdir()
            sources[0].rename(moved)
            app._last_cur_scan = 0
            self.assertEqual(app.ingest_once(), 0)
        c = app.db()
        self.assertEqual(c.execute("select count(*) from message_deliveries").fetchone()[0], 2)
        self.assertEqual(c.execute("select count(distinct raw_path) from messages").fetchone()[0], 1)
        c.close()
        result = self.request("GET", "/messages?meta=true&recipient=one@example.test").json()
        self.assertEqual(result["total"], 1)
        self.assertEqual(self.request("GET", "/messages?meta=true&recipient_domain=example.test").json()["total"], 2)
        self.assertEqual(self.request("GET", "/messages?meta=true&recipient=none@example.test").json()["total"], 0)


if __name__ == "__main__":
    unittest.main()

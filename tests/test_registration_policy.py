"""Registration policy is separate from delivery/DNS policy."""
import json
import shutil
import time
import uuid
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from test_domain_routing import app
from api.migrations.schema import migrate
from api.services.routing import config_hash, recipient_policy


class RegistrationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(".test-run-temp") / f"registration-policy-{uuid.uuid4().hex}"
        self.root.mkdir(parents=True, exist_ok=True)
        self.patches = [
            patch.multiple(app, DB=self.root / "mail.db", RUNTIME_DIR=self.root / "runtime",
                           _schema_initialized=False),
            patch.object(app, "key_ok", side_effect=lambda key: key == "fixture"),
            patch.object(app, "admin_ok", side_effect=lambda key: key == "fixture"),
        ]
        for p in self.patches:
            p.start()
        self.client = TestClient(app.app)
        self.headers = {"X-API-Key": "fixture"}

    def tearDown(self):
        self.client.close()
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.root, ignore_errors=True)

    def domain(self, **options):
        row = app._save_domain({
            "domain": "example.test", "receive_mode": "catch_all",
            "receive_subdomains": True, "max_subdomain_depth": 3,
            **options,
        })
        (app.RUNTIME_DIR / "postfix-applied.json").write_text(json.dumps({
            "generation": row["generation"], "status": "applied", "applied_at": time.time(),
        }))
        c = app.db()
        for name in ("mx", "wildcard_mx"):
            c.execute("INSERT OR REPLACE INTO domain_checks VALUES(?,?,?,?,?,?)",
                      (row["domain"], name, "passed", row["config_hash"], time.time(), "fixture"))
        c.commit()
        c.close()
        return row

    def available(self, capability):
        response = self.client.get("/api/v1/domains/available",
                                   params={"capability": capability}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        return response.json()["items"]

    def test_disabled_registration_preserves_receive_and_dns_readiness(self):
        before = self.domain()
        self.assertEqual(len(self.available("registration")), 1)
        response = self.client.patch("/api/v1/mail-domains/example.test",
                                     json={"registration_enabled": False}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        row = response.json()
        self.assertFalse(row["registration_enabled"])
        self.assertFalse(row["registration_ready"])
        self.assertTrue(row["receive_ready"])
        self.assertEqual(before["config_hash"], row["config_hash"])
        self.assertEqual(before["generation"], row["generation"])
        self.assertEqual(self.available("registration"), [])
        self.assertEqual(len(self.available("receive")), 1)
        self.assertTrue(recipient_policy("otp@one.two.example.test", app._domain_rows())["ok"])

    def test_random_policy_requires_wildcard_readiness(self):
        self.domain(registration_random_subdomain_depth=True)
        row = self.available("registration")[0]
        self.assertTrue(row["registration_random_subdomain_depth"])
        self.assertEqual(row["max_subdomain_depth"], 3)
        c = app.db()
        c.execute("UPDATE domain_checks SET status='failed' WHERE check_name='wildcard_mx'")
        c.commit()
        c.close()
        self.assertEqual(self.available("registration"), [])
        self.assertEqual(len(self.available("receive")), 1)
        response = self.client.patch("/api/v1/mail-domains/example.test",
                                     json={"registration_random_subdomain_depth": False}, headers=self.headers)
        self.assertTrue(response.json()["registration_ready"])

    def test_disabling_subdomains_or_zero_depth_clears_random_policy(self):
        for change in ({"receive_subdomains": False}, {"max_subdomain_depth": 0}):
            with self.subTest(change=change):
                self.domain(registration_random_subdomain_depth=True)
                response = self.client.patch("/api/v1/mail-domains/example.test",
                                             json=change, headers=self.headers)
                self.assertEqual(response.status_code, 200)
                self.assertFalse(response.json()["registration_random_subdomain_depth"])
                self.assertFalse(response.json()["subdomain_receive_ready"])

    def test_fixed_or_disabled_receive_never_participates(self):
        for options in ({"receive_mode": "fixed", "users": ["listed"]},
                        {"enabled": False}, {"receive_enabled": False},
                        {"source_status": "released"}):
            with self.subTest(options=options):
                self.domain(**options)
                self.assertEqual(self.available("registration"), [])

    def test_new_input_defaults_and_invalid_depth(self):
        response = self.client.post("/api/v1/mail-domains", json={
            "domain": "new.test",
        }, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["receive_mode"], "catch_all")
        self.assertTrue(response.json()["receive_subdomains"])
        self.assertEqual(response.json()["max_subdomain_depth"], 6)
        self.assertTrue(response.json()["registration_enabled"])
        self.assertTrue(response.json()["registration_random_subdomain_depth"])
        response = self.client.patch("/api/v1/mail-domains/new.test",
                                     json={"max_subdomain_depth": 8}, headers=self.headers)
        self.assertEqual(response.status_code, 422)

    def test_v12_upgrade_is_additive_and_idempotent(self):
        self.domain(registration_enabled=False, registration_random_subdomain_depth=True)
        c = app.db()
        # Simulate an existing v11 database and preserve its domain/delivery settings.
        c.execute("ALTER TABLE mail_domains DROP COLUMN registration_enabled")
        c.execute("ALTER TABLE mail_domains DROP COLUMN registration_random_subdomain_depth")
        c.execute("DELETE FROM schema_migrations WHERE version=12")
        c.commit()
        before = dict(c.execute("SELECT * FROM mail_domains").fetchone())
        migrate(c)
        c.commit()
        row = dict(c.execute("SELECT * FROM mail_domains").fetchone())
        self.assertEqual({k: row[k] for k in before}, before)
        self.assertEqual(row["registration_enabled"], 1)
        self.assertEqual(row["registration_random_subdomain_depth"], 0)
        c.execute("UPDATE mail_domains SET registration_enabled=0")
        c.commit()
        migrate(c)
        c.commit()
        self.assertEqual(c.execute("SELECT registration_enabled FROM mail_domains").fetchone()[0], 0)
        self.assertEqual(c.execute("SELECT count(*) FROM schema_migrations WHERE version=12").fetchone()[0], 1)
        c.close()


if __name__ == "__main__":
    unittest.main()

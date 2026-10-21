"""Registered-pool API -> durable allocation -> disabled domain, without live claims."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import test_domain_control as control_tests
from api.providers.http import JsonTransport, ProviderError
from api.repositories.domain_jobs import JobConflict


TOKEN = control_tests.TOKEN


class RegisteredPoolTests(unittest.TestCase):
    setUp = control_tests.P2Tests.setUp
    tearDown = control_tests.P2Tests.tearDown
    source = control_tests.P2Tests.source

    def test_preview_uses_registered_pool_without_allocating_or_leaking(self):
        source = self.source()
        self.http.payload = {"ok": True, "items": [
            {"id": 5330, "domain": "registered.test", "status": "registered", "api_token": TOKEN},
            {"id": 5331, "domain": "failed.test", "status": "sync_failed", "account_password": TOKEN},
        ]}
        response = self.client.get(f"/api/v1/domain-sources/{source['id']}/candidates",
            headers=self.headers, params={"count": 200, "status": "registered", "sync_provider": "none"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["allocation"], "none")
        self.assertEqual(response.json()["items"][0]["external_id"], "5330")
        self.assertEqual(response.json()["items"][0]["status"], "registered")
        self.assertEqual(response.json()["items"][1]["status"], "sync_failed")
        self.assertNotIn(TOKEN, response.text)
        method, _, path, kwargs = self.http.calls[0]
        self.assertEqual((method, path), ("GET", "/api/domains/available"))
        self.assertEqual(kwargs["query"], {"count": 200, "status": "registered", "sync_provider": "none"})
        self.assertEqual(self.manager.claims(), [])
        self.assertEqual(self.manager.jobs.list()["total"], 0)

    def test_old_mx_preview_and_explicit_mx_choice_keep_original_contract(self):
        source = self.source()
        self.manager.candidates(source["id"], 10)
        self.manager.candidates(source["id"], 10, status="synced", sync_provider="digitalplat_dns")
        for call in self.http.calls:
            self.assertEqual(call[2], "/api/digitalplat-dns/domains/available")
            self.assertEqual(call[3]["query"], {"count": 10})
        with self.assertRaises(ValueError):
            self.manager.candidates(source["id"], 10, status="registered", sync_provider="digitalplat_dns")

    def test_registered_allocation_imports_dns_credentials_and_is_locally_idempotent(self):
        source = self.source()
        self.http.payload = {"items": [{"domain": "registered.test", "id": 5330,
            "claim_id": "upstream-registered-1", "status": "reserved", "provider": "none",
            "dns": {"provider": "digitalplat", "api_base": "https://dns.fixture.test/api/v1",
                    "account_id": "acct-1", "account_name": "Fixture account",
                    "account_email": "dns@example.test", "api_token": TOKEN}}]}
        kwargs = {"count": 1, "status": "registered", "sync_provider": "none"}
        job = self.manager.create_claim_job(source["id"], "registered-allocation-001", **kwargs)
        self.assertEqual(self.http.calls, [], "Enqueue must not allocate")
        with patch.dict("os.environ", {"MAIL_HOST": ""}):
            self.assertTrue(self.manager.run_once())
        result = self.manager.jobs.get(job["id"])
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["result"]["items"][0]["status"], "imported")
        domain = self.manager.domain("registered.test")
        self.assertFalse(domain["enabled"])
        self.assertEqual(domain["dns_provider"], "digitalplat")
        self.assertIsNotNone(domain["dns_credential_ref"])
        c = self.manager.db()
        try:
            secret = self.manager.credentials().get(c, domain["dns_credential_ref"],
                                                    provider="digitalplat", domain="registered.test")
        finally:
            c.close()
        self.assertEqual(secret, {"api_token": TOKEN, "api_base": "https://dns.fixture.test/api/v1"})
        self.assertEqual(self.manager.claims()[0]["upstream_claim_id"], "upstream-registered-1")
        self.assertEqual(self.manager.claims()[0]["external_id"], "5330")
        call = self.http.calls[0]
        self.assertEqual((call[0], call[2]), ("GET", "/api/domains/claim"))
        self.assertEqual(call[3]["query"], {"count": 1, "status": "registered", "sync_provider": "none"})
        self.assertEqual(call[3]["headers"]["Idempotency-Key"], job["upstream_idempotency_key"])
        self.assertEqual(self.manager.create_claim_job(source["id"], "registered-allocation-001", **kwargs)["id"], job["id"])
        hosting = result["result"]["items"][0]["dns_hosting_job"]
        self.assertEqual(hosting["kind"], "dns_hosting")
        self.assertTrue(self.manager.run_once(), "Registered claims automatically prepare DNS hosting")
        self.assertEqual(self.manager.jobs.get(hosting["id"])["status"], "succeeded")
        self.assertFalse(self.manager.run_once())
        self.assertEqual(len(self.http.calls), 2)
        self.assertEqual(sum(call[2] == "/api/domains/claim" for call in self.http.calls), 1)
        with self.assertRaises(JobConflict):
            self.manager.create_claim_job(source["id"], "registered-allocation-001",
                status="all", sync_provider="all")
        claim = self.manager.claims()[0]
        with self.assertRaises(ValueError):
            self.manager.create_claim_refresh_job(claim["id"], "wrong-mx-refresh")

    def test_registered_claim_skips_nameserver_provision_and_keeps_tokens_private(self):
        source = self.source()
        self.http.payload = {"items": [{"domain": "registered.test", "id": 5330,
            "claim_id": "upstream-provision-1", "status": "reserved", "provider": "none",
            "dns": {"api_base": "https://dns.fixture.test/api/v1", "api_token": TOKEN}}]}
        claim_job = self.manager.create_claim_job(source["id"], "registered-provision-001",
                                                   status="registered", sync_provider="none")
        self.assertTrue(self.manager.run_once())
        key = self.root / "keys/registered.test/default.txt"
        key.parent.mkdir(parents=True, exist_ok=True)
        key.write_text('default._domainkey IN TXT ("v=DKIM1; k=rsa; " "p=QUJD")')

        claim = self.manager.claims()[0]
        self.assertFalse(claim["nameserver_required"])
        response = self.manager.create_claim_provision_job(claim["id"], "registered-provision-job-001")
        self.assertEqual(response["status"], "not_required")
        self.assertIn("无需同步 Nameserver", response["message"])
        self.assertEqual(len(self.http.calls), 1)
        legacy_job = self.manager.jobs.enqueue("claim_provision", claim["id"],
                                                "legacy-provision-job-001", {})
        self.assertTrue(self.manager.run_once())  # Queued Hosted DNS check, without NS sync.
        self.assertTrue(self.manager.run_once())
        result = self.manager.jobs.get(legacy_job["id"])
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["step"], "nameserver_sync_not_required")
        self.assertEqual(result["result"]["nameservers"], [])
        self.assertEqual(len(self.http.calls), 2)
        self.assertFalse(any(call[0] != "GET" for call in self.http.calls))
        stored = self.manager.claims()[0]
        self.assertEqual(stored["nameservers"], [])
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn(TOKEN, json.dumps(stored))
        self.assertEqual(self.manager.jobs.get(claim_job["id"])["status"], "succeeded")

    def test_any_registered_claim_uses_direct_dns_without_nameserver_provision(self):
        source = self.source()
        self.http.payload = {"items": [{"domain": "afp258.example.test", "id": 5334,
            "claim_id": "upstream-direct-dns-1", "status": "reserved", "provider": "none",
            "dns": {"api_base": "https://dns.fixture.test/api/v1", "api_token": TOKEN}}]}
        claim_job = self.manager.create_claim_job(source["id"], "direct-dns-001",
                                                   status="registered", sync_provider="none")
        self.assertTrue(self.manager.run_once())
        claim = self.manager.claims()[0]
        self.assertEqual(claim["domain"], "afp258.example.test")
        self.assertEqual(claim["dns_mode"], "direct_dns")
        self.assertFalse(claim["nameserver_required"])
        self.assertEqual(self.manager.create_claim_provision_job(claim["id"], "direct-dns-no-ns-001")["status"], "not_required")
        self.assertEqual(self.manager.jobs.get(claim_job["id"])["status"], "succeeded")

    def test_registered_allocation_without_dns_waits_for_binding(self):
        source = self.source()
        self.http.payload = {"items": [{"domain": "registered.test", "id": 5330,
            "claim_id": "upstream-registered-1", "status": "reserved", "provider": "none"}]}
        job = self.manager.create_claim_job(source["id"], "registered-no-dns-001",
                                            status="registered", sync_provider="none")
        self.assertTrue(self.manager.run_once())
        self.assertEqual(self.manager.jobs.get(job["id"])["result"]["items"][0]["status"], "awaiting_dns")
        self.assertEqual(self.manager.domain("registered.test")["dns_provider"], "manual")

    def test_registered_reclaim_after_upstream_rollback_preserves_local_domain(self):
        source = self.source()
        self.http.payload = {"items": [{"domain": "registered.test", "id": 5330,
            "claim_id": "upstream-registered-1", "status": "reserved", "provider": "none"}]}
        first = self.manager.create_claim_job(source["id"], "registered-rollback-old",
                                              status="registered", sync_provider="none")
        self.assertTrue(self.manager.run_once())
        original_claim = self.manager.claims()[0]
        row = self.manager.domain("registered.test")
        row["users"] = json.loads(row["users"])
        row["mx"] = "custom.mail.example"
        self.manager.save_domain(row, "registered.test")

        self.http.payload = {"items": [{"domain": "registered.test", "id": 5330,
            "claim_id": "upstream-registered-2", "status": "reserved", "provider": "none",
            "dns": {"api_base": "https://dns.fixture.test/api/v1", "api_token": TOKEN}}]}
        second = self.manager.create_claim_job(source["id"], "registered-rollback-new",
                                               status="registered", sync_provider="none")
        self.assertTrue(self.manager.run_once())
        self.assertEqual(self.manager.jobs.get(first["id"])["status"], "succeeded")
        self.assertEqual(self.manager.jobs.get(second["id"])["status"], "succeeded")
        claim = self.manager.claims()[0]
        self.assertEqual(claim["id"], original_claim["id"])
        self.assertEqual(claim["upstream_claim_id"], "upstream-registered-2")
        domain = self.manager.domain("registered.test")
        self.assertEqual(domain["mx"], "custom.mail.example")
        self.assertEqual(domain["dns_provider"], "digitalplat")
        self.assertIsNotNone(domain["dns_credential_ref"])

    def test_selected_ids_and_filters_reach_upstream_and_recovery_never_reclaims(self):
        source = self.source()
        self.http.payload = {"items": [{"domain": "registered.test", "id": 5330,
            "claim_id": "upstream-selected-1", "status": "used",
            "dns": {"api_token": TOKEN, "api_base": "https://dns.fixture.test/api/v1"}}]}
        response = self.client.post(f"/api/v1/domain-sources/{source['id']}/claim",
            headers={**self.headers, "Idempotency-Key": "registered-selected-001"},
            json={"count": 1, "external_ids": ["5330"], "status": "registered", "sync_provider": "none"})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(self.http.calls, [])
        self.manager.run_once()
        call = self.http.calls[0]
        self.assertEqual((call[0], call[2]), ("GET", "/api/domains/claim-by-ids"))
        self.assertEqual(call[3]["query"], {"ids": "5330", "status": "registered", "sync_provider": "none"})
        claim = self.manager.claims()[0]
        self.assertEqual(claim["upstream_status"], "used")
        self.assertIsNotNone(claim["dns_credential_ref"], "SFREG claim DNS tokens must become encrypted DigitalPlat credentials")
        self.assertEqual(self.manager.domain("registered.test")["dns_provider"], "digitalplat")
        self.assertNotIn(TOKEN, json.dumps(self.manager.jobs.get(response.json()["id"])))
        self.manager.run_once()  # Complete the automatic hosting check before explicit recovery.
        recovery = self.manager.create_recover_job(claim["id"], "recover-registered")
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(recovery["id"])["status"], "succeeded")
        self.assertEqual(len(self.http.calls), 2)

    def test_recovery_preserves_explicit_cloudflare_binding(self):
        source = self.source()
        self.http.payload = {"items": [{"domain": "registered.test", "id": 5, "status": "used"}]}
        self.manager.create_claim_job(source["id"], "registered-bind-001", status="registered", sync_provider="none")
        self.manager.run_once()
        claim = self.manager.claims()[0]
        credential = self.manager.add_dns_credential("cloudflare", None, "fixture DNS", {"api_token": TOKEN})
        self.manager.bind_dns_credential("registered.test", credential["id"])
        self.manager.create_recover_job(claim["id"], "registered-bind-recover")
        self.manager.run_once()
        domain = self.manager.domain("registered.test")
        self.assertEqual(domain["dns_provider"], "cloudflare")
        self.assertEqual(domain["dns_credential_ref"], credential["id"])
        self.assertFalse(domain["enabled"])
        self.assertEqual(len(self.http.calls), 1)

    def test_filters_and_selected_id_validation_fail_before_dispatch(self):
        source = self.source()
        for body in [
            {"status": "used"}, {"sync_provider": "other"},
            {"status": "registered", "sync_provider": "digitalplat_dns"},
            {"count": 2, "status": "registered", "sync_provider": "none", "external_ids": ["1"]},
            {"count": 2, "status": "registered", "sync_provider": "none", "external_ids": ["1", "1"]},
            {"status": "registered", "sync_provider": "none", "external_ids": ["1,2"]},
            {"status": "registered", "sync_provider": "none", "external_ids": ["0"]},
            {"external_ids": ["1"]},
        ]:
            response = self.client.post(f"/api/v1/domain-sources/{source['id']}/claim",
                headers={**self.headers, "Idempotency-Key": "invalid-registered"}, json=body)
            self.assertIn(response.status_code, (400, 422), body)
        legacy = self.source("legacy_digitalplat_pool")
        response = self.client.get(f"/api/v1/domain-sources/{legacy['id']}/candidates",
            headers=self.headers, params={"status": "registered", "sync_provider": "none"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.manager.jobs.list()["total"], 0)

    def test_ambiguous_get_allocation_blocks_reclaim_even_from_another_pool(self):
        source = self.source()
        self.http.failure = ProviderError("provider_transport_or_json_error", uncertain=True)
        job = self.manager.create_claim_job(source["id"], "registered-timeout", status="registered", sync_provider="none")
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(job["id"])["status"], "unknown")
        self.assertFalse(self.manager.run_once())
        with self.assertRaises(JobConflict):
            self.manager.create_claim_job(source["id"], "registered-retry-new", status="all", sync_provider="all")
        with self.assertRaises(JobConflict):
            self.manager.create_claim_job(source["id"], "mx-retry-new")
        self.assertEqual(len(self.http.calls), 1)

    def test_real_http_preview_selected_claim_and_local_import(self):
        observed, allocations = [], []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                path = urlsplit(self.path)
                query = parse_qs(path.query)
                observed.append((path.path, query))
                if path.path == "/api/domains/available":
                    rows = [{"id": 5330, "domain": "registered.test", "status": "registered", "api_token": TOKEN}]
                elif path.path == "/api/domains/claim-by-ids":
                    allocations.append(query["ids"])
                    rows = [{"id": 5330, "domain": "registered.test", "status": "reserved", "claim_id": "generic-claim"}]
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True, "items": rows}).encode())
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.dict("os.environ", {"ALLOW_LOCAL_PROVIDER_HTTP": "1"}):
                source = self.manager.create_source("registered", "sfreg_mx",
                    f"http://127.0.0.1:{server.server_port}", "fixture-client", {"api_key": TOKEN})
                self.manager.http = JsonTransport(timeout=2)
                path = f"/api/v1/domain-sources/{source['id']}"
                preview = self.client.get(path + "/candidates?status=registered&sync_provider=none", headers=self.headers)
                self.assertEqual(preview.status_code, 200)
                self.assertEqual(preview.json()["items"][0]["status"], "registered")
                self.assertNotIn(TOKEN, preview.text)
                self.assertEqual(allocations, [])
                body = {"count": 1, "external_ids": ["5330"], "status": "registered", "sync_provider": "none"}
                headers = {**self.headers, "Idempotency-Key": "real-http-selected"}
                job = self.client.post(path + "/claim", headers=headers, json=body).json()
                self.assertEqual(allocations, [])
                self.manager.run_once()
                self.assertEqual(self.manager.jobs.get(job["id"])["status"], "succeeded")
                self.assertFalse(self.manager.domain("registered.test")["enabled"])
                self.client.post(path + "/claim", headers=headers, json=body)
                self.assertFalse(self.manager.run_once())
                self.assertEqual(allocations, [["5330"]])
                self.assertEqual(observed[-1][1], {"ids": ["5330"], "status": ["registered"], "sync_provider": ["none"]})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

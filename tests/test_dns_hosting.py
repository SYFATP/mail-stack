"""Hosted DNS preparation is durable, scoped and never replays uncertain writes."""
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import test_domain_control as fixture
from api.providers.dns.digitalplat import DIGITALPLAT_DNS_NOT_ENABLED
from api.providers.http import ProviderError


class DNSHostingTests(unittest.TestCase):
    setUpBase = fixture.P2Tests.setUp
    tearDown = fixture.P2Tests.tearDown
    domain = fixture.P2Tests.domain

    def setUp(self):
        self.setUpBase()
        self.domain(enabled=False)
        credential = self.manager.add_dns_credential(
            "digitalplat", "example.test", "fixture",
            {"api_token": fixture.TOKEN, "api_base": "https://dns.fixture.test/api/v1"})
        self.manager.bind_dns_credential("example.test", credential["id"])
        self.active = False
        self.mode = ""
        self.nameservers = []
        self.detail_domain = "example.test"
        self.post_count = 0
        self.http.callback = self.respond
        self.enterContext(patch("api.services.domain_manager.time.sleep"))

    def respond(self, method, base, path, **kwargs):
        if method == "GET" and path.endswith("/dns/records"):
            if self.mode == "auth":
                raise ProviderError("provider_http_403")
            if self.mode == "generic404":
                raise ProviderError("provider_http_404")
            if self.mode == "readback502" and self.post_count:
                raise ProviderError("digitalplat_dns_upstream_unavailable", uncertain=True)
            if not self.active:
                raise ProviderError("provider_http_404", upstream_code="hosted_dns_zone_not_found")
            return {"data": []}
        if method == "GET" and path == "/domains/example.test":
            return {"data": {"domain": self.detail_domain, "status": "ok", "nameservers": self.nameservers}}
        if method == "POST" and path.endswith("/dns/enable"):
            c = self.manager.db()
            try:
                dispatched = c.execute(
                    "SELECT step,result_json FROM domain_jobs WHERE kind='dns_hosting' AND status='running'").fetchone()
            finally:
                c.close()
            self.assertEqual(dispatched["step"], "dns_hosting_enabling")
            self.assertTrue(json.loads(dispatched["result_json"])["enable_dispatched"])
            self.assertRegex(kwargs["headers"]["Idempotency-Key"], "^mail-stack-dns-hosting-")
            self.post_count += 1
            if self.mode == "rejected":
                raise ProviderError("provider_http_403")
            if self.mode == "timeout":
                raise ProviderError("provider_transport_or_json_error", uncertain=True)
            self.active = self.mode != "pending"
            return {"data": {"mode": "hosted", "status": "pending" if not self.active else "active"}}
        raise AssertionError((method, path))

    def prepare(self, key="hosting-prepare-fixture"):
        job = self.manager.create_dns_hosting_job("example.test", key)
        self.assertTrue(self.manager.run_once())
        return self.manager.jobs.get(job["id"])

    def test_missing_service_is_enabled_once_and_verified_without_mail_dns_writes(self):
        before = self.manager.domain("example.test")
        job = self.prepare()
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(job["step"], "dns_hosting_ready")
        self.assertEqual(self.post_count, 1)
        self.assertEqual(self.manager.domain("example.test"), before)
        self.assertEqual([call[2] for call in self.http.calls if call[0] != "GET"],
                         ["/domains/example.test/dns/enable"])
        self.assertNotIn(fixture.TOKEN, json.dumps(job))
        self.assertFalse(self.manager.run_once())

    def test_readable_service_is_never_reenabled(self):
        self.active = True
        job = self.prepare()
        self.assertEqual(job["status"], "succeeded")
        self.assertFalse(job["result"]["enable_dispatched"])
        self.assertEqual(len(self.http.calls), 1)
        self.assertEqual(self.post_count, 0)

    def test_only_explicit_missing_service_error_authorizes_enable(self):
        for mode in ("auth", "generic404"):
            with self.subTest(mode=mode):
                self.mode = mode
                job = self.prepare("hosting-error-" + mode)
                self.assertEqual(job["status"], "failed")
                self.assertEqual(self.post_count, 0)

    def test_custom_nameservers_and_wrong_domain_are_preserved(self):
        self.nameservers = ["ns1.external.test"]
        job = self.prepare()
        self.assertEqual(job["error_code"], "digitalplat_external_dns_in_use")
        self.nameservers = []
        self.detail_domain = "other.test"
        job = self.prepare("hosting-wrong-domain")
        self.assertEqual(job["error_code"], "digitalplat_domain_not_ready")
        self.assertEqual(self.post_count, 0)

    def test_timeout_is_not_replayed_and_later_read_reconciles_unknown(self):
        self.mode = "timeout"
        first = self.prepare()
        self.assertEqual(first["status"], "unknown")
        second = self.prepare("hosting-timeout-recheck")
        self.assertEqual(second["status"], "partial")
        self.assertEqual(self.post_count, 1)
        self.active = True
        observed = self.prepare("hosting-timeout-observed")
        self.assertEqual(observed["status"], "succeeded")
        self.assertEqual(self.post_count, 1)
        for old in (first, second):
            updated = self.manager.jobs.get(old["id"])
            self.assertEqual(updated["status"], "succeeded")
            self.assertEqual(updated["step"], "dns_hosting_observed")
            self.assertEqual(updated["result"]["reconciled_by"], observed["id"])

    def test_pending_enable_ack_needs_readback_and_does_not_repeat_enable(self):
        self.mode = "pending"
        first = self.prepare()
        self.assertEqual(first["status"], "partial")
        self.assertTrue(first["result"]["enable_dispatched"])
        self.prepare("hosting-pending-recheck")
        self.assertEqual(self.post_count, 1)
        self.active = True
        self.assertEqual(self.prepare("hosting-pending-ready")["status"], "succeeded")

    def test_readback_error_after_accepted_enable_is_unknown(self):
        self.mode = "readback502"
        job = self.prepare()
        self.assertEqual(job["status"], "unknown")
        self.assertTrue(job["result"]["enable_dispatched"])
        self.assertEqual(self.post_count, 1)

    def test_definitive_enable_rejection_is_failed(self):
        self.mode = "rejected"
        job = self.prepare()
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["error_code"], "provider_http_403")

    def test_changed_binding_is_fenced_before_dispatch(self):
        job = self.manager.create_dns_hosting_job("example.test", "hosting-changed-binding")
        other = self.manager.add_dns_credential(
            "digitalplat", "example.test", "replacement",
            {"api_token": "replacement-token", "api_base": "https://dns.fixture.test/api/v1"})
        self.manager.bind_dns_credential("example.test", other["id"])
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(job["id"])["status"], "failed")
        self.assertEqual(self.http.calls, [])

    def test_concurrent_enqueue_coalesces_and_idempotency_is_retained(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            jobs = list(pool.map(lambda n: self.manager.create_dns_hosting_job(
                "example.test", "hosting-concurrent-" + str(n)), range(8)))
        self.assertEqual(len({job["id"] for job in jobs}), 1)
        self.manager.run_once()
        self.assertEqual(self.post_count, 1)
        self.assertEqual(self.manager.create_dns_hosting_job(
            "example.test", jobs[0]["idempotency_key"])["status"], "succeeded")

    def test_interrupted_enable_is_read_only_until_observed(self):
        job = self.manager.create_dns_hosting_job("example.test", "hosting-interrupted")
        self.manager.jobs.take()
        self.manager.jobs.recover_interrupted()
        recheck = self.prepare("hosting-after-restart")
        self.assertEqual(recheck["status"], "partial")
        self.assertEqual(self.post_count, 0)
        self.active = True
        self.prepare("hosting-restart-observed")
        self.assertEqual(self.manager.jobs.get(job["id"])["status"], "succeeded")

    def test_preview_returns_typed_recoverable_error_without_implicit_write(self):
        response = self.client.post("/api/v1/mail-domains/example.test/dns-preview", headers=self.headers)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"]["code"], DIGITALPLAT_DNS_NOT_ENABLED)
        self.assertEqual(self.post_count, 0)
        response = self.client.post("/api/v1/mail-domains/example.test/dns-hosting",
                                    headers={**self.headers, "Idempotency-Key": "hosting-api-prepare"})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["kind"], "dns_hosting")
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(response.json()["id"])["status"], "succeeded")

    def test_hosting_endpoint_requires_admin_and_valid_scope(self):
        self.assertEqual(self.client.post("/api/v1/mail-domains/example.test/dns-hosting",
                         headers={"Idempotency-Key": "hosting-no-admin"}).status_code, 401)
        self.domain(dns_provider="manual", dns_credential_ref=None)
        response = self.client.post("/api/v1/mail-domains/example.test/dns-hosting",
                                   headers={**self.headers, "Idempotency-Key": "hosting-manual-domain"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.post_count, 0)

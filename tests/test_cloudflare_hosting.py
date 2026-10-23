"""Offline Cloudflare creation, uncertain readback and delegation lifecycle tests."""
import copy
import io
import json
import unittest
import urllib.error
from types import SimpleNamespace
from unittest.mock import patch
import test_domain_control as base
import test_dns_reconcile as dnsbase
from api.providers.dns.cloudflare import CloudflareDNS
from api.providers.http import JsonTransport, ProviderError
from api.services.domain_manager import clean_secret

ACCOUNT = "a" * 32
NS = ["alice.ns.cloudflare.com", "bob.ns.cloudflare.com"]


class CloudflareHostingTests(unittest.TestCase):
    def setUp(self):
        self.case = base.P2Tests(methodName="runTest")
        self.case.setUp()
        self.addCleanup(self.case.tearDown)
        self.m = self.case.manager
        self.case.domain(enabled=False, dns_provider="manual")
        self.ref = self.m.add_dns_credential("cloudflare", None, "CF fixture", {"api_token": base.TOKEN, "account_id": ACCOUNT})["id"]
        self.zone = None
        self.posts = 0
        self.failure = ""
        self.case.http.callback = self.request

    def request(self, method, base_url, path, **kw):
        if path == "/zones" and method == "GET":
            name = kw["query"]["name"]
            self.assertEqual(kw["query"].get("account.id"), ACCOUNT)
            return {"success": True, "result": [copy.deepcopy(self.zone)] if self.zone and self.zone["name"] == name else []}
        if path == "/zones" and method == "POST":
            self.posts += 1
            self.assertEqual(kw["body"], {"name": "example.test", "account": {"id": ACCOUNT}, "type": "full"})
            c = self.m.db()
            saved = json.loads(c.execute("SELECT result_json FROM domain_jobs WHERE kind='dns_hosting' AND status='running'").fetchone()[0]);c.close()
            self.assertTrue(saved["registration_dispatched"])
            if self.failure == "rejected":
                raise ProviderError("cloudflare_error_1061", uncertain=False)
            if self.failure != "timeout-no-commit":
                self.zone = {"id": "zone-fixture", "name": "example.test", "status": "pending", "type": "full", "account": {"id": ACCOUNT}, "name_servers": NS}
            if self.failure.startswith("timeout"):
                raise ProviderError("provider_transport_or_json_error", uncertain=True)
            return {"success": True, "result": copy.deepcopy(self.zone)}
        raise AssertionError((method, path))

    def execute(self, key="cloudflare-setup-fixture", **kw):
        job = self.m.cloudflare_registration.enqueue("example.test", key, self.ref, **kw)
        self.assertTrue(self.m.run_once())
        return self.m.jobs.get(job["id"])

    def test_creates_pending_zone_binds_and_exposes_target_ns(self):
        result = self.execute()
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(self.posts, 1)
        self.assertEqual(result["result"]["nameservers"], NS)
        self.assertEqual(result["result"]["zone_status"], "pending")
        self.assertEqual(self.m.domain("example.test")["dns_provider"], "cloudflare")
        self.assertFalse(self.m.domain("example.test")["enabled"])
        summary = self.m.jobs.list(limit=1)["domain_hosting"]["example.test"]
        self.assertEqual(summary["nameservers"], NS)
        self.assertNotIn(base.TOKEN, json.dumps(result))
        self.assertEqual(self.m.cloudflare_registration.enqueue("example.test", result["idempotency_key"], self.ref)["id"], result["id"])
        self.assertEqual(self.posts, 1)

    def test_standalone_onboarding_route_is_queued_without_binding_or_network_calls(self):
        response = self.case.client.post('/api/v1/mail-domains/example.test/cloudflare-hosting',
            headers={**self.case.headers, "Idempotency-Key": "cf-onboarding-route"}, json={"credential_ref": self.ref})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["kind"], "dns_hosting")
        self.assertEqual(response.json()["request"]["provider"], "cloudflare")
        self.assertEqual(self.case.http.calls, [])
        self.assertEqual(self.m.domain("example.test")["dns_provider"], "manual")

    def test_existing_pending_zone_reuses_without_post(self):
        self.zone = {"id": "existing-zone", "name": "example.test", "status": "pending", "name_servers": NS, "account": {"id": ACCOUNT}}
        self.assertEqual(self.execute()["status"], "succeeded")
        self.assertEqual(self.posts, 0)

    def test_rejected_creation_preserves_original_binding(self):
        self.failure = "rejected"
        result = self.execute()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "cloudflare_error_1061")
        self.assertEqual(self.m.domain("example.test")["dns_provider"], "manual")
        self.assertIsNone(self.m.domain("example.test")["dns_credential_ref"])

    def test_timeout_after_commit_is_read_back_then_only_binding_is_retried(self):
        self.failure = "timeout-after-commit"
        first = self.execute()
        self.assertEqual(first["status"], "partial", first)
        self.assertEqual(first["result"]["registration_status"], "registered")
        self.failure = ""
        second = self.execute("cloudflare-bind-retry")
        self.assertEqual(second["status"], "succeeded")
        self.assertEqual(self.posts, 1)

    def test_unknown_creation_is_not_replayed_even_with_new_key(self):
        self.failure = "timeout-no-commit"
        self.assertEqual(self.execute()["status"], "unknown")
        self.failure = ""
        second = self.execute("cloudflare-readback-retry")
        self.assertEqual(second["error_code"], "cloudflare_zone_creation_unconfirmed")
        self.assertEqual(self.posts, 1)

    def test_configuration_change_fences_create(self):
        job = self.m.cloudflare_registration.enqueue("example.test", "cloudflare-fenced-fixture", self.ref)
        row = self.m.domain("example.test");row["users"] = json.loads(row["users"]);row["mx"] = "changed.example.test";self.m.save_domain(row)
        self.m.run_once()
        self.assertEqual(self.m.jobs.get(job["id"])["status"], "failed")
        self.assertEqual(self.posts, 0)

    def test_new_zone_continues_configuration_with_selected_account(self):
        child = {"id": "apply-next", "kind": "dns_apply", "scope": "example.test", "status": "queued"}
        with patch.object(self.m, "_queue_claim_completion", return_value={"dns_apply_job": child}) as queue:
            # A real claim identity is fenced separately in the allocation tests.
            with patch.object(self.m.cloudflare_registration, "check"):
                result = self.execute(completion={"credential_ref": self.ref, "claim_id": "fixture", "allocation_job_id": "fixture"})
        self.assertEqual(result["result"]["dns_apply_job"]["id"], child["id"])
        self.assertEqual(queue.call_args.args[0]["credential_ref"], self.ref)


class CloudflareAPITests(unittest.TestCase):
    def test_accounts_are_unique_or_explicit_never_arbitrarily_selected(self):
        for ids in ([ACCOUNT], [ACCOUNT, "b" * 32], []):
            wire = SimpleNamespace(request=lambda *a, **kw: {"result": [{"id": value} for value in ids]})
            adapter = CloudflareDNS(wire, {"api_token": base.TOKEN})
            if len(ids) == 1:
                self.assertEqual(adapter.creation_account(), ACCOUNT)
            else:
                with self.assertRaisesRegex(ProviderError, "cloudflare_account_id_required"):
                    adapter.creation_account()
        adapter = CloudflareDNS(SimpleNamespace(request=lambda *a, **k: self.fail("Explicit Account ID must skip account enumeration")), {"api_token": base.TOKEN, "account_id": ACCOUNT})
        self.assertEqual(adapter.creation_account(), ACCOUNT)

    def test_zone_creation_does_not_hardcode_domain_suffix_or_label_depth(self):
        for name in ("example.test", "child.qd.je", "nested.child.allowed.test"):
            calls = []
            def create(method, base_url, path, **kw):
                calls.append(kw["body"])
                return {"result": {"id": "zone-fixture", "name": name, "status": "pending", "name_servers": NS}}
            CloudflareDNS(SimpleNamespace(request=create), {"api_token": base.TOKEN}).create_zone(name, ACCOUNT)
            self.assertEqual(calls[0]["name"], name)

    def test_pending_exact_zone_can_be_written_but_pending_ancestor_is_not_inferred(self):
        def request(method, base_url, path, **kw):
            if path == "/zones":
                return {"result": [{"id": "zone", "name": "example.test", "status": "pending"}]}
            return {"result": [], "result_info": {"total_pages": 1}}
        adapter = CloudflareDNS(SimpleNamespace(request=request), {"api_token": base.TOKEN})
        self.assertEqual(adapter.inventory("example.test")["zone_status"], "pending")
        with self.assertRaisesRegex(ProviderError, "cloudflare_zone_not_accessible"):
            adapter.inventory("child.example.test")

    def test_cloudflare_error_code_is_retained_without_raw_messages(self):
        body = json.dumps({"success": False, "errors": [{"code": 1061, "message": base.TOKEN}]}).encode()
        transport = JsonTransport()
        error = urllib.error.HTTPError("https://api.cloudflare.com/client/v4/zones", 400, "Bad Request", {}, io.BytesIO(body))
        with patch.object(transport.opener, "open", side_effect=error), self.assertRaises(ProviderError) as caught:
            transport.request("POST", "https://api.cloudflare.com/client/v4", "/zones", body={})
        self.assertEqual(caught.exception.code, "cloudflare_error_1061")
        self.assertFalse(caught.exception.uncertain)
        self.assertNotIn(base.TOKEN, str(caught.exception))

    def test_account_id_contract_preserves_legacy_credentials(self):
        for fields in ({"api_token": base.TOKEN}, {"api_email": "fixture@example.test", "api_key": base.TOKEN}):
            self.assertEqual(clean_secret("cloudflare", fields), fields)
            self.assertEqual(clean_secret("cloudflare", {**fields, "account_id": ACCOUNT})["account_id"], ACCOUNT)
            with self.assertRaises(ValueError):clean_secret("cloudflare", {**fields, "account_id": "invalid"})


class CloudflareCompletionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = dnsbase.DNSWriteTests(methodName="runTest");self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown);self.addCleanup(self.fixture.doCleanups)
        self.m = self.fixture.m
        (self.fixture.case.root / "keys/example.test/default.private").write_text("fixture-private-key")
        self.assertEqual(self.fixture.apply()["status"], "succeeded")
        wire = self.fixture.respond
        def pending(method, base_url, path, **kw):
            result = wire(method, base_url, path, **kw)
            if method == "GET" and path == "/zones":
                result["result"][0].update(status="pending", name_servers=NS)
            return result
        self.fixture.http.callback = pending
        self.current = ["dns1.digitalplat.org", "dns2.digitalplat.org"]
        self.writes = []
        self.manual_parent_ready = False
        def parent(domain, nameservers):
            self.assertEqual(list(nameservers), NS)
            passed = self.manual_parent_ready or set(self.current) == set(NS)
            return {"passed": passed, "checks": [{"host": "parent.fixture", "nameservers": list(self.current), "passed": passed}]}
        self.enterContext(patch.object(self.m.dns_completion.probe, "parents", side_effect=parent))
        self.enterContext(patch.object(self.m.dns_completion.probe, "targets", return_value={"passed": True, "checks": []}))

    def execute(self, job):
        c = self.m.db()
        with c:c.execute("UPDATE domain_jobs SET result_json=json_set(result_json,'$.retry_at',0) WHERE id=?", (job["id"],))
        c.close();self.assertTrue(self.m.run_once());return self.m.jobs.get(job["id"])

    def enqueue(self):
        return self.m.create_validate_job("example.test", "cf-delegation-fixture", activate_on_success=True)

    def test_normal_domain_waits_for_manual_ns_then_automatically_enables(self):
        job = self.enqueue();self.assertEqual(job["kind"], "dns_complete")
        first = self.execute(job)
        self.assertEqual(first["status"], "queued", first)
        self.assertEqual(first["step"], "dns_completion_waiting_manual_nameservers")
        self.assertEqual(first["result"]["next_action"], "update_nameservers")
        self.assertEqual(self.m.jobs.list()["domain_hosting"]["example.test"]["nameservers"], NS)
        self.assertFalse(self.m.domain("example.test")["enabled"])
        self.manual_parent_ready = True
        final = self.execute(job)
        self.assertEqual(final["status"], "succeeded", final)
        self.assertTrue(self.m.domain("example.test")["enabled"])
        self.assertEqual(len(self.fixture.writes()), 4, "No additional DNS writes during delegation polling")

    def test_digitalplat_credential_switches_to_assigned_cf_nameservers(self):
        def switch(nameservers, key, force=False):
            self.writes.append((list(nameservers), force));self.current = list(nameservers);return "operation-fixture"
        registrar = SimpleNamespace(delegation_status=lambda: self.current, switch_external=switch)
        self.enterContext(patch.object(self.m.dns_completion, "registrar", return_value=registrar))
        job = self.enqueue();first = self.execute(job)
        self.assertEqual(first["status"], "queued", first)
        self.assertEqual(self.writes, [(NS, False)])
        self.assertFalse(self.m.domain("example.test")["enabled"])
        self.assertEqual(self.execute(job)["status"], "succeeded")
        self.assertTrue(self.m.domain("example.test")["enabled"])
        self.assertEqual(len(self.writes), 1)

    def test_digitalplat_precheck_confirmation_uses_cloudflare_assigned_ns(self):
        def switch(nameservers, key, force=False):
            self.writes.append((list(nameservers), force))
            if not force:
                raise ProviderError("provider_http_409", upstream_code="external_nameserver_precheck_failed", uncertain=False)
            self.current = list(nameservers)
            return "confirmed-operation-fixture"
        registrar = SimpleNamespace(delegation_status=lambda: self.current, switch_external=switch)
        self.enterContext(patch.object(self.m.dns_completion, "registrar", return_value=registrar))
        job = self.enqueue()
        first = self.execute(job)
        self.assertEqual(first["status"], "queued", first)
        self.assertEqual(self.writes, [(NS, False), (NS, True)])
        self.assertEqual(self.execute(job)["status"], "succeeded")
        self.assertTrue(self.m.domain("example.test")["enabled"])
        self.assertEqual(len(self.writes), 2)

    def test_uncertain_delegation_is_read_back_without_replaying_post(self):
        def switch(nameservers, key, force=False):
            self.writes.append((list(nameservers), force))
            raise ProviderError("provider_transport_or_json_error", uncertain=True)
        registrar = SimpleNamespace(delegation_status=lambda: self.current, switch_external=switch)
        self.enterContext(patch.object(self.m.dns_completion, "registrar", return_value=registrar))
        job = self.enqueue()
        self.assertEqual(self.execute(job)["status"], "queued")
        second = self.execute(job)
        self.assertEqual(second["step"], "dns_completion_readback_pending")
        self.assertEqual(self.writes, [(NS, False)])
        self.assertFalse(self.m.domain("example.test")["enabled"])

    def test_existing_external_ns_are_not_overwritten(self):
        self.current = ["external.example.test"]
        registrar = SimpleNamespace(delegation_status=lambda: self.current, switch_external=lambda *a, **k: self.fail("Unexpected NS write"))
        self.enterContext(patch.object(self.m.dns_completion, "registrar", return_value=registrar))
        result = self.execute(self.enqueue())
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["error_code"], "dns_delegation_external_provider_conflict")
        self.assertFalse(self.m.domain("example.test")["enabled"])

    def test_manual_wait_deadline_is_terminal_not_requeued(self):
        job = self.enqueue()
        c = self.m.db()
        with c:c.execute("UPDATE domain_jobs SET result_json=? WHERE id=?", (json.dumps({"deadline": 1}), job["id"]))
        c.close();result = self.execute(job)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["step"], "dns_completion_timed_out")


if __name__ == "__main__":
    unittest.main()

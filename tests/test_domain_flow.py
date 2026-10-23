"""Offline durable claim -> hosting -> preview -> validate/apply -> enable."""
import json
import time
import unittest
from unittest.mock import patch

import test_domain_control as base
import test_dns_reconcile as dnsbase
import test_dns_hosting as hostingbase


class ClaimFlowTests(unittest.TestCase):
    setUp = base.P2Tests.setUp
    tearDown = base.P2Tests.tearDown
    source = base.P2Tests.source
    batch_payload = base.P2Tests.batch_payload

    def test_auto_claim_intent_is_optional_strict_and_keeps_legacy_retry_payload(self):
        source = self.source()
        job = self.manager.create_claim_job(source["id"], "legacy-claim-payload")
        self.assertNotIn("configure_on_success", job["request"])
        response = self.client.post(
            f'/api/v1/domain-sources/{source["id"]}/claim',
            headers={**self.headers, "Idempotency-Key": "automatic-claim-request"},
            json={"status": "registered", "sync_provider": "none", "configure_on_success": True})
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.json()["request"]["configure_on_success"])
        response = self.client.post(
            f'/api/v1/domain-sources/{source["id"]}/claim',
            headers={**self.headers, "Idempotency-Key": "invalid-automatic-claim"},
            json={"configure_on_success": "false"})
        self.assertEqual(response.status_code, 422)

    def test_auto_claim_queues_durable_setup_and_hosting_without_duplicate_brevo_calls(self):
        source = self.source()
        self.http.payload = self.batch_payload(2)
        job = self.manager.create_claim_job(source["id"], "automatic-batch-claim", count=2,
            status="registered", sync_provider="none", configure_on_success=True)
        with patch.object(self.manager, "brevo_sync_enabled", return_value=True), \
             patch.object(self.manager, "ensure_brevo_domain") as brevo:
            self.manager.run_once()
            parent = self.manager.jobs.get(job["id"])
            self.assertEqual(parent["status"], "succeeded")
            children = [item["claim_setup_job"] for item in parent["result"]["items"]]
            self.assertEqual(len(children), 2)
            self.assertTrue(all(child["request"]["configure_on_success"] for child in children))
            self.manager.run_once()
            child = self.manager.jobs.get(children[0]["id"])
            brevo.assert_not_called()
        hosting = child["result"]["dns_hosting_job"]
        self.assertEqual(hosting["status"], "queued")
        self.assertEqual(hosting["request"]["completion"]["allocation_job_id"], job["id"])
        self.assertFalse(any(row["enabled"] for row in base.app._domain_rows()))
        self.assertEqual(len(self.http.calls), 1, "Only allocation is dispatched on this path")
        self.assertNotIn(base.TOKEN, json.dumps(parent))

    def test_single_auto_claim_also_defers_slow_setup(self):
        source = self.source()
        job = self.manager.create_claim_job(source["id"], "single-automatic-claim", configure_on_success=True)
        with patch.object(self.manager, "ensure_brevo_domain") as brevo:
            self.manager.run_once()
            brevo.assert_not_called()
        result = self.manager.jobs.get(job["id"])
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["result"]["items"][0]["claim_setup_job"]["request"]["configure_on_success"])


class ClaimHostingTests(ClaimFlowTests):
    def account(self, provider="dynv6", domain=None, session=True):
        ref = self.manager.add_dns_credential(provider, domain, "hosting fixture", {"api_token": base.TOKEN})["id"]
        if provider == "dynv6" and session:
            c = self.manager.db()
            try:
                with c:
                    self.manager.credentials().put(c, provider, {"api_token": base.TOKEN, "session_cookie": "fixture-cookie"},
                                                   domain=domain, credential_id=ref)
            finally:
                c.close()
        return ref

    def allocate(self, provider, ref=None):
        source = self.source()
        job = self.manager.create_claim_job(source["id"], "selected-hosting-claim", status="registered", sync_provider="none",
            configure_on_success=True, hosting_provider=provider, hosting_credential_ref=ref)
        self.manager.run_once()
        parent = self.manager.jobs.get(job["id"])
        self.assertEqual(parent["status"], "succeeded", parent)
        return job, parent["result"]["items"][0]["claim_setup_job"]

    def test_invalid_hosting_accounts_fail_before_allocation(self):
        source = self.source()
        scoped = self.account(domain="another.test")
        token_only = self.account(session=False)
        wrong = self.account("cloudflare")
        for options in [
            {"hosting_provider": "other"},
            {"hosting_provider": "dynv6"},
            {"hosting_provider": "dynv6", "hosting_credential_ref": scoped},
            {"hosting_provider": "dynv6", "hosting_credential_ref": token_only},
            {"hosting_provider": "dynv6", "hosting_credential_ref": wrong},
            {"hosting_provider": "original", "hosting_credential_ref": wrong},
            {"hosting_provider": "cloudflare", "hosting_credential_ref": wrong, "configure_on_success": False},
        ]:
            response = self.client.post(f'/api/v1/domain-sources/{source["id"]}/claim',
                headers={**self.headers, "Idempotency-Key": "invalid-hosting-options"},
                json={"configure_on_success": True, **options})
            self.assertGreaterEqual(response.status_code, 400, options)
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.manager.claims(), [])

    def test_dynv6_claim_defers_hosting_then_continues_after_confirmed_registration(self):
        from test_dynv6_registration import SessionWire
        ref = self.account()
        allocation, setup = self.allocate("dynv6", ref)
        original = self.manager.domain("claimed.test")["dns_credential_ref"]
        self.assertEqual(setup["request"]["hosting_provider"], "dynv6")
        with patch.object(self.manager, "create_dns_hosting_job") as hosted:
            self.manager.run_once()
            hosted.assert_not_called()
        registration = self.manager.jobs.get(setup["id"])["result"]["dynv6_registration_job"]
        self.assertEqual(registration["request"]["completion"]["allocation_job_id"], allocation["id"])
        self.assertEqual(self.manager.domain("claimed.test")["dns_credential_ref"], original)
        wire = SessionWire()
        self.manager.http = wire
        self.manager.dynv6_registration.session_factory = wire.session
        child = {"id": "next-apply", "kind": "dns_apply", "scope": "claimed.test", "status": "queued"}
        with patch.object(self.manager, "_queue_claim_completion", return_value={"dns_apply_job": child}) as continuation:
            self.manager.run_once()
        result = self.manager.jobs.get(registration["id"])
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(wire.posts, 1)
        self.assertEqual(result["result"]["dns_apply_job"]["id"], child["id"])
        self.assertEqual(continuation.call_args.args[0]["credential_ref"], ref)
        row = self.manager.domain("claimed.test")
        self.assertEqual((row["dns_provider"], row["dns_credential_ref"], row["max_subdomain_depth"]), ("dynv6", ref, 1))
        self.assertFalse(row["enabled"])
        self.assertEqual(self.manager.claim_row(row["claim_id"])["dns_credential_ref"], original)

    def test_dynv6_changed_claim_is_fenced_before_any_registration_request(self):
        _, setup = self.allocate("dynv6", self.account())
        self.manager.run_once()
        registration = self.manager.jobs.get(setup["id"])["result"]["dynv6_registration_job"]
        c = self.manager.db()
        try:
            with c:c.execute("UPDATE mail_domains SET dns_credential_ref=NULL WHERE domain='claimed.test'")
        finally:
            c.close()
        with patch.object(self.manager.dynv6_accounts, "zones") as zones:
            self.manager.run_once()
            zones.assert_not_called()
        self.assertEqual(self.manager.jobs.get(registration["id"])["status"], "failed")

    def test_cloudflare_claim_queues_setup_before_rebinding(self):
        ref = self.account("cloudflare")
        _, setup = self.allocate("cloudflare", ref)
        original = self.manager.domain("claimed.test")["dns_credential_ref"]
        with patch.object(self.manager, "_queue_claim_completion") as continuation:
            self.manager.run_once()
            continuation.assert_not_called()
        parent = self.manager.jobs.get(setup["id"])
        self.assertEqual(parent["status"], "succeeded")
        child = parent["result"]["dns_hosting_job"]
        self.assertEqual(child["request"]["provider"], "cloudflare")
        self.assertEqual(child["request"]["credential_ref"], ref)
        self.assertEqual(self.manager.domain("claimed.test")["dns_credential_ref"], original)
        self.assertFalse(self.manager.domain("claimed.test")["enabled"])

    def test_cloudflare_missing_zone_is_a_durable_create_task(self):
        _, setup = self.allocate("cloudflare", self.account("cloudflare"))
        with patch("api.providers.dns.cloudflare.CloudflareDNS.zone_info") as lookup:
            self.manager.run_once()
            lookup.assert_not_called()
        child = self.manager.jobs.get(setup["id"])["result"]["dns_hosting_job"]
        self.assertEqual(child["kind"], "dns_hosting")
        self.assertEqual(child["status"], "queued")

    def test_cloudflare_registration_hands_off_claim_and_preserves_registrar_token(self):
        ref = self.account("cloudflare")
        allocation, setup = self.allocate("cloudflare", ref)
        original = self.manager.domain("claimed.test")["dns_credential_ref"]
        self.manager.run_once()
        child = self.manager.jobs.get(setup["id"])["result"]["dns_hosting_job"]
        ns = ["alice.ns.cloudflare.com", "bob.ns.cloudflare.com"]
        zone = {}
        def wire(method, base_url, path, **kw):
            if path == "/accounts":return {"result": [{"id": "a" * 32}]}
            if method == "GET" and path == "/zones":return {"result": [dict(zone)] if zone and kw["query"]["name"] == "claimed.test" else []}
            if method == "POST" and path == "/zones":
                zone.update(id="new-zone", name="claimed.test", status="pending", name_servers=ns)
                return {"result": dict(zone)}
            raise AssertionError((method, path))
        self.http.callback = wire
        expected_apply = {"id": "durable-next-apply", "kind": "dns_apply", "scope": "claimed.test", "status": "queued"}
        with patch.object(self.manager.dns, "preview", return_value={"id": "preview-cf", "executable": True, "actions": [{"action": "create"}]}), \
             patch.object(self.manager.dns, "enqueue", return_value=expected_apply) as apply:
            self.manager.run_once()
        completed = self.manager.jobs.get(child["id"])
        self.assertEqual(completed["status"], "succeeded", completed)
        self.assertEqual(completed["result"]["dns_apply_job"]["id"], expected_apply["id"])
        self.assertTrue(apply.call_args.kwargs["activate_on_success"])
        row = self.manager.domain("claimed.test")
        self.assertEqual(row["dns_credential_ref"], ref)
        self.assertEqual(self.manager.claim_row(row["claim_id"])["dns_credential_ref"], original)
        self.assertEqual(completed["request"]["completion"]["allocation_job_id"], allocation["id"])
        self.assertFalse(row["enabled"])

    def test_explicit_digitalplat_keeps_the_existing_hosting_chain(self):
        _, setup = self.allocate("digitalplat")
        self.manager.run_once()
        result = self.manager.jobs.get(setup["id"])
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["result"]["dns_hosting_job"]["kind"], "dns_hosting")


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = dnsbase.DNSWriteTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)
        self.m = self.fixture.m
        self.private = self.fixture.case.root / "keys/example.test/default.private"
        self.private.write_text("fixture-private-key")
        source = self.fixture.case.source()
        allocation = self.m.create_claim_job(source["id"], "completion-allocation", configure_on_success=True)
        claim_id = self.m._record_claim(source, allocation, {
            "domain": "example.test", "claim_id": "upstream-completion", "status": "active"})
        row = self.m.domain("example.test")
        c = self.m.db()
        with c:
            c.execute("UPDATE mail_domains SET claim_id=? WHERE domain='example.test'", (claim_id,))
            c.execute("UPDATE domain_claims SET dns_credential_ref=? WHERE id=?", (row["dns_credential_ref"], claim_id))
        c.close()
        self.assertEqual(self.m.jobs.take()["id"], allocation["id"])
        self.m.jobs.finish(allocation["id"], "succeeded", step="fixture_imported")
        self.expected = {"claim_id": claim_id, "allocation_job_id": allocation["id"],
                         "credential_ref": row["dns_credential_ref"]}

    def test_durable_child_uses_preview_and_activates_only_after_fresh_checks(self):
        queued = self.m._queue_claim_completion(self.expected)
        child = queued["dns_apply_job"]
        self.assertEqual(child["kind"], "dns_apply")
        self.assertTrue(child["request"]["activate_on_success"])
        self.assertFalse(self.m.domain("example.test")["enabled"])
        self.assertEqual(self.fixture.writes(), [])
        self.assertTrue(self.m.run_once())
        finished = self.m.jobs.get(child["id"])
        self.assertEqual(finished["status"], "succeeded")
        self.assertEqual(finished["result"]["validation_status"], "passed")
        self.assertTrue(self.m.domain("example.test")["enabled"])
        self.assertEqual(len(self.fixture.writes()), 4)
        with patch.object(self.m.dns, "preview") as preview:
            retry = self.m._queue_claim_completion(self.expected)
            preview.assert_not_called()
        self.assertEqual(retry["dns_apply_job"]["id"], child["id"])
        self.assertEqual(len(self.fixture.writes()), 4)

    def test_all_existing_records_queue_validation_only(self):
        self.fixture.apply()
        count = len(self.fixture.writes())
        child = self.m._queue_claim_completion(self.expected)["dns_apply_job"]
        self.assertEqual(child["kind"], "dns_validate")
        self.assertTrue(self.m.run_once())
        self.assertTrue(self.m.domain("example.test")["enabled"])
        self.assertEqual(len(self.fixture.writes()), count)

    def test_conflicts_leave_the_domain_disabled_without_enqueuing_writes(self):
        self.fixture.records.append({"id": "foreign", "type": "MX", "name": "example.test",
                                     "content": "other.example.test", "priority": 10, "ttl": 300})
        result = self.m._queue_claim_completion(self.expected)
        self.assertEqual(result["configuration_status"], "blocked")
        self.assertNotIn("dns_apply_job", result)
        self.assertTrue(result["configuration_conflicts"])
        self.assertFalse(self.m.domain("example.test")["enabled"])
        self.assertEqual(self.fixture.writes(), [])

    def test_changed_ownership_binding_and_missing_credentials_are_fenced(self):
        for field in ("allocation_job_id", "credential_ref", "claim_id"):
            invalid = {**self.expected, field: "invalid-fixture"}
            with patch.object(self.m.dns, "preview") as preview:
                result = self.m._queue_claim_completion(invalid)
                preview.assert_not_called()
            self.assertEqual(result["configuration_status"], "pending")
            self.assertNotIn("dns_apply_job", result)
        self.assertEqual(self.fixture.writes(), [])

    def queue_key_wait(self):
        key = self.fixture.case.root / "keys/example.test/default.txt"
        contents = key.read_text()
        key.unlink()
        result = self.m._queue_claim_completion(self.expected)
        self.assertEqual(result["configuration_status"], "queued", result)
        return key, contents, result["claim_setup_job"]

    def make_due(self, job):
        c = self.m.db()
        with c:
            c.execute("UPDATE domain_jobs SET result_json=json_set(result_json,'$.retry_at',0) WHERE id=?", (job["id"],))
        c.close()

    def test_missing_dkim_waits_durably_then_configures_without_replaying_hosting(self):
        key, contents, job = self.queue_key_wait()
        with patch.object(self.m, "_prepare_claim_services") as hosting, patch.object(self.m.dns, "preview") as preview:
            self.assertTrue(self.m.run_once())
            hosting.assert_not_called()
            preview.assert_not_called()
        waiting = self.m.jobs.get(job["id"])
        self.assertEqual(waiting["step"], "claim_waiting_dkim")
        self.assertEqual(waiting["status"], "queued")
        self.assertEqual(waiting["wait_reason"], "retry_at")
        self.assertFalse(self.m.run_once(), "Waiting for the key must release the worker")
        self.m.jobs.recover_interrupted()
        self.assertEqual(self.m.jobs.get(job["id"])["status"], "queued")
        self.assertEqual(self.fixture.writes(), [])
        key.write_text(contents)
        self.make_due(job)
        with patch.object(self.m, "_prepare_claim_services") as hosting:
            self.assertTrue(self.m.run_once())
            hosting.assert_not_called()
        prepared = self.m.jobs.get(job["id"])
        self.assertEqual(prepared["status"], "succeeded", prepared)
        self.assertEqual(prepared["result"]["dns_apply_job"]["kind"], "dns_apply")
        self.assertFalse(self.m.domain("example.test")["enabled"])
        self.assertEqual(self.fixture.writes(), [])
        self.assertTrue(self.m.run_once())
        self.assertTrue(self.m.domain("example.test")["enabled"])
        self.assertEqual(len(self.fixture.writes()), 4)

    def test_ready_continuation_runs_before_old_import_queue_but_wait_releases_others(self):
        other = self.m.jobs.enqueue("claim_setup", "other.test", "older-general-setup", {})
        _, _, job = self.queue_key_wait()
        self.assertTrue(self.m.run_once())
        self.assertEqual(self.m.jobs.get(job["id"])["step"], "claim_waiting_dkim")
        self.assertEqual(self.m.jobs.take()["id"], other["id"])
        self.m.jobs.finish(other["id"], "succeeded", step="fixture")
        self.assertEqual(self.fixture.writes(), [])

    def test_missing_dkim_reuses_the_same_wait_task(self):
        _, _, job = self.queue_key_wait()
        duplicate = self.m._queue_claim_completion(self.expected)
        self.assertEqual(duplicate["claim_setup_job"]["id"], job["id"])
        self.assertEqual(self.fixture.writes(), [])

    def test_missing_dkim_deadline_is_actionable_without_writes(self):
        _, _, job = self.queue_key_wait()
        c = self.m.db()
        with c:
            c.execute("UPDATE domain_jobs SET created_at=? WHERE id=?", (time.time() - 1801, job["id"]))
        c.close()
        with patch.object(self.m.dns, "preview") as preview:
            self.assertTrue(self.m.run_once())
            preview.assert_not_called()
        result = self.m.jobs.get(job["id"])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["error_code"], "dkim_public_key_pending")
        self.assertEqual(result["result"]["next_action"], "retry_configuration")
        self.assertFalse(self.m.domain("example.test")["enabled"])
        self.assertEqual(self.fixture.writes(), [])

    def test_changed_configuration_cancels_old_key_wait(self):
        key, contents, job = self.queue_key_wait()
        key.write_text(contents)
        c = self.m.db()
        with c:
            c.execute("UPDATE mail_domains SET spf='v=spf1 -all' WHERE domain='example.test'")
        c.close()
        with patch.object(self.m.dns, "preview") as preview:
            self.assertTrue(self.m.run_once())
            preview.assert_not_called()
        result = self.m.jobs.get(job["id"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "claim_configuration_changed")
        self.assertEqual(self.fixture.writes(), [])

    def test_changed_ownership_cancels_old_key_wait(self):
        key, contents, job = self.queue_key_wait()
        key.write_text(contents)
        newer = self.m.jobs.enqueue("claim", self.m.sources()[0]["id"], "key-wait-new-generation", {})
        c = self.m.db()
        try:
            with c:
                c.execute("UPDATE domain_jobs SET status='succeeded' WHERE id=?", (newer["id"],))
                c.execute("UPDATE domain_claims SET job_id=? WHERE id=?", (newer["id"], self.expected["claim_id"]))
        finally:
            c.close()
        with patch.object(self.m.dns, "preview") as preview:
            self.assertTrue(self.m.run_once())
            preview.assert_not_called()
        self.assertEqual(self.m.jobs.get(job["id"])["status"], "failed")
        self.assertEqual(self.fixture.writes(), [])

    def test_key_becoming_ready_still_requires_a_fresh_conflict_free_preview(self):
        key, contents, job = self.queue_key_wait()
        key.write_text(contents)
        self.fixture.records.append({"id": "foreign", "type": "MX", "name": "example.test",
                                     "content": "other.example.test", "priority": 10, "ttl": 300})
        self.assertTrue(self.m.run_once())
        result = self.m.jobs.get(job["id"])
        self.assertEqual(result["status"], "partial", result)
        self.assertEqual(result["result"]["configuration_status"], "blocked")
        self.assertNotIn("dns_apply_job", result["result"])
        self.assertEqual(self.fixture.writes(), [])
        self.assertFalse(self.m.domain("example.test")["enabled"])

    def test_missing_dkim_with_external_conflicts_does_not_start_automatic_wait(self):
        key = self.fixture.case.root / "keys/example.test/default.txt"
        key.unlink()
        self.fixture.records.append({"id": "foreign", "type": "MX", "name": "example.test",
                                     "content": "other.example.test", "priority": 10, "ttl": 300})
        result = self.m._queue_claim_completion(self.expected)
        self.assertEqual(result["configuration_status"], "blocked")
        self.assertNotIn("claim_setup_job", result)
        self.assertEqual(self.fixture.writes(), [])

    def test_failed_validation_keeps_confirmed_writes_and_stays_disabled(self):
        original = self.m.validator.validate
        def fail(*args):
            result = original(*args)
            result["checks"]["mx"] = {"status": "failed", "detail": "fixture_waiting_for_dns"}
            return result
        child = self.m._queue_claim_completion(self.expected)["dns_apply_job"]
        with patch.object(self.m.validator, "validate", side_effect=fail):
            self.m.run_once()
        result = self.m.jobs.get(child["id"])
        self.assertEqual(result["result"]["validation_status"], "failed")
        self.assertFalse(self.m.domain("example.test")["enabled"])
        self.assertEqual(len(self.fixture.writes()), 4)


class HostingContinuationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = hostingbase.DNSHostingTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)
        self.m = self.fixture.manager

    def test_hosting_completion_enqueues_configuration_after_success(self):
        child = {"id": "fixture-apply", "kind": "dns_apply", "status": "queued", "scope": "example.test"}
        with patch.object(self.m, "_queue_claim_completion", return_value={"dns_apply_job": child}) as queue:
            job = self.m.create_dns_hosting_job("example.test", "hosting-with-completion",
                                                completion={"claim_id": "fixture"})
            self.m.run_once()
        queue.assert_called_once_with({"claim_id": "fixture"})
        result = self.m.jobs.get(job["id"])
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["result"]["dns_apply_job"]["id"], child["id"])
        self.assertEqual(self.fixture.post_count, 1)

    def test_unconfirmed_hosting_never_starts_record_configuration(self):
        self.fixture.mode = "timeout"
        with patch.object(self.m, "_queue_claim_completion") as queue:
            job = self.m.create_dns_hosting_job("example.test", "hosting-uncertain-completion",
                                                completion={"claim_id": "fixture"})
            self.m.run_once()
            queue.assert_not_called()
        self.assertEqual(self.m.jobs.get(job["id"])["status"], "unknown")


if __name__ == "__main__":
    unittest.main()

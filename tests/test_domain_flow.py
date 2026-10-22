"""Offline durable claim -> hosting -> preview -> validate/apply -> enable."""
import json
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

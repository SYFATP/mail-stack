"""Recover transient reads without replaying ambiguous DNS writes."""
import json
import time
import unittest
from unittest.mock import patch
import test_dynv6 as base
from api.providers.http import ProviderError


class DNSApplyRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = base.Dynv6Tests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)
        self.m, self.wire = self.fixture.m, self.fixture.wire

    def enqueue(self):
        plan = self.m.dns.preview("example.test")
        return self.m.dns.enqueue("example.test", plan["id"], "auto-apply-recovery-fixture",
                                  activate_on_success=True)

    def execute(self, job):
        c = self.m.db()
        try:
            with c:
                row = c.execute("SELECT result_json FROM domain_jobs WHERE id=?", (job["id"],)).fetchone()
                result = json.loads(row[0])
                result["retry_at"] = 0
                c.execute("UPDATE domain_jobs SET result_json=? WHERE id=?", (json.dumps(result), job["id"]))
        finally:
            c.close()
        self.assertTrue(self.m.run_once())
        return self.m.jobs.get(job["id"])

    def journal(self):
        c = self.m.db()
        try:
            return [dict(r) for r in c.execute("SELECT * FROM domain_dns_operations")]
        finally:
            c.close()

    def test_initial_inventory_failure_defers_and_eventually_queues_completion(self):
        job = self.enqueue()
        with patch.object(self.m.dns, "capture", side_effect=ProviderError(
                "provider_transport_or_json_error", uncertain=True)):
            waiting = self.execute(job)
        self.assertEqual(waiting["status"], "queued")
        self.assertEqual(waiting["step"], "dns_apply_waiting_upstream")
        self.assertEqual(self.fixture.writes(), [])
        done = self.execute(job)
        self.assertEqual(done["status"], "succeeded")
        self.assertEqual(done["result"]["completion_job"]["kind"], "dns_complete")
        self.assertEqual(len(self.fixture.writes()), 4)

    def test_failure_after_three_confirmed_writes_resumes_only_the_fourth(self):
        job = self.enqueue()
        request = self.wire.request
        def flaky(method, url, path, **kwargs):
            if method == "GET" and path.endswith("/records") and len(self.wire.records) == 3:
                confirmed = sum(op["status"] == "confirmed" for op in self.journal())
                if confirmed == 3:
                    raise ProviderError("provider_transport_or_json_error", uncertain=True)
            return request(method, url, path, **kwargs)
        with patch.object(self.wire, "request", side_effect=flaky):
            waiting = self.execute(job)
        self.assertEqual(waiting["status"], "queued")
        self.assertEqual(len(waiting["result"]["completed"]), 3)
        self.assertEqual(waiting["result"]["apply_recovery"]["index"], 3)
        done = self.execute(job)
        self.assertEqual(done["status"], "succeeded")
        self.assertEqual(len(self.fixture.writes()), 4)
        self.assertEqual([op["status"] for op in self.journal()], ["confirmed"] * 4)

    def test_uncertain_post_is_observed_without_adoption_or_replay(self):
        job = self.enqueue()
        self.wire.failure = "timeout"
        waiting = self.execute(job)
        self.assertEqual((waiting["status"], waiting["step"]), ("queued", "dns_apply_readback_pending"))
        self.assertEqual(len(self.fixture.writes()), 1)
        self.assertEqual(self.journal()[0]["status"], "unknown")
        done = self.execute(job)
        self.assertEqual(done["status"], "succeeded")
        self.assertEqual(len(self.fixture.writes()), 4)
        self.assertEqual(self.journal()[0]["status"], "observed")
        c = self.m.db()
        try:
            self.assertEqual(c.execute("SELECT count(*) FROM managed_dns_records").fetchone()[0], 3)
        finally:
            c.close()

    def test_post_success_then_verification_get_failure_uses_readback(self):
        job = self.enqueue()
        request = self.wire.request
        def flaky(method, url, path, **kwargs):
            if method == "GET" and path.endswith("/records") and self.wire.records:
                raise ProviderError("provider_http_503")
            return request(method, url, path, **kwargs)
        with patch.object(self.wire, "request", side_effect=flaky):
            waiting = self.execute(job)
        self.assertEqual(waiting["step"], "dns_apply_readback_pending")
        self.assertEqual(len(self.fixture.writes()), 1)
        self.assertEqual(self.execute(job)["status"], "succeeded")
        self.assertEqual(len(self.fixture.writes()), 4)

    def test_successful_write_not_yet_visible_is_read_back_without_replay(self):
        job = self.enqueue()
        request = self.wire.request
        def delayed(method, url, path, **kwargs):
            result = request(method, url, path, **kwargs)
            if method == "GET" and path.endswith("/records") and self.wire.records:
                return []
            return result
        with patch.object(self.wire, "request", side_effect=delayed):
            waiting = self.execute(job)
        self.assertEqual(waiting["step"], "dns_apply_readback_pending")
        self.assertEqual(len(self.fixture.writes()), 1)
        self.assertEqual(self.execute(job)["status"], "succeeded")
        self.assertEqual(len(self.fixture.writes()), 4)

    def test_missing_uncertain_write_waits_until_deadline_and_never_replays(self):
        job = self.enqueue()
        self.wire.failure = "timeout"
        self.execute(job)
        self.wire.records.clear()
        for _ in range(2):
            waiting = self.execute(job)
            self.assertEqual(waiting["status"], "queued")
        self.assertEqual(len(self.fixture.writes()), 1)
        c = self.m.db()
        try:
            with c:
                result = self.m.jobs.get(job["id"])["result"]
                result["apply_recovery"]["deadline"] = time.time() - 1
                c.execute("UPDATE domain_jobs SET result_json=? WHERE id=?", (json.dumps(result), job["id"]))
        finally:
            c.close()
        done = self.execute(job)
        self.assertEqual((done["status"], done["error_code"]), ("unknown", "dns_write_unconfirmed"))
        self.assertTrue(done["result"]["operation_id"])
        self.assertEqual(self.journal()[0]["status"], "unknown")
        self.assertEqual(len(self.fixture.writes()), 1)

    def test_conflicting_readback_stops_before_remaining_writes(self):
        job = self.enqueue()
        self.wire.failure = "timeout"
        self.execute(job)
        self.wire.records[0]["data"] = "foreign.example.test."
        done = self.execute(job)
        self.assertEqual((done["status"], done["error_code"]), ("unknown", "dns_readback_conflict"))
        self.assertEqual(len(self.fixture.writes()), 1)
        self.assertTrue(done["result"]["operation_id"])

    def test_unrelated_external_drift_during_readback_is_not_accepted(self):
        job = self.enqueue()
        self.wire.failure = "timeout"
        self.execute(job)
        self.wire.records.append({"id": 900, "zoneID": 100, "flags": 0, "weight": 0,
                                  "type": "TXT", "name": "external", "data": "preserve"})
        done = self.execute(job)
        self.assertEqual(done["status"], "unknown")
        self.assertEqual(done["error_code"], "dns_inventory_changed_during_write")
        self.assertEqual(len(self.fixture.writes()), 1)

    def test_readback_get_failure_retains_pending_operation_and_retries_only_reads(self):
        job = self.enqueue()
        self.wire.failure = "timeout"
        first = self.execute(job)
        with patch.object(self.m.dns, "capture", side_effect=ProviderError("provider_http_504")):
            second = self.execute(job)
        self.assertEqual(second["status"], "queued")
        self.assertEqual(second["result"]["operation_id"], first["result"]["operation_id"])
        self.assertEqual(len(self.fixture.writes()), 1)
        self.assertEqual(self.execute(job)["status"], "succeeded")
        self.assertEqual(len(self.fixture.writes()), 4)

    def test_completion_discovery_read_failure_retries_without_rewriting_dns(self):
        job = self.enqueue()
        with patch.object(self.m.dns_completion, "required", side_effect=ProviderError("provider_http_502")):
            waiting = self.execute(job)
        self.assertEqual(waiting["status"], "queued")
        self.assertEqual(waiting["result"]["apply_recovery"]["index"], 4)
        self.assertEqual(len(self.fixture.writes()), 4)
        self.assertEqual(self.execute(job)["status"], "succeeded")
        self.assertEqual(len(self.fixture.writes()), 4)

    def test_authentication_failure_is_terminal_without_retry(self):
        job = self.enqueue()
        with patch.object(self.m.dns, "capture", side_effect=ProviderError("provider_http_401")):
            done = self.execute(job)
        self.assertEqual(done["status"], "failed")
        self.assertEqual(self.fixture.writes(), [])

    def test_binding_change_while_waiting_never_continues_old_plan(self):
        job = self.enqueue()
        self.wire.failure = "timeout"
        self.execute(job)
        credential = self.m.add_dns_credential("dynv6", None, "changed", {"api_token": base.base.TOKEN})
        self.m.bind_dns_credential("example.test", credential["id"])
        done = self.execute(job)
        self.assertEqual(done["status"], "failed")
        self.assertEqual(len(self.fixture.writes()), 1)


if __name__ == "__main__":
    unittest.main()

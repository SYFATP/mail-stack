"""Real SQLite admission, overlapping DNS reads and serialized write fences."""
import collections
import copy
import json
import os
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from fastapi import HTTPException

import test_domain_control as base
from api.providers.http import ProviderError
from api.repositories.domain_jobs import JobConflict, job_concurrency
from api.workers.domain_jobs import DomainWorker


class DomainConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.case = base.P2Tests(methodName="runTest")
        self.case.setUp()
        self.addCleanup(self.case.tearDown)
        self.m = self.case.manager
        self.m.job_concurrency = 2
        self.names = getattr(self, "fixture_domains", ["one.test", "two.test", "three.test"])
        self.records = collections.defaultdict(list)
        self.guard = threading.Lock()
        self.sequence = 0
        self.read_hook = None
        self.write_hook = None
        self.case.http.callback = self.respond
        for name in self.names:
            self.case.domain(domain=name, receive_subdomains=False, enabled=False)
            key = self.case.root / "keys" / name / "default.txt"
            key.parent.mkdir(parents=True, exist_ok=True)
            key.write_text('"v=DKIM1; k=rsa; p=QUJD"')
            key.with_suffix(".private").write_text("fixture-private-key")
            credential = self.m.add_dns_credential("digitalplat", name, "fixture",
                {"api_token": base.TOKEN, "api_base": "https://dns.fixture.test"})
            self.m.bind_dns_credential(name, credential["id"])
        self.enterContext(patch.dict(os.environ, {"BREVO_DNS_SYNC_ENABLED": "0"}))
        self.enterContext(patch("api.services.readiness_refresh.smtp_submission_check",
            return_value={"status": "passed", "detail": "fixture_no_data"}))

    def respond(self, method, base_url, path, **kwargs):
        name = path.split("/")[2]
        if method == "GET":
            if self.read_hook:
                self.read_hook(name)
            with self.guard:
                return {"data": copy.deepcopy(self.records[name])}
        if method == "POST":
            if self.write_hook:
                self.write_hook(name)
            with self.guard:
                self.sequence += 1
                record = {"id": "fixture-" + str(self.sequence), **copy.deepcopy(kwargs["body"])}
                self.records[name].append(record)
                return {"data": copy.deepcopy(record)}
        raise AssertionError((method, path))

    def enqueue(self, name, key=None, activate=False):
        plan = self.m.dns.preview(name)
        return self.m.dns.enqueue(name, plan["id"], key or ("parallel-" + name),
                                  activate_on_success=activate)

    def raw(self, kind, scope, suffix):
        return self.m.jobs.enqueue(kind, scope, "parallel-raw-" + suffix, {})

    def test_atomic_admission_caps_two_and_excludes_active_namespaces(self):
        first = self.raw("dns_apply", "one.test", "first")
        same = self.raw("dns_apply", "one.test", "same")
        child = self.raw("dns_apply", "child.one.test", "child")
        second = self.raw("dns_validate", "two.test", "second")
        self.raw("dns_apply", "three.test", "third")
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.m.jobs.take(), range(8)))
        admitted = [job for job in results if job]
        self.assertEqual({job["id"] for job in admitted}, {first["id"], second["id"]})
        self.assertEqual(self.m.jobs.get(same["id"])["status"], "queued")
        self.assertEqual(self.m.jobs.get(child["id"])["status"], "queued")

    def test_exclusive_job_drains_pool_and_runs_alone(self):
        first = self.raw("dns_apply", "one.test", "first")
        self.m.jobs.take()
        exclusive = self.raw("claim", "source-fixture", "exclusive")
        later = self.raw("dns_apply", "two.test", "later")
        self.assertIsNone(self.m.jobs.take())
        self.m.jobs.finish(first["id"], "succeeded", step="fixture")
        self.assertEqual(self.m.jobs.take()["id"], exclusive["id"])
        self.assertIsNone(self.m.jobs.take())
        self.m.jobs.finish(exclusive["id"], "succeeded", step="fixture")
        self.assertEqual(self.m.jobs.take()["id"], later["id"])

    def test_dynv6_setup_backlog_does_not_idle_second_dns_worker(self):
        first = self.raw("dns_apply", "one.test", "first")
        self.assertEqual(self.m.jobs.take()["id"], first["id"])
        setup = self.m.jobs.enqueue("claim_setup", "three.test", "parallel-light-setup", {
            "configure_on_success": True, "hosting_provider": "dynv6"})
        second = self.raw("dns_apply", "two.test", "second")
        self.assertEqual(self.m.jobs.take()["id"], second["id"])
        self.assertEqual(self.m.jobs.get(setup["id"])["status"], "queued")

    def test_dynv6_registration_overlaps_other_domain_dns_but_not_another_registration(self):
        register = self.raw("dynv6_register", "one.test", "register-first")
        self.assertEqual(self.m.jobs.take()["id"], register["id"])
        another = self.raw("dynv6_register", "two.test", "register-second")
        peer = self.raw("dns_apply", "three.test", "register-peer")
        self.assertEqual(self.m.jobs.take()["id"], peer["id"])
        self.m.jobs.finish(peer["id"], "succeeded", step="fixture")
        self.assertIsNone(self.m.jobs.take())
        self.assertEqual(self.m.jobs.get(another["id"])["status"], "queued")
        self.m.jobs.finish(register["id"], "succeeded", step="fixture")
        self.assertEqual(self.m.jobs.take()["id"], another["id"])

    def test_finish_dns_before_starting_another_registration(self):
        registration = self.raw("dynv6_register", "one.test", "older-register")
        apply = self.raw("dns_apply", "two.test", "newer-apply")
        self.assertEqual(self.m.jobs.take()["id"], apply["id"])
        self.assertEqual(self.m.jobs.take()["id"], registration["id"])

    def test_running_light_setup_is_shareable_and_namespace_exclusion_stays(self):
        setup = self.m.jobs.enqueue("claim_setup", "one.test", "parallel-active-setup", {
            "configure_on_success": True, "hosting_provider": "dynv6"})
        self.assertEqual(self.m.jobs.take()["id"], setup["id"])
        child = self.raw("dns_apply", "child.one.test", "setup-child")
        peer = self.raw("dns_validate", "two.test", "setup-peer")
        self.assertEqual(self.m.jobs.take()["id"], peer["id"])
        self.assertEqual(self.m.jobs.get(child["id"])["status"], "queued")

    def test_other_setup_modes_still_drain_and_run_exclusively(self):
        for number, request in enumerate(({}, {"configure_on_success": False, "hosting_provider": "dynv6"},
                {"configure_on_success": True, "hosting_provider": "cloudflare"},
                {"configure_on_success": True, "hosting_provider": "dynv6", "configuration_only": True})):
            with self.subTest(request=request):
                first = self.raw("dns_apply", "one.test", "exclusive-first-" + str(number))
                self.assertEqual(self.m.jobs.take()["id"], first["id"])
                setup = self.m.jobs.enqueue("claim_setup", "two.test", "exclusive-setup-" + str(number), request)
                later = self.raw("dns_apply", "three.test", "exclusive-later-" + str(number))
                self.assertIsNone(self.m.jobs.take())
                self.m.jobs.finish(first["id"], "succeeded", step="fixture")
                ordered = (setup, later) if request.get("configuration_only") else (later, setup)
                self.assertEqual(self.m.jobs.take()["id"], ordered[0]["id"])
                self.assertIsNone(self.m.jobs.take())
                self.m.jobs.finish(ordered[0]["id"], "succeeded", step="fixture")
                self.assertEqual(self.m.jobs.take()["id"], ordered[1]["id"])
                self.m.jobs.finish(ordered[1]["id"], "succeeded", step="fixture")

    def test_serial_setting_retry_at_and_crash_recovery_are_retained(self):
        first = self.raw("dns_apply", "one.test", "first")
        later = self.raw("dns_apply", "two.test", "later")
        self.assertEqual(self.m.jobs.take(capacity=1)["id"], first["id"])
        self.assertIsNone(self.m.jobs.take(capacity=1))
        self.m.jobs.recover_interrupted()
        self.assertEqual(self.m.jobs.get(first["id"])["status"], "unknown")
        c = self.m.db()
        try:
            with c:
                c.execute("UPDATE domain_jobs SET result_json=? WHERE id=?",
                          (json.dumps({"retry_at": time.time() + 3600}), later["id"]))
        finally:
            c.close()
        self.assertIsNone(self.m.jobs.take())

    def test_active_domain_mutations_rejected_but_owner_can_activate(self):
        job = self.raw("dns_apply", "one.test", "first")
        self.m.jobs.take()
        row = self.m.domain("one.test")
        for name in ("one.test", "child.one.test"):
            with self.subTest(domain=name), self.assertRaises(HTTPException) as caught:
                self.m.save_domain({**row, "domain": name, "users": []})
            self.assertEqual(caught.exception.status_code, 409)
        self.raw("dns_apply", "leaf.parent.test", "parent-block")
        self.m.jobs.take()
        with self.assertRaises(HTTPException) as caught:
            self.m.save_domain({**row, "domain": "parent.test", "users": []})
        self.assertEqual(caught.exception.status_code, 409)
        with self.assertRaises(JobConflict):
            self.m.bind_dns_credential("one.test", row["dns_credential_ref"])
        with patch.object(base.app, "admin_ok", return_value=True), self.assertRaises(HTTPException) as caught:
            base.app.delete_mail_domain("one.test", "fixture")
        self.assertEqual(caught.exception.status_code, 409)
        self.m.save_domain({**self.m.domain("two.test"), "users": [], "enabled": True})
        with self.m.jobs.execution(job):
            self.m.save_domain({**row, "users": [], "enabled": True})
        with self.assertRaises(HTTPException):
            self.m.save_domain({**row, "users": []})

    def test_two_applies_overlap_reads_keep_write_gate_and_activate(self):
        jobs = [self.enqueue(name, activate=True) for name in self.names]
        entered = threading.Barrier(2)
        seen = set()
        write_active = write_peak = 0
        def read(name):
            with self.guard:
                first = name not in seen
                seen.add(name)
            if first:
                entered.wait(timeout=4)
            time.sleep(0.005)
        def write(name):
            nonlocal write_active, write_peak
            with self.guard:
                write_active += 1
                write_peak = max(write_peak, write_active)
            time.sleep(0.005)
            with self.guard:
                write_active -= 1
        self.read_hook, self.write_hook = read, write
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.m.run_once) for _ in range(2)]
            for future in futures:
                self.assertTrue(future.result(timeout=10))
        self.read_hook = None
        self.assertEqual(seen, set(self.names[:2]))
        self.assertEqual(write_peak, 1)
        for job in jobs[:2]:
            result = self.m.jobs.get(job["id"])
            self.assertEqual(result["status"], "succeeded", result)
            self.assertEqual(result["result"]["validation_status"], "passed")
            self.assertTrue(self.m.domain(job["scope"])["enabled"])
        self.assertEqual(self.m.jobs.get(jobs[2]["id"])["status"], "queued")
        self.assertTrue(self.m.run_once())

    def test_429_blocks_already_running_peer_before_next_dispatch(self):
        jobs = [self.enqueue(name) for name in self.names]
        entered = threading.Barrier(2)
        seen = set()
        writes = []
        def read(name):
            with self.guard:
                first = name not in seen
                seen.add(name)
            if first:
                entered.wait(timeout=4)
        def write(name):
            writes.append(name)
            raise ProviderError("provider_http_429", uncertain=True,
                                rate_limit={"code": "hosted_dns_daily_limit", "window": "day", "retry_after": 0})
        self.read_hook, self.write_hook = read, write
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.m.run_once) for _ in range(2)]
            for future in futures:
                self.assertTrue(future.result(timeout=10))
        self.assertEqual(len(writes), 1)
        results = [self.m.jobs.get(job["id"]) for job in jobs[:2]]
        self.assertEqual({job["status"] for job in results}, {"unknown", "failed"})
        backoffs = [job["result"]["provider_backoff"] for job in results]
        self.assertEqual(backoffs[0], backoffs[1])
        self.assertEqual(backoffs[0]["reset_time_source"], "assumed_utc_midnight")
        self.assertEqual(backoffs[0]["until"] % 86400, 0)
        self.assertGreater(backoffs[0]["until"], time.time())
        self.assertEqual(self.m.jobs.get(jobs[2]["id"])["status"], "queued")
        self.assertFalse(self.m.run_once())
        c = self.m.db()
        try:
            self.assertEqual(c.execute("SELECT count(*) FROM domain_dns_operations").fetchone()[0], 1)
        finally:
            c.close()

    def test_worker_starts_exactly_two_threads_and_recovers_only_once(self):
        worker = DomainWorker(self.m)
        barrier = threading.Barrier(3)
        def run():
            barrier.wait(timeout=4)
            worker.stop_event.wait(4)
        with patch.object(worker, "_run", side_effect=run), \
             patch.object(self.m.jobs, "recover_interrupted") as recover:
            worker.start()
            try:
                barrier.wait(timeout=4)
                worker.start()
                self.assertEqual(len(worker.threads), 2)
                self.assertEqual(worker.status(), {"concurrency": 2, "threads_alive": 2, "stopping": False})
                recover.assert_called_once()
            finally:
                worker.stop()
            self.assertTrue(all(not thread.is_alive() for thread in worker.threads))

    def test_concurrency_environment_is_bounded_and_can_restore_serial(self):
        for value, expected in (("1", 1), ("2", 2), ("99", 2), ("0", 1), ("bad", 2)):
            with self.subTest(value=value), patch.dict(os.environ, {"DOMAIN_JOB_CONCURRENCY": value}):
                self.assertEqual(job_concurrency(), expected)


if __name__ == "__main__":
    unittest.main()

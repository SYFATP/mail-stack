"""Bounded DNS concurrency, immutable preview fencing and isolated evidence."""
import collections
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import test_dns_reconcile as dnsbase
import test_domain_control as base
from api.services.dns_plan import DNSValidator
from api.repositories.domain_jobs import JobConflict


class DNSBatchPerformanceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = dnsbase.DNSWriteTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)
        self.m = self.fixture.m

    def test_previews_overlap_without_holding_global_lock_and_limit_upstream_load(self):
        original = self.m.dns.capture
        lock, release, filled = threading.Lock(), threading.Event(), threading.Event()
        active = peak = 0
        def capture(domain):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
                if active == 3:
                    filled.set()
            try:
                if not release.wait(5):
                    raise AssertionError('preview workers were not released')
                return original(domain)
            finally:
                with lock:
                    active -= 1
        with patch.object(self.m.dns, 'capture', side_effect=capture), ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(self.m.dns.preview, 'example.test') for _ in range(8)]
            try:
                self.assertTrue(filled.wait(3), 'Three upstream reads should overlap')
                acquired = self.m.lock.acquire(timeout=0.2)
                self.assertTrue(acquired, 'Upstream preview reads must not hold the global domain lock')
                if acquired:
                    self.m.lock.release()
            finally:
                release.set()
            plans = [future.result() for future in futures]
        self.assertEqual(peak, 3)
        self.assertEqual(len({plan['id'] for plan in plans}), 8)
        self.assertTrue(all(plan['executable'] for plan in plans))
        self.assertEqual(self.fixture.writes(), [])

    def test_configuration_change_during_upstream_read_rejects_preview(self):
        original = self.m.dns.plan_for
        def changed(row, **kwargs):
            self.fixture.edit(mx='changed.example.test')
            return original(row, **kwargs)
        with patch.object(self.m.dns, 'plan_for', side_effect=changed), self.assertRaises(JobConflict):
            self.fixture.preview()
        self.assertEqual(self.fixture.writes(), [])

    def test_credential_change_during_upstream_read_rejects_preview(self):
        credential = self.m.add_dns_credential('cloudflare', None, 'second', {'api_token': base.TOKEN})
        original = self.m.dns.plan_for
        def changed(row, **kwargs):
            self.m.bind_dns_credential('example.test', credential['id'])
            return original(row, **kwargs)
        with patch.object(self.m.dns, 'plan_for', side_effect=changed), self.assertRaises(JobConflict):
            self.fixture.preview()

    def test_key_change_during_upstream_read_rejects_preview(self):
        original = self.m.dns.plan_for
        def changed(row, **kwargs):
            (self.m.key_root / 'example.test/default.txt').write_text('"v=DKIM1; p=REVG"')
            return original(row, **kwargs)
        with patch.object(self.m.dns, 'plan_for', side_effect=changed), self.assertRaises(JobConflict):
            self.fixture.preview()

    def test_accepted_preview_survives_long_queue_but_still_fences_live_inventory(self):
        plan = self.fixture.preview()
        job = self.m.dns.enqueue('example.test', plan['id'], 'long-dns-queue-valid')
        with patch('api.services.dns_reconcile.time.time', return_value=plan['expires_at'] + 1200):
            self.m.run_once()
        self.assertEqual(self.m.jobs.get(job['id'])['status'], 'succeeded')
        plan = self.fixture.preview()
        job = self.m.dns.enqueue('example.test', plan['id'], 'long-dns-queue-stale')
        self.fixture.records.append({'id': 'foreign', 'type': 'A', 'name': 'example.test', 'content': '192.0.2.3'})
        writes = len(self.fixture.writes())
        with patch('api.services.dns_reconcile.time.time', return_value=plan['expires_at'] + 1200):
            self.m.run_once()
        self.assertEqual(self.m.jobs.get(job['id'])['status'], 'failed')
        self.assertEqual(len(self.fixture.writes()), writes)

    def test_expired_preview_cannot_be_queued_directly_to_bypass_acceptance(self):
        plan = self.fixture.preview()
        with patch('api.services.dns_reconcile.time.time', return_value=plan['expires_at'] + 1):
            job = self.m.jobs.enqueue('dns_apply', 'example.test', 'expired-direct-queue', {'plan_id': plan['id']})
            self.m.run_once()
        self.assertEqual(self.m.jobs.get(job['id'])['status'], 'failed')
        self.assertEqual(self.fixture.writes(), [])

    def test_validation_releases_global_domain_lock_after_confirmed_writes(self):
        original = self.m.validator.validate
        def validate(row, root):
            def probe_lock():
                acquired = self.m.lock.acquire(timeout=0.2)
                if acquired:
                    self.m.lock.release()
                return acquired
            with ThreadPoolExecutor(max_workers=1) as pool:
                self.assertTrue(pool.submit(probe_lock).result())
            return original(row, root)
        with patch.object(self.m.validator, 'validate', side_effect=validate):
            result = self.fixture.apply()
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(result['result']['validation_status'], 'passed')

    def test_resolver_queries_are_bounded_and_mx_host_evidence_is_shared_only_per_run(self):
        class Resolver(base.FakeResolver):
            def __init__(self):
                self.lock = threading.Lock()
                self.active = self.peak = 0
                self.calls = collections.Counter()
                self.fail = False
            def resolve(self, name, kind, **kwargs):
                with self.lock:
                    self.active += 1
                    self.peak = max(self.peak, self.active)
                    self.calls[(name, kind)] += 1
                try:
                    time.sleep(0.01)
                    if self.fail and name == 'mail.example.test' and kind == 'CNAME':
                        raise OSError('fixture DNS failure')
                    return super().resolve(name, kind, **kwargs)
                finally:
                    with self.lock:
                        self.active -= 1
        self.fixture.edit(receive_subdomains=True, max_subdomain_depth=3)
        resolver = Resolver()
        validator = DNSValidator(resolver)
        row = self.m.domain('example.test')
        first = validator.validate(row, self.m.key_root)
        self.assertTrue(all(check['status'] == 'passed' for check in first['checks'].values()))
        self.assertEqual([probe['depth'] for probe in first['wildcard_probes']], [0, 1, 2, 3])
        self.assertGreater(resolver.peak, 1)
        self.assertLessEqual(resolver.peak, 4)
        for kind in ['CNAME', 'A', 'AAAA']:
            self.assertEqual(resolver.calls[('mail.example.test', kind)], 1)
        self.assertEqual(sum(resolver.calls.values()), 11)
        resolver.fail = True
        second = validator.validate(row, self.m.key_root)
        self.assertEqual(resolver.calls[('mail.example.test', 'CNAME')], 2)
        self.assertEqual(second['checks']['mx']['status'], 'failed')
        self.assertEqual(second['checks']['wildcard_mx']['status'], 'failed')
        self.assertTrue(all(not probe['passed'] for probe in second['wildcard_probes']))
        self.assertNotEqual(first['wildcard_probes'][1]['name'], second['wildcard_probes'][1]['name'])


if __name__ == '__main__':
    unittest.main()

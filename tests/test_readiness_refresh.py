import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from test_domain_control import FakeResolver
from test_domain_routing import app
from api.services.dns_plan import DNSValidator
from api.services.domain_manager import DomainManager
from api.services.readiness_refresh import ReadinessRefresh, smtp_submission_check
from api.services.routing import config_hash
from api.workers.domain_jobs import DomainWorker


class FakeSMTP:
    def __init__(self, failure=None):
        self.calls = []
        self.failure = failure

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.calls.append(("close",))

    def _call(self, name, *args):
        self.calls.append((name, *args))
        return (550, b"private-upstream-text") if self.failure == name else (250, b"OK")

    def ehlo(self):
        return self._call("ehlo")

    def mail(self, value):
        return self._call("mail", value)

    def rcpt(self, value):
        return self._call("rcpt", value)

    def rset(self):
        return self._call("rset")

    def data(self, *args):
        raise AssertionError("readiness must never send DATA")

    def sendmail(self, *args):
        raise AssertionError("readiness must never submit a message")


class SMTPReadinessTests(unittest.TestCase):
    def test_envelope_probe_has_no_data_or_real_recipient(self):
        smtp = FakeSMTP()
        endpoints = []
        def factory(*args, **kwargs):
            endpoints.append((args, kwargs))
            return smtp
        with patch.dict(os.environ, {"SMTP_SUBMISSION_HOST": "local.fixture", "SMTP_SUBMISSION_PORT": "2525"}):
            result = smtp_submission_check({"domain": "example.test"}, smtp_factory=factory)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(endpoints, [(("local.fixture", 2525), {"timeout": 10})])
        self.assertEqual([c[0] for c in smtp.calls], ["ehlo", "mail", "rcpt", "rset", "close"])
        self.assertEqual(smtp.calls[2], ("rcpt", "readiness-probe@example.invalid"))

    def test_each_smtp_refusal_is_fail_closed_and_redacted(self):
        for operation in ("ehlo", "mail", "rcpt", "rset"):
            with self.subTest(operation=operation):
                result = smtp_submission_check({"domain": "example.test"},
                                               smtp_factory=lambda *a, **k: FakeSMTP(operation))
                self.assertEqual(result["status"], "failed")
                self.assertNotIn("private-upstream", json.dumps(result))

    def test_transport_exception_is_fail_closed_and_redacted(self):
        def factory(*args, **kwargs):
            raise RuntimeError("token-secret-must-not-leak")
        result = smtp_submission_check({"domain": "example.test"}, smtp_factory=factory)
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("token-secret", json.dumps(result))

    def test_invalid_port_never_connects(self):
        with patch.dict(os.environ, {"SMTP_SUBMISSION_PORT": "invalid"}), \
             patch("api.services.readiness_refresh.smtplib.SMTP") as factory:
            self.assertEqual(smtp_submission_check({"domain": "example.test"})["status"], "failed")
            factory.assert_not_called()


class ReadinessRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [
            patch.multiple(app, DB=self.root / "mail.db", RUNTIME_DIR=self.root / "runtime",
                           _schema_initialized=False),
            patch.dict(os.environ, {"DNS_CHECK_MAX_AGE_SECONDS": "3600",
                                    "DNS_READINESS_REFRESH_ENABLED": "1",
                                    "DNS_READINESS_SCAN_SECONDS": "30",
                                    "DNS_READINESS_RETRY_SECONDS": "60",
                                    "DNS_READINESS_BATCH_SIZE": "16"}),
        ]
        for p in self.patches:
            p.start()
        self.now = time.time()
        self.mono = 100
        self.manager = DomainManager(app.db, app._save_domain, app._domain_mutation_lock,
                                     validator=DNSValidator(FakeResolver()), key_root=self.root / "keys")
        self.scheduler = ReadinessRefresh(self.manager, clock=lambda: self.now, monotonic=lambda: self.mono)
        self.domain()
        c = app.db()
        digest = app.hashlib.sha256(("fixture" + os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
        c.execute("insert into api_keys(name,key_hash,scopes,created_at,global_access) values('fixture',?,'mail.read',?,1)",
                  (digest, time.time()))
        c.commit()
        c.close()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def domain(self, name="example.test", **options):
        app._save_domain({"domain": name, "enabled": True, "users": [], "receive_mode": "catch_all",
                          "receive_subdomains": False, "mx": "mail.example.test",
                          "spf": "v=spf1 ip4:203.0.113.10 -all", "dmarc": "v=DMARC1; p=none",
                          **options})
        path = self.root / "keys" / name / "default.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('default._domainkey IN TXT ("v=DKIM1; k=rsa; " "p=QUJD")')

    def checks(self, name="example.test", *, age=0, status="passed", revision=None, missing=None):
        revision = revision or config_hash(self.manager.domain(name))
        c = app.db()
        try:
            with c:
                for check in ("mx", "spf", "dkim", "dmarc", "smtp_submission"):
                    if check != missing:
                        c.execute("INSERT OR REPLACE INTO domain_checks VALUES(?,?,?,?,?,?)",
                                  (name, check, status, revision, self.now - age, "fixture"))
        finally:
            c.close()

    def advance(self, seconds=61):
        self.now += seconds
        self.mono += seconds

    def execute(self):
        with patch("api.services.readiness_refresh.smtplib.SMTP", side_effect=lambda *a, **k: FakeSMTP()):
            self.assertTrue(self.manager.run_once())

    def test_missing_checks_schedule_only_read_only_validation(self):
        jobs = self.scheduler.tick()
        self.assertEqual(len(jobs), 1)
        job = self.manager.jobs.get(jobs[0])
        self.assertEqual(job["kind"], "dns_validate")
        self.assertTrue(job["request"]["refresh_smtp_submission"])
        self.assertTrue(job["idempotency_key"].startswith("auto-readiness:"))

    def test_fresh_checks_do_not_enqueue(self):
        self.checks(age=1799)
        self.assertEqual(self.scheduler.tick(), [])

    def test_refresh_before_expiry_at_half_lifetime(self):
        self.checks(age=1800)
        self.assertEqual(len(self.scheduler.tick()), 1)

    def test_expired_checks_refresh_and_record_actual_smtp_probe(self):
        self.checks(age=7200)
        job = self.scheduler.tick()[0]
        self.execute()
        result = self.manager.jobs.get(job)
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["result"]["checks"]["smtp_submission"]["status"], "passed")
        c = app.db()
        try:
            rows = c.execute("SELECT * FROM domain_checks").fetchall()
            self.assertTrue(all(r["checked_at"] > self.now - 5 for r in rows))
            self.assertEqual(next(r for r in rows if r["check_name"] == "smtp_submission")["detail"],
                             "smtp_submission_envelope_accepted_no_data")
        finally:
            c.close()
        self.advance(31)
        self.assertEqual(self.scheduler.tick(), [])

    def test_missing_smtp_evidence_is_not_inferred_from_dns(self):
        self.checks(missing="smtp_submission")
        self.assertEqual(len(self.scheduler.tick()), 1)

    def test_revision_mismatch_and_future_timestamp_are_due(self):
        for kwargs in ({"revision": "old"}, {"age": -300}):
            with self.subTest(kwargs=kwargs):
                self.checks(**kwargs)
                self.assertEqual(len(self.scheduler.tick()), 1)
                self.execute()
                self.advance()

    def test_disabled_expired_released_domains_are_not_scheduled(self):
        c = app.db()
        try:
            for enabled, status in ((0, "imported"), (1, "released"), (1, "revoked"),
                                    (1, "expired"), (1, "releasing")):
                with c:
                    c.execute("UPDATE mail_domains SET enabled=?,source_status=?", (enabled, status))
                self.assertEqual(self.scheduler.tick(), [])
                self.advance()
        finally:
            c.close()

    def test_manual_queued_validation_blocks_automatic_duplicate(self):
        self.manager.create_validate_job("example.test", "manual-validation")
        self.assertEqual(self.scheduler.tick(), [])

    def test_active_automatic_job_blocks_duplicate_on_restart(self):
        first = self.scheduler.tick()
        other = ReadinessRefresh(self.manager, clock=lambda: self.now)
        self.assertEqual(other.tick(), [])
        self.assertEqual(self.manager.jobs.list()["total"], 1)
        self.assertEqual(len(first), 1)

    def test_failure_is_recorded_and_retried_with_backoff(self):
        job = self.scheduler.tick()[0]
        with patch.object(self.manager.validator, "validate", side_effect=RuntimeError("fixture")):
            self.assertTrue(self.manager.run_once())
        self.assertEqual(self.manager.jobs.get(job)["status"], "failed")
        self.advance(31)
        self.assertEqual(self.scheduler.tick(), [])
        self.advance(31)
        retry = self.scheduler.tick()
        self.assertEqual(len(retry), 1)
        self.assertNotEqual(retry[0], job)

    def test_dns_failure_is_not_relabelled_passed_or_retimestamped_old_pass(self):
        self.checks(age=7200)
        job = self.scheduler.tick()[0]
        original = self.manager.validator.validate
        def failed(row, root):
            result = original(row, root)
            result["checks"]["mx"] = {"status": "failed", "detail": "dns_query_failed"}
            return result
        with patch.object(self.manager.validator, "validate", side_effect=failed):
            self.execute()
        self.assertEqual(self.manager.jobs.get(job)["result"]["checks"]["mx"]["status"], "failed")
        c = app.db()
        row = c.execute("SELECT status FROM domain_checks WHERE check_name='mx'").fetchone()
        c.close()
        self.assertEqual(row["status"], "failed")

    def test_receive_only_domain_does_not_probe_smtp(self):
        c = app.db()
        with c:
            c.execute("UPDATE mail_domains SET send_enabled=0")
        c.close()
        self.scheduler.tick()
        with patch("api.services.readiness_refresh.smtplib.SMTP") as smtp:
            self.assertTrue(self.manager.run_once())
            smtp.assert_not_called()

    def test_config_change_during_validation_rejects_stale_results(self):
        job = self.scheduler.tick()[0]
        original = self.manager.validator.validate
        def changing(row, root):
            result = original(row, root)
            c = app.db()
            with c:
                c.execute("UPDATE mail_domains SET mx='changed.example.test'")
            c.close()
            return result
        with patch.object(self.manager.validator, "validate", side_effect=changing):
            self.execute()
        self.assertEqual(self.manager.jobs.get(job)["status"], "failed")
        c = app.db()
        self.assertEqual(c.execute("SELECT count(*) FROM domain_checks").fetchone()[0], 0)
        c.close()

    def test_interrupted_read_only_job_can_get_new_probe_but_no_claim_replayed(self):
        first = self.scheduler.tick()[0]
        self.manager.jobs.take()
        self.manager.jobs.recover_interrupted()
        self.assertEqual(self.manager.jobs.get(first)["status"], "unknown")
        self.advance()
        self.assertEqual(len(self.scheduler.tick()), 1)
        self.assertTrue(all(j["kind"] == "dns_validate" for j in self.manager.jobs.list()["items"]))

    def test_batch_limit_and_fairness(self):
        self.domain("second.test")
        with patch.dict(os.environ, {"DNS_READINESS_BATCH_SIZE": "1"}):
            first = self.scheduler.tick()[0]
            self.execute()
            self.advance()
            second = self.scheduler.tick()[0]
            self.assertNotEqual(self.manager.jobs.get(first)["scope"], self.manager.jobs.get(second)["scope"])

    def test_scheduler_can_be_disabled(self):
        with patch.dict(os.environ, {"DNS_READINESS_REFRESH_ENABLED": "0"}):
            self.assertEqual(self.scheduler.tick(), [])
        self.assertEqual(self.manager.jobs.list()["total"], 0)

    def test_invalid_intervals_use_defaults_and_scan_is_throttled(self):
        with patch.dict(os.environ, {"DNS_CHECK_MAX_AGE_SECONDS": "invalid",
                                    "DNS_READINESS_SCAN_SECONDS": "invalid"}):
            self.assertEqual(len(self.scheduler.tick()), 1)
            self.assertEqual(self.scheduler.tick(), [])

    def test_worker_calls_scheduler_and_validation_without_new_thread(self):
        worker = DomainWorker(self.manager)
        with patch.object(worker.readiness, "tick") as tick, \
             patch.object(self.manager, "run_once", side_effect=lambda: worker.stop_event.set() or True):
            worker._run()
            tick.assert_called_once()

    def test_worker_keeps_processing_when_scheduler_fails(self):
        worker = DomainWorker(self.manager)
        with patch.object(worker.readiness, "tick", side_effect=RuntimeError("fixture")), \
             patch.object(self.manager, "run_once", side_effect=lambda: worker.stop_event.set() or True) as run:
            worker._run()
            run.assert_called_once()

    def test_available_domains_recovers_and_stays_ready_beyond_original_ttl(self):
        self.checks(age=7200)
        with patch.object(app.AppliedStateSnapshot, "for_row", return_value={"status": "applied", "generation": "fixture"}), \
             patch.object(app, "key_ok", return_value=True), \
             patch("time.time", side_effect=lambda: self.now):
            self.assertEqual(app.available_domains("receive", "fixture")["items"], [])
            self.scheduler.tick()
            self.execute()
            self.assertEqual(app.available_domains("receive", "fixture")["items"][0]["domain"], "example.test")
            # Three half-life refreshes take us beyond the original one-hour
            # expiry. A fresh timestamp must come from a new real validation.
            for _ in range(3):
                self.advance(1801)
                self.assertEqual(len(self.scheduler.tick()), 1)
                self.execute()
                self.assertTrue(app.available_domains("receive", "fixture")["items"][0]["receive_ready"])

    def test_real_worker_thread_refreshes_without_manual_tick(self):
        worker = DomainWorker(self.manager)
        with patch("api.services.readiness_refresh.smtplib.SMTP", side_effect=lambda *a, **k: FakeSMTP()):
            worker.start()
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    items = self.manager.jobs.list()["items"]
                    if items and items[0]["status"] == "succeeded":
                        break
                    time.sleep(0.02)
                self.assertTrue(items)
                self.assertEqual(items[0]["status"], "succeeded")
            finally:
                worker.stop()

    def test_aged_auto_and_manual_validation_preempt_200_unrelated_applies(self):
        for number in range(200):
            self.manager.jobs.enqueue('dns_apply', f'batch-{number}.test',
                                      f'bulk-readiness-{number:03}', {'plan_id': 'fixture'})
        c = app.db()
        try:
            with c:
                c.execute("UPDATE domain_jobs SET created_at=? WHERE kind='dns_apply'", (self.now - 600,))
        finally:
            c.close()
        for key in ('auto-readiness:aged-fixture', 'explicit-aged-fixture'):
            job = self.manager.create_validate_job('example.test', key)
            c = app.db()
            try:
                with c:
                    c.execute('UPDATE domain_jobs SET created_at=? WHERE id=?', (self.now - 121, job['id']))
            finally:
                c.close()
            with patch('api.repositories.domain_jobs.time.time', return_value=self.now):
                self.assertEqual(self.manager.jobs.take()['id'], job['id'])
            self.manager.jobs.finish(job['id'], 'succeeded', step='fixture')
        self.assertEqual(self.manager.jobs.list(limit=200, status='queued')['total'], 200)

    def hold(self, job, **result):
        c = app.db()
        try:
            with c:
                c.execute("UPDATE domain_jobs SET result_json=?,created_at=? WHERE id=?",
                          (json.dumps(result), self.now - 600, job["id"]))
            return dict(c.execute("SELECT * FROM domain_jobs WHERE id=?", (job["id"],)).fetchone())
        finally:
            c.close()

    def test_incident_holds_never_dispatch_after_retry_deadline(self):
        from api.repositories.domain_jobs import DomainJobs
        jobs = []
        for kind in ("dns_apply", "dns_hosting", "dns_repair", "claim_setup"):
            job = self.manager.jobs.enqueue(kind, kind + ".test", "held-" + kind, {})
            self.hold(job, incident_hold="fixture-incident", retry_at=self.now - 1)
            jobs.append(job)
        restarted = DomainJobs(app.db)
        with patch("api.repositories.domain_jobs.time.time", return_value=self.now + 86400):
            self.assertIsNone(restarted.take())
            for job in jobs:
                current = restarted.get(job["id"])
                self.assertEqual(current["status"], "queued")
                self.assertEqual(current["wait_reason"], "incident_hold")
                self.assertIsNone(current["wait_until"])

    def test_paused_writer_allows_automatic_readiness_without_mutating_write_ledger(self):
        self.checks(age=7200)
        write = self.manager.jobs.enqueue("dns_apply", "example.test", "held-auto-fixture", {})
        before = self.hold(write, incident_hold="fixture-incident", retry_at=self.now - 1)
        ids = self.scheduler.tick()
        self.assertEqual(len(ids), 1)
        self.assertEqual(self.scheduler.tick(), [])
        self.execute()
        validation = self.manager.jobs.get(ids[0])
        self.assertEqual(validation["status"], "succeeded")
        self.assertTrue(validation["automatic"])
        self.assertTrue(validation["read_only"])
        c = app.db()
        try:
            self.assertEqual(dict(c.execute("SELECT * FROM domain_jobs WHERE id=?", (write["id"],)).fetchone()), before)
            checks = {r["check_name"]: dict(r) for r in c.execute("SELECT * FROM domain_checks")}
            for name in ("mx", "spf", "dkim", "dmarc", "smtp_submission"):
                self.assertEqual(checks[name]["status"], "passed")
                self.assertGreater(checks[name]["checked_at"], self.now - 5)
            self.assertEqual(c.execute("SELECT count(*) FROM domain_dns_operations").fetchone()[0], 0)
        finally:
            c.close()
        self.assertIsNone(self.manager.jobs.take())
        with patch.object(app.AppliedStateSnapshot, "for_row", return_value={"status": "applied", "generation": "fixture"}), \
             patch.object(app, "key_ok", return_value=True):
            self.assertTrue(app.available_domains("receive", "fixture")["items"][0]["receive_ready"])

    def test_future_retry_and_provider_cooldown_allow_same_namespace_reads(self):
        self.domain(dns_provider="digitalplat")
        write = self.manager.jobs.enqueue("dns_apply", "example.test", "waiting-writer-fixture", {})
        self.hold(write, retry_at=self.now + 60)
        for reason in ("retry_at", "provider_cooldown"):
            with self.subTest(reason=reason):
                if reason == "provider_cooldown":
                    self.hold(write, provider_backoff={"provider": "digitalplat", "until": self.now + 60})
                with patch("api.repositories.domain_jobs.time.time", return_value=self.now):
                    summary = self.manager.jobs.list()["active_domain_jobs"][0]
                    self.assertEqual(summary["wait_reason"], reason)
                    self.assertEqual(summary["wait_until"], self.now + 60)
                    self.assertNotIn("request", summary)
                    self.assertNotIn("result", summary)
                    validation = self.scheduler.tick()[0]
                    self.assertEqual(self.manager.jobs.take()["id"], validation)
                    self.manager.jobs.finish(validation, "succeeded", step="fixture")
                    self.assertIsNone(self.manager.jobs.take())
                self.advance(61)
                # The next subcase gets a new pause and idempotency window.
                c = app.db()
                try:
                    with c:
                        c.execute("UPDATE domain_jobs SET updated_at=? WHERE id=?", (self.now - 61, validation))
                finally:
                    c.close()
        with patch("api.repositories.domain_jobs.time.time", return_value=self.now + 61):
            self.assertEqual(self.manager.jobs.take()["id"], write["id"])

    def test_held_exclusive_writer_does_not_drain_read_pool(self):
        self.domain("other.test")
        held = self.manager.jobs.enqueue("dns_hosting", "example.test", "held-exclusive-fixture", {})
        self.hold(held, incident_hold="fixture-incident")
        first = self.manager.create_validate_job("other.test", "first-read-fixture")
        second = self.manager.create_validate_job("example.test", "second-read-fixture")
        self.assertEqual(self.manager.jobs.take()["id"], first["id"])
        self.assertEqual(self.manager.jobs.take()["id"], second["id"])
        self.assertIsNone(self.manager.jobs.take())

    def test_running_same_namespace_write_still_blocks_readiness(self):
        writer = self.manager.jobs.enqueue("dns_apply", "example.test", "running-write-fixture", {})
        self.assertEqual(self.manager.jobs.take()["id"], writer["id"])
        self.assertEqual(self.scheduler.tick(), [])
        read = self.manager.create_validate_job("example.test", "running-read-fixture")
        self.assertIsNone(self.manager.jobs.take())
        self.manager.jobs.finish(writer["id"], "succeeded", step="fixture")
        self.assertEqual(self.manager.jobs.take()["id"], read["id"])

    def test_validation_waits_for_earlier_same_domain_write(self):
        cases = [('dns_apply', 121), ('dns_hosting', 121), ('dns_repair', 121),
                 ('dns_hosting', 1), ('dns_repair', 1)]
        for number, (kind, age) in enumerate(cases):
            with self.subTest(kind=kind, age=age):
                write = self.manager.jobs.enqueue(kind, 'example.test', f'dependent-apply-{number}', {'plan_id': 'fixture'})
                validation = self.manager.create_validate_job('example.test', f'dependent-check-{number}')
                c = app.db()
                try:
                    with c:
                        c.execute('UPDATE domain_jobs SET created_at=? WHERE id=?', (self.now - 600, write['id']))
                        c.execute('UPDATE domain_jobs SET created_at=? WHERE id=?', (self.now - age, validation['id']))
                finally:
                    c.close()
                with patch('api.repositories.domain_jobs.time.time', return_value=self.now):
                    self.assertEqual(self.manager.jobs.take()['id'], write['id'])
                    self.manager.jobs.finish(write['id'], 'succeeded', step='fixture')
                    self.assertEqual(self.manager.jobs.take()['id'], validation['id'])
                    self.manager.jobs.finish(validation['id'], 'succeeded', step='fixture')

    def test_aged_validation_respects_future_retry_time(self):
        write = self.manager.jobs.enqueue('dns_apply', 'batch.test', 'deferred-apply-fixture', {'plan_id': 'fixture'})
        validation = self.manager.create_validate_job('example.test', 'deferred-check-fixture')
        c = app.db()
        try:
            with c:
                c.execute('UPDATE domain_jobs SET created_at=?,result_json=? WHERE id=?',
                          (self.now - 600, json.dumps({'retry_at': self.now + 60}), validation['id']))
        finally:
            c.close()
        with patch('api.repositories.domain_jobs.time.time', return_value=self.now):
            self.assertEqual(self.manager.jobs.take()['id'], write['id'])
        with patch('api.repositories.domain_jobs.time.time', return_value=self.now + 61):
            self.assertEqual(self.manager.jobs.take()['id'], validation['id'])

    def test_provider_cooldown_survives_repository_reload_and_leaves_reads_eligible(self):
        from api.providers.http import ProviderError
        from api.repositories.domain_jobs import DomainJobs
        self.domain(dns_provider='digitalplat')
        self.domain('second.test', dns_provider='digitalplat')
        first = self.manager.jobs.enqueue('dns_apply', 'example.test', 'rate-first-fixture', {})
        self.manager.jobs.take()
        with patch('api.repositories.domain_jobs.time.time', return_value=self.now):
            metadata = self.manager.jobs.provider_backoff('example.test', ProviderError('provider_http_429', uncertain=True, retry_after=900))
            self.manager.jobs.finish(first['id'], 'unknown', step='fixture', result=metadata, error='provider_http_429')
        pending = self.manager.jobs.enqueue('dns_apply', 'example.test', 'rate-pending-fixture', {})
        probe = self.manager.create_validate_job('second.test', 'rate-probe-fixture')
        restarted = DomainJobs(app.db)
        with patch('api.repositories.domain_jobs.time.time', return_value=self.now + 1):
            self.assertEqual(restarted.take()['id'], probe['id'])
            restarted.finish(probe['id'], 'succeeded', step='fixture')
            self.assertIsNone(restarted.take())
        self.assertEqual(restarted.get(first['id'])['status'], 'unknown')
        with patch('api.repositories.domain_jobs.time.time', return_value=self.now + 901):
            self.assertEqual(restarted.take()['id'], pending['id'])

    def test_provider_cooldown_is_scoped_and_defaults_to_five_minutes(self):
        from api.providers.http import ProviderError
        self.domain(dns_provider='digitalplat')
        self.domain('second.test', dns_provider='cloudflare')
        first = self.manager.jobs.enqueue('dns_apply', 'example.test', 'rate-default-first', {})
        self.manager.jobs.take()
        with patch('api.repositories.domain_jobs.time.time', return_value=self.now):
            metadata = self.manager.jobs.provider_backoff('example.test', ProviderError('provider_http_429', uncertain=True))
            self.assertEqual(metadata['provider_backoff']['until'], self.now + 300)
            self.manager.jobs.finish(first['id'], 'unknown', step='fixture', result=metadata)
        self.manager.jobs.enqueue('dns_hosting', 'example.test', 'rate-hosting-fixture', {})
        other = self.manager.jobs.enqueue('dns_apply', 'second.test', 'rate-other-fixture', {})
        with patch('api.repositories.domain_jobs.time.time', return_value=self.now + 1):
            self.assertEqual(self.manager.jobs.take()['id'], other['id'])
        self.assertEqual(self.manager.jobs.provider_backoff('example.test', ProviderError('provider_http_500')), {})

    def test_other_provider_daily_and_hourly_fallbacks_honor_explicit_delay(self):
        from api.providers.http import ProviderError
        self.domain(dns_provider="cloudflare")
        with patch('api.repositories.domain_jobs.time.time', return_value=self.now):
            for window, expected in (("day", 86400), ("hour", 3600)):
                result = self.manager.jobs.provider_backoff('example.test', ProviderError(
                    'provider_http_429', uncertain=True, rate_limit={"window": window}))
                self.assertEqual(result['provider_backoff']['until'], self.now + expected)
            result = self.manager.jobs.provider_backoff('example.test', ProviderError(
                'provider_http_429', uncertain=True, retry_after=900, rate_limit={"window": "day"}))
            self.assertEqual(result['provider_backoff']['until'], self.now + 900)

    def test_digitalplat_daily_fallback_uses_next_utc_midnight_including_boundaries(self):
        from datetime import datetime, timezone
        from api.providers.http import ProviderError
        self.domain(dns_provider="digitalplat")
        next_day = datetime(2026, 10, 20, tzinfo=timezone.utc).timestamp()
        for now in (next_day - 86400, next_day - 43200, next_day - 1, next_day - 0.25):
            with self.subTest(now=now), patch('api.repositories.domain_jobs.time.time', return_value=now), \
                 patch.dict(os.environ, {"TZ": "Asia/Shanghai"}):
                result = self.manager.jobs.provider_backoff('example.test', ProviderError(
                    'provider_http_429', uncertain=True, rate_limit={"window": "day"}))['provider_backoff']
                self.assertEqual(result['until'], next_day)
                self.assertEqual(result['reset_time_source'], 'assumed_utc_midnight')
                self.assertGreaterEqual(result['retry_after_seconds'], 1)
                self.assertLessEqual(result['retry_after_seconds'], 86400)

    def test_digitalplat_daily_code_works_without_window_and_explicit_delay_wins(self):
        from api.providers.http import ProviderError
        self.domain(dns_provider="digitalplat")
        midnight = 86400 * 20000
        now = midnight - 10
        with patch('api.repositories.domain_jobs.time.time', return_value=now):
            error = ProviderError('provider_http_429', uncertain=True,
                                 rate_limit={"code": "hosted_dns_daily_limit", "window": ""})
            result = self.manager.jobs.provider_backoff('example.test', error)['provider_backoff']
            self.assertEqual(result['until'], midnight)
            error = ProviderError('provider_http_429', uncertain=True, retry_after=900,
                                 rate_limit={"code": "hosted_dns_daily_limit", "window": "day"})
            result = self.manager.jobs.provider_backoff('example.test', error)['provider_backoff']
            self.assertEqual(result['until'], now + 900)
            self.assertNotIn('reset_time_source', result)

    def test_midnight_cooldown_survives_reload_and_does_not_replay_unknown_write(self):
        from api.providers.http import ProviderError
        from api.repositories.domain_jobs import DomainJobs
        self.domain(dns_provider="digitalplat")
        first = self.manager.jobs.enqueue('dns_apply', 'example.test', 'midnight-first-fixture', {})
        self.manager.jobs.take()
        midnight = 86400 * 20000
        with patch('api.repositories.domain_jobs.time.time', return_value=midnight - 0.5):
            backoff = self.manager.jobs.provider_backoff('example.test', ProviderError(
                'provider_http_429', uncertain=True, rate_limit={"window": "day"}))
            self.manager.jobs.finish(first['id'], 'unknown', step='fixture', result=backoff)
        pending = self.manager.jobs.enqueue('dns_apply', 'example.test', 'midnight-next-fixture', {})
        restarted = DomainJobs(app.db)
        with patch('api.repositories.domain_jobs.time.time', return_value=midnight - 0.25):
            self.assertIsNone(restarted.take())
            with self.assertRaises(ProviderError) as caught:
                restarted.check_provider_backoff('digitalplat')
            inherited = restarted.provider_backoff('example.test', caught.exception)
            self.assertEqual(inherited, backoff)
        with patch('api.repositories.domain_jobs.time.time', return_value=midnight):
            # A peer fenced before midnight may persist after midnight. It must
            # retain the expired deadline rather than start another cooldown.
            self.assertEqual(restarted.provider_backoff('example.test', caught.exception), backoff)
            restarted.check_provider_backoff('digitalplat')
            self.assertEqual(restarted.take()['id'], pending['id'])
        self.assertEqual(restarted.get(first['id'])['status'], 'unknown')

    def test_manual_dns_validation_keeps_existing_no_smtp_contract(self):
        job = self.manager.create_validate_job("example.test", "manual-no-smtp-fixture")
        with patch("api.services.readiness_refresh.smtplib.SMTP") as smtp:
            self.assertTrue(self.manager.run_once())
            smtp.assert_not_called()
        self.assertNotIn("smtp_submission", self.manager.jobs.get(job["id"])["result"]["checks"])


if __name__ == "__main__":
    unittest.main()

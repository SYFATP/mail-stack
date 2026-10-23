import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from test_domain_routing import app
from api.providers.http import ProviderError, validate_base_url
from api.providers.projections import public_items
from api.providers.dns.cloudflare import CloudflareDNS
from api.providers.dns.digitalplat import DigitalPlatDNS
from api.repositories.credentials import CredentialStore, CredentialError
from api.repositories.domain_jobs import JobConflict
from api.services.domain_manager import DomainManager
from api.services.dns_plan import DNSValidator
from api.routers.domain_control import build_router
from fastapi import FastAPI

TOKEN = 'fixture-secret-must-not-leak'


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.payload = {"data": [{"domain": "claimed.test", "claim_id": "upstream-1", "status": "active",
            "dns": {"token": TOKEN, "api_base": "https://dns.fixture.test/api/v1"}, "hidden_secret": TOKEN}]}
        self.failure = None
        self.callback = None

    def request(self, method, base, path, **kwargs):
        self.calls.append((method, base, path, kwargs))
        if self.callback:
            return self.callback(method, base, path, **kwargs)
        if self.failure:
            raise self.failure
        return self.payload


class FakeResolver:
    def resolve(self, name, kind, **kwargs):
        if kind == 'MX':
            return [SimpleNamespace(exchange='mail.example.test.')]
        if kind == 'A':
            return ['203.0.113.10']
        if kind in {'AAAA', 'CNAME'}:
            return []
        if kind == 'TXT':
            if name.startswith('_dmarc.'):
                txt = 'v=DMARC1; p=none'
            elif '._domainkey.' in name:
                txt = 'v=DKIM1; k=rsa; p=QUJD'
            else:
                txt = 'v=spf1 ip4:203.0.113.10 -all'
            return [SimpleNamespace(strings=[txt[:10].encode(), txt[10:].encode()])]
        return []


class P2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state_patch = patch.multiple(app, DB=self.root / 'mail.db', RUNTIME_DIR=self.root / 'runtime', _schema_initialized=False)
        self.state_patch.start()
        self.key = Fernet.generate_key().decode()
        self.factory = lambda: CredentialStore({'v1': self.key}, 'v1')
        self.http = FakeTransport()
        self.manager = DomainManager(app.db, app._save_domain, app._domain_mutation_lock,
            transport=self.http, credential_factory=self.factory, validator=DNSValidator(FakeResolver()), key_root=self.root / 'keys')
        api = FastAPI()
        api.include_router(build_router(self.manager, lambda key, password: key == 'admin-fixture'))
        self.client = TestClient(api)
        self.headers = {'X-API-Key': 'admin-fixture'}

    def tearDown(self):
        self.client.close()
        self.state_patch.stop()
        self.temp.cleanup()

    def source(self, kind='sfreg_mx'):
        fields = {'sfreg_mx': {'api_key': TOKEN}, 'legacy_digitalplat_pool': {'admin_key': TOKEN}, 'cloudflare_import': {'api_token': TOKEN}}
        base = 'https://api.cloudflare.com/client/v4' if kind == 'cloudflare_import' else 'https://source.fixture.test'
        return self.manager.create_source('fixture', kind, base, 'immutable-client', fields[kind])

    def domain(self, **kwargs):
        result = app._save_domain({'domain': 'example.test', 'enabled': True, 'users': [], 'receive_mode': 'catch_all',
            'receive_subdomains': True, 'max_subdomain_depth': 3, 'mx': 'mail.example.test',
            'spf': 'v=spf1 ip4:203.0.113.10 -all', 'dmarc': 'v=DMARC1; p=none', 'dns_provider': 'manual', **kwargs})
        key = self.root / 'keys/example.test/default.txt'
        key.parent.mkdir(parents=True, exist_ok=True)
        key.write_text('default._domainkey IN TXT ("v=DKIM1; k=rsa; " "p=QUJD")')
        return result

    def test_migration_v3_is_additive_and_repeatable(self):
        self.domain()
        c = app.db()
        app.migrate(c); c.commit()
        self.assertEqual([r[0] for r in c.execute('SELECT version FROM schema_migrations ORDER BY version')], list(range(1, 16)))
        self.assertEqual(c.execute('SELECT count(*) FROM mail_domains').fetchone()[0], 1)
        c.close()

    def test_credential_ciphertext_and_public_projection(self):
        source = self.source()
        c = app.db()
        row = c.execute('SELECT * FROM dns_credentials').fetchone()
        self.assertNotIn(TOKEN, row['ciphertext'])
        self.assertEqual(self.factory().get(c, row['id'])['api_key'], TOKEN)
        self.assertNotIn(TOKEN, json.dumps(source))
        self.assertNotIn(TOKEN, json.dumps(CredentialStore.public(c)))
        c.close()

    def test_key_configuration_strict_and_missing_key_fail_closed(self):
        with self.assertRaises(CredentialError):
            CredentialStore({'v1': 'arbitrary-passphrase'}, 'v1')
        with self.assertRaises(CredentialError):
            CredentialStore({}, '').require_writer()
        with patch.object(self.manager, 'credentials', return_value=CredentialStore({}, '')):
            with self.assertRaises(CredentialError):
                self.source()
        self.assertEqual(self.manager.sources(), [])

    def test_context_binding_detects_swapped_ciphertext(self):
        source = self.source()
        c = app.db()
        row = c.execute('SELECT * FROM dns_credentials').fetchone()
        with c:
            second = self.factory().put(c, 'sfreg_mx', {'api_key': 'second'})
            c.execute('UPDATE dns_credentials SET ciphertext=? WHERE id=?', (row['ciphertext'], second))
        with self.assertRaises(CredentialError):
            self.factory().get(c, second)
        with self.assertRaises(CredentialError):
            self.factory().get(c, source['credential_ref'], provider='digitalplat')
        c.close()

    def test_key_rotation_rewrap_retains_context(self):
        source = self.source()
        new_key = Fernet.generate_key().decode()
        store = CredentialStore({'v1': self.key, 'v2': new_key}, 'v2')
        c = app.db()
        with c:
            store.rewrap(c, source['credential_ref'])
        self.assertEqual(CredentialStore({'v2': new_key}, 'v2').get(c, source['credential_ref'])['api_key'], TOKEN)
        c.close()

    def test_claim_idempotency_payload_conflict_and_concurrency(self):
        source = self.source()
        def enqueue(_):
            return self.manager.create_claim_job(source['id'], 'same-key-001')['id']
        with ThreadPoolExecutor(max_workers=8) as pool:
            ids = list(pool.map(enqueue, range(12)))
        self.assertEqual(len(set(ids)), 1)
        with self.assertRaises(JobConflict):
            self.manager.create_claim_job(source['id'], 'same-key-001', local_part='different')
        self.assertEqual(self.http.calls, [])

    def test_sfreg_claim_saves_ownership_credentials_and_disabled_domain(self):
        source = self.source()
        job = self.manager.create_claim_job(source['id'], 'claim-fixture-001')
        self.assertTrue(self.manager.run_once())
        result = self.manager.jobs.get(job['id'])
        self.assertEqual(result['status'], 'succeeded')
        row = self.manager.domain('claimed.test')
        self.assertFalse(row['enabled'])
        self.assertEqual(row['source_status'], 'claimed')
        self.assertEqual(row['source_id'], source['id'])
        claim = self.manager.claims()[0]
        self.assertEqual(claim['client_id'], 'immutable-client')
        self.assertEqual(claim['upstream_claim_id'], 'upstream-1')
        self.assertEqual(self.http.calls[0][0], 'POST')
        request = self.http.calls[0][3]
        self.assertEqual(request['headers']['Idempotency-Key'], job['upstream_idempotency_key'])
        self.assertEqual(request['body']['client_id'], 'immutable-client')
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn(TOKEN, json.dumps(self.manager.claims()))
        c = app.db()
        secret = self.factory().get(c, claim['dns_credential_ref'], provider='digitalplat', domain='claimed.test')
        self.assertEqual(secret['api_token'], TOKEN)
        c.close()
        self.assertFalse(self.manager.run_once())

    def test_claim_refresh_keeps_existing_domains_ready_during_routing_publish(self):
        self.domain(claim_id="existing-claim", source_type="sfreg_mx", source_status="claimed")
        private_key = self.root / "keys/example.test/default.private"
        private_key.write_text("fixture-private-key")
        existing = self.manager.domain("example.test")
        c = app.db()
        with c:
            for name in ("mx", "spf", "dkim", "dmarc", "smtp_submission", "wildcard_mx"):
                c.execute("INSERT INTO domain_checks(domain,check_name,status,config_hash,checked_at) VALUES(?,?,?,?,?)",
                          ("example.test", name, "passed", app.config_hash(existing), time.time()))
        c.close()
        generation = (app.RUNTIME_DIR / "routing.current").read_text().strip()
        (app.RUNTIME_DIR / "postfix-applied.json").write_text(json.dumps({
            "generation": generation, "status": "applied", "applied_at": time.time()}))
        source = self.source()
        # The second allocation is inside the existing domain's namespace.
        # Only that domain must wait for the changed wildcard routes to apply.
        self.http.payload = {"data": [
            {"domain": "claimed.test", "claim_id": "upstream-1", "dns": {"token": TOKEN}},
            {"domain": "child.example.test", "claim_id": "upstream-2", "dns": {"token": TOKEN}},
        ]}
        observations = []
        save = self.manager.save_domain

        def save_and_refresh(*args):
            result = save(*args)
            observations.append(app._domain_public(self.manager.domain("example.test")))
            return result

        def mapped_path(value):
            return self.root / "keys" if value == "/dkim/keys" else Path(value)

        with patch.object(app, "Path", side_effect=mapped_path):
            before = app._domain_public(existing)
            self.assertTrue(before["receive_ready"])
            self.assertTrue(before["send_ready"])
            job = self.manager.create_claim_job(source["id"], "claim-refresh-readiness", count=2)
            with patch.object(self.manager, "save_domain", side_effect=save_and_refresh):
                self.assertTrue(self.manager.run_once())
            self.assertEqual(self.manager.jobs.get(job["id"])["status"], "succeeded")
            self.assertEqual(app.applied_state(app.RUNTIME_DIR)["status"], "pending")
            self.assertTrue(observations[0]["receive_ready"], "Unrelated claim must preserve existing readiness")
            self.assertTrue(observations[0]["subdomain_receive_ready"])
            self.assertTrue(observations[0]["send_ready"])
            self.assertFalse(observations[1]["receive_ready"], "New child policy must await its routing ACK")
            self.assertFalse(observations[1]["subdomain_receive_ready"])
            claimed = app._domain_public(self.manager.domain("claimed.test"))
            self.assertFalse(claimed["enabled"])
            self.assertFalse(claimed["receive_ready"])
            self.assertFalse(claimed["send_ready"])
            current = (app.RUNTIME_DIR / "routing.current").read_text().strip()
            (app.RUNTIME_DIR / "postfix-applied.json").write_text(json.dumps({
                "generation": current, "status": "applied", "applied_at": time.time()}))
            after = app._domain_public(self.manager.domain("example.test"))
            self.assertTrue(after["receive_ready"])
            self.assertTrue(after["subdomain_receive_ready"])

    def test_sfreg_claim_auto_registers_brevo_domain(self):
        source = self.source()
        brevo_record = {
            'domain_name': 'claimed.test',
            'dns_records': {
                'brevo_code': {
                    'type': 'TXT',
                    'host_name': 'claimed',
                    'value': 'brevo-code:fixture',
                },
            },
        }

        def callback(method, base, path, **kwargs):
            if base == 'https://api.brevo.com':
                if method == 'GET':
                    raise ProviderError('provider_http_404')
                if method == 'POST':
                    return brevo_record
            return self.http.payload

        self.http.callback = callback
        with patch.dict(os.environ, {'BREVO_API_KEY': 'brevo-fixture', 'BREVO_DNS_SYNC_ENABLED': '1'}, clear=False):
            job = self.manager.create_claim_job(source['id'], 'claim-brevo-fixture-001')
            self.assertTrue(self.manager.run_once())
        result = self.manager.jobs.get(job['id'])
        self.assertEqual(result['status'], 'succeeded')
        item = result['result']['items'][0]
        self.assertEqual(item['brevo_registration'], {'status': 'registered', 'created': True})
        self.assertEqual(
            [(method, path) for method, base, path, _ in self.http.calls if base == 'https://api.brevo.com'],
            [('GET', '/v3/senders/domains/claimed.test'), ('POST', '/v3/senders/domains')],
        )

    def test_brevo_dns_preview_repairs_missing_registration(self):
        self.domain(receive_subdomains=False, enabled=False)
        brevo_record = {
            'domain_name': 'example.test',
            'dns_records': {
                'brevo_code': {
                    'type': 'TXT',
                    'host_name': 'example',
                    'value': 'brevo-code:fixture',
                },
            },
        }

        def callback(method, base, path, **kwargs):
            if base == 'https://api.brevo.com':
                if method == 'GET':
                    raise ProviderError('provider_http_404')
                if method == 'POST':
                    return brevo_record
            return {'result': [{'id': 'zone-fixture', 'name': 'example.test', 'status': 'active'}]}

        self.http.callback = callback
        row = self.manager.domain('example.test')
        with patch.dict(os.environ, {'BREVO_API_KEY': 'brevo-fixture', 'BREVO_DNS_SYNC_ENABLED': '1'}, clear=False):
            targets = self.manager.brevo_dns_targets(row)
        self.assertEqual(targets[0]['role'], 'brevo_auth')
        self.assertEqual(targets[0]['name'], 'example.test')
        self.assertEqual(
            [(method, path) for method, base, path, _ in self.http.calls if base == 'https://api.brevo.com'],
            [('GET', '/v3/senders/domains/example.test'), ('POST', '/v3/senders/domains')],
        )

    def test_dns_validation_retries_brevo_authentication_after_dns_is_ready(self):
        self.domain(receive_subdomains=False, enabled=False)
        with patch.dict(os.environ, {'BREVO_DNS_SYNC_ENABLED': '1'}, clear=False), \
             patch.object(self.manager, 'brevo_authentication_result', return_value={
                 'status': 'authenticated', 'authenticated': True, 'verified': True,
             }) as authenticate:
            job = self.manager.create_validate_job('example.test', 'brevo-auth-validation-001')
            self.assertTrue(self.manager.run_once())
        result = self.manager.jobs.get(job['id'])
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(result['result']['brevo_authentication']['status'], 'authenticated')
        authenticate.assert_called_once_with('example.test')

    def test_brevo_authentication_reads_provider_state_after_request(self):
        self.domain(receive_subdomains=False, enabled=False)
        responses = iter([
            {'domain_name': 'example.test', 'authenticated': False, 'verified': False},
            {'message': 'Authentication request accepted'},
            {'domain_name': 'example.test', 'authenticated': True, 'verified': True},
        ])

        def callback(method, base, path, **kwargs):
            self.assertEqual(base, 'https://api.brevo.com')
            if method == 'GET' and path == '/v3/senders/domains/example.test':
                return next(responses)
            if method == 'PUT' and path == '/v3/senders/domains/example.test/authenticate':
                return next(responses)
            raise AssertionError((method, path))

        self.http.callback = callback
        with patch.dict(os.environ, {
            'BREVO_API_KEY': 'brevo-fixture',
            'BREVO_DNS_SYNC_ENABLED': '1',
        }, clear=False):
            result = self.manager.brevo_authentication_result('example.test')
        self.assertEqual(result, {
            'status': 'authenticated',
            'authenticated': True,
            'verified': True,
        })

    def test_sfreg_status_job_records_allowlisted_upstream_status(self):
        source = self.source()
        claim_job = self.manager.create_claim_job(source['id'], 'status-claim-001')
        self.manager.run_once()
        claim = self.manager.claims()[0]
        self.http.callback = lambda method, base, path, **kw: {'status': 'active'} if path.endswith('/status') else self.http.payload
        status_job = self.manager.create_claim_status_job(claim['id'], 'status-refresh-001')
        self.assertEqual(self.manager.run_once(), True)
        result = self.manager.jobs.get(status_job['id'])
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(result['result']['upstream_status'], 'active')
        self.assertEqual(self.manager.claims()[0]['upstream_status'], 'active')
        self.assertNotIn(TOKEN, json.dumps(result))

    def test_sfreg_report_status_allowlist_and_persisted_state(self):
        source = self.source()
        claim_job = self.manager.create_claim_job(source['id'], 'report-claim-001')
        self.manager.run_once()
        claim = self.manager.claims()[0]
        with self.assertRaises(ValueError):
            self.manager.create_claim_report_job(claim['id'], 'report-invalid-001', 'bogus')
        report_job = self.manager.create_claim_report_job(claim['id'], 'report-valid-001', 'active',
                                                          checks={'mx': 'passed'}, verified_at='2026-10-05T00:00:00Z')
        self.assertTrue(self.manager.run_once())
        result = self.manager.jobs.get(report_job['id'])
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(result['result']['upstream_status'], 'active')
        self.assertEqual(self.manager.claims()[0]['upstream_status'], 'active')
        self.assertEqual(self.http.calls[-1][0], 'PATCH')
        self.assertEqual(self.http.calls[-1][3]['body']['checks'], {'mx': 'passed'})

    def test_sfreg_refresh_replaces_original_credential_without_projection(self):
        source = self.source()
        claim_job = self.manager.create_claim_job(source['id'], 'refresh-claim-001')
        self.manager.run_once()
        claim = self.manager.claims()[0]
        old_ref = claim['dns_credential_ref']
        self.http.callback = lambda method, base, path, **kw: (
            {'api_token': 'refreshed-fixture-token', 'api_base': 'https://dns.fixture.test/api/v1'}
            if path.endswith('/credentials/refresh') else self.http.payload)
        refresh_job = self.manager.create_claim_refresh_job(claim['id'], 'refresh-job-001')
        self.assertTrue(self.manager.run_once())
        result = self.manager.jobs.get(refresh_job['id'])
        self.assertEqual(result['status'], 'succeeded')
        self.assertNotIn('refreshed-fixture-token', json.dumps(result))
        refreshed_claim = self.manager.claims()[0]
        self.assertEqual(refreshed_claim['dns_credential_ref'], old_ref)
        c = app.db()
        secret = self.factory().get(c, old_ref, provider='digitalplat', domain='claimed.test')
        self.assertEqual(secret['api_token'], 'refreshed-fixture-token')
        self.assertNotIn('refreshed-fixture-token', c.execute('SELECT ciphertext FROM dns_credentials WHERE id=?', (old_ref,)).fetchone()[0])
        c.close()

    def test_sfreg_refresh_missing_token_is_unknown_without_replay(self):
        source = self.source()
        claim_job = self.manager.create_claim_job(source['id'], 'refresh-missing-claim')
        self.manager.run_once()
        claim = self.manager.claims()[0]
        self.http.callback = lambda method, base, path, **kw: {} if path.endswith('/credentials/refresh') else self.http.payload
        refresh_job = self.manager.create_claim_refresh_job(claim['id'], 'refresh-missing-job')
        self.assertTrue(self.manager.run_once())
        self.assertEqual(self.manager.jobs.get(refresh_job['id'])['status'], 'unknown')
        self.assertFalse(self.manager.run_once())
        self.assertEqual(len([c for c in self.http.calls if c[2].endswith('/credentials/refresh')]), 1)

    def test_sfreg_release_disables_local_routing_before_upstream_call(self):
        source = self.source()
        claim_job = self.manager.create_claim_job(source['id'], 'release-claim-001')
        self.manager.run_once()
        claim = self.manager.claims()[0]
        observed = {}
        def release_response(method, base, path, **kw):
            if path.endswith('/release'):
                observed.update(self.manager.domain('claimed.test'))
                return {'status': 'released'}
            return self.http.payload
        self.http.callback = release_response
        release_job = self.manager.create_claim_release_job(claim['id'], 'release-job-001',
                                                             reason='fixture_cleanup', environment_stopped=True)
        self.assertTrue(self.manager.run_once())
        self.assertFalse(observed['enabled'])
        self.assertFalse(observed['receive_enabled'])
        self.assertFalse(observed['send_enabled'])
        self.assertEqual(self.manager.jobs.get(release_job['id'])['status'], 'succeeded')
        self.assertEqual(self.manager.domain('claimed.test')['source_status'], 'released')
        self.assertEqual(self.manager.claims()[0]['status'], 'released')

    def test_sfreg_release_timeout_is_unknown_and_not_automatically_replayed(self):
        source = self.source()
        claim_job = self.manager.create_claim_job(source['id'], 'release-timeout-claim')
        self.manager.run_once()
        claim = self.manager.claims()[0]
        self.http.callback = lambda method, base, path, **kw: (
            (_ for _ in ()).throw(ProviderError('provider_transport_or_json_error', uncertain=True))
            if path.endswith('/release') else self.http.payload)
        release_job = self.manager.create_claim_release_job(claim['id'], 'release-timeout-job')
        self.assertTrue(self.manager.run_once())
        self.assertEqual(self.manager.jobs.get(release_job['id'])['status'], 'unknown')
        self.assertFalse(self.manager.run_once())
        self.assertEqual(len([c for c in self.http.calls if c[2].endswith('/release')]), 1)
        self.assertFalse(self.manager.domain('claimed.test')['enabled'])

    def test_status_job_is_fenced_to_sfreg_contract(self):
        source = self.source('legacy_digitalplat_pool')
        self.http.payload = [{'domain': 'legacy.test', 'id': 'external-17'}]
        claim_job = self.manager.create_claim_job(source['id'], 'legacy-status-001', external_ids=['external-17'])
        self.manager.run_once()
        claim = self.manager.claims()[0]
        with self.assertRaises(ValueError):
            self.manager.create_claim_status_job(claim['id'], 'legacy-status-refresh-001')

    def test_legacy_source_rejects_all_claim_lifecycle_jobs(self):
        source = self.source('legacy_digitalplat_pool')
        self.http.payload = [{'domain': 'legacy.test', 'id': 'external-17'}]
        claim_job = self.manager.create_claim_job(source['id'], 'legacy-lifecycle-001', external_ids=['external-17'])
        self.manager.run_once()
        claim = self.manager.claims()[0]
        for index, kind in enumerate(('report', 'refresh', 'release')):
            with self.assertRaises(ValueError):
                key = 'legacy-lifecycle-' + kind + '-' + str(index) + 'x'
                if kind == 'report':
                    self.manager.create_claim_report_job(claim['id'], key, 'active')
                elif kind == 'refresh':
                    self.manager.create_claim_refresh_job(claim['id'], key)
                else:
                    self.manager.create_claim_release_job(claim['id'], key)

    def test_claim_timeout_unknown_no_automatic_retry_or_new_key_reclaim(self):
        source = self.source()
        self.http.failure = ProviderError('provider_transport_or_json_error', uncertain=True)
        job = self.manager.create_claim_job(source['id'], 'timeout-fixture-001')
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(job['id'])['status'], 'unknown')
        self.assertFalse(self.manager.run_once())
        self.assertEqual(len(self.http.calls), 1)
        self.assertEqual(self.manager.create_claim_job(source['id'], 'timeout-fixture-001')['id'], job['id'])
        with self.assertRaises(JobConflict):
            self.manager.create_claim_job(source['id'], 'new-key-after-timeout')

    def test_queued_second_claim_is_fenced_after_first_unknown(self):
        source = self.source()
        first = self.manager.create_claim_job(source['id'], 'unknown-first')
        second = self.manager.create_claim_job(source['id'], 'queued-second')
        self.http.failure = ProviderError('provider_http_503', uncertain=True)
        self.manager.run_once(); self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(second['id'])['error_code'], 'unresolved_prior_allocation')
        self.assertEqual(len(self.http.calls), 1)

    def test_restart_running_job_becomes_unknown_without_dispatch(self):
        source = self.source()
        job = self.manager.create_claim_job(source['id'], 'restart-fixture')
        self.manager.jobs.take()
        self.manager.jobs.recover_interrupted()
        self.assertEqual(self.manager.jobs.get(job['id'])['status'], 'unknown')
        self.assertFalse(self.manager.run_once())
        self.assertEqual(self.http.calls, [])

    def test_credential_failure_partial_and_local_receipt_recovery(self):
        source = self.source()
        job = self.manager.create_claim_job(source['id'], 'partial-fixture')
        with patch.object(self.manager, '_attach_claim', side_effect=CredentialError('fixture disk failure')):
            self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(job['id'])['status'], 'partial')
        claim = self.manager.claims()[0]
        self.assertIsNotNone(claim['receipt_ref'])
        recovery = self.manager.create_recover_job(claim['id'], 'recover-fixture')
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(recovery['id'])['status'], 'succeeded')
        self.assertEqual(len(self.http.calls), 1)

    def test_disabled_source_preflight_is_failed_not_unknown_and_not_dispatched(self):
        source = self.source()
        job = self.manager.create_claim_job(source['id'], 'disabled-source-001')
        c = app.db()
        with c:
            c.execute('UPDATE domain_sources SET enabled=0 WHERE id=?', (source['id'],))
        c.close()
        self.manager.run_once()
        outcome = self.manager.jobs.get(job['id'])
        self.assertEqual(outcome['status'], 'failed')
        self.assertEqual(outcome['step'], 'not_dispatched')
        self.assertEqual(self.http.calls, [])

    def test_cloudflare_repeat_import_preserves_existing_managed_policy(self):
        source = self.source('cloudflare_import')
        self.http.payload = {'result': [{'id': 'zone1', 'name': 'example.test', 'status': 'active'}]}
        first = self.manager.create_import_job(source['id'], 'example.test', 'first-cf-import')
        self.manager.run_once()
        data = self.manager.domain('example.test'); data['users'] = ['fixed']; data['receive_mode'] = 'fixed'
        app._save_domain(data)
        second = self.manager.create_import_job(source['id'], 'example.test', 'repeat-cf-import')
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(second['id'])['status'], 'succeeded')
        self.assertEqual(len(self.manager.claims()), 1)
        self.assertEqual(self.manager.domain('example.test')['receive_mode'], 'fixed')

    def test_missing_claim_token_stays_partial_not_ready(self):
        source = self.source()
        self.http.payload['data'][0].pop('dns')
        job = self.manager.create_claim_job(source['id'], 'missing-token-001')
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(job['id'])['status'], 'partial')
        self.assertEqual(self.manager.claims()[0]['status'], 'credential_pending')
        with self.assertRaises(ValueError):
            self.manager.domain('claimed.test')

    def test_existing_manual_domain_is_not_overwritten_by_claim(self):
        app._save_domain({'domain': 'claimed.test', 'enabled': True, 'users': ['fixed'], 'receive_mode': 'fixed'})
        source = self.source()
        job = self.manager.create_claim_job(source['id'], 'domain-conflict-001')
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(job['id'])['status'], 'partial')
        self.assertEqual(self.manager.domain('claimed.test')['receive_mode'], 'fixed')
        self.assertTrue(self.manager.domain('claimed.test')['enabled'])

    def test_legacy_pool_uses_durable_get_once_and_separate_admin_headers(self):
        source = self.source('legacy_digitalplat_pool')
        self.http.payload = [{'domain': 'legacy.test', 'id': 'external-17'}]
        job = self.manager.create_claim_job(source['id'], 'legacy-fixture-001', external_ids=['external-17'])
        self.manager.run_once()
        request = self.http.calls[0]
        self.assertEqual(request[0], 'GET')
        self.assertEqual(request[2], '/api/domains/claim-by-ids')
        self.assertEqual(request[3]['headers']['X-Admin-Key'], TOKEN)
        self.assertEqual(request[3]['query'], {'ids': 'external-17'})
        self.assertEqual(self.manager.domain('legacy.test')['dns_provider'], 'manual')
        self.assertEqual(self.manager.jobs.get(job['id'])['result']['items'][0]['status'], 'awaiting_dns')
        self.assertFalse(self.manager.run_once())

    def test_public_candidate_allowlist_removes_all_secret_aliases(self):
        payload = {'data': {'domains': [{'name': 'example.test', 'api_token': TOKEN, 'token': TOKEN, 'raw_payload': {'secret': TOKEN}, 'dns': {'token': TOKEN}}]}}
        self.assertNotIn(TOKEN, json.dumps(public_items(payload)))
        source = self.source()
        self.http.payload = payload
        response = self.client.get('/api/v1/domain-sources/' + source['id'] + '/candidates', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(TOKEN, response.text)

    def test_management_routes_reject_service_key_and_validation_does_not_echo_secret(self):
        for path in ('/domain-sources', '/dns-credentials', '/domain-jobs', '/domain-claims'):
            self.assertEqual(self.client.get('/api/v1' + path, headers={'X-API-Key': 'service-fixture'}).status_code, 401)
        for path, method, payload in (
            ('/domain-claims/nope/report', 'post', {'status': 'active'}),
            ('/domain-claims/nope/refresh', 'post', None),
            ('/domain-claims/nope/release', 'post', {'reason': 'fixture'}),
        ):
            response = getattr(self.client, method)('/api/v1' + path,
                                                     headers={'X-API-Key': 'service-fixture', 'Idempotency-Key': 'service-key-001'},
                                                     json=payload)
            self.assertEqual(response.status_code, 401)
        response = self.client.post('/api/v1/domain-sources', headers=self.headers, json={
            'name': 'fixture', 'source_type': 'sfreg_mx', 'base_url': 'https://fixture.test', 'secret': {'api_key': TOKEN}, 'unexpected': TOKEN})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(TOKEN, response.text)

    def test_create_source_http_api_does_not_echo_secret(self):
        response = self.client.post('/api/v1/domain-sources', headers=self.headers, json={
            'name': 'fixture', 'source_type': 'sfreg_mx', 'base_url': 'https://fixture.test', 'secret': {'api_key': TOKEN}})
        self.assertEqual(response.status_code, 201)
        self.assertNotIn(TOKEN, response.text)
        response = self.client.post('/api/v1/domain-sources/' + response.json()['id'] + '/claim', headers={**self.headers, 'Idempotency-Key': 'api-claim-key-001'}, json={})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['status'], 'queued')
        self.assertNotIn(TOKEN, response.text)

    def test_dns_credential_binding_enforces_domain_scope(self):
        self.domain()
        credential = self.manager.add_dns_credential('digitalplat', 'elsewhere.test', 'fixture', {'api_token': TOKEN, 'api_base': 'https://dns.fixture.test'})
        with self.assertRaises(CredentialError):
            self.manager.bind_dns_credential('example.test', credential['id'])
        credential = self.manager.add_dns_credential('digitalplat', 'example.test', 'fixture', {'api_token': TOKEN, 'api_base': 'https://dns.fixture.test'})
        self.manager.bind_dns_credential('example.test', credential['id'])
        self.assertEqual(self.manager.domain('example.test')['dns_credential_ref'], credential['id'])
        self.assertEqual(self.manager.domain('example.test')['dns_provider'], 'digitalplat')

    def global_cloudflare_fixture(self, secret):
        self.domain(dns_provider='cloudflare')
        self.manager.global_cloudflare_secret = lambda: secret
        def respond(method, base, path, **kwargs):
            self.assertEqual(method, 'GET', 'Credential import must not write upstream DNS')
            if path == '/zones':
                return {'result': [{'id': 'zone-fixture', 'name': 'example.test', 'status': 'active'}]}
            return {'result': [], 'result_info': {'total_pages': 1}}
        self.http.callback = respond

    def assert_global_cloudflare_import(self, secret, headers):
        self.global_cloudflare_fixture(secret)
        validate = self.manager.create_validate_job('example.test', 'pre-import-validation')
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(validate['id'])['status'], 'succeeded')
        before = self.manager.domain('example.test')
        c = self.manager.db()
        checks = [tuple(r) for r in c.execute('SELECT * FROM domain_checks')]
        c.close()
        path = '/api/v1/mail-domains/example.test/dns-binding/global-cloudflare'
        response = self.client.post(path, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn(TOKEN, response.text)
        ref = response.json()['dns_credential_ref']
        after = self.manager.domain('example.test')
        self.assertEqual({k: v for k, v in before.items() if k not in {'dns_credential_ref', 'updated_at'}},
                         {k: v for k, v in after.items() if k not in {'dns_credential_ref', 'updated_at'}})
        c = self.manager.db()
        self.assertEqual([tuple(r) for r in c.execute('SELECT * FROM domain_checks')], checks)
        self.assertEqual(self.manager.credentials().get(c, ref, provider='cloudflare', domain='example.test'), secret)
        self.assertNotIn(TOKEN, c.execute('SELECT ciphertext FROM dns_credentials WHERE id=?', (ref,)).fetchone()[0])
        c.close()
        self.assertEqual(self.http.calls[-1][3]['headers'], headers)
        metadata = self.client.get('/api/v1/dns-credentials', headers=self.headers)
        self.assertNotIn(TOKEN, metadata.text)
        self.assertNotIn('fixture@example.test', metadata.text)
        self.assertTrue(metadata.json()['global_cloudflare']['configured'])
        calls = len(self.http.calls)
        retry = self.client.post(path, headers=self.headers)
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.json()['dns_credential_ref'], ref)
        self.assertEqual(len(self.http.calls), calls, 'An ACK retry must not import another credential')
        self.assertEqual(self.client.post(path, headers={'X-API-Key': 'service'}).status_code, 401)

    def test_import_global_cloudflare_key_is_encrypted_scoped_and_preserves_checks(self):
        self.assert_global_cloudflare_import(
            {'api_email': 'fixture@example.test', 'api_key': TOKEN},
            {'X-Auth-Email': 'fixture@example.test', 'X-Auth-Key': TOKEN})

    def test_import_global_cloudflare_token_uses_bearer_auth(self):
        self.assert_global_cloudflare_import({'api_token': TOKEN}, {'Authorization': 'Bearer ' + TOKEN})

    def test_import_global_cloudflare_access_failure_changes_nothing(self):
        self.global_cloudflare_fixture({'api_token': TOKEN})
        self.http.callback = lambda *args, **kwargs: {'result': []}
        before = self.manager.domain('example.test')
        response = self.client.post('/api/v1/mail-domains/example.test/dns-binding/global-cloudflare',
                                    headers=self.headers)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()['detail']['code'], 'cloudflare_zone_not_accessible')
        self.assertEqual(self.manager.domain('example.test'), before)
        c = self.manager.db()
        self.assertEqual(c.execute('SELECT count(*) FROM dns_credentials').fetchone()[0], 0)
        c.close()

    def test_import_global_cloudflare_does_not_replace_existing_or_other_provider(self):
        self.global_cloudflare_fixture({'api_token': TOKEN})
        credential = self.manager.add_dns_credential('cloudflare', 'example.test', 'explicit', {'api_token': TOKEN})
        self.manager.bind_dns_credential('example.test', credential['id'])
        path = '/api/v1/mail-domains/example.test/dns-binding/global-cloudflare'
        self.assertEqual(self.client.post(path, headers=self.headers).status_code, 409)
        self.assertEqual(self.manager.domain('example.test')['dns_credential_ref'], credential['id'])
        c = self.manager.db()
        with c:
            c.execute("UPDATE mail_domains SET dns_provider='digitalplat',dns_credential_ref=NULL")
        c.close()
        self.assertEqual(self.client.post(path, headers=self.headers).status_code, 400)
        self.assertEqual(self.http.calls, [])

    def test_cloudflare_zone_longest_accessible_boundary_and_inventory_pagination(self):
        def response(method, base, path, **kw):
            q = kw['query']
            if path == '/zones':
                self.assertNotEqual(q['name'], 'co.uk')
                return {'result': [] if q['name'] == 'a.example.co.uk' else [{'id': 'zone1', 'name': 'example.co.uk', 'status': 'active'}]}
            return {'result': [{'id': 'record' + str(q['page'])}], 'result_info': {'total_pages': 2}}
        self.http.callback = response
        inventory = CloudflareDNS(self.http, {'api_token': TOKEN}).inventory('a.example.co.uk')
        self.assertEqual(inventory['zone_name'], 'example.co.uk')
        self.assertEqual(len(inventory['records']), 2)
        self.assertTrue(all(c[0] == 'GET' for c in self.http.calls))

    def test_cloudflare_import_not_claim_and_disabled_until_validation(self):
        source = self.source('cloudflare_import')
        with self.assertRaises(ValueError):
            self.manager.create_claim_job(source['id'], 'cf-not-claim')
        self.http.payload = {'result': [{'id': 'zone1', 'name': 'example.test', 'status': 'active'}]}
        job = self.manager.create_import_job(source['id'], 'example.test', 'cf-import-001')
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(job['id'])['status'], 'succeeded')
        row = self.manager.domain('example.test')
        self.assertFalse(row['enabled'])
        self.assertEqual(row['dns_provider'], 'cloudflare')
        self.assertFalse(app._domain_public(row)['receive_ready'])

    def test_dns_plan_actual_dkim_and_wildcard_warning(self):
        self.domain()
        plan = self.manager.plan('example.test')
        dkim = next(r for r in plan['records'] if r['role'] == 'dkim')
        self.assertEqual(dkim['content'], 'v=DKIM1; k=rsa; p=QUJD')
        self.assertEqual(plan['write_policy'], 'plan_only')
        self.assertIn('wildcard_requires_existing_node_and_delegation_reconciliation', plan['warnings'])
        self.assertEqual(self.http.calls, [])

    def test_validator_records_revision_and_keeps_wildcard_and_submission_closed(self):
        self.domain()
        job = self.manager.create_validate_job('example.test', 'dns-validate-001')
        self.manager.run_once()
        result = self.manager.jobs.get(job['id'])
        self.assertEqual(result['status'], 'succeeded')
        checks = result['result']['checks']
        self.assertEqual(checks['mx']['status'], 'passed')
        self.assertEqual(checks['dkim']['status'], 'passed')
        self.assertEqual(checks['wildcard_mx']['status'], 'passed')
        self.assertEqual(checks['wildcard_mx']['detail'], 'wildcard_owner_and_depth_probes_passed')
        self.assertNotIn('smtp_submission', checks)
        self.assertEqual(len(result['result']['wildcard_probes']), 4)
        self.assertEqual(result['result']['wildcard_probes'][0]['kind'], 'wildcard_owner')
        with patch.object(app, 'applied_state', return_value={'status': 'applied', 'generation': 'fixture'}):
            row = app._domain_public(self.manager.domain('example.test'))
        self.assertTrue(row['subdomain_receive_ready'])
        self.assertFalse(row['send_ready'])

    def test_validator_fails_closed_when_wildcard_owner_is_missing(self):
        self.domain()
        class MissingWildcardResolver(FakeResolver):
            def resolve(self, name, kind, **kwargs):
                if kind == 'MX' and str(name).startswith('*.'):
                    return []
                return super().resolve(name, kind, **kwargs)

        validator = DNSValidator(MissingWildcardResolver())
        result = validator.validate(self.manager.domain('example.test'), self.manager.key_root)
        self.assertEqual(result['checks']['wildcard_mx']['status'], 'failed')
        self.assertEqual(result['checks']['wildcard_mx']['detail'],
                         'wildcard_owner_or_depth_probe_failed')
        self.assertFalse(app._domain_public(self.manager.domain('example.test'))['subdomain_receive_ready'])

    def test_configuration_change_during_validation_cannot_stamp_new_revision(self):
        self.domain()
        job = self.manager.create_validate_job('example.test', 'stale-validate-001')
        original = self.manager.validator.validate
        def change(row, root):
            result = original(row, root)
            data = self.manager.domain('example.test'); data['users'] = []; data['mx'] = 'changed.example.test'
            app._save_domain(data)
            return result
        with patch.object(self.manager.validator, 'validate', side_effect=change):
            self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(job['id'])['status'], 'failed')
        c = app.db()
        self.assertEqual(c.execute('SELECT count(*) FROM domain_checks').fetchone()[0], 0)
        c.close()

    def test_dkim_key_change_after_enqueue_requires_new_plan(self):
        self.domain()
        job = self.manager.create_validate_job('example.test', 'key-stale-validate')
        (self.root / 'keys/example.test/default.txt').write_text('"v=DKIM1; p=REVG"')
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(job['id'])['status'], 'failed')

    def test_dns_checks_expire_and_domain_delete_clears_old_checks(self):
        self.domain()
        job = self.manager.create_validate_job('example.test', 'expire-dns-001')
        self.manager.run_once()
        c = app.db()
        with c:
            c.execute("UPDATE domain_checks SET checked_at=?", (time.time() - 4000,))
        c.close()
        # Fake fresh routing ACK only; stale DNS still forbids availability.
        with patch.object(app, 'applied_state', return_value={'status': 'applied', 'generation': 'fixture'}):
            self.assertFalse(app._domain_public(self.manager.domain('example.test'))['receive_ready'])
        with patch.object(app, 'admin_ok', return_value=True):
            app.delete_mail_domain('example.test', 'admin')
        c = app.db()
        self.assertEqual(c.execute('SELECT count(*) FROM domain_checks').fetchone()[0], 0)
        c.close()

    def test_dns_conflicting_txt_and_mx_cname_fail(self):
        self.domain()
        resolver = FakeResolver()
        original = resolver.resolve
        def conflicting(name, kind, **kw):
            if kind == 'CNAME':
                return ['alias.fixture.test.']
            if kind == 'TXT' and name == 'example.test':
                return [SimpleNamespace(strings=[b'v=spf1 -all']), SimpleNamespace(strings=[b'v=spf1 ~all'])]
            return original(name, kind, **kw)
        resolver.resolve = conflicting
        result = DNSValidator(resolver).validate(self.manager.domain('example.test'), self.manager.key_root)
        self.assertEqual(result['checks']['mx']['status'], 'failed')
        self.assertEqual(result['checks']['spf']['status'], 'failed')

    def test_provider_url_http_loopback_optin_and_redirect_surface_rejected(self):
        for url in ('http://provider.test', 'https://user:pass@provider.test', 'https://provider.test?token=secret', 'file:///tmp/fixture'):
            with self.assertRaises(ValueError):
                validate_base_url(url)
        with patch.dict('os.environ', {'ALLOW_LOCAL_PROVIDER_HTTP': '1'}):
            self.assertEqual(validate_base_url('http://127.0.0.1:19123/'), 'http://127.0.0.1:19123')
            with self.assertRaises(ValueError):
                validate_base_url('http://192.0.2.10/')


    def batch_payload(self, count):
        return {"data": [{"domain": f"batch-{n}.test", "claim_id": f"upstream-{n}", "status": "active",
                          "dns": {"token": TOKEN, "api_base": "https://dns.fixture.test/api/v1"}}
                         for n in range(count)]}

    def test_batch_sfreg_count_forwarded_and_each_domain_recorded(self):
        source = self.source()
        self.http.payload = self.batch_payload(3)
        response = self.client.post('/api/v1/domain-sources/' + source['id'] + '/claim',
            headers={**self.headers, 'Idempotency-Key': 'batch-api-claim-001'}, json={"count": 3})
        self.assertEqual(response.status_code, 202)
        job = response.json()
        self.assertEqual(job['request']['count'], 3)
        self.manager.run_once()
        result = self.manager.jobs.get(job['id'])
        self.assertEqual(self.http.calls[0][3]['body']['count'], 3)
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(result['result']['recorded_count'], 3)
        self.assertEqual(len(result['result']['items']), 3)
        self.assertEqual(len(self.manager.claims()), 3)
        refs = set()
        for n in range(3):
            row = self.manager.domain(f'batch-{n}.test')
            self.assertFalse(row['enabled'])
            refs.add(row['dns_credential_ref'])
        self.assertEqual(len(refs), 3)
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertEqual(self.manager.create_claim_job(source['id'], 'batch-api-claim-001', count=3)['id'], job['id'])
        with self.assertRaises(JobConflict):
            self.manager.create_claim_job(source['id'], 'batch-api-claim-001', count=2)

    def test_batch_claim_input_bounds_strict_and_legacy_ids(self):
        source = self.source()
        for count in (0, -1, 201, True, 1.5, '2'):
            response = self.client.post('/api/v1/domain-sources/' + source['id'] + '/claim',
                headers={**self.headers, 'Idempotency-Key': 'invalid-batch-key'}, json={"count": count})
            self.assertEqual(response.status_code, 422)
            with self.assertRaises(ValueError):
                self.manager.create_claim_job(source['id'], 'invalid-batch-key', count=count)
        legacy = self.source('legacy_digitalplat_pool')
        for ids in ([], ['one'], ['one', 'one'], ['one', 'bad/']):
            with self.assertRaises(ValueError):
                self.manager.create_claim_job(legacy['id'], 'invalid-legacy-batch', count=2, external_ids=ids)
        self.assertEqual(self.http.calls, [])
        self.http.payload = [{"domain": "legacy-a.test", "id": "one"}, {"domain": "legacy-b.test", "id": "two"}]
        job = self.manager.create_claim_job(legacy['id'], 'valid-legacy-batch', count=2, external_ids=['one', 'two'])
        self.manager.run_once()
        self.assertEqual(self.http.calls[0][3]['query'], {'ids': 'one,two'})
        self.assertEqual(self.manager.jobs.get(job['id'])['status'], 'succeeded')

    def test_batch_short_response_keeps_successes_without_reclaim(self):
        source = self.source()
        self.http.payload = self.batch_payload(2)
        job = self.manager.create_claim_job(source['id'], 'batch-short-response', count=3)
        self.manager.run_once()
        result = self.manager.jobs.get(job['id'])
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['result']['warnings'], ['claim_count_mismatch'])
        self.assertEqual(result['result']['requested_count'], 3)
        self.assertEqual(result['result']['received_count'], 2)
        self.assertEqual(len(self.manager.claims()), 2)
        self.assertFalse(self.manager.run_once())
        self.assertEqual(len(self.http.calls), 1)

    def test_batch_duplicate_response_blocks_new_allocation(self):
        source = self.source()
        item = self.batch_payload(1)['data'][0]
        self.http.payload = {'data': [item, item]}
        job = self.manager.create_claim_job(source['id'], 'batch-duplicate-response', count=2)
        self.manager.run_once()
        result = self.manager.jobs.get(job['id'])
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(self.manager.claims()), 1)
        self.assertEqual(result['result']['items'][1]['error_code'], 'duplicate_domain_in_claim_response')
        with self.assertRaises(JobConflict):
            self.manager.create_claim_job(source['id'], 'duplicate-reclaim-key', count=2)

    def test_job_search_pagination_status_and_global_blocking(self):
        c = app.db()
        rows = [(f'job-{n:03d}', 'dns_validate', f'domain-{n}.test', f'key-{n:03d}', 'hash', '{}',
                 'succeeded' if n % 2 else 'failed', 'dns_checks_recorded', '{}', '', n, n)
                for n in range(145)]
        rows.extend([
            ('old-pending', 'claim', 'old-source', 'old-pending-key', 'hash', '{}', 'queued', 'persisted', '{}', '', -2, -2),
            ('old-unknown', 'claim', 'unknown-source', 'old-unknown-key', 'hash', '{}', 'partial', 'allocation_recorded',
             json.dumps({'items': [{'status': 'unknown'}]}), '', -1, -1),
            ('literal-job', 'dns_apply', 'literal%_.test', 'literal-key', 'hash', '{}', 'succeeded', 'recorded', '{}', '', 200, 200),
        ])
        c.executemany('INSERT INTO domain_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', rows)
        c.commit(); c.close()
        listing = self.manager.jobs.list(20, 20)
        self.assertEqual(listing['total'], 148)
        self.assertEqual(len(listing['items']), 20)
        self.assertEqual(listing['items'][0]['id'], 'job-125')
        self.assertEqual(set(listing['blocked_claim_sources']), {'old-source', 'unknown-source'})
        self.assertEqual(listing['status_counts']['queued'], 1)
        self.assertEqual(self.manager.jobs.list(q='%_')['total'], 1)
        self.assertEqual(self.manager.jobs.list(q="' OR 1=1 --")['total'], 0)
        self.assertEqual(self.manager.jobs.list(q='DOMAIN-14')['total'], 6)
        response = self.client.get('/api/v1/domain-jobs?limit=10&offset=0&q=domain-1&status=failed', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertGreater(result['total'], 10)
        self.assertEqual(len(result['items']), 10)
        self.assertTrue(all(r['status'] == 'failed' and 'domain-1' in r['scope'] for r in result['items']))
        self.assertEqual(self.client.get('/api/v1/domain-jobs?status=bogus', headers=self.headers).status_code, 422)
        self.assertEqual(self.client.get('/api/v1/domain-jobs?q=' + 'a' * 201, headers=self.headers).status_code, 422)


class HTTPBoundaryTests(unittest.TestCase):
    def test_real_loopback_http_claim_timeout_redirect_and_error_redaction(self):
        # Real HTTP boundary, no external provider or DNS writes.
        import threading
        import urllib.parse
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from api.providers.http import JsonTransport
        from api.providers.sources.sfreg_mx import SFRegMX
        observed = []
        mode = ["success"]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                observed.append({"path": self.path, "body": body, "key": self.headers.get("Idempotency-Key")})
                if mode[0] == "redirect":
                    self.send_response(302); self.send_header("Location", "/credential-leak"); self.end_headers(); return
                if mode[0] == "timeout":
                    # Allocation can commit BEFORE the response times out.
                    time.sleep(0.3)
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                try:
                    self.wfile.write(json.dumps({"domain": "http.test", "claim_id": "http-claim-1", "dns": {"api_token": TOKEN}}).encode())
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass
            def do_GET(self):
                observed.append({"path": self.path})
                self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"error": TOKEN}).encode())
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            base = "http://127.0.0.1:" + str(server.server_port)
            with patch.dict('os.environ', {'ALLOW_LOCAL_PROVIDER_HTTP': '1'}):
                adapter = SFRegMX(JsonTransport(timeout=0.1), base, {'api_key': TOKEN}, 'fixture-client')
                response = adapter.claim({'local_part': 'support'}, 'persisted-http-key')
                self.assertEqual(response['domain'], 'http.test')
                self.assertEqual(observed[0]['body']['idempotency_key'], 'persisted-http-key')
                mode[0] = 'timeout'
                with self.assertRaises(ProviderError) as exc:
                    adapter.claim({'local_part': 'support'}, 'timeout-http-key')
                self.assertTrue(exc.exception.uncertain)
                self.assertNotIn(TOKEN, str(exc.exception))
                mode[0] = 'redirect'
                with self.assertRaises(ProviderError) as exc:
                    adapter.claim({'local_part': 'support'}, 'redirect-http-key')
                self.assertTrue(exc.exception.uncertain)
                self.assertFalse(any(r['path'] == '/credential-leak' for r in observed))
                with self.assertRaises(ProviderError) as exc:
                    adapter.candidates(1)
                self.assertEqual(exc.exception.code, 'provider_http_401')
                self.assertNotIn(TOKEN, str(exc.exception))
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_migration_failure_rolls_back_ddl_and_can_retry(self):
        from api.migrations.schema import migrate
        class FailingConnection(sqlite3.Connection):
            inject = True
            def execute(self, sql, parameters=()):
                if self.inject and 'CREATE TABLE domain_jobs(' in sql:
                    raise sqlite3.OperationalError('fixture interrupted migration')
                return super().execute(sql, parameters)
        c = sqlite3.connect(':memory:', factory=FailingConnection)
        c.row_factory = sqlite3.Row
        c.execute('CREATE TABLE mail_domains(domain TEXT PRIMARY KEY)')
        c.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY,source_path TEXT,received_at REAL)')
        with self.assertRaises(sqlite3.OperationalError):
            migrate(c)
        c.rollback()
        self.assertEqual([r[1] for r in c.execute('PRAGMA table_info(mail_domains)')], ['domain'])
        self.assertIsNone(c.execute("SELECT name FROM sqlite_master WHERE name='dns_credentials'").fetchone())
        c.inject = False
        migrate(c); c.commit()
        self.assertEqual(c.execute('SELECT count(*) FROM schema_migrations').fetchone()[0], 15)
        c.close()


if __name__ == '__main__':
    unittest.main()

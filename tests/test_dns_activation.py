import json
import unittest
from unittest.mock import patch
import test_dns_reconcile as dnsbase
from api.services.routing import config_hash


class DNSActivationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = dnsbase.DNSWriteTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)
        self.m = self.fixture.m
        self.private = self.fixture.case.root / 'keys/example.test/default.private'
        self.private.write_text('fixture-private-key')

    def apply(self, *, activate=True, key='apply-activation-fixture'):
        preview = self.fixture.preview()
        job = self.m.dns.enqueue('example.test', preview['id'], key, activate_on_success=activate)
        self.assertTrue(self.m.run_once())
        return self.m.jobs.get(job['id'])

    def test_apply_activates_and_rebinds_only_fresh_validation_to_enabled_revision(self):
        before = self.m.domain('example.test')
        result = self.apply()
        row = self.m.domain('example.test')
        self.assertTrue(row['enabled'])
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(result['result']['activation']['status'], 'enabled')
        self.assertEqual(result['result']['validated_config_hash'], config_hash(before))
        self.assertEqual(result['result']['config_hash'], config_hash(row))
        self.assertNotEqual(config_hash(before), config_hash(row))
        c = self.m.db()
        checks = c.execute('SELECT check_name,status,config_hash FROM domain_checks').fetchall()
        c.close()
        self.assertEqual(len(checks), 6)
        self.assertEqual({r['config_hash'] for r in checks}, {config_hash(row)})
        self.assertEqual(len(self.fixture.writes()), 4)
        retry = self.m.dns.enqueue('example.test', result['request']['plan_id'],
                                  result['idempotency_key'], activate_on_success=True)
        self.assertEqual(retry['id'], result['id'])
        self.assertFalse(self.m.run_once())

    def test_original_apply_contract_preserves_disabled_domains(self):
        result = self.apply(activate=False)
        self.assertFalse(self.m.domain('example.test')['enabled'])
        self.assertNotIn('activation', result['result'])
        self.assertNotIn('activate_on_success', result['request'])

    def test_failed_wildcard_never_enables_claim(self):
        self.fixture.edit(receive_subdomains=True, max_subdomain_depth=2)
        validate = self.m.validator.validate
        def failed(row, keys):
            result = validate(row, keys)
            result['checks']['wildcard_mx'] = {'status': 'failed', 'detail': 'not_published'}
            return result
        with patch.object(self.m.validator, 'validate', side_effect=failed):
            result = self.apply()
        self.assertFalse(self.m.domain('example.test')['enabled'])
        self.assertEqual(result['result']['activation']['pending_checks'], ['wildcard_mx'])
        self.assertEqual(result['result']['validation_status'], 'failed')

    def test_smtp_or_private_key_failure_does_not_enable_domain(self):
        with patch('api.services.readiness_refresh.smtp_submission_check',
                   return_value={'status': 'failed', 'detail': 'submission_unavailable'}):
            result = self.apply()
        self.assertFalse(self.m.domain('example.test')['enabled'])
        self.assertIn('smtp_submission', result['result']['activation']['pending_checks'])
        self.private.unlink()
        result = self.apply(key='apply-missing-private-key')
        self.assertEqual(result['result']['activation']['pending_checks'], ['dkim_private_key'])
        self.assertFalse(self.m.domain('example.test')['enabled'])

    def test_explicit_validate_can_finish_already_applied_dns_without_dns_writes(self):
        self.fixture.apply()
        before = len(self.fixture.writes())
        job = self.m.create_validate_job('example.test', 'validate-activation-fixture', activate_on_success=True)
        self.assertTrue(job['request']['refresh_smtp_submission'])
        self.assertTrue(self.m.run_once())
        result = self.m.jobs.get(job['id'])
        self.assertTrue(self.m.domain('example.test')['enabled'])
        self.assertEqual(result['result']['activation']['status'], 'enabled')
        self.assertEqual(len(self.fixture.writes()), before)

    def test_validate_activation_retry_keeps_original_job_after_revision_change(self):
        job = self.m.create_validate_job('example.test', 'validate-activation-retry', activate_on_success=True)
        self.assertTrue(self.m.run_once())
        self.assertTrue(self.m.domain('example.test')['enabled'])
        retry = self.m.create_validate_job('example.test', 'validate-activation-retry', activate_on_success=True)
        self.assertEqual(retry['id'], job['id'])
        self.assertEqual(retry['status'], 'succeeded')
        self.assertFalse(self.m.run_once())

    def test_background_validation_does_not_reenable_manually_disabled_domain(self):
        job = self.m.create_validate_job('example.test', 'periodic-readiness-fixture')
        self.assertTrue(self.m.run_once())
        self.assertFalse(self.m.domain('example.test')['enabled'])
        self.assertNotIn('activation', self.m.jobs.get(job['id'])['result'])

    def test_waits_for_actual_routing_readiness_while_job_is_running(self):
        calls = []
        def public(row):
            c = self.m.db()
            active = c.execute("SELECT status FROM domain_jobs WHERE kind='dns_apply' ORDER BY created_at DESC LIMIT 1").fetchone()
            c.close()
            self.assertEqual(active['status'], 'running')
            calls.append(row['enabled'])
            return {'enabled': True, 'receive_ready': len(calls) >= 2, 'send_ready': True,
                    'subdomain_receive_ready': True, 'subdomain_send_ready': True}
        self.m.domain_public = public
        with patch('api.services.domain_manager.time.sleep'):
            result = self.apply()
        self.assertEqual(calls, [1, 1])
        self.assertEqual(result['result']['activation']['status'], 'ready')

    def test_missing_route_ack_is_reported_pending_instead_of_ready(self):
        self.m.domain_public = lambda row: {'enabled': True, 'receive_ready': False,
                                          'send_ready': True}
        with patch('api.services.domain_manager.time.sleep'):
            result = self.apply()
        self.assertEqual(result['result']['activation']['status'], 'routing_pending')
        self.assertEqual(result['result']['next_action'], 'wait_for_routing')

    def test_policy_change_during_validation_blocks_activation(self):
        validate = self.m.validator.validate
        def changed(row, keys):
            result = validate(row, keys)
            self.fixture.edit(receive_enabled=False)
            return result
        with patch.object(self.m.validator, 'validate', side_effect=changed):
            result = self.apply()
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(self.m.domain('example.test')['enabled'])

    def test_api_requires_admin_and_explicit_activation_body(self):
        client = self.fixture.case.client
        path = '/api/v1/mail-domains/example.test/dns-validate'
        headers = {'X-API-Key': 'admin-fixture', 'Idempotency-Key': 'api-activation-fixture'}
        self.assertEqual(client.post(path, headers={'Idempotency-Key': 'api-no-admin-key'},
                                     json={'activate_on_success': True}).status_code, 401)
        response = client.post(path, headers=headers, json={'activate_on_success': True})
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.json()['request']['activate_on_success'])
        self.assertTrue(self.m.run_once())
        self.assertTrue(self.m.domain('example.test')['enabled'])

    def test_inactive_ownership_never_activates(self):
        self.fixture.edit(source_status='released')
        job = self.m.create_validate_job('example.test', 'released-activation-fixture', activate_on_success=True)
        self.assertTrue(self.m.run_once())
        self.assertEqual(self.m.jobs.get(job['id'])['status'], 'failed')
        self.assertFalse(self.m.domain('example.test')['enabled'])

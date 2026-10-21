import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_dns_reconcile as base
from api.providers.http import ProviderError
from api.repositories.domain_jobs import JobConflict


class DNSRepairTests(unittest.TestCase):
    def setUp(self):
        self.fixture = base.DNSWriteTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.digitalplat_fixture()
        self.fixture.edit(receive_subdomains=True, max_subdomain_depth=6, enabled=True)
        self.m = self.fixture.m
        self.assertEqual(self.fixture.apply()['status'], 'succeeded')
        self.old_id = next(r['id'] for r in self.fixture.records if r['name'] == '*')
        self.before = copy.deepcopy(self.fixture.records)
        self.start_calls = len(self.fixture.http.calls)
        self.mode = ''
        self.visible = False
        self.wait = False
        self.created = 0
        original = self.fixture.http.callback

        def respond(method, base_url, path, **kwargs):
            if method == 'GET' and self.mode == 'delete_readback_once':
                self.mode = ''
                raise ProviderError('fixture_readback_failed', uncertain=True)
            if method == 'DELETE':
                c = self.m.db()
                operation = c.execute("SELECT * FROM domain_dns_operations WHERE action='delete' ORDER BY updated_at DESC LIMIT 1").fetchone()
                c.close()
                self.assertEqual(operation['status'], 'dispatched')
                backup = self.fixture.case.root / 'dns-repair-backups' / (operation['job_id'] + '.json')
                self.assertTrue(backup.is_file(), 'Full backup must precede DELETE')
                self.assertTrue(json.loads(backup.read_text())['records'])
                self.assertEqual(path, '/domains/example.test/dns/records/' + self.old_id)
                if self.mode == 'delete_denied':
                    raise ProviderError('provider_http_405')
                if self.mode == 'delete_timeout_before':
                    raise ProviderError('provider_transport_or_json_error', uncertain=True)
                self.fixture.records[:] = [r for r in self.fixture.records if r['id'] != self.old_id]
                if self.mode == 'delete_readback_error':
                    self.mode = 'delete_readback_once'
                if self.mode == 'delete_204':
                    raise ProviderError('provider_transport_or_json_error', uncertain=True)
                if self.mode == 'delete_race':
                    self.fixture.records.append({'id': 'external-change', 'name': 'www', 'type': 'TXT', 'value': 'external', 'ttl': 300})
                return {'success': True}
            if method == 'POST':
                if self.mode == 'create_denied':
                    raise ProviderError('provider_http_422')
                self.created += 1
                record = {'id': 'repaired-' + str(self.created), **copy.deepcopy(kwargs['body'])}
                self.fixture.records.append(record)
                self.visible = not self.wait
                if self.mode == 'create_timeout':
                    raise ProviderError('fixture_timeout', uncertain=True)
                return {'data': record}
            return original(method, base_url, path, **kwargs)
        self.fixture.http.callback = respond
        validate = self.m.validator.validate

        def observed(row, keys):
            result = validate(row, keys)
            if not self.visible:
                result['checks']['wildcard_mx'] = {'status': 'failed', 'detail': 'fixture_negative_cache'}
            return result
        self.enterContext(patch.object(self.m.validator, 'validate', side_effect=observed))
        self.authority = self.enterContext(patch.object(self.m.dns_repair, 'authority_state', return_value='missing'))

    def writes(self):
        return [call for call in self.fixture.http.calls[self.start_calls:] if call[0] != 'GET']

    def enqueue(self, key='repair-fixture-key', **kwargs):
        return self.m.dns_repair.enqueue('example.test', key, **kwargs)

    def repair(self, **kwargs):
        job = self.enqueue(**kwargs)
        self.assertTrue(self.m.run_once())
        return self.m.jobs.get(job['id'])

    def release_retry(self, job):
        result = self.m.jobs.get(job['id'])['result']
        result['retry_at'] = 0
        c = self.m.db()
        with c:
            c.execute('UPDATE domain_jobs SET result_json=? WHERE id=?', (json.dumps(result), job['id']))
        c.close()

    def test_exact_record_rebuilt_with_backup_ledger_and_other_records_preserved(self):
        job = self.repair()
        self.assertEqual(job['status'], 'succeeded')
        self.assertEqual(job['result']['checks']['wildcard_mx']['status'], 'passed')
        self.assertEqual([call[0] for call in self.writes()], ['DELETE', 'POST'])
        self.assertEqual(self.writes()[1][3]['body'], {'type': 'MX', 'name': '*', 'ttl': 300, 'value': '10 mail.example.test.'})
        self.assertEqual([r for r in self.fixture.records if r['name'] != '*'], [r for r in self.before if r['name'] != '*'])
        c = self.m.db()
        operations = c.execute("SELECT action,status FROM domain_dns_operations WHERE job_id=? ORDER BY updated_at", (job['id'],)).fetchall()
        owner = c.execute("SELECT provider_record_id FROM managed_dns_records WHERE provider_record_id='repaired-1'").fetchone()
        c.close()
        self.assertEqual([(r['action'], r['status']) for r in operations], [('delete', 'confirmed'), ('create', 'confirmed')])
        self.assertIsNotNone(owner)

    def test_duplicate_click_uses_same_job_and_does_not_delete_again(self):
        first = self.enqueue()
        self.assertEqual(self.enqueue()['id'], first['id'])
        self.m.run_once()
        self.assertEqual(self.enqueue()['id'], first['id'])
        self.assertFalse(self.m.run_once())
        self.assertEqual([call[0] for call in self.writes()], ['DELETE', 'POST'])
        with self.assertRaises(JobConflict):
            self.enqueue(activate_on_success=True)

    def test_propagation_retry_releases_worker_and_never_repeats_writes(self):
        self.wait = True
        job = self.repair()
        self.assertEqual(job['status'], 'queued')
        self.assertEqual(job['step'], 'dns_repair_waiting_for_dns')
        self.assertFalse(self.m.run_once(), 'A propagation delay must not busy-spin the worker')
        other = self.m.create_validate_job('example.test', 'another-readonly-job')
        self.assertTrue(self.m.run_once())
        self.assertEqual(self.m.jobs.get(other['id'])['status'], 'succeeded')
        self.m.jobs.recover_interrupted()
        self.visible = True
        self.release_retry(job)
        self.assertTrue(self.m.run_once())
        self.assertEqual(self.m.jobs.get(job['id'])['status'], 'succeeded')
        self.assertEqual([call[0] for call in self.writes()], ['DELETE', 'POST'])

    def test_authority_already_published_or_propagating_only_waits(self):
        for state in ('published', 'propagating'):
            with self.subTest(state=state):
                self.authority.return_value = state
                job = self.repair(key='authority-' + state)
                self.assertEqual(job['status'], 'queued')
                self.assertEqual(job['result']['repair']['phase'], 'publication_wait')
                self.visible = True
                self.release_retry(job)
                self.m.run_once()
                self.assertEqual(self.m.jobs.get(job['id'])['status'], 'succeeded')
                self.assertEqual(self.writes(), [])
                self.visible = False

    def test_fresh_resolver_success_skips_rebuild(self):
        self.visible = True
        self.assertEqual(self.repair()['status'], 'succeeded')
        self.assertEqual(self.writes(), [])
        self.authority.assert_not_called()

    def test_authority_error_does_not_delete(self):
        self.authority.side_effect = ProviderError('digitalplat_authority_unconfirmed')
        self.assertEqual(self.repair()['status'], 'failed')
        self.assertEqual(self.writes(), [])

    def test_delete_204_or_timeout_with_confirmed_absence_is_not_replayed(self):
        self.mode = 'delete_204'
        self.assertEqual(self.repair()['status'], 'succeeded')
        self.assertEqual([call[0] for call in self.writes()], ['DELETE', 'POST'])

    def test_rejected_delete_leaves_record_intact_without_create(self):
        self.mode = 'delete_denied'
        job = self.repair()
        self.assertEqual(job['status'], 'failed')
        self.assertEqual(self.fixture.records, self.before)
        self.assertEqual([call[0] for call in self.writes()], ['DELETE'])

    def test_uncertain_delete_with_existing_record_requires_reconciliation(self):
        self.mode = 'delete_timeout_before'
        job = self.repair()
        self.assertEqual(job['status'], 'unknown')
        self.assertEqual(self.enqueue()['id'], job['id'])
        self.assertFalse(self.m.run_once())
        self.assertEqual([call[0] for call in self.writes()], ['DELETE'])
        with self.assertRaises(JobConflict):
            self.enqueue(key='fresh-after-unknown-delete')

    def test_uncertain_create_is_not_automatically_adopted_or_retried(self):
        self.mode = 'create_timeout'
        job = self.repair()
        self.assertEqual(job['status'], 'unknown')
        c = self.m.db()
        self.assertIsNone(c.execute("SELECT 1 FROM managed_dns_records WHERE provider_record_id='repaired-1'").fetchone())
        c.close()
        self.assertFalse(self.m.dns.preview('example.test')['executable'])
        self.assertEqual(self.enqueue()['id'], job['id'])
        self.assertFalse(self.m.run_once())
        self.assertEqual([call[0] for call in self.writes()], ['DELETE', 'POST'])

    def test_definite_create_failure_allows_fresh_apply_to_restore_missing_record(self):
        self.mode = 'create_denied'
        job = self.repair()
        self.assertEqual(job['status'], 'partial')
        preview = self.m.dns.preview('example.test')
        self.assertTrue(preview['executable'])
        self.assertEqual([a['action'] for a in preview['actions'] if a['action'] != 'exists'], ['create'])

    def test_inventory_drift_and_backup_failure_stop_before_delete(self):
        job = self.enqueue()
        self.fixture.records.append({'id': 'new', 'name': 'www', 'type': 'TXT', 'value': 'external', 'ttl': 300})
        self.m.run_once()
        self.assertEqual(self.m.jobs.get(job['id'])['status'], 'failed')
        self.assertEqual(self.writes(), [])
        self.fixture.records.pop()
        with patch.object(self.m.dns_repair, '_backup', side_effect=OSError('fixture backup disk error')):
            self.assertEqual(self.repair(key='backup-failure-fixture')['status'], 'failed')
        self.assertEqual(self.writes(), [])

    def test_other_record_drift_after_delete_stops_recreation(self):
        self.mode = 'delete_race'
        self.assertEqual(self.repair()['status'], 'unknown')
        self.assertEqual([call[0] for call in self.writes()], ['DELETE'])

    def test_lost_delete_readback_reconciles_absence_and_fresh_apply_restores_without_delete(self):
        self.mode = 'delete_readback_error'
        job = self.repair()
        self.assertEqual(job['status'], 'unknown')
        self.assertEqual([call[0] for call in self.writes()], ['DELETE'])
        self.assertFalse(self.m.dns.preview('example.test')['executable'])
        observed = self.m.dns.reconcile_operation('example.test', job['result']['operation_id'])
        self.assertEqual(observed['status'], 'observed')
        self.assertEqual(observed['dns_writes'], 0)
        preview = self.m.dns.preview('example.test')
        self.assertTrue(preview['executable'])
        restore = self.m.dns.enqueue('example.test', preview['id'], 'restore-after-lost-delete')
        self.m.run_once()
        self.assertEqual(self.m.jobs.get(restore['id'])['status'], 'succeeded')
        self.assertEqual([call[0] for call in self.writes()], ['DELETE', 'POST'])

    def test_unowned_or_cloudflare_record_cannot_be_rebuilt(self):
        c = self.m.db()
        with c:
            c.execute('DELETE FROM managed_dns_records WHERE provider_record_id=?', (self.old_id,))
        c.close()
        with self.assertRaises(JobConflict):
            self.enqueue()
        self.assertEqual(self.writes(), [])

    def test_active_repair_blocks_other_dns_writes_but_not_validation(self):
        job = self.enqueue()
        for kind in ('dns_apply', 'dns_hosting', 'dns_repair'):
            with self.assertRaises(JobConflict):
                self.m.jobs.enqueue(kind, 'example.test', 'other-' + kind, {})
        self.assertIsNotNone(self.m.create_validate_job('example.test', 'readonly-alongside-repair'))
        active = self.m.jobs.list(limit=1)['active_domain_jobs']
        self.assertIn(job['id'], [item['id'] for item in active])

    def test_timeout_finishes_partial_with_no_repeated_delete(self):
        self.wait = True
        job = self.repair()
        result = job['result']
        result['repair']['deadline'] = 0
        result['retry_at'] = 0
        c = self.m.db()
        with c:
            c.execute('UPDATE domain_jobs SET result_json=? WHERE id=?', (json.dumps(result), job['id']))
        c.close()
        self.m.run_once()
        final = self.m.jobs.get(job['id'])
        self.assertEqual(final['status'], 'partial')
        self.assertEqual(final['result']['next_action'], 'dns_validate')
        self.assertEqual([call[0] for call in self.writes()], ['DELETE', 'POST'])

    def test_authority_requires_two_matching_authoritative_replies(self):
        import dns.flags
        import dns.message
        import dns.rrset
        from api.services.dns_repair import DNSRepair
        wanted = {'name': '*.example.test', 'type': 'MX', 'content': 'mail.example.test', 'priority': 10}
        query = dns.message.make_query(wanted['name'], 'MX')
        good = dns.message.make_response(query)
        good.flags |= dns.flags.AA
        good.answer.append(dns.rrset.from_text(wanted['name'], 300, 'IN', 'MX', '10 mail.example.test.'))
        missing = dns.message.make_response(query)
        missing.flags |= dns.flags.AA
        missing.set_rcode(3)
        missing.authority.append(dns.rrset.from_text('example.test', 300, 'IN', 'SOA',
            'dns1.digitalplat.org. hostmaster.digitalplat.org. 2026101801 10800 3600 604800 300'))
        with patch('api.services.dns_repair.dns.resolver.Resolver') as resolver, patch('api.services.dns_repair.dns.query.udp') as udp:
            resolver.return_value.resolve.return_value = ['192.0.2.1']
            for responses, expected in [([good, good], 'published'), ([missing, missing], 'missing'), ([good, missing], 'propagating')]:
                udp.side_effect = responses
                self.assertEqual(DNSRepair.authority_state(self.m.dns_repair, 'example.test', wanted), expected)
            self.assertFalse(udp.call_args.args[0].flags & dns.flags.RD)
            bad = copy.deepcopy(missing)
            bad.flags &= ~dns.flags.AA
            udp.side_effect = [bad]
            with self.assertRaises(ProviderError):
                DNSRepair.authority_state(self.m.dns_repair, 'example.test', wanted)
            parent = copy.deepcopy(missing)
            parent.authority[0] = dns.rrset.from_text('test', 300, 'IN', 'SOA',
                'dns1.digitalplat.org. hostmaster.digitalplat.org. 1 10800 3600 604800 300')
            udp.side_effect = [parent]
            with self.assertRaises(ProviderError):
                DNSRepair.authority_state(self.m.dns_repair, 'example.test', wanted)

    def test_api_admin_only_and_idempotency(self):
        path = '/api/v1/mail-domains/example.test/dns-repair'
        client = self.fixture.case.client
        self.assertEqual(client.post(path, headers={'Idempotency-Key': 'repair-api-unauth'}, json={}).status_code, 401)
        headers = {**self.fixture.case.headers, 'Idempotency-Key': 'repair-api-fixture'}
        response = client.post(path, headers=headers, json={'activate_on_success': False})
        self.assertEqual(response.status_code, 202, response.text)
        self.assertNotIn('fixture-secret-must-not-leak', response.text)
        self.assertEqual(client.post(path, headers=headers, json={}).json()['id'], response.json()['id'])
        self.assertEqual(self.writes(), [])


if __name__ == '__main__':
    unittest.main()

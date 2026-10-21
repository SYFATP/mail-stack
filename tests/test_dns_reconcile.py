import copy
import json
import time
import unittest
from unittest.mock import patch
import test_domain_control as base
from api.providers.http import ProviderError
from api.repositories.domain_jobs import JobConflict
from api.services.routing import publish, recipient_policy


class DNSWriteTests(unittest.TestCase):
    def setUp(self):
        self.case = base.P2Tests(methodName='runTest')
        self.case.setUp()
        self.m, self.http = self.case.manager, self.case.http
        self.records = []
        self.sequence = 0
        self.mode = ''
        self.http.callback = self.respond
        self.smtp_check = self.enterContext(patch(
            'api.services.readiness_refresh.smtp_submission_check',
            return_value={'status': 'passed', 'detail': 'fixture_smtp_envelope_no_data'},
        ))
        self.case.domain(receive_subdomains=False, enabled=False)
        credential = self.m.add_dns_credential('cloudflare', None, 'fixture', {'api_token': base.TOKEN})
        self.m.bind_dns_credential('example.test', credential['id'])

    def tearDown(self):
        self.case.tearDown()

    def respond(self, method, base_url, path, **kw):
        if method == 'GET' and path == '/zones':
            return {'success': True, 'result': [{'id': 'zone_fixture', 'name': 'example.test', 'status': 'active'}]}
        if method == 'GET' and path.endswith('/dns_records'):
            return {'success': True, 'result': copy.deepcopy(self.records), 'result_info': {'total_pages': 1}}
        if method in {'POST', 'PATCH'}:
            body = copy.deepcopy(kw['body'])
            if method == 'POST':
                self.sequence += 1
                row = {'id': 'record-' + str(self.sequence), **body}
                self.records.append(row)
            else:
                row = next(r for r in self.records if r['id'] == path.split('/')[-1])
                row.update(body)
            if self.mode == 'timeout':
                self.mode = ''
                raise ProviderError('provider_transport_or_json_error', uncertain=True)
            if self.mode == 'invalid_id':
                self.mode = ''
                return {'success': True, 'result': {'id': '../invalid'}}
            return {'success': True, 'result': copy.deepcopy(row)}
        raise AssertionError((method, path))

    def preview(self):
        return self.m.dns.preview('example.test')

    def apply(self, plan=None, key='dns-apply-fixture'):
        plan = plan or self.preview()
        job = self.m.dns.enqueue('example.test', plan['id'], key)
        self.m.run_once()
        return self.m.jobs.get(job['id'])

    def writes(self):
        return [r for r in self.http.calls if r[0] in {'POST', 'PATCH'}]

    def edit(self, **fields):
        row = self.m.domain('example.test'); row['users'] = json.loads(row['users']); row.update(fields)
        self.m.save_domain(row)

    def test_rate_limited_write_holds_later_jobs_and_preserves_unknown_operation(self):
        plan = self.preview()
        original = self.http.callback
        def limited(method, base_url, path, **kwargs):
            if method in {'POST', 'PATCH'}:
                raise ProviderError('provider_http_429', uncertain=True, retry_after=1200)
            return original(method, base_url, path, **kwargs)
        self.http.callback = limited
        job = self.apply(plan)
        self.assertEqual(job['status'], 'unknown')
        self.assertEqual(job['error_code'], 'provider_http_429')
        self.assertEqual(job['result']['provider_backoff']['retry_after_seconds'], 1200)
        c = self.m.db()
        try:
            op = c.execute('SELECT status FROM domain_dns_operations WHERE id=?', (job['result']['operation_id'],)).fetchone()
        finally:
            c.close()
        self.assertEqual(op['status'], 'unknown')
        queued = self.m.jobs.enqueue('dns_apply', 'example.test', 'rate-followup-fixture', {'plan_id': plan['id']})
        self.assertIsNone(self.m.jobs.take())
        self.assertEqual(self.m.jobs.get(queued['id'])['status'], 'queued')

    def test_create_four_records_journaled_owned_and_automatically_validated(self):
        plan = self.preview()
        self.assertTrue(plan['executable'])
        self.assertEqual(len(plan['actions']), 4)
        self.assertEqual(self.writes(), [])
        result = self.apply(plan)
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(result['step'], 'dns_applied_and_validated')
        self.assertEqual(result['result']['validation_status'], 'passed')
        self.assertEqual(result['result']['next_action'], 'none')
        self.assertEqual(result['result']['checks']['smtp_submission']['status'], 'passed')
        self.smtp_check.assert_called_once()
        self.assertEqual(len(self.writes()), 4)
        c = self.m.db()
        self.assertEqual(c.execute('SELECT count(*) FROM managed_dns_records').fetchone()[0], 4)
        self.assertEqual(c.execute("SELECT count(*) FROM domain_dns_operations WHERE status='confirmed'").fetchone()[0], 4)
        self.assertEqual(c.execute('SELECT count(*) FROM domain_checks').fetchone()[0], 6)
        c.close()
        self.assertFalse(self.m.domain('example.test')['enabled'])

    def test_existing_records_are_validated_without_additional_dns_writes(self):
        self.apply()
        before = len(self.writes())
        with patch.object(self.m.validator, 'validate', wraps=self.m.validator.validate) as validate:
            result = self.apply(key='existing-dns-auto-validation')
        self.assertEqual(result['result']['validation_status'], 'passed')
        validate.assert_called_once()
        self.assertEqual(len(self.writes()), before)

    def test_apply_keeps_job_running_until_wildcard_validation_result_is_saved(self):
        self.edit(receive_subdomains=True, max_subdomain_depth=2)
        original = self.m.validator.validate
        def not_propagated(row, key_root):
            c = self.m.db()
            active = c.execute("SELECT status,step FROM domain_jobs WHERE kind='dns_apply' ORDER BY created_at DESC LIMIT 1").fetchone()
            self.assertEqual(tuple(active), ('running', 'dns_validating'))
            self.assertEqual(c.execute('SELECT count(*) FROM domain_checks').fetchone()[0], 0)
            c.close()
            result = original(row, key_root)
            result['checks']['wildcard_mx'] = {'status': 'failed', 'detail': 'wildcard_not_published'}
            return result
        with patch.object(self.m.validator, 'validate', side_effect=not_propagated):
            result = self.apply()
        self.assertEqual(result['status'], 'succeeded', 'Confirmed writes and completed checks have a known outcome')
        self.assertEqual(result['result']['validation_status'], 'failed')
        self.assertEqual(result['result']['next_action'], 'wait_for_dns')
        c = self.m.db()
        self.assertEqual(c.execute("SELECT status FROM domain_checks WHERE check_name='wildcard_mx'").fetchone()[0], 'failed')
        c.close()
        self.assertEqual(len(self.writes()), 5)

    def test_validation_exception_does_not_make_confirmed_dns_writes_unknown_or_replay_them(self):
        with patch.object(self.m.validator, 'validate', side_effect=OSError(base.TOKEN)):
            result = self.apply()
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['error_code'], 'dns_validation_failed')
        self.assertEqual(result['result']['validation_status'], 'error')
        self.assertEqual(len(self.writes()), 4)
        self.assertNotIn(base.TOKEN, json.dumps(result))
        self.assertFalse(self.m.run_once(), 'No write or validation is implicitly queued again')
        result = self.apply(key='retry-read-only-after-validation-error')
        self.assertEqual(result['result']['validation_status'], 'passed')
        self.assertEqual(len(self.writes()), 4)

    def test_partial_dns_write_does_not_run_validation(self):
        self.mode = 'timeout'
        with patch.object(self.m.validator, 'validate') as validate:
            result = self.apply()
        self.assertEqual(result['status'], 'unknown')
        validate.assert_not_called()

    def test_distinct_same_owner_txt_targets_are_preserved(self):
        with patch.object(self.m, 'brevo_dns_targets', return_value=[{
            'role': 'brevo_auth',
            'type': 'TXT',
            'name': 'example.test',
            'content': 'brevo-code:fixture',
            'ttl': 300,
        }]):
            plan = self.preview()
        same_owner = [
            action['target'] for action in plan['actions']
            if action['target']['type'] == 'TXT' and action['target']['name'] == 'example.test'
        ]
        self.assertEqual(
            {(target['role'], target['content']) for target in same_owner},
            {('spf', 'v=spf1 ip4:203.0.113.10 -all'), ('brevo_auth', 'brevo-code:fixture')},
        )

    def test_foreign_txt_preserved_and_no_secret_projection(self):
        self.records.append({'id': 'verify', 'name': 'example.test', 'type': 'TXT', 'content': base.TOKEN, 'ttl': 300})
        plan = self.preview()
        self.assertNotIn(base.TOKEN, json.dumps(plan))
        self.assertEqual(self.apply(plan)['status'], 'succeeded')
        self.assertEqual(next(r for r in self.records if r['id'] == 'verify')['content'], base.TOKEN)

    def test_foreign_spf_conflict_blocks_entire_plan_before_write(self):
        self.records.append({'id': 'foreign', 'name': 'example.test', 'type': 'TXT', 'content': 'v=spf1 -all', 'ttl': 300})
        plan = self.preview()
        self.assertFalse(plan['executable'])
        self.assertIn('foreign_record_conflict', [x['code'] for x in plan['conflicts']])
        with self.assertRaises(JobConflict):
            self.m.dns.enqueue('example.test', plan['id'], 'blocked-apply-001')
        self.assertEqual(self.writes(), [])

    def test_identical_foreign_record_skipped_without_adoption(self):
        self.records.append({'id': 'external-mx', 'name': 'example.test', 'type': 'MX', 'content': 'mail.example.test', 'priority': 10, 'ttl': 900})
        result = self.apply()
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(len(self.writes()), 3)
        c = self.m.db()
        self.assertIsNone(c.execute("SELECT 1 FROM managed_dns_records WHERE provider_record_id='external-mx'").fetchone())
        c.close()

    def test_owned_update_uses_patch_and_preserves_other_txt(self):
        self.apply()
        self.records.append({'id': 'verify', 'name': 'example.test', 'type': 'TXT', 'content': 'verification=x', 'ttl': 300})
        before = len(self.writes())
        self.edit(spf='v=spf1 ip4:203.0.113.20 -all')
        result = self.apply(key='update-owned-001')
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(len(self.writes()), before + 1)
        self.assertEqual(self.writes()[-1][0], 'PATCH')
        self.assertEqual(next(r for r in self.records if r['id'] == 'verify')['content'], 'verification=x')

    def test_owned_external_edit_or_marker_loss_is_conflict(self):
        self.apply()
        self.records[0]['comment'] = 'other-owner'
        plan = self.preview()
        self.assertFalse(plan['executable'])
        self.assertIn('owned_record_changed_externally', [c['code'] for c in plan['conflicts']])

    def test_multiple_spf_and_cname_are_blocked(self):
        self.records += [{'id': 'spf1', 'name': 'example.test', 'type': 'TXT', 'content': 'v=spf1 -all'},
                         {'id': 'spf2', 'name': 'example.test', 'type': 'TXT', 'content': 'v=spf1 ~all'},
                         {'id': 'alias', 'name': '_domainkey.example.test', 'type': 'CNAME', 'content': 'outside.test'}]
        plan = self.preview()
        self.assertFalse(plan['executable'])
        self.assertGreaterEqual(len(plan['conflicts']), 2)

    def test_stale_inventory_or_configuration_rejects_before_write(self):
        plan = self.preview()
        job = self.m.dns.enqueue('example.test', plan['id'], 'stale-inventory-001')
        self.records.append({'id': 'new', 'name': 'foo.example.test', 'type': 'A', 'content': '192.0.2.1'})
        self.m.run_once()
        self.assertEqual(self.m.jobs.get(job['id'])['status'], 'failed')
        self.assertEqual(self.writes(), [])
        plan = self.preview()
        job = self.m.dns.enqueue('example.test', plan['id'], 'stale-config-001')
        self.edit(mx='changed.example.test')
        self.m.run_once()
        self.assertEqual(self.m.jobs.get(job['id'])['status'], 'failed')
        self.assertEqual(self.writes(), [])

    def test_preview_expiry_and_cross_domain_rejected(self):
        plan = self.preview()
        with patch('api.services.dns_reconcile.time.time', return_value=plan['expires_at'] + 1):
            with self.assertRaises(JobConflict):
                self.m.dns.enqueue('example.test', plan['id'], 'expired-dns-001')
        with self.assertRaises(JobConflict):
            self.m.dns.enqueue('different.test', plan['id'], 'cross-domain-001')

    def test_cloudflare_timeout_recovery_uses_marker_without_duplicate_post(self):
        self.mode = 'timeout'
        result = self.apply()
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(self.m.dns.enqueue('example.test', result['request']['plan_id'], result['idempotency_key'])['id'], result['id'])
        fresh = self.preview()
        self.assertTrue(fresh['executable'])
        self.assertEqual(fresh['actions'][0]['action'], 'recover')
        recovered = self.apply(fresh, key='recover-dns-001')
        self.assertEqual(recovered['status'], 'succeeded')
        self.assertEqual(len(self.writes()), 4)
        self.assertEqual(len(self.records), 4)

    def test_cloudflare_invalid_response_after_commit_stays_unknown(self):
        self.mode = 'invalid_id'
        result = self.apply()
        self.assertEqual(result['status'], 'unknown')
        self.assertTrue(self.preview()['executable'])

    def test_local_confirm_failure_recovers_from_persisted_intent(self):
        with patch.object(self.m.dns, 'confirm', side_effect=OSError('fixture disk error')):
            result = self.apply()
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(self.apply(key='local-recover-001')['status'], 'succeeded')
        self.assertEqual(len(self.records), 4)

    def test_unknown_operation_with_missing_remote_marker_blocks_new_write(self):
        self.mode = 'timeout'; self.apply(); self.records.clear()
        plan = self.preview()
        self.assertFalse(plan['executable'])
        self.assertIn('unresolved_dns_write', [r['code'] for r in plan['conflicts']])
        self.assertEqual(len(self.writes()), 1)

    def test_existing_nodes_and_empty_nonterminals_get_precise_mx(self):
        self.edit(receive_subdomains=True, max_subdomain_depth=3)
        self.records += [{'id': 'a', 'name': 'www.example.test', 'type': 'A', 'content': '192.0.2.1'},
                         {'id': 'txt', 'name': '_proof.b.a.example.test', 'type': 'TXT', 'content': 'verification=x'}]
        plan = self.preview()
        names = {a['target']['name'] for a in plan['actions'] if a['target']['type'] == 'MX'}
        for expected in ('www.example.test', '*.www.example.test', 'a.example.test', '*.a.example.test', 'b.a.example.test', '*.b.a.example.test'):
            self.assertIn(expected, names)
        self.assertTrue(plan['executable'])
        self.assertEqual(plan['wildcard_readiness'], 'pending_until_resolver_and_boundary_validation')

    def test_external_cname_boundaries_skip_wildcard_mx_without_blocking_plan(self):
        self.edit(receive_subdomains=True, max_subdomain_depth=3)
        self.records += [
            {'id': 'send', 'name': 'send.example.test', 'type': 'CNAME', 'content': 'brand.brevosend.com'},
            {'id': 'r-send', 'name': 'r.send.example.test', 'type': 'CNAME', 'content': 'r.brand.brevosend.com'},
            {'id': 'img-send', 'name': 'img.send.example.test', 'type': 'CNAME', 'content': 'img.brand.brevosend.com'},
        ]
        plan = self.preview()
        self.assertTrue(plan['executable'])
        self.assertNotIn('cname_or_multiple_semantic_records', [c['code'] for c in plan['conflicts']])
        names = {a['target']['name'] for a in plan['actions'] if a['target']['role'] == 'wildcard_mx'}
        self.assertIn('*.example.test', names)
        for name in ('send.example.test', '*.send.example.test',
                     'r.send.example.test', '*.r.send.example.test',
                     'img.send.example.test', '*.img.send.example.test'):
            self.assertNotIn(name, names)
        self.assertTrue(any(n['code'] == 'external_cname_boundary_skipped' for n in plan['notices']))

    def test_delegation_blocks_wildcard_and_explicit_managed_child_is_excluded(self):
        self.edit(receive_subdomains=True, max_subdomain_depth=3)
        self.records.append({'id': 'ns', 'name': 'delegate.example.test', 'type': 'NS', 'content': 'ns.outside.test'})
        self.assertFalse(self.preview()['executable'])
        self.m.save_domain({'domain': 'delegate.example.test', 'enabled': False, 'users': [], 'receive_mode': 'catch_all'})
        plan = self.preview()
        self.assertTrue(plan['executable'])
        self.assertFalse(any(a['target']['name'].endswith('.delegate.example.test') or a['target']['name'] == 'delegate.example.test' for a in plan['actions']))

    def test_admin_routes_and_preview_api_never_returns_verification_token(self):
        self.records.append({'id': 'verify', 'name': 'example.test', 'type': 'TXT', 'content': base.TOKEN})
        response = self.case.client.post('/api/v1/mail-domains/example.test/dns-preview', headers=self.case.headers)
        self.assertEqual(response.status_code, 201)
        self.assertNotIn(base.TOKEN, response.text)
        plan = response.json()
        path = '/api/v1/mail-domains/example.test/dns-apply'
        self.assertEqual(self.case.client.post(path, headers={'X-API-Key': 'service', 'Idempotency-Key': 'service-blocked'}, json={'plan_id': plan['id']}).status_code, 401)
        response = self.case.client.post(path, headers={**self.case.headers, 'Idempotency-Key': 'api-apply-001'}, json={'plan_id': plan['id']})
        self.assertEqual(response.status_code, 202)
        self.assertNotIn(base.TOKEN, response.text)

    def test_digitalplat_mx_create_contract_is_supported(self):
        credential = self.m.add_dns_credential('digitalplat', 'example.test', 'fixture', {'api_token': base.TOKEN, 'api_base': 'https://dns.fixture.test'})
        self.m.bind_dns_credential('example.test', credential['id'])
        self.http.callback = lambda *a, **kw: {'data': []}
        plan = self.preview()
        self.assertTrue(plan['executable'])
        mx_actions = [a for a in plan['actions'] if a['target']['type'] == 'MX']
        self.assertEqual(len(mx_actions), 1)
        self.assertEqual(mx_actions[0]['action'], 'create')

    def parent_zone_fixture(self):
        original = self.respond
        # Use a multi-label real parent boundary, not a TLD-only zone lookup.
        domain = 'mail.a.example.test'
        self.m.save_domain({'domain': domain, 'enabled': False, 'users': [], 'receive_mode': 'catch_all',
                            'receive_subdomains': False, 'mx': 'mail.example.test'})
        key = self.case.root / 'keys' / domain / 'default.txt'
        key.parent.mkdir(parents=True, exist_ok=True)
        key.write_text('default._domainkey IN TXT ("v=DKIM1; k=rsa; p=QUJD")')
        self.m.bind_dns_credential(domain, self.m.domain('example.test')['dns_credential_ref'])
        def respond(method, base_url, path, **kw):
            if path == '/zones':
                name = kw['query']['name']
                return {'result': [{'id': 'parent-zone', 'name': 'example.test', 'status': 'active'}]} if name == 'example.test' else {'result': []}
            return original(method, base_url, path, **kw)
        self.http.callback = respond
        return domain

    def test_managed_subdomain_under_parent_ns_delegation_is_blocked(self):
        domain = self.parent_zone_fixture()
        self.records.append({'id': 'delegate', 'type': 'NS', 'name': 'a.example.test', 'content': 'ns.outside.test'})
        with self.assertRaises(ProviderError) as exc:
            self.m.dns.preview(domain)
        self.assertEqual(exc.exception.code, 'domain_delegated_outside_accessible_zone')
        self.assertEqual(self.writes(), [])

    def test_managed_subdomain_sees_parent_cname_not_unrelated_zone_txt(self):
        domain = self.parent_zone_fixture()
        self.records.extend([{'id': 'alias', 'type': 'CNAME', 'name': 'a.example.test', 'content': 'outside.test'},
                             {'id': 'verify', 'type': 'TXT', 'name': 'example.test', 'content': base.TOKEN}])
        plan = self.m.dns.preview(domain)
        self.assertFalse(plan['executable'])
        self.assertIn('cname_or_multiple_semantic_records', [x['code'] for x in plan['conflicts']])
        self.assertNotIn(base.TOKEN, json.dumps(plan))

    def test_mid_apply_external_ns_cname_or_txt_drift_stops_next_write(self):
        original = self.respond
        for kind in ('NS', 'CNAME', 'TXT'):
            with self.subTest(kind=kind):
                self.records.clear()
                self.http.calls.clear()
                def raced(method, base_url, path, **kw):
                    result = original(method, base_url, path, **kw)
                    if method == 'POST':
                        self.records.append({'id': 'external', 'name': '_domainkey.example.test',
                                             'type': kind, 'content': 'external.test'})
                    return result
                self.http.callback = raced
                result = self.apply(key='race-' + kind + '-fixture')
                self.assertEqual(result['status'], 'unknown')
                self.assertEqual(len(self.writes()), 1)
                self.assertEqual(result['error_code'], 'dns_inventory_changed_during_write')
                # New previews still require reconciling any pending intent.
                c = self.m.db()
                with c:
                    c.execute('DELETE FROM managed_dns_records')
                    c.execute('DELETE FROM domain_dns_operations')
                c.close()
        self.http.callback = original

    def test_drift_between_confirmed_write_and_next_inventory_is_partial(self):
        original = self.m.dns.confirm
        def confirm_then_drift(*args):
            original(*args)
            self.records.append({'id': 'external', 'name': '_domainkey.example.test',
                                 'type': 'CNAME', 'content': 'elsewhere.test'})
        with patch.object(self.m.dns, 'confirm', side_effect=confirm_then_drift):
            result = self.apply()
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(result['error_code'], 'dns_changed_before_write')

    def test_error_journal_failure_keeps_dispatched_job_unknown(self):
        self.mode = 'timeout'
        with patch.object(self.m.dns, 'set_operation_error', side_effect=OSError('fixture disk error')):
            result = self.apply()
        self.assertEqual(result['status'], 'unknown')
        self.assertTrue(self.preview()['executable'])
        self.assertEqual(self.apply(key='recover-journal-error')['status'], 'succeeded')
        self.assertEqual(len(self.writes()), 4)

    def test_readonly_preflight_timeout_has_no_unknown_write(self):
        plan = self.preview()
        self.http.callback = lambda *args, **kw: (_ for _ in ()).throw(ProviderError('fixture_timeout', uncertain=True))
        result = self.apply(plan)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.writes(), [])

    def digitalplat_fixture(self, mode='normal'):
        credential = self.m.add_dns_credential('digitalplat', 'example.test', 'fixture',
            {'api_token': base.TOKEN, 'api_base': 'https://dns.fixture.test'})
        self.m.bind_dns_credential('example.test', credential['id'])
        self.records = [{'id': 'external-mx', 'name': '@', 'type': 'MX',
                         'value': '10 mail.example.test.', 'ttl': 300}]
        def respond(method, base_url, path, **kw):
            if method == 'GET':
                return {'data': copy.deepcopy(self.records)}
            body = kw['body']
            self.assertIn(method, {'POST', 'PATCH'})
            if method == 'PATCH':
                row = next(r for r in self.records if r['id'] == path.rsplit('/', 1)[-1])
                row.update(copy.deepcopy(body))
                return {'data': copy.deepcopy(row)}
            self.assertEqual(set(body), {'type', 'name', 'ttl', 'value'})
            row_body = body
            row = {'id': 'dp-' + str(len(self.records)), **copy.deepcopy(row_body)}
            self.records.append(row)
            if mode == 'timeout':
                raise ProviderError('fixture_timeout', uncertain=True)
            return {'data': row}
        self.http.callback = respond

    def test_digitalplat_observed_txt_post_and_owned_update_fenced(self):
        self.digitalplat_fixture()
        result = self.apply()
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(len(self.writes()), 3)
        self.assertTrue(all(w[3]['body']['type'] == 'TXT' for w in self.writes()))
        self.edit(spf='v=spf1 -all')
        plan = self.preview()
        self.assertTrue(plan['executable'])
        self.assertTrue(any(a['action'] == 'update' and a['target']['role'] == 'spf' for a in plan['actions']))
        result = self.apply(key='digitalplat-owned-update-001')
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(self.writes()[-1][0], 'PATCH')

    def test_digitalplat_regenerated_apex_ns_ids_do_not_interrupt_apply(self):
        self.digitalplat_fixture()
        self.records.extend([
            {'id': 'ns-1', 'name': '@', 'type': 'NS', 'value': 'ns1.example.test.', 'ttl': 86400},
            {'id': 'ns-2', 'name': '@', 'type': 'NS', 'value': 'ns2.example.test.', 'ttl': 86400},
        ])
        original = self.http.callback
        reads = 0
        def regenerated(method, base_url, path, **kw):
            nonlocal reads
            if method == 'GET':
                reads += 1
                for i, record in enumerate(self.records):
                    if record['type'] == 'NS':
                        record['id'] = f'regenerated-{reads}-{i}'
            return original(method, base_url, path, **kw)
        self.http.callback = regenerated
        result = self.apply()
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(len(self.writes()), 3)
        self.assertTrue(all(w[3]['body']['type'] == 'TXT' for w in self.writes()))
        self.assertTrue(self.preview()['executable'])

    def test_digitalplat_apex_ns_content_change_still_stops_apply(self):
        self.digitalplat_fixture()
        self.records.append({'id': 'ns-1', 'name': '@', 'type': 'NS',
                             'value': 'ns1.example.test.', 'ttl': 86400})
        original = self.http.callback
        def changed(method, base_url, path, **kw):
            response = original(method, base_url, path, **kw)
            if method == 'POST':
                ns = next(r for r in self.records if r['type'] == 'NS')
                ns.update(id='regenerated-ns', value='ns.other.test.')
            return response
        self.http.callback = changed
        result = self.apply()
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['error_code'], 'dns_inventory_changed_during_write')
        self.assertEqual(len(self.writes()), 1)

    def test_digitalplat_ambiguous_post_never_recovers_by_content_only(self):
        self.digitalplat_fixture(mode='timeout')
        self.assertEqual(self.apply()['status'], 'unknown')
        self.assertIn('unresolved_dns_write', [x['code'] for x in self.preview()['conflicts']])
        self.assertEqual(len(self.writes()), 1)

    def interrupted_digitalplat_write(self):
        self.digitalplat_fixture()
        with patch.object(self.m.dns, 'confirm', side_effect=OSError('fixture disk error')):
            result = self.apply()
        self.assertEqual(result['status'], 'unknown')
        return result, result['result']['operation_id']

    def test_digitalplat_reconcile_observes_without_adoption_or_duplicate_write(self):
        original, operation_id = self.interrupted_digitalplat_write()
        self.assertFalse(self.preview()['executable'])
        result = self.m.dns.reconcile_operation('example.test', operation_id)
        self.assertEqual(result['status'], 'observed')
        self.assertFalse(result['ownership_adopted'])
        self.assertEqual(result['dns_writes'], 0)
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(self.m.jobs.get(original['id'])['status'], 'partial')
        self.assertEqual(self.m.dns.owned(self.m.domain('example.test'), 'example.test'), {})
        self.assertEqual(self.m.dns.reconcile_operation('example.test', operation_id), result)
        fresh = self.preview()
        self.assertTrue(fresh['executable'])
        self.assertEqual(self.apply(fresh, key='reconciled-digitalplat')['status'], 'succeeded')
        self.assertEqual(len(self.writes()), 3, 'The observed SPF must not be posted again')
        self.edit(spf='v=spf1 -all')
        self.assertIn('foreign_record_conflict', [x['code'] for x in self.preview()['conflicts']],
                      'Observed content must not grant future update ownership')

    def test_digitalplat_reconcile_missing_changed_or_duplicate_record_stays_blocked(self):
        _, operation_id = self.interrupted_digitalplat_write()
        saved = copy.deepcopy(self.records)
        for records in (
            saved[:-1],
            [saved[0], {**saved[-1], 'value': '"v=spf1 -all"'}],
            saved + [{**saved[-1], 'id': 'duplicate-spf'}],
        ):
            with self.subTest(records=len(records)):
                self.records = copy.deepcopy(records)
                with self.assertRaises(JobConflict):
                    self.m.dns.reconcile_operation('example.test', operation_id)
                self.assertIn('unresolved_dns_write', [x['code'] for x in self.preview()['conflicts']])
        self.assertEqual(len(self.writes()), 1)

    def test_digitalplat_reconcile_rejects_changed_target_binding_and_active_apply(self):
        original, operation_id = self.interrupted_digitalplat_write()
        self.edit(spf='v=spf1 -all')
        with self.assertRaises(JobConflict):
            self.m.dns.reconcile_operation('example.test', operation_id)
        self.edit(spf='v=spf1 ip4:203.0.113.10 -all')
        credential = self.m.add_dns_credential('digitalplat', 'example.test', 'replacement',
            {'api_token': base.TOKEN, 'api_base': 'https://dns.fixture.test'})
        old_ref = self.m.domain('example.test')['dns_credential_ref']
        self.m.bind_dns_credential('example.test', credential['id'])
        with self.assertRaises(JobConflict):
            self.m.dns.reconcile_operation('example.test', operation_id)
        self.m.bind_dns_credential('example.test', old_ref)
        self.m.jobs.enqueue('dns_apply', 'example.test', 'active-reconciliation-fixture',
                            {'plan_id': original['request']['plan_id']})
        with self.assertRaises(JobConflict):
            self.m.dns.reconcile_operation('example.test', operation_id)
        self.assertEqual(self.m.jobs.get(original['id'])['status'], 'unknown')
        self.assertIn('unresolved_dns_write', [x['code'] for x in self.preview()['conflicts']])
        self.assertEqual(len(self.writes()), 1)

    def test_digitalplat_reconcile_route_requires_admin_and_scoped_operation(self):
        _, operation_id = self.interrupted_digitalplat_write()
        path = f'/api/v1/mail-domains/example.test/dns-operations/{operation_id}/reconcile'
        self.assertEqual(self.case.client.post(path).status_code, 401)
        response = self.case.client.post(path, headers={'X-API-Key': 'admin-fixture'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['status'], 'observed')
        self.assertNotIn(base.TOKEN, response.text)
        wrong = path.replace(operation_id, 'unrelated-operation')
        self.assertEqual(self.case.client.post(wrong, headers={'X-API-Key': 'admin-fixture'}).status_code, 409)

    def shared_digitalplat_txt_fixture(self, mutate_peer=False):
        self.digitalplat_fixture()
        self.records.append({'id': 'apex-txt', 'rrset_id': 'apex-txt', 'name': '@',
                             'type': 'TXT', 'value': '"foreign-verification"', 'ttl': 300})
        original = self.http.callback
        def respond(method, base_url, path, **kw):
            if method == 'POST' and kw['body']['type'] == 'TXT' and kw['body']['name'] == '@':
                self.records.append({'id': 'apex-txt', 'rrset_id': 'apex-txt', **copy.deepcopy(kw['body'])})
                if mutate_peer:
                    next(r for r in self.records if r.get('value') == '"foreign-verification"')['value'] = '"externally-changed"'
                return {'data': {'id': 'apex-txt'}}
            if method == 'PATCH' and path.endswith('/apex-txt'):
                body = kw['body']
                self.assertIn('values', body, 'Shared RRset updates must retain every TXT value')
                self.records[:] = [r for r in self.records if r['id'] != 'apex-txt']
                self.records.extend({'id': 'apex-txt', 'rrset_id': 'apex-txt', 'name': '@', 'type': 'TXT',
                                     'value': value, 'ttl': body['ttl']} for value in body['values'])
                return {'data': {'id': 'apex-txt'}}
            return original(method, base_url, path, **kw)
        self.http.callback = respond

    def test_shared_txt_rrset_owns_each_value_and_preserves_peers_on_update(self):
        self.shared_digitalplat_txt_fixture()
        extra = {'role': 'brevo_auth', 'type': 'TXT', 'name': 'example.test',
                 'content': 'brevo-code:fixture', 'ttl': 300}
        with patch.object(self.m, 'brevo_dns_targets', return_value=[extra]):
            self.assertEqual(self.apply()['status'], 'succeeded')
            self.assertTrue(self.preview()['executable'])
            owner = self.m.dns.owned(self.m.domain('example.test'), 'example.test')['apex-txt']
            proofs = json.loads(owner['last_content'])['owned_records']
            self.assertEqual({proof['target']['role'] for proof in proofs}, {'spf', 'brevo_auth'})
            self.edit(spf='v=spf1 ip4:203.0.113.20 -all')
            before = len(self.writes())
            result = self.apply(key='shared-txt-update-001')
            self.assertEqual(result['status'], 'succeeded')
            self.assertEqual(len(self.writes()), before + 1)
            values = self.writes()[-1][3]['body']['values']
            self.assertEqual(set(values), {'"foreign-verification"', '"brevo-code:fixture"',
                                           '"v=spf1 ip4:203.0.113.20 -all"'})
            self.assertTrue(self.preview()['executable'])

    def test_shared_txt_rrset_peer_drift_is_detected_after_write(self):
        self.shared_digitalplat_txt_fixture(mutate_peer=True)
        result = self.apply()
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['error_code'], 'dns_inventory_changed_during_write')
        self.assertEqual(len(self.writes()), 1)

    def test_disabled_domain_key_snapshot_does_not_grant_smtp(self):
        row = self.m.domain('example.test')
        generation = publish([row], self.case.root / 'snapshot')
        root = self.case.root / 'snapshot/generations' / generation
        self.assertEqual((root / 'domains.list').read_text(), '')
        self.assertEqual((root / 'key-domains.list').read_text(), 'example.test\n')
        self.assertFalse(recipient_policy('any@example.test', [row])['ok'])


if __name__ == '__main__':
    unittest.main()

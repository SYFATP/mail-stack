"""Offline end-to-end delegation, durable retry, and no-replay regression tests."""
import copy
import io
import json
import time
import unittest
import urllib.error
from types import SimpleNamespace
from unittest.mock import patch

import test_domain_control as base
import test_dynv6 as dynbase
from api.providers.http import JsonTransport, ProviderError
from api.repositories.domain_jobs import JobConflict, assert_domain_mutable
from api.services.dns_completion import DelegationProbe, TARGET_NS, HOSTED_NS


class DNSCompletionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = dynbase.Dynv6Tests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)
        self.m, self.wire = self.fixture.m, self.fixture.wire
        self.private = self.fixture.case.root / 'keys/example.test/default.private'
        self.private.write_text('fixture-private-key')
        self.assertEqual(self.fixture.apply()['status'], 'succeeded')
        source = self.fixture.case.source()
        allocation = self.m.create_claim_job(source['id'], 'delegation-allocation')
        claim_id = self.m._record_claim(source, allocation, {'domain': 'example.test', 'claim_id': 'upstream-delegation', 'status': 'active'})
        dp = self.m.add_dns_credential('digitalplat', 'example.test', 'original registrar',
            {'api_token': base.TOKEN, 'api_base': 'https://dns.fixture.test'})
        c = self.m.db()
        with c:
            c.execute("UPDATE mail_domains SET claim_id=? WHERE domain='example.test'", (claim_id,))
            c.execute('UPDATE domain_claims SET dns_credential_ref=? WHERE id=?', (dp['id'], claim_id))
        c.close()
        self.assertEqual(self.m.jobs.take()['id'], allocation['id'])
        self.m.jobs.finish(allocation['id'], 'succeeded', step='fixture_imported')
        self.current_ns, self.posts = list(HOSTED_NS), []
        self.failure, self.authorities_ready, self.parents_ready = '', True, True
        self.m.http = SimpleNamespace(request=self.request)
        self.enterContext(patch.object(self.m.dns_completion.probe, 'targets', side_effect=self.targets))
        self.enterContext(patch.object(self.m.dns_completion.probe, 'parents', side_effect=self.parents))

    def request(self, method, base_url, path, **kwargs):
        if base_url != 'https://dns.fixture.test':
            return self.wire.request(method, base_url, path, **kwargs)
        if method == 'GET':
            return {'data': {'domain': 'example.test', 'status': 'active', 'nameservers': list(self.current_ns)}}
        self.assertEqual(path, '/domains/example.test/dns/switch-external')
        c = self.m.db()
        saved = c.execute("SELECT result_json FROM domain_jobs WHERE status='running' AND kind='dns_complete'").fetchone()
        c.close()
        self.assertEqual(json.loads(saved[0])['delegation']['writes'][-1]['phase'], 'dispatched')
        self.posts.append(copy.deepcopy(kwargs))
        if self.failure == 'ambiguous409':
            raise ProviderError('provider_http_409', uncertain=True)
        if not kwargs['body']['force']:
            raise ProviderError('provider_http_409', uncertain=False, upstream_code='external_nameserver_precheck_failed')
        if self.failure == 'rate':
            raise ProviderError('provider_http_429', uncertain=True, retry_after=1200)
        if self.failure != 'timeout-no-commit':
            self.current_ns = list(TARGET_NS)
        if self.failure.startswith('timeout'):
            raise ProviderError('provider_transport_or_json_error', uncertain=True)
        return {'success': True, 'data': {'operation_id': 'fixture-operation'}}

    def targets(self, row, targets):
        return {'passed': self.authorities_ready, 'checks': [{'passed': self.authorities_ready}]}

    def parents(self, domain):
        return {'passed': self.parents_ready and set(self.current_ns) == set(TARGET_NS),
                'checks': [{'host': 'parent.fixture', 'nameservers': list(self.current_ns),
                            'passed': self.parents_ready and set(self.current_ns) == set(TARGET_NS)}]}

    def enqueue(self, key='completion-fixture'):
        return self.m.create_validate_job('example.test', key, activate_on_success=True)

    def execute(self, job):
        c = self.m.db()
        with c:
            c.execute("UPDATE domain_jobs SET result_json=json_set(result_json,'$.retry_at',0) WHERE id=?", (job['id'],))
        c.close()
        self.assertTrue(self.m.run_once())
        return self.m.jobs.get(job['id'])

    def test_migrates_once_after_all_authorities_pass_then_validates_and_activates(self):
        job = self.enqueue()
        self.assertEqual(job['kind'], 'dns_complete')
        self.assertFalse(job['read_only'])
        first = self.execute(job)
        self.assertEqual(first['status'], 'queued')
        self.assertEqual(first['step'], 'dns_completion_waiting_delegation')
        self.assertFalse(self.m.domain('example.test')['enabled'])
        self.assertEqual([p['body']['force'] for p in self.posts], [False, True])
        self.assertNotEqual(*(p['headers']['Idempotency-Key'] for p in self.posts))
        self.assertEqual(self.m.dns_completion.probe.targets.call_count, 2)
        final = self.execute(job)
        self.assertEqual(final['status'], 'succeeded', final)
        self.assertTrue(self.m.domain('example.test')['enabled'])
        self.assertEqual(final['result']['delegation']['phase'], 'confirmed')
        self.assertEqual(len(self.posts), 2)
        self.assertEqual(len(self.fixture.writes()), 4)
        self.assertNotIn(base.TOKEN, json.dumps(final))
        self.assertEqual(self.enqueue()['id'], job['id'], 'Retry keeps original identity after enabled revision changes')

    def test_apply_schedules_durable_completion_before_recursive_validation(self):
        preview = self.m.dns.preview('example.test')
        job = self.m.dns.enqueue('example.test', preview['id'], 'apply-complete-fixture', activate_on_success=True)
        with patch.object(self.m.validator, 'validate') as validate:
            self.assertTrue(self.m.run_once())
            validate.assert_not_called()
        applied = self.m.jobs.get(job['id'])
        child = applied['result']['completion_job']
        self.assertEqual(child['kind'], 'dns_complete')
        self.assertEqual(applied['step'], 'dns_applied_completion_queued')
        self.execute(child)
        self.assertEqual(self.execute(child)['status'], 'succeeded')

    def test_existing_dynv6_delegation_skips_all_ns_writes(self):
        self.current_ns = list(TARGET_NS)
        self.assertEqual(self.execute(self.enqueue())['status'], 'succeeded')
        self.assertEqual(self.posts, [])

    def test_new_empty_delegation_is_created_after_every_parent_proves_absence(self):
        self.current_ns = []
        def parents(domain):
            current = list(self.current_ns)
            return {'passed': set(current) == set(TARGET_NS), 'checks': [
                {'host': host, 'nameservers': current, 'passed': set(current) == set(TARGET_NS),
                 'undelegated': not current} for host in ('ns1.parent.test', 'ns2.parent.test')]}
        self.m.dns_completion.probe.parents.side_effect = parents
        job = self.enqueue()
        first = self.execute(job)
        self.assertEqual(first['status'], 'queued', first)
        self.assertEqual(first['result']['delegation']['before_nameservers'], [])
        self.assertEqual([p['body']['force'] for p in self.posts], [False, True])
        final = self.execute(job)
        self.assertEqual(final['status'], 'succeeded', final)
        self.assertTrue(self.m.domain('example.test')['enabled'])
        self.assertEqual(len(self.posts), 2)
        self.assertEqual(len(self.fixture.writes()), 4, 'Resume must not rewrite mail DNS')

    def initial_delegation(self, *, failure='', response=None):
        self.current_ns, self.patches = [], []
        request = self.m.http.request
        def initial_request(method, base_url, path, **kwargs):
            if base_url == 'https://dns.fixture.test':
                if method == 'GET' and path == '/domains/example.test/dns':
                    raise ProviderError('provider_http_404', upstream_code='hosted_dns_zone_not_found')
                if method == 'PATCH' and path == '/domains/example.test/nameservers':
                    c = self.m.db()
                    try:
                        saved = c.execute("SELECT result_json FROM domain_jobs WHERE status='running' AND kind='dns_complete'").fetchone()
                    finally:
                        c.close()
                    delegation = json.loads(saved[0])['delegation']
                    self.assertEqual(delegation['operation'], 'set_nameservers')
                    self.assertEqual(delegation['writes'][-1]['phase'], 'dispatched')
                    self.assertEqual(kwargs['body'], {'nameservers': list(TARGET_NS)})
                    self.assertEqual(kwargs['headers']['Idempotency-Key'], delegation['writes'][-1]['idempotency_key'])
                    self.patches.append(copy.deepcopy(kwargs))
                    if failure == 'precheck409':
                        raise ProviderError('provider_http_409', upstream_code='external_nameserver_precheck_failed')
                    if failure != 'timeout-no-commit':
                        self.current_ns = list(TARGET_NS)
                    if failure.startswith('timeout'):
                        raise ProviderError('provider_transport_or_json_error', uncertain=True)
                    return response if response is not None else {
                        'success': True, 'data': {'name': 'example.test', 'nameservers': list(TARGET_NS)}}
            return request(method, base_url, path, **kwargs)
        self.m.http.request = initial_request
        def parents(domain):
            current = list(self.current_ns)
            return {'passed': set(current) == set(TARGET_NS), 'checks': [
                {'host': host, 'nameservers': current, 'passed': set(current) == set(TARGET_NS),
                 'undelegated': not current} for host in ('ns1.parent.test', 'ns2.parent.test')]}
        self.m.dns_completion.probe.parents.side_effect = parents

    def test_first_delegation_without_hosted_zone_uses_patch_then_validates_and_enables(self):
        self.initial_delegation()
        job = self.enqueue()
        first = self.execute(job)
        self.assertEqual(first['step'], 'dns_completion_waiting_delegation', first)
        self.assertFalse(self.m.domain('example.test')['enabled'])
        self.assertEqual(first['result']['delegation']['writes'][0]['phase'], 'accepted')
        self.assertEqual(self.execute(job)['status'], 'succeeded')
        self.assertTrue(self.m.domain('example.test')['enabled'])
        self.assertEqual(len(self.patches), 1)
        self.assertEqual(self.posts, [])
        self.assertEqual(len(self.fixture.writes()), 4, 'First delegation must not recreate mail DNS')

    def test_first_delegation_timeout_after_commit_is_read_back_without_replay(self):
        self.initial_delegation(failure='timeout-committed')
        job = self.enqueue()
        first = self.execute(job)
        self.assertEqual(first['result']['delegation']['writes'][0]['phase'], 'uncertain')
        self.assertEqual(self.execute(job)['status'], 'succeeded')
        self.assertTrue(self.m.domain('example.test')['enabled'])
        self.assertEqual(len(self.patches), 1)
        self.assertEqual(self.posts, [])

    def test_first_delegation_unconfirmed_timeout_blocks_replay_even_in_a_new_job(self):
        self.initial_delegation(failure='timeout-no-commit')
        job = self.enqueue()
        self.execute(job)
        waiting = self.execute(job)
        self.assertEqual(waiting['step'], 'dns_completion_readback_pending', waiting)
        c = self.m.db()
        with c:
            c.execute("UPDATE domain_jobs SET result_json=json_set(result_json,'$.retry_at',0) WHERE id=?", (job['id'],))
        c.close()
        self.assertEqual(self.m.jobs.take()['id'], job['id'])
        self.m.jobs.finish(job['id'], 'partial', step='fixture_timed_out', result=waiting['result'])
        newer = self.enqueue('initial-after-timeout')
        self.assertNotEqual(newer['id'], job['id'])
        self.assertEqual(self.execute(newer)['step'], 'dns_completion_readback_pending')
        self.assertEqual(len(self.patches), 1)
        self.assertEqual(self.posts, [])
        self.assertFalse(self.m.domain('example.test')['enabled'])

    def test_first_delegation_patch_rejection_never_enters_validation_or_force_switch(self):
        self.initial_delegation(failure='precheck409')
        with patch.object(self.m.validator, 'validate') as validate:
            result = self.execute(self.enqueue())
            validate.assert_not_called()
        self.assertEqual(result['status'], 'partial', result)
        self.assertEqual(result['error_code'], 'provider_http_409')
        self.assertEqual(result['result']['delegation']['writes'][0]['phase'], 'rejected')
        self.assertEqual(len(self.patches), 1)
        self.assertEqual(self.posts, [])
        self.assertFalse(self.m.domain('example.test')['enabled'])

    def test_first_delegation_unrecognized_success_is_confirmed_only_by_readback(self):
        self.initial_delegation(response={'success': True, 'data': {}})
        job = self.enqueue()
        first = self.execute(job)
        self.assertEqual(first['result']['delegation']['writes'][0]['phase'], 'uncertain')
        self.assertEqual(first['result']['delegation']['writes'][0]['error_code'], 'digitalplat_ns_set_unconfirmed')
        self.assertFalse(self.m.domain('example.test')['enabled'])
        self.assertEqual(self.execute(job)['status'], 'succeeded')
        self.assertEqual(len(self.patches), 1)
        self.assertEqual(self.posts, [])

    def test_empty_registrar_ns_and_unavailable_parent_never_authorize_a_write(self):
        self.current_ns = []
        result = self.execute(self.enqueue())
        self.assertEqual(result['status'], 'queued', result)
        self.assertEqual(result['step'], 'dns_completion_waiting_authorities')
        self.assertEqual(self.posts, [])
        self.assertFalse(self.m.domain('example.test')['enabled'])

    def test_empty_registrar_ns_does_not_overwrite_actual_external_delegation(self):
        self.current_ns = []
        self.m.dns_completion.probe.parents.side_effect = lambda domain: {
            'passed': False, 'checks': [{'host': 'ns.parent.test', 'nameservers': ['external.test'],
                                       'passed': False, 'undelegated': False}]}
        result = self.execute(self.enqueue())
        self.assertEqual(result['error_code'], 'dns_delegation_parent_conflict')
        self.assertEqual(self.posts, [])

    def test_target_parent_delegation_is_authoritative_even_if_registrar_cache_is_empty(self):
        self.current_ns = []
        self.m.dns_completion.probe.parents.side_effect = lambda domain: {
            'passed': True, 'checks': [{'host': 'ns.parent.test', 'nameservers': list(TARGET_NS),
                                      'passed': True, 'undelegated': False}]}
        result = self.execute(self.enqueue())
        self.assertEqual(result['status'], 'succeeded', result)
        self.assertTrue(self.m.domain('example.test')['enabled'])
        self.assertEqual(self.posts, [])

    def test_empty_delegation_is_rechecked_before_dispatch(self):
        self.current_ns = []
        self.m.dns_completion.probe.parents.side_effect = lambda domain: {
            'passed': False, 'checks': [{'host': 'ns.parent.test', 'nameservers': [],
                                       'passed': False, 'undelegated': True}]}
        def targets(row, records):
            self.current_ns = ['new-external.test']
            return {'passed': True, 'checks': []}
        self.m.dns_completion.probe.targets.side_effect = targets
        result = self.execute(self.enqueue())
        self.assertEqual(result['status'], 'queued', result)
        self.assertEqual(result['step'], 'dns_completion_readback_pending')
        self.assertEqual(self.posts, [])

    def test_other_provider_is_never_overwritten(self):
        self.current_ns = ['alice.ns.cloudflare.com', 'bob.ns.cloudflare.com']
        final = self.execute(self.enqueue())
        self.assertEqual(final['error_code'], 'dns_delegation_external_provider_conflict')
        self.assertEqual(self.posts, [])
        self.assertFalse(self.m.domain('example.test')['enabled'])

    def test_unready_target_authority_defers_without_switching_or_holding_worker(self):
        self.authorities_ready = False
        final = self.execute(self.enqueue())
        self.assertEqual(final['status'], 'queued')
        self.assertEqual(final['step'], 'dns_completion_waiting_authorities')
        self.assertEqual(self.posts, [])
        self.assertIsNone(self.m.jobs.take())

    def test_record_inventory_must_contain_the_entire_plan(self):
        self.wire.records.pop()
        final = self.execute(self.enqueue())
        self.assertEqual(final['error_code'], 'dns_completion_records_missing')
        self.assertEqual(self.posts, [])

    def test_explicit_precheck_failure_is_the_only_reason_to_force(self):
        self.failure = 'ambiguous409'
        job = self.enqueue()
        self.assertEqual(self.execute(job)['status'], 'queued')
        self.assertEqual(self.execute(job)['status'], 'queued')
        self.assertEqual(len(self.posts), 1)
        self.assertFalse(self.posts[0]['body']['force'])

    def test_timeout_after_commit_is_resolved_by_readback_without_replay(self):
        self.failure = 'timeout-committed'
        job = self.enqueue()
        self.execute(job)
        self.assertEqual(self.execute(job)['status'], 'succeeded')
        self.assertEqual(len(self.posts), 2)

    def test_ambiguous_timeout_never_replays_even_after_explicit_new_job(self):
        self.failure = 'timeout-no-commit'
        job = self.enqueue()
        self.execute(job)
        self.assertEqual(self.execute(job)['step'], 'dns_completion_readback_pending')
        # Simulate a crash after admission. Startup preserves the previous dispatch ledger.
        c = self.m.db()
        with c:
            c.execute("UPDATE domain_jobs SET status='running' WHERE id=?", (job['id'],))
        c.close()
        self.m.jobs.recover_interrupted()
        newer = self.enqueue('completion-after-restart')
        self.assertEqual(newer['id'], job['id'])
        self.assertEqual(self.execute(newer)['step'], 'dns_completion_readback_pending')
        self.assertEqual(len(self.posts), 2)
        self.assertFalse(self.m.domain('example.test')['enabled'])

    def test_validation_retries_release_worker_and_only_enable_after_dns_passes(self):
        self.current_ns = list(TARGET_NS)
        job = self.enqueue()
        original = self.m.validator.validate
        def stale(row, keys):
            result = original(row, keys)
            result['checks']['mx'] = {'status': 'failed', 'detail': 'cached_old_delegation'}
            return result
        with patch.object(self.m.validator, 'validate', side_effect=stale):
            waiting = self.execute(job)
        self.assertEqual(waiting['step'], 'dns_completion_waiting_dns')
        self.assertFalse(self.m.domain('example.test')['enabled'])
        self.assertIsNone(self.m.jobs.take())
        self.assertEqual(self.execute(job)['status'], 'succeeded')
        self.assertTrue(self.m.domain('example.test')['enabled'])
        self.assertEqual(self.posts, [])

    def test_revision_change_while_waiting_cancels_activation(self):
        job = self.enqueue()
        self.execute(job)
        c = self.m.db()
        with c:
            c.execute("UPDATE mail_domains SET spf='v=spf1 -all' WHERE domain='example.test'")
        c.close()
        final = self.execute(job)
        self.assertEqual(final['error_code'], 'dns_completion_configuration_changed')
        self.assertFalse(self.m.domain('example.test')['enabled'])
        self.assertEqual(len(self.posts), 2)

    def test_double_click_reuses_pending_completion_for_the_same_revision(self):
        job = self.enqueue()
        self.assertEqual(self.enqueue('completion-second-click')['id'], job['id'])

    def test_missing_registrar_credential_does_not_block_existing_valid_delegation(self):
        c = self.m.db()
        with c:
            c.execute("UPDATE mail_domains SET claim_id=NULL WHERE domain='example.test'")
        c.close()
        job = self.enqueue()
        self.assertEqual(self.execute(job)['error_code'], 'digitalplat_delegation_credential_required')
        self.current_ns = list(TARGET_NS)
        self.assertEqual(self.execute(self.enqueue('completion-manual-existing'))['status'], 'succeeded')

    def test_deadline_produces_actionable_partial_status_without_enabling(self):
        self.authorities_ready = False
        job = self.enqueue()
        waiting = self.execute(job)
        saved = waiting['result']; saved['deadline'] = time.time() - 1
        c = self.m.db()
        with c:
            c.execute('UPDATE domain_jobs SET result_json=? WHERE id=?', (json.dumps(saved), job['id']))
        c.close()
        final = self.execute(job)
        self.assertEqual(final['status'], 'partial')
        self.assertEqual(final['step'], 'dns_completion_timed_out')
        self.assertEqual(self.posts, [])

    def test_rate_limit_is_attributed_to_digitalplat_and_retains_dispatch(self):
        self.failure = 'rate'
        job = self.enqueue()
        waiting = self.execute(job)
        self.assertEqual(waiting['result']['provider_backoff']['provider'], 'digitalplat')
        self.assertEqual(waiting['wait_reason'], 'retry_at')
        self.assertEqual(waiting['result']['delegation']['writes'][-1]['phase'], 'uncertain')
        self.assertIsNone(self.m.jobs.take())
        self.current_ns = list(TARGET_NS)
        self.assertEqual(self.execute(job)['status'], 'succeeded', 'Readback proceeds during provider cooldown')

    def test_active_completion_locks_its_domain_and_child_namespace(self):
        job = self.enqueue()
        self.assertEqual(self.m.jobs.take()['id'], job['id'])
        for name in ('example.test', 'sub.example.test'):
            with self.assertRaises(JobConflict):
                assert_domain_mutable(self.m.db, name)
        self.assertIn(job['id'], [r['id'] for r in self.m.jobs.list()['active_domain_jobs']])

    def test_startup_resumes_an_interrupted_switch_by_readback_only(self):
        job = self.enqueue()
        self.execute(job)
        c = self.m.db()
        with c:
            c.execute("UPDATE domain_jobs SET status='running' WHERE id=?", (job['id'],))
        c.close()
        self.m.jobs.recover_interrupted()
        self.assertEqual(self.m.jobs.get(job['id'])['status'], 'queued')
        self.assertEqual(self.execute(job)['status'], 'succeeded')
        self.assertEqual(len(self.posts), 2)

    def test_unavailable_parent_authority_is_not_permission_to_force_a_switch(self):
        with patch.object(self.m.dns_completion.probe, 'parents', return_value={
                'passed': False, 'checks': [{'host': 'parent.fixture', 'nameservers': [], 'passed': False}]}):
            waiting = self.execute(self.enqueue())
        self.assertEqual(waiting['step'], 'dns_completion_waiting_authorities')
        self.assertEqual(self.posts, [])

    def test_changed_claim_generation_blocks_an_old_waiting_completion(self):
        job = self.enqueue()
        self.execute(job)
        newer = self.m.jobs.enqueue('claim', self.m.sources()[0]['id'], 'new-claim-generation-fixture', {})
        c = self.m.db()
        try:
            with c:
                c.execute("UPDATE domain_jobs SET status='succeeded' WHERE id=?", (newer['id'],))
                c.execute("UPDATE domain_claims SET job_id=? WHERE domain='example.test'", (newer['id'],))
        finally:
            c.close()
        self.assertEqual(self.execute(job)['error_code'], 'dns_completion_configuration_changed')
        self.assertFalse(self.m.domain('example.test')['enabled'])

    def test_provider_read_failure_does_not_discard_switch_checkpoint(self):
        job = self.enqueue()
        self.execute(job)
        request = self.m.http.request
        def unavailable(method, base_url, path, **kwargs):
            if method == 'GET' and base_url == 'https://dns.fixture.test':
                raise ProviderError('provider_http_503', uncertain=True)
            return request(method, base_url, path, **kwargs)
        with patch.object(self.m.http, 'request', side_effect=unavailable):
            waiting = self.execute(job)
        self.assertEqual(waiting['step'], 'dns_completion_waiting_upstream')
        self.assertEqual(len(waiting['result']['delegation']['writes']), 2)
        self.assertEqual(self.execute(job)['status'], 'succeeded')
        self.assertEqual(len(self.posts), 2)

    def test_read_only_validation_never_changes_ns(self):
        job = self.m.create_validate_job('example.test', 'read-only-completion-fixture')
        self.assertEqual(job['kind'], 'dns_validate')
        self.execute(job)
        self.assertEqual(self.posts, [])
        self.assertFalse(self.m.domain('example.test')['enabled'])

    def test_api_activation_returns_completion_and_admin_is_required(self):
        path = '/api/v1/mail-domains/example.test/dns-validate'
        self.assertEqual(self.fixture.case.client.post(path, json={'activate_on_success': True}).status_code, 401)
        response = self.fixture.case.client.post(path, json={'activate_on_success': True},
            headers={**self.fixture.case.headers, 'Idempotency-Key': 'completion-api-fixture'})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()['kind'], 'dns_complete')


class DelegationProbeTests(unittest.TestCase):
    def test_queries_target_authorities_without_recursion_and_requires_aa(self):
        import dns.flags, dns.message, dns.rrset
        probe = DelegationProbe()
        answer = dns.message.make_response(dns.message.make_query('example.test', 'MX'))
        answer.answer.append(dns.rrset.from_text('example.test.', 60, 'IN', 'MX', '10 mail.example.test.'))
        def exchange(query, address, **kw):
            self.assertFalse(query.flags & dns.flags.RD)
            self.assertEqual(address, '203.0.113.25')
            return answer
        with patch.object(probe.resolver, 'resolve', return_value=['203.0.113.25']), \
             patch('api.services.dns_completion.dns.query.tcp', side_effect=exchange):
            self.assertIsNone(probe.query('ns1.dynv6.com', 'example.test', 'MX'))
            answer.flags |= dns.flags.AA
            self.assertEqual(probe.query('ns1.dynv6.com', 'example.test', 'MX'), {'10 mail.example.test'})

    def test_authoritative_negative_parent_answer_proves_no_delegation(self):
        import dns.flags, dns.message, dns.rrset
        probe = DelegationProbe()
        for rcode in (0, 3):
            with self.subTest(rcode=rcode):
                response = dns.message.make_response(dns.message.make_query('new.qd.je', 'NS'))
                response.flags |= dns.flags.AA
                response.set_rcode(rcode)
                response.authority.append(dns.rrset.from_text('qd.je.', 300, 'IN', 'SOA',
                    'ns1.parent.test. admin.parent.test. 1 600 180 1209600 300'))
                with patch.object(probe.resolver, 'resolve', return_value=['203.0.113.25']), \
                     patch('api.services.dns_completion.dns.query.tcp', return_value=response):
                    self.assertEqual(probe.query('ns1.parent.test', 'new.qd.je', 'NS', authoritative=False), set())
                    if rcode:
                        self.assertIsNone(probe.query('ns1.parent.test', 'new.qd.je', 'NS'))

    def test_empty_or_unrelated_or_aliased_parent_response_is_not_absence_proof(self):
        import dns.flags, dns.message, dns.rrset
        probe = DelegationProbe()
        for case in ('no-aa', 'no-soa', 'unrelated-soa', 'child-soa', 'alias'):
            with self.subTest(case=case):
                response = dns.message.make_response(dns.message.make_query('new.qd.je', 'NS'))
                response.flags |= dns.flags.AA
                zone = 'other.test.' if case == 'unrelated-soa' else 'new.qd.je.' if case == 'child-soa' else 'qd.je.'
                if case != 'no-soa':
                    response.authority.append(dns.rrset.from_text(zone, 300, 'IN', 'SOA',
                        'ns1.parent.test. admin.parent.test. 1 600 180 1209600 300'))
                if case == 'no-aa':
                    response.flags &= ~dns.flags.AA
                if case == 'alias':
                    response.answer.append(dns.rrset.from_text('new.qd.je.', 60, 'IN', 'CNAME', 'external.test.'))
                with patch.object(probe.resolver, 'resolve', return_value=['203.0.113.25']), \
                     patch('api.services.dns_completion.dns.query.tcp', return_value=response):
                    self.assertIsNone(probe.query('ns1.parent.test', 'new.qd.je', 'NS', authoritative=False))

    def test_parent_checks_distinguish_confirmed_absence_from_unavailable_reads(self):
        import dns.name
        probe = DelegationProbe()
        hosts = [SimpleNamespace(target='ns1.parent.test.'), SimpleNamespace(target='ns2.parent.test.')]
        with patch('api.services.dns_completion.dns.resolver.zone_for_name', return_value=dns.name.from_text('qd.je.')), \
             patch.object(probe.resolver, 'resolve', return_value=hosts), \
             patch.object(probe, 'query', side_effect=lambda host,*a,**k: set() if host.startswith('ns1') else None):
            result = probe.parents('new.qd.je')
        self.assertFalse(result['passed'])
        self.assertEqual([c['undelegated'] for c in result['checks']], [True, False])

    def test_every_target_authority_must_serve_all_records(self):
        row = {'domain': 'example.test', 'receive_subdomains': False, 'max_subdomain_depth': 1}
        records = [{'type': 'TXT', 'name': 'example.test', 'content': 'v=spf1 -all'}]
        probe = DelegationProbe()
        def query(host, name, kind):
            if kind == 'NS':
                return set(TARGET_NS)
            return {'v=spf1 -all', 'unrelated-TXT'} if host != 'ns3.dynv6.com' else None
        with patch.object(probe, 'query', side_effect=query) as queries:
            result = probe.targets(row, records)
        self.assertFalse(result['passed'])
        self.assertEqual(queries.call_count, 6)
        self.assertEqual(sum(c['passed'] for c in result['checks']), 5)

    def test_parent_discovery_uses_parent_zone_and_checks_all_its_authorities(self):
        import dns.name
        probe = DelegationProbe()
        hosts = [SimpleNamespace(target='ns1.parent.test.'), SimpleNamespace(target='ns2.parent.test.')]
        def query(host, domain, kind, **kw):
            self.assertFalse(kw['authoritative'])
            self.assertEqual((domain, kind), ('example.qd.je', 'NS'))
            return set(TARGET_NS) if host.startswith('ns1') else set(HOSTED_NS)
        with patch('api.services.dns_completion.dns.resolver.zone_for_name', return_value=dns.name.from_text('qd.je.')) as zone, \
             patch.object(probe.resolver, 'resolve', return_value=hosts), \
             patch.object(probe, 'query', side_effect=query):
            result = probe.parents('example.qd.je')
        self.assertEqual(zone.call_args.args[0], dns.name.from_text('qd.je.'))
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['checks']), 2)


class DelegationTransportTests(unittest.TestCase):
    def test_empty_nameserver_list_is_valid_but_missing_or_malformed_state_is_rejected(self):
        from api.providers.dns.digitalplat import DigitalPlatDNS
        for ns in ([], ['dns1.digitalplat.org.'], None, '', {}, ['bad name']):
            with self.subTest(nameservers=ns):
                transport = SimpleNamespace(request=lambda *a,**k: {
                    'data': {'domain': 'new.qd.je', 'status': 'ok', 'nameservers': ns}})
                adapter = DigitalPlatDNS(transport, {'api_base': 'https://dns.fixture.test', 'api_token': base.TOKEN}, 'new.qd.je')
                if isinstance(ns, list) and ns in ([], ['dns1.digitalplat.org.']):
                    self.assertEqual(adapter.delegation_status(), [n.lower().rstrip('.') for n in ns])
                else:
                    with self.assertRaisesRegex(ProviderError, 'invalid_digitalplat_domain_response'):
                        adapter.delegation_status()

    def test_initial_ns_transport_accepts_sync_and_async_documented_responses(self):
        from api.providers.dns.digitalplat import DigitalPlatDNS
        for data, operation in [
            ({'name': 'new.qd.je', 'nameservers': list(TARGET_NS)}, ''),
            ({'domain': 'new.qd.je', 'nameservers': [n.upper() + '.' for n in TARGET_NS]}, ''),
            ({'operation_id': 'fixture-initial-ns'}, 'fixture-initial-ns'),
        ]:
            with self.subTest(data=data):
                request = unittest.mock.Mock(return_value={'success': True, 'data': data})
                adapter = DigitalPlatDNS(SimpleNamespace(request=request), {
                    'api_base': 'https://dns.fixture.test', 'api_token': base.TOKEN}, 'new.qd.je')
                self.assertEqual(adapter.set_nameservers(TARGET_NS, 'initial-ns-fixture'), operation)
                self.assertEqual(request.call_count, 1)
                self.assertEqual(request.call_args.args, ('PATCH', 'https://dns.fixture.test', '/domains/new.qd.je/nameservers'))
                self.assertEqual(request.call_args.kwargs['body'], {'nameservers': list(TARGET_NS)})
                self.assertEqual(request.call_args.kwargs['headers']['Idempotency-Key'], 'initial-ns-fixture')

    def test_initial_ns_transport_malformed_success_stays_uncertain(self):
        from api.providers.dns.digitalplat import DigitalPlatDNS
        for data in (None, {}, {'name': 'other.test', 'nameservers': list(TARGET_NS)},
                     {'name': 'new.qd.je', 'nameservers': []},
                     {'name': 'new.qd.je', 'nameservers': [None]}, {'operation_id': '../bad-operation'}):
            with self.subTest(data=data):
                request = unittest.mock.Mock(return_value={'success': True, 'data': data})
                adapter = DigitalPlatDNS(SimpleNamespace(request=request), {
                    'api_base': 'https://dns.fixture.test', 'api_token': base.TOKEN}, 'new.qd.je')
                with self.assertRaises(ProviderError) as caught:
                    adapter.set_nameservers(TARGET_NS, 'initial-ns-fixture')
                self.assertEqual(caught.exception.code, 'digitalplat_ns_set_unconfirmed')
                self.assertTrue(caught.exception.uncertain)
                self.assertEqual(request.call_count, 1)

    def test_transport_retains_only_exact_precheck_code_and_never_body_secrets(self):
        for code, expected in [('external_nameserver_precheck_failed', True), ('domain_busy', False), ('fixture-secret', False)]:
            raw = json.dumps({'error': {'code': code, 'message': base.TOKEN}}).encode()
            error = urllib.error.HTTPError('https://dns.fixture.test', 409, 'Conflict', {}, io.BytesIO(raw))
            transport = JsonTransport()
            with patch.object(transport.opener, 'open', side_effect=error) as send:
                with self.assertRaises(ProviderError) as caught:
                    transport.request('POST', 'https://dns.fixture.test', '/dns/switch-external', body={})
            self.assertEqual(caught.exception.upstream_code, code if expected else '')
            self.assertEqual(caught.exception.uncertain, not expected)
            self.assertNotIn(base.TOKEN, str(caught.exception))
            self.assertEqual(send.call_count, 1)


if __name__ == '__main__':
    unittest.main()

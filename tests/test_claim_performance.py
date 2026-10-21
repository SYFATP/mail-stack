import json
import time
import unittest
from unittest.mock import patch, Mock
import test_domain_control as fixture
import test_domain_routing as routing_fixture
from api.services import routing
from api.providers.http import ProviderError

app = fixture.app


class ClaimPerformanceTests(unittest.TestCase):
    setUp = fixture.P2Tests.setUp
    tearDown = fixture.P2Tests.tearDown
    source = fixture.P2Tests.source
    batch_payload = fixture.P2Tests.batch_payload

    def bulk(self, count=3):
        source = self.source()
        self.http.payload = self.batch_payload(count)
        self.manager.bulk_save_domain = lambda data, domain: app._save_domain(
            data, domain, publish_runtime=False, return_public=False)
        self.manager.publish_domains = app._write_runtime_files
        return self.manager.create_claim_job(source['id'], 'performance-bulk-claim', count=count,
                                             status='registered', sync_provider='none')

    def test_200_imports_publish_once_and_do_not_wait_for_provider_setup(self):
        job = self.bulk(200)
        with patch.object(self.manager, 'brevo_sync_enabled', return_value=True), \
             patch.object(self.manager, 'ensure_brevo_domain', return_value={'created': True}) as brevo, \
             patch.object(app, 'publish', wraps=app.publish) as publish:
            self.manager.run_once()
            result = self.manager.jobs.get(job['id'])
            self.assertEqual(result['status'], 'succeeded')
            self.assertEqual(publish.call_count, 1)
            self.assertEqual(brevo.call_count, 0, 'Provider work must be off the allocation/import path')
            self.assertEqual(len(self.http.calls), 1, 'Dispatch exactly one upstream allocation')
            children = [item['claim_setup_job'] for item in result['result']['items']]
            self.assertEqual(len(children), 200)
            self.assertTrue(all(item['status'] == 'queued' for item in children))
            self.assertEqual(len(self.manager.claims()), 200)
            self.assertTrue(all(not row['enabled'] for row in app._domain_rows()))
            self.assertEqual(len(self.manager.jobs.list(limit=1)['active_domain_jobs']), 200)
            self.manager.run_once()
            self.assertEqual(brevo.call_count, 1, 'Background preparation still registers Brevo automatically')
        first = self.manager.jobs.get(children[0]['id'])
        self.assertEqual(first['status'], 'succeeded')
        hosting = first['result']['dns_hosting_job']
        self.assertEqual(hosting['status'], 'queued')
        self.assertEqual(self.manager.jobs.take()['id'], hosting['id'], 'Finish one domain before the next background setup')
        self.assertNotIn(fixture.TOKEN, json.dumps(result))

    def test_setup_failure_preserves_import_and_continues_hosting_preparation(self):
        job = self.bulk()
        with patch.object(self.manager, 'brevo_sync_enabled', return_value=True), \
             patch.object(self.manager, 'ensure_brevo_domain', side_effect=ProviderError('provider_http_429')):
            self.manager.run_once()
            parent = self.manager.jobs.get(job['id'])
            child = parent['result']['items'][0]['claim_setup_job']
            self.manager.run_once()
        result = self.manager.jobs.get(child['id'])
        self.assertEqual(parent['status'], 'succeeded')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['result']['brevo_registration']['error_code'], 'provider_http_429')
        self.assertEqual(result['result']['dns_hosting_job']['kind'], 'dns_hosting')
        self.assertEqual(len(self.http.calls), 1)
        self.assertEqual(len(self.manager.claims()), 3)

    def test_changed_binding_is_fenced_before_any_setup_request(self):
        job = self.bulk()
        with patch.object(self.manager, 'brevo_sync_enabled', return_value=True), \
             patch.object(self.manager, 'ensure_brevo_domain') as brevo:
            self.manager.run_once()
            child = self.manager.jobs.get(job['id'])['result']['items'][0]['claim_setup_job']
            c = app.db()
            with c:c.execute('UPDATE mail_domains SET dns_credential_ref=NULL WHERE domain=?', (child['scope'],))
            c.close()
            self.manager.run_once()
            brevo.assert_not_called()
        self.assertEqual(self.manager.jobs.get(child['id'])['status'], 'failed')
        self.assertEqual(len(self.http.calls), 1)

    def test_binding_changed_during_brevo_call_does_not_queue_new_credential_hosting(self):
        job = self.bulk()
        with patch.object(self.manager, 'brevo_sync_enabled', return_value=True):
            self.manager.run_once()
        child = self.manager.jobs.get(job['id'])['result']['items'][0]['claim_setup_job']

        def rebind(domain):
            c = app.db()
            with c:c.execute('UPDATE mail_domains SET dns_credential_ref=NULL WHERE domain=?', (domain,))
            c.close()
            return {'created': True}

        with patch.object(self.manager, 'brevo_sync_enabled', return_value=True), \
             patch.object(self.manager, 'ensure_brevo_domain', side_effect=rebind):
            self.manager.run_once()
        result = self.manager.jobs.get(child['id'])
        self.assertEqual(result['status'], 'partial')
        self.assertNotIn('dns_hosting_job', result['result'])
        self.assertEqual(result['result']['dns_hosting_error'], 'dns_hosting_prepare_not_queued')
        self.assertEqual(len(self.http.calls), 1)

    def test_publish_failure_keeps_all_receipts_and_does_not_reclaim(self):
        job = self.bulk()
        self.manager.publish_domains = Mock(side_effect=OSError('fixture disk error'))
        self.manager.run_once()
        self.assertEqual(self.manager.jobs.get(job['id'])['status'], 'unknown')
        claims = self.manager.claims()
        self.assertEqual(len(claims), 3)
        self.assertTrue(all(row['receipt_ref'] for row in claims))
        self.assertEqual(len(self.http.calls), 1)
        with self.assertRaises(fixture.JobConflict):
            self.manager.create_claim_job(job['scope'], 'no-automatic-reclaim', count=3)

    def test_new_claim_and_user_validation_precede_background_queue(self):
        specifications = [('claim_setup', 'background-setup'), ('dns_hosting', 'background-hosting'),
                          ('dns_validate', 'auto-readiness:fixture'), ('dns_validate', 'user-validation'),
                          ('claim', 'next-user-claim')]
        jobs = [self.manager.jobs.enqueue(kind, key, key, {}) for kind, key in specifications]
        order = []
        for _ in jobs:
            job = self.manager.jobs.take()
            order.append(job['id'])
            self.manager.jobs.finish(job['id'], 'succeeded', step='fixture')
        self.assertEqual(order, [jobs[n]['id'] for n in (4,3,2,1,0)])

    def test_whole_domain_list_uses_one_db_snapshot_and_preserves_serialization(self):
        self.bulk(8)
        self.manager.run_once()
        expected = [app._domain_public(row) for row in app._domain_rows()]
        with patch.object(app, 'db', wraps=app.db) as db:
            observed = app._domain_public_rows()
        self.assertEqual(db.call_count, 1)
        self.assertEqual(observed, expected)

    def test_routing_snapshot_reads_each_verified_manifest_once_and_does_not_cache_across_requests(self):
        rows = [routing_fixture.domain(f'{n}.example.test') for n in range(30)]
        first = routing.publish(rows, self.root / 'snapshot')
        root = self.root / 'snapshot'
        (root / 'postfix-applied.json').write_text(json.dumps({
            'generation': first, 'status': 'applied', 'applied_at': time.time()}))
        routing.publish(rows + [routing_fixture.domain('claimed.test', enabled=False)], root)
        snapshot = routing.AppliedStateSnapshot(root)
        with patch.object(routing, '_generation_domains', wraps=routing._generation_domains) as reads:
            self.assertTrue(all(snapshot.for_row(row)['status'] == 'applied' for row in rows))
            self.assertEqual(reads.call_count, 2)
        (root / 'postfix-applied.json').write_text(json.dumps({
            'generation': first, 'status': 'applied', 'applied_at': time.time()-60}))
        self.assertEqual(routing.AppliedStateSnapshot(root).for_row(rows[0])['status'], 'pending')


if __name__ == '__main__':
    unittest.main()

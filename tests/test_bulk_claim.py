import json
import unittest
from unittest.mock import patch
import test_domain_control as fixture


class BulkClaimTests(unittest.TestCase):
    setUp = fixture.P2Tests.setUp
    tearDown = fixture.P2Tests.tearDown
    source = fixture.P2Tests.source
    batch_payload = fixture.P2Tests.batch_payload

    def test_all_200_receipts_are_durable_before_slow_import_and_progress_is_live(self):
        source = self.source()
        self.http.payload = self.batch_payload(200)
        job = self.manager.create_claim_job(source['id'], 'bulk-200-progress', count=200)
        imported = []

        def attach(claim_id, **options):
            claims = self.manager.claims()
            self.assertEqual(len(claims), 200)
            self.assertTrue(all(row['receipt_ref'] for row in claims))
            live = self.manager.jobs.get(job['id'])
            self.assertEqual(live['status'], 'running')
            self.assertEqual(live['result']['recorded_count'], 200)
            self.assertEqual(live['result']['processed_count'], len(imported))
            row = self.manager.claim_row(claim_id)
            imported.append(claim_id)
            return {'claim_id': claim_id, 'domain': row['domain'], 'status': 'imported'}

        with patch.object(self.manager, '_attach_claim', side_effect=attach):
            self.manager.run_once()
        final = self.manager.jobs.get(job['id'])
        self.assertEqual(final['status'], 'succeeded')
        self.assertEqual(final['result']['processed_count'], 200)
        self.assertEqual(len(imported), 200)
        self.assertEqual(len(self.http.calls), 1, 'Claim the upstream batch exactly once')
        self.assertNotIn(fixture.TOKEN, json.dumps(final))

    def test_import_failure_keeps_all_receipts_recoverable_without_new_claim(self):
        source = self.source()
        self.http.payload = self.batch_payload(3)
        job = self.manager.create_claim_job(source['id'], 'bulk-import-failure', count=3)
        with patch.object(self.manager, '_attach_claim', side_effect=RuntimeError('fixture failure')):
            self.manager.run_once()
        final = self.manager.jobs.get(job['id'])
        self.assertEqual(final['status'], 'partial')
        self.assertEqual(final['result']['recorded_count'], 3)
        self.assertEqual(final['result']['processed_count'], 3)
        self.assertTrue(all(r['receipt_ref'] for r in self.manager.claims()))
        self.assertFalse(self.manager.run_once())
        self.assertEqual(len(self.http.calls), 1)

    def test_bounded_status_snapshot_is_admin_only_ordered_and_secret_free(self):
        jobs = [self.manager.jobs.enqueue('dns_validate', f'{n}.test', f'bulk-status-{n:03}', {}) for n in range(200)]
        ids = [job['id'] for job in reversed(jobs)]
        url = '/api/v1/domain-jobs/status'
        response = self.client.get(url, params={'ids': ','.join(ids)}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r['id'] for r in response.json()['items']], ids)
        self.assertNotIn(fixture.TOKEN, response.text)
        self.assertEqual(self.client.get(url, params={'ids': ids[0]}).status_code, 401)
        for invalid in ('', 'bad id', 'a,' * 200 + 'a', "x' OR 1=1 --"):
            self.assertIn(self.client.get(url, params={'ids': invalid}, headers=self.headers).status_code, (400, 422))
        self.assertEqual(self.manager.jobs.get_many([ids[0], ids[0], 'missing'])['items'], [jobs[-1]])

    def test_reload_restores_old_active_claim_even_when_latest_job_is_different(self):
        source = self.source()
        job = self.manager.create_claim_job(source['id'], 'bulk-reload-claim', count=200)
        self.manager.jobs.take()
        self.manager.jobs.progress(job['id'], step='importing_domains', result={
            'requested_count': 200, 'received_count': 200, 'recorded_count': 200, 'processed_count': 71})
        self.manager.jobs.enqueue('dns_hosting', 'later.test', 'later-hosting-job', {})
        listing = self.manager.jobs.list(limit=1)
        self.assertNotEqual(listing['items'][0]['id'], job['id'])
        restored = listing['active_claim_jobs'][0]
        self.assertEqual(restored['id'], job['id'])
        self.assertEqual(restored['result']['processed_count'], 71)
        self.manager.jobs.finish(job['id'], 'succeeded', step='allocation_recorded', result={'processed_count': 200})
        self.manager.jobs.progress(job['id'], step='stale', result={})
        self.assertEqual(self.manager.jobs.get(job['id'])['step'], 'allocation_recorded')
        self.assertEqual(self.manager.jobs.list(limit=1)['active_claim_jobs'], [])


if __name__ == '__main__':
    unittest.main()

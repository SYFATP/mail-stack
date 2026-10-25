"""Real SQLite cost and correctness with retained task history."""
import json
import sqlite3
import unittest
from unittest.mock import patch

from api.migrations.schema import migrate, _migrate_v15, _migrate_v16
from api.providers.http import ProviderError
from api.repositories.domain_jobs import DomainJobs


class KeptConnection(sqlite3.Connection):
    def close(self):
        pass


class JobPollingCostTests(unittest.TestCase):
    def setUp(self):
        self.c = sqlite3.connect(':memory:', factory=KeptConnection)
        self.c.row_factory = sqlite3.Row
        self.addCleanup(lambda: sqlite3.Connection.close(self.c))
        self.c.execute('CREATE TABLE mail_domains(domain TEXT PRIMARY KEY)')
        self.c.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY,source_path TEXT,received_at REAL)')
        migrate(self.c)
        self.c.commit()
        self.jobs = DomainJobs(lambda: self.c)
        # Hundreds of completed jobs must not make each idle tick parse blobs.
        payload = json.dumps({'records': ['historical-result-' + 'x' * 200] * 10})
        self.c.executemany('''INSERT INTO domain_jobs(
            id,kind,scope,idempotency_key,request_hash,request_json,status,result_json,created_at,updated_at)
            VALUES(?, 'dns_validate', ?, ?, '', '{}', 'succeeded', ?, ?, ?)''',
            [('history-' + str(i), 'domain-' + str(i % 20) + '.test',
              'auto-readiness:history-' + str(i), payload, i, i) for i in range(2500)])
        self.c.commit()

    def measured(self, fn):
        blocks = []
        self.c.set_progress_handler(lambda: blocks.append(1) or 0, 100)
        try:
            result = fn()
        finally:
            self.c.set_progress_handler(None, 0)
        return result, len(blocks) * 100

    def backoff(self, identity, provider, until, status='unknown'):
        payload = json.dumps({'provider_backoff': {'provider': provider, 'until': until}})
        self.c.execute('''INSERT INTO domain_jobs(
            id,kind,scope,idempotency_key,request_hash,request_json,status,result_json,created_at,updated_at)
            VALUES(?, 'dns_apply', ?, ?, '', '{}', ?, ?, 0, 0)''',
            (identity, identity + '.test', identity + '-key', status, payload))
        self.c.commit()

    def test_idle_poll_uses_bounded_work_without_writer_transaction(self):
        trace = []
        self.c.set_trace_callback(trace.append)
        with patch.object(self.jobs, 'cooldowns', side_effect=AssertionError('history read on idle poll')):
            result, steps = self.measured(self.jobs.take)
        self.c.set_trace_callback(None)
        self.assertIsNone(result)
        self.assertLess(steps, 300)
        self.assertFalse(any('BEGIN' in sql.upper() for sql in trace))

    def test_backoff_query_work_does_not_scale_with_terminal_result_blobs(self):
        result, steps = self.measured(lambda: self.jobs.cooldowns(self.c, 1000))
        self.assertEqual(result, {})
        self.assertLess(steps, 300)
        self.backoff('future-dyn', 'dynv6', 1200)
        self.backoff('later-dyn', 'dynv6', 1600, status='failed')
        self.backoff('past-dyn', 'dynv6', 900)
        self.backoff('future-cf', 'cloudflare', 1300, status='succeeded')
        result, steps = self.measured(lambda: self.jobs.cooldowns(self.c, 1000))
        self.assertEqual(result, {'dynv6': 1600, 'cloudflare': 1300})
        self.assertLess(steps, 600)

    def test_running_write_fence_reads_latest_backoff_without_cached_state(self):
        self.backoff('future-dyn', 'dynv6', 1200)
        self.backoff('later-dyn', 'dynv6', 1600)
        self.backoff('future-cf', 'cloudflare', 1900)
        with patch('api.repositories.domain_jobs.time.time', return_value=1000):
            with self.assertRaises(ProviderError) as caught:
                self.jobs.check_provider_backoff('dynv6')
            self.assertEqual(caught.exception.retry_after, 600)
            self.c.execute("UPDATE domain_jobs SET result_json='{}' WHERE id='later-dyn'")
            self.c.commit()
            with self.assertRaises(ProviderError) as caught:
                self.jobs.check_provider_backoff('dynv6')
            self.assertEqual(caught.exception.retry_after, 200)
            self.c.execute("UPDATE domain_jobs SET result_json='{}' WHERE id='future-dyn'")
            self.c.commit()
            result, steps = self.measured(lambda: self.jobs.check_provider_backoff('dynv6'))
            self.assertIsNone(result)
            self.assertLess(steps, 300)

    def test_finish_backoff_and_expiry_remain_visible_for_unknown_writes(self):
        job = self.jobs.enqueue('dns_apply', 'new.test', 'poll-cost-new-job', {})
        self.assertEqual(self.jobs.take()['id'], job['id'])
        self.jobs.finish(job['id'], 'unknown', step='provider_write',
                         result={'provider_backoff': {'provider': 'digitalplat', 'until': 1600}})
        self.assertEqual(self.jobs.cooldowns(self.c, 1000), {'digitalplat': 1600})
        self.assertEqual(self.jobs.cooldowns(self.c, 1600), {})
        self.assertEqual(self.jobs.get(job['id'])['status'], 'unknown')
        self.assertIsNone(self.jobs.take())

    def test_readiness_attempt_scan_is_covered_without_loading_result_json(self):
        sql = '''SELECT scope,max(updated_at) AS updated_at FROM domain_jobs
                 WHERE kind='dns_validate' AND idempotency_key LIKE 'auto-readiness:%'
                 GROUP BY scope'''
        rows = self.c.execute(sql).fetchall()
        self.assertEqual(len(rows), 20)
        self.assertEqual(dict(rows)['domain-19.test'], 2499)
        plan = ' '.join(r[3] for r in self.c.execute('EXPLAIN QUERY PLAN ' + sql))
        self.assertIn('idx_domain_jobs_readiness_attempts', plan)
        self.assertNotIn('USE TEMP B-TREE', plan)

    def test_overview_work_is_independent_of_completed_history(self):
        result, steps = self.measured(lambda: self.jobs.list(1, overview=True))
        self.assertEqual(result["items"], [])
        self.assertIsNone(result["total"])
        self.assertEqual(result["status_counts"], {})
        self.assertLess(steps, 2500, "The domain table must not count/encode completed history")
        self.c.commit()
        write = self.jobs.enqueue("dns_apply", "active.test", "overview-write", {})
        read = self.jobs.enqueue("dns_validate", "read.test", "auto-readiness:overview", {})
        claim = self.jobs.enqueue("claim", "source-test", "overview-claim", {})
        full = self.jobs.list(1)
        self.c.commit()
        overview = self.jobs.list(1, overview=True)
        for field in ("active_domain_jobs", "active_claim_jobs", "blocked_claim_sources", "domain_hosting"):
            self.assertEqual(overview[field], full[field])
        self.assertEqual(overview["status_counts"], {"queued": 3})
        self.assertEqual({r["id"] for r in overview["active_domain_jobs"]}, {write["id"], read["id"]})
        self.assertEqual(overview["active_claim_jobs"][0]["id"], claim["id"])
        self.assertIn("source-test", overview["blocked_claim_sources"])
        self.assertEqual(full["total"], 2503)

    def test_latest_page_uses_index_without_sorting_history(self):
        sql = 'SELECT * FROM domain_jobs ORDER BY created_at DESC,id LIMIT 1 OFFSET 0'
        rows, steps = self.measured(lambda: self.c.execute(sql).fetchall())
        self.assertEqual(rows[0]['id'], 'history-2499')
        self.assertLess(steps, 100)
        plan = ' '.join(r[3] for r in self.c.execute('EXPLAIN QUERY PLAN ' + sql))
        self.assertIn('idx_domain_jobs_created', plan)
        self.assertNotIn('USE TEMP B-TREE', plan)
        self.c.execute("UPDATE domain_jobs SET created_at=3000 WHERE id IN ('history-1','history-2')")
        self.assertEqual(self.c.execute(sql).fetchone()['id'], 'history-1')

    def test_latest_index_accepts_online_preinstallation_and_rolls_back(self):
        self.c.execute('DELETE FROM schema_migrations WHERE version=16')
        self.c.commit()
        before = self.c.execute('SELECT count(*) FROM domain_jobs').fetchone()[0]
        _migrate_v16(self.c)
        self.c.commit()
        self.assertEqual(self.c.execute('SELECT count(*) FROM domain_jobs').fetchone()[0], before)
        self.c.execute('DROP INDEX idx_domain_jobs_created')
        self.c.execute('DELETE FROM schema_migrations WHERE version=16')
        self.c.commit()
        self.c.execute('BEGIN IMMEDIATE')
        _migrate_v16(self.c)
        self.c.rollback()
        self.assertIsNone(self.c.execute("SELECT 1 FROM sqlite_master WHERE name='idx_domain_jobs_created'").fetchone())
        self.assertIsNone(self.c.execute('SELECT 1 FROM schema_migrations WHERE version=16').fetchone())
        migrate(self.c)
        self.c.commit()
        self.assertIsNotNone(self.c.execute("SELECT 1 FROM sqlite_master WHERE name='idx_domain_jobs_created'").fetchone())

    def test_migration_is_additive_and_repeatable(self):
        before = [tuple(r) for r in self.c.execute('SELECT * FROM domain_jobs ORDER BY id')]
        migrate(self.c)
        self.c.commit()
        self.assertEqual([r[0] for r in self.c.execute('SELECT version FROM schema_migrations ORDER BY version')], list(range(1, 17)))
        self.assertEqual([tuple(r) for r in self.c.execute('SELECT * FROM domain_jobs ORDER BY id')], before)

    def test_index_migration_rolls_back_and_retries(self):
        self.c.execute('DROP INDEX idx_domain_jobs_backoff_until')
        self.c.execute('DROP INDEX idx_domain_jobs_readiness_attempts')
        self.c.execute('DELETE FROM schema_migrations WHERE version=15')
        self.c.commit()
        def authorize(action, name, *_):
            return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_CREATE_INDEX and name == 'idx_domain_jobs_readiness_attempts' else sqlite3.SQLITE_OK
        self.c.set_authorizer(authorize)
        self.c.execute('BEGIN IMMEDIATE')
        with self.assertRaises(sqlite3.DatabaseError):
            _migrate_v15(self.c)
        self.c.rollback()
        self.c.set_authorizer(None)
        self.assertIsNone(self.c.execute("SELECT 1 FROM schema_migrations WHERE version=15").fetchone())
        self.assertIsNone(self.c.execute("SELECT 1 FROM sqlite_master WHERE name='idx_domain_jobs_backoff_until'").fetchone())
        migrate(self.c)
        self.c.commit()
        self.assertEqual(self.c.execute('SELECT count(*) FROM domain_jobs').fetchone()[0], 2500)
        self.assertIsNotNone(self.c.execute("SELECT 1 FROM schema_migrations WHERE version=15").fetchone())


if __name__ == '__main__':
    unittest.main()

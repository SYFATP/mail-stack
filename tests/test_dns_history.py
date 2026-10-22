"""History settlement must observe current DNS, preserve errors, and never replay writes."""
import copy
import json
import time
import unittest
import uuid
from unittest.mock import patch

import test_dns_reconcile as fixtures
from api.providers.http import ProviderError
from api.services.dns_plan import build_plan


class DNSHistoryTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.DNSWriteTests(methodName='runTest')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.addCleanup(self.f.tearDown)
        self.m = self.f.m
        self.f.digitalplat_fixture()
        self.good = self.f.apply()
        self.assertEqual(self.good['status'], 'succeeded')
        self.sequence = 0

    def seed(self, status='unknown', *, role='spf', record_id=True):
        c = self.m.db()
        op = next(dict(r) for r in c.execute('SELECT * FROM domain_dns_operations WHERE job_id=?',
                  (self.good['id'],)) if json.loads(r['target_json'])['role'] == role)
        c.close()
        old = self.m.jobs.enqueue('dns_apply', 'example.test', 'history-fixture-' + uuid.uuid4().hex,
                                 self.good['request'])
        self.assertEqual(self.m.jobs.take()['id'], old['id'])
        op.update(id=uuid.uuid4().hex, job_id=old['id'], status=status,
                  error_code='fixture_ambiguous_write', updated_at=time.time())
        if not record_id:
            op['provider_record_id'] = None
        c = self.m.db()
        with c:
            c.execute('INSERT INTO domain_dns_operations (' + ','.join(op) + ') VALUES (' +
                      ','.join('?' for _ in op) + ')', list(op.values()))
        c.close()
        self.m.jobs.finish(old['id'], 'unknown', step='dns_apply_interrupted',
            result={'completed': [{'role': 'mx', 'action': 'exists'}], 'operation_id': op['id']},
            error='fixture_ambiguous_write')
        return self.m.jobs.get(old['id']), op

    def validate(self):
        self.sequence += 1
        job = self.m.create_validate_job('example.test', 'history-validation-' + str(self.sequence))
        self.assertTrue(self.m.run_once())
        return self.m.jobs.get(job['id'])

    def operation(self, op):
        c = self.m.db()
        try:
            return dict(c.execute('SELECT * FROM domain_dns_operations WHERE id=?', (op['id'],)).fetchone())
        finally:
            c.close()

    def evidence(self):
        # Prepare valid evidence without invoking the post-job hook yet.
        plan = build_plan(self.m.domain('example.test'), self.m.key_root)
        job = self.m.create_validate_job('example.test', 'history-evidence-' + uuid.uuid4().hex)
        self.assertEqual(self.m.jobs.take()['id'], job['id'])
        result = self.m.validate_domain('example.test', plan, refresh_smtp_submission=True)
        self.m.jobs.finish(job['id'], 'succeeded', step='dns_checks_recorded', result=result)
        return self.m.jobs.get(job['id'])

    def test_validation_settles_confirmed_history_and_preserves_original_failure(self):
        old, op = self.seed('confirmed')
        before = len(self.f.writes())
        evidence = self.validate()
        saved = self.m.jobs.get(old['id'])
        self.assertEqual(saved['status'], 'partial')
        self.assertEqual(saved['step'], 'dns_history_reconciled')
        self.assertEqual(saved['error_code'], old['error_code'])
        self.assertEqual(saved['result']['completed'], old['result']['completed'])
        audit = saved['result']['reconciliation']
        self.assertEqual(audit['evidence_job_id'], evidence['id'])
        self.assertEqual(audit['dns_writes'], 0)
        self.assertFalse(audit['ownership_adopted'])
        self.assertEqual(self.operation(op), op, 'Confirmed original record evidence is immutable')
        self.assertEqual(len(self.f.writes()), before)
        self.assertEqual(self.m.jobs.list()['status_counts'].get('unknown', 0), 0)
        self.assertEqual(self.m.dns_history.reconcile('example.test', evidence['id']), [])

    def test_unknown_record_without_id_becomes_observed_without_new_ownership(self):
        old, op = self.seed(record_id=False)
        c = self.m.db()
        with c:
            c.execute("DELETE FROM managed_dns_records WHERE role='spf'")
        c.close()
        owned = self.m.dns.owned(self.m.domain('example.test'), 'example.test')
        writes = len(self.f.writes())
        self.validate()
        self.assertEqual(self.m.jobs.get(old['id'])['status'], 'partial')
        self.assertEqual(self.operation(op)['status'], 'observed')
        self.assertEqual(self.operation(op)['error_code'], 'fixture_ambiguous_write')
        self.assertEqual(self.m.dns.owned(self.m.domain('example.test'), 'example.test'), owned)
        self.assertEqual(len(self.f.writes()), writes)
        self.f.edit(spf='v=spf1 -all')
        self.assertIn('foreign_record_conflict', [r['code'] for r in self.f.preview()['conflicts']])

    def test_confirmed_record_with_replaced_id_retains_original_id_and_audits_current_id(self):
        old, op = self.seed('confirmed')
        next(r for r in self.f.records if r['id'] == op['provider_record_id'])['id'] = 'replacement-record'
        self.validate()
        saved = self.m.jobs.get(old['id'])
        self.assertEqual(saved['status'], 'partial')
        self.assertEqual(self.operation(op)['provider_record_id'], op['provider_record_id'])
        self.assertEqual(saved['result']['reconciliation']['operations'][0]['record_id'], 'replacement-record')

    def test_unknown_write_with_different_record_id_remains_unresolved(self):
        old, op = self.seed()
        next(r for r in self.f.records if r['id'] == op['provider_record_id'])['id'] = 'unrelated-record'
        self.validate()
        self.assertEqual(self.m.jobs.get(old['id'])['status'], 'unknown')
        self.assertEqual(self.operation(op), op)

    def test_missing_changed_or_duplicate_inventory_never_clears_history(self):
        old, op = self.seed()
        evidence = self.evidence()
        original = copy.deepcopy(self.f.records)
        for mode in ('missing', 'changed', 'duplicate', 'other_required_record_missing'):
            with self.subTest(mode=mode):
                self.f.records = copy.deepcopy(original)
                record = next(r for r in self.f.records if r['id'] == op['provider_record_id'])
                if mode == 'missing':
                    self.f.records.remove(record)
                elif mode == 'changed':
                    record['value'] = 'v=spf1 -all'
                elif mode == 'duplicate':
                    self.f.records.append({**record, 'id': 'duplicate-record'})
                else:
                    self.f.records.remove(next(r for r in self.f.records if r['type'] == 'MX'))
                self.assertEqual(self.m.dns_history.reconcile('example.test', evidence['id']), [])
                self.assertEqual(self.operation(op), op)
                self.assertEqual(self.m.jobs.get(old['id'])['status'], 'unknown')

    def test_failed_checks_on_succeeded_job_do_not_settle_history(self):
        old, _ = self.seed('confirmed')
        original = self.m.validator.validate
        def failed(*args):
            result = original(*args)
            result['checks']['spf']['status'] = 'failed'
            return result
        with patch.object(self.m.validator, 'validate', side_effect=failed), patch.object(self.m.dns, 'capture') as capture:
            evidence = self.validate()
            self.assertEqual(evidence['status'], 'succeeded')
            capture.assert_not_called()
        self.assertEqual(self.m.jobs.get(old['id'])['status'], 'unknown')

    def test_stale_missing_or_changed_revision_evidence_is_rejected_without_inventory(self):
        old, _ = self.seed()
        evidence = self.evidence()
        c = self.m.db()
        original = dict(c.execute('SELECT * FROM domain_jobs WHERE id=?', (evidence['id'],)).fetchone())
        c.close()
        for mode in ('stale', 'future', 'revision', 'missing_check', 'failed_job', 'wrong_kind', 'wrong_scope'):
            with self.subTest(mode=mode):
                saved = dict(original)
                result = json.loads(saved['result_json'])
                if mode == 'stale': saved['updated_at'] = time.time() - 7200
                elif mode == 'future': saved['updated_at'] = time.time() + 3600
                elif mode == 'revision': result['config_hash'] = 'stale-config'
                elif mode == 'missing_check': result['checks'].pop('dkim')
                elif mode == 'failed_job': saved['status'] = 'failed'
                elif mode == 'wrong_kind': saved['kind'] = 'claim'
                else: saved['scope'] = 'other.test'
                saved['result_json'] = json.dumps(result)
                c = self.m.db()
                with c:
                    c.execute('UPDATE domain_jobs SET ' + ','.join(k+'=?' for k in saved) + ' WHERE id=?',
                              [*saved.values(), evidence['id']])
                c.close()
                with patch.object(self.m.dns, 'capture') as capture:
                    self.assertEqual(self.m.dns_history.reconcile('example.test', evidence['id']), [])
                    capture.assert_not_called()
        self.assertEqual(self.m.jobs.get(old['id'])['status'], 'unknown')

    def test_queued_parent_namespace_blocks_history_until_it_finishes(self):
        old, _ = self.seed()
        evidence = self.evidence()
        blocker = self.m.jobs.enqueue('dns_hosting', 'test', 'history-parent-queued', {})
        self.assertEqual(self.m.dns_history.reconcile('example.test', evidence['id']), [])
        self.assertEqual(self.m.jobs.get(old['id'])['status'], 'unknown')
        self.assertEqual(self.m.jobs.take()['id'], blocker['id'])
        self.assertEqual(self.m.dns_history.reconcile('example.test', evidence['id']), [])
        self.m.jobs.finish(blocker['id'], 'failed', step='fixture_cancelled')
        self.assertEqual(self.m.dns_history.reconcile('example.test', evidence['id']), [old['id']])

    def test_binding_or_zone_change_never_settles_historical_write(self):
        old, op = self.seed()
        evidence = self.evidence()
        for column, value in (('credential_ref', 'other-credential'), ('zone_id', 'other-zone')):
            c = self.m.db()
            with c:
                c.execute('UPDATE domain_dns_operations SET '+column+'=? WHERE id=?', (value, op['id']))
            c.close()
            self.assertEqual(self.m.dns_history.reconcile('example.test', evidence['id']), [])
            c = self.m.db()
            with c:
                c.execute('UPDATE domain_dns_operations SET '+column+'=? WHERE id=?', (op[column], op['id']))
            c.close()
        self.assertEqual(self.m.jobs.get(old['id'])['status'], 'unknown')

    def test_configuration_changed_during_inventory_read_leaves_history_untouched(self):
        old, op = self.seed()
        evidence = self.evidence()
        capture = self.m.dns.capture
        def changed(domain):
            state = capture(domain)
            self.f.edit(mx='other.example.test')
            return state
        with patch.object(self.m.dns, 'capture', side_effect=changed):
            self.assertEqual(self.m.dns_history.reconcile('example.test', evidence['id']), [])
        self.assertEqual(self.m.jobs.get(old['id'])['status'], 'unknown')
        self.assertEqual(self.operation(op), op)

    def test_ledger_change_during_inventory_read_is_not_overwritten(self):
        old, op = self.seed()
        evidence = self.evidence()
        capture = self.m.dns.capture
        def changed(domain):
            state = capture(domain)
            c = self.m.db()
            with c:
                c.execute("UPDATE domain_dns_operations SET status='failed' WHERE id=?", (op['id'],))
            c.close()
            return state
        with patch.object(self.m.dns, 'capture', side_effect=changed):
            self.assertEqual(self.m.dns_history.reconcile('example.test', evidence['id']), [])
        self.assertEqual(self.m.jobs.get(old['id'])['status'], 'unknown')
        self.assertEqual(self.operation(op)['status'], 'failed')

    def test_readback_failure_preserves_successful_validation_and_old_unknown(self):
        old, _ = self.seed()
        before = len(self.f.writes())
        with patch.object(self.m.dns, 'capture', side_effect=ProviderError('fixture_read_failure')):
            with self.assertLogs('domain-jobs', level='WARNING'):
                evidence = self.validate()
        self.assertEqual(evidence['status'], 'succeeded')
        self.assertEqual(self.m.jobs.get(old['id'])['status'], 'unknown')
        self.assertEqual(len(self.f.writes()), before)

    def test_one_unresolved_operation_keeps_entire_old_job_unknown(self):
        old, op = self.seed()
        c = self.m.db()
        other = {**op, 'id': uuid.uuid4().hex, 'provider_record_id': 'different-record'}
        with c:
            c.execute('INSERT INTO domain_dns_operations (' + ','.join(other) + ') VALUES (' +
                      ','.join('?' for _ in other) + ')', list(other.values()))
        c.close()
        self.validate()
        self.assertEqual(self.m.jobs.get(old['id'])['status'], 'unknown')
        self.assertEqual(self.operation(op), op)

    def test_no_candidates_adds_no_provider_inventory_requests(self):
        with patch.object(self.m.dns, 'capture') as capture:
            self.assertEqual(self.validate()['status'], 'succeeded')
            capture.assert_not_called()

    def test_claim_history_and_dns_job_without_journal_remain_unresolved(self):
        jobs = []
        for kind in ('claim', 'dns_apply'):
            job = self.m.jobs.enqueue(kind, 'example.test', 'history-no-journal-' + kind, {})
            self.assertEqual(self.m.jobs.take()['id'], job['id'])
            self.m.jobs.finish(job['id'], 'unknown', step='fixture_interrupted')
            jobs.append(job)
        self.validate()
        self.assertTrue(all(self.m.jobs.get(job['id'])['status'] == 'unknown' for job in jobs))


if __name__ == '__main__':
    unittest.main()

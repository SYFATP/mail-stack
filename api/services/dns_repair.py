"""Explicit DigitalPlat wildcard MX repair, backed up before a single recreation.

Propagation retries use the durable queue and perform validation only. A crash or
an uncertain write never automatically replays the destructive stage.
"""
import json
import os
from pathlib import Path
import time

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from api.providers.http import ProviderError
from api.repositories.domain_jobs import JobConflict
from api.services.dns_inventory import fingerprint, inventory_hash, matches, scoped_inventory
from api.services.dns_plan import build_plan


class DNSRepair:
    RETRY_SECONDS = 30
    WAIT_SECONDS = 660

    def __init__(self, manager):
        self.m = manager

    def enqueue(self, domain, key, *, activate_on_success=False):
        row = self.m.domain(domain)
        domain = row['domain']
        c = self.m.db()
        try:
            prior = c.execute("SELECT id FROM domain_jobs WHERE kind='dns_repair' AND scope=? AND idempotency_key=?",
                              (domain, key)).fetchone()
        finally:
            c.close()
        if prior:
            job = self.m.jobs.get(prior['id'])
            if job['request']['activate_on_success'] != activate_on_success:
                raise JobConflict('idempotency key reused with a different repair request')
            return job
        if row['dns_provider'] != 'digitalplat' or not row['receive_subdomains'] or not row['max_subdomain_depth']:
            raise JobConflict('Wildcard MX repair requires DigitalPlat and subdomain receiving')
        snapshot = self.m.dns.preview(domain)
        if not snapshot['executable'] or any(action['action'] != 'exists' for action in snapshot['actions']):
            raise JobConflict('Apply or reconcile the current DNS plan before repairing wildcard MX')
        selected = [a for a in snapshot['actions'] if a['target']['role'] == 'wildcard_mx'
                    and a['target']['name'] == '*.' + domain]
        if len(selected) != 1 or not selected[0].get('owned'):
            raise JobConflict('Wildcard MX repair requires one unchanged record managed by this project')
        row, _, inventory, records = self.m.dns.capture(domain)
        if inventory_hash(records, 'digitalplat', inventory['zone_name']) != snapshot['inventory_hash']:
            raise JobConflict('DNS inventory changed; prepare the repair again')
        candidates = [r for r in records if r['id'] == selected[0]['record_id']]
        if len(candidates) != 1:
            raise JobConflict('Wildcard MX record identifier is ambiguous')
        record = candidates[0]
        if record['locked'] or fingerprint(record) != selected[0]['before_hash']:
            raise JobConflict('Wildcard MX changed or is locked')
        snapshot['repair'] = {
            'record': record, 'target': {**selected[0]['target'], 'ttl': record['ttl']},
            'other_inventory_hash': inventory_hash([r for r in records if r['id'] != record['id']], 'digitalplat', domain),
        }
        c = self.m.db()
        try:
            with c:
                c.execute('UPDATE domain_dns_plans SET snapshot_json=? WHERE id=?', (json.dumps(snapshot), snapshot['id']))
        finally:
            c.close()
        return self.m.jobs.enqueue('dns_repair', domain, key,
                                   {'plan_id': snapshot['id'], 'activate_on_success': activate_on_success})

    def _progress(self, job, step, result):
        c = self.m.db()
        try:
            with c:
                c.execute("UPDATE domain_jobs SET step=?,result_json=?,updated_at=? WHERE id=? AND status='running'",
                          (step, json.dumps(result), time.time(), job['id']))
        finally:
            c.close()

    def _capture(self, snapshot):
        row, adapter, inventory, records = self.m.dns.capture(snapshot['domain'])
        if (row['dns_provider'] != 'digitalplat' or row['dns_credential_ref'] != snapshot['credential_ref']
                or inventory['zone_id'] != snapshot['zone_id'] or inventory['zone_name'] != snapshot['zone_name']
                or self.m.dns.plan_for(row)['plan_hash'] != snapshot['plan_hash']):
            raise JobConflict('DNS configuration changed during repair')
        return row, adapter, records

    def _others_unchanged(self, snapshot, records):
        target = snapshot['repair']['target']
        others = [r for r in records if not (r['type'] == 'MX' and r['name'] == target['name'])]
        return inventory_hash(others, 'digitalplat', snapshot['zone_name']) == snapshot['repair']['other_inventory_hash']

    def _backup(self, job, snapshot, records):
        c = self.m.db()
        try:
            database = next(r[2] for r in c.execute('PRAGMA database_list') if r[1] == 'main')
        finally:
            c.close()
        root = Path(database).parent / 'dns-repair-backups'
        root.mkdir(mode=0o700, exist_ok=True)
        path = root / (job['id'] + '.json')
        # Exclusive creation also fences accidental replay of this job's writes.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump({'job_id': job['id'], 'created_at': time.time(), 'snapshot': snapshot, 'records': records}, stream)
            stream.flush()
            os.fsync(stream.fileno())

    def _confirm_delete(self, operation_id):
        c = self.m.db()
        try:
            with c:
                c.execute("UPDATE domain_dns_operations SET status='confirmed',updated_at=? WHERE id=?", (time.time(), operation_id))
        finally:
            c.close()

    def authority_state(self, domain, wanted):
        """Distinguish an unpublished record from stale recursive negative cache."""
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        states = []
        try:
            for host in ('dns1.digitalplat.org', 'dns2.digitalplat.org'):
                addresses = resolver.resolve(host, 'A', search=False)
                query = dns.message.make_query(wanted['name'], 'MX')
                query.flags &= ~dns.flags.RD
                response = dns.query.udp(query, str(addresses[0]), timeout=5)
                if response.flags & dns.flags.TC:
                    response = dns.query.tcp(query, str(addresses[0]), timeout=5)
                if not response.flags & dns.flags.AA:
                    raise ValueError('non-authoritative reply')
                mx = {(str(rr.exchange).rstrip('.').lower(), rr.preference)
                      for rrset in response.answer if rrset.rdtype == dns.rdatatype.MX for rr in rrset}
                if response.rcode() == dns.rcode.NOERROR and mx == {(wanted['content'], wanted['priority'])}:
                    states.append('published')
                elif (response.rcode() in {dns.rcode.NXDOMAIN, dns.rcode.NOERROR} and not response.answer
                      and any(rrset.rdtype == dns.rdatatype.SOA and str(rrset.name).rstrip('.') == domain
                              for rrset in response.authority)):
                    states.append('missing')
                else:
                    raise ValueError('unexpected authoritative record')
        except Exception:
            raise ProviderError('digitalplat_authority_unconfirmed') from None
        return states[0] if len(set(states)) == 1 else 'propagating'

    def execute(self, job):
        with self.m.lock:
            self._execute(job)

    def _execute(self, job):
        snapshot = self.m.dns.plan(job['request']['plan_id'])
        if job['result'].get('repair', {}).get('phase') in {'recreated', 'publication_wait'}:
            self._validate(job, snapshot, job['result'])
            return
        op_id, dispatched, write_returned, completed = None, False, False, []
        try:
            if snapshot['expires_at'] < time.time():
                raise JobConflict('DNS repair preview expired')
            row, adapter, records = self._capture(snapshot)
            if inventory_hash(records, 'digitalplat', snapshot['zone_name']) != snapshot['inventory_hash']:
                raise JobConflict('DNS inventory changed before repair')
            wanted = snapshot['repair']['target']
            old = snapshot['repair']['record']
            validation = self.m.validator.validate(row, self.m.key_root)
            if validation['checks']['wildcard_mx']['status'] == 'passed':
                self._validate(job, snapshot, {'repair': {'phase': 'publication_wait', 'attempts': 0, 'deadline': time.time() + self.WAIT_SECONDS}})
                return
            publication = self.authority_state(row['domain'], wanted)
            if publication != 'missing':
                self._validate(job, snapshot, {'repair': {'phase': 'publication_wait', 'attempts': 0,
                    'authoritative_state': publication, 'deadline': time.time() + self.WAIT_SECONDS}})
                return
            # Repeat the full fence after DNS probing and immediately before dispatch.
            row, adapter, records = self._capture(snapshot)
            if inventory_hash(records, 'digitalplat', snapshot['zone_name']) != snapshot['inventory_hash']:
                raise JobConflict('DNS inventory changed before repair')
            self._backup(job, snapshot, records)
            action = {'action': 'delete', 'target': wanted, 'record_id': old['id'], 'before_hash': fingerprint(old)}
            op_id, _ = self.m.dns.operation(job, snapshot, action)
            self._progress(job, 'dns_repair_deleting', {'repair': {'phase': 'delete_dispatched', 'old_record_id': old['id']}})
            dispatched = True
            error = None
            try:
                adapter.delete(old['id'], 'mail-stack-delete-' + op_id)
            except ProviderError as exc:
                error = exc
            try:
                row, adapter, records = self._capture(snapshot)
            except Exception:
                raise ProviderError('dns_delete_readback_failed', uncertain=True) from None
            if not self._others_unchanged(snapshot, records):
                raise ProviderError('dns_inventory_changed_during_repair', uncertain=True)
            remaining = [r for r in records if r['type'] == 'MX' and r['name'] == wanted['name']]
            if remaining:
                raise ProviderError(error.code if error else 'dns_delete_unconfirmed', uncertain=not error or error.uncertain)
            # An empty DELETE response or timeout is resolved by exact readback.
            self._confirm_delete(op_id)
            completed.append({'name': wanted['name'], 'role': 'wildcard_mx', 'action': 'delete'})
            op_id, dispatched = None, False
            row, adapter, fresh = self._capture(snapshot)
            if not self._others_unchanged(snapshot, fresh) or any(r['name'] == wanted['name'] for r in fresh):
                raise ProviderError('dns_changed_before_recreation')
            action = {'action': 'create', 'target': wanted, 'before_hash': ''}
            op_id, marker = self.m.dns.operation(job, snapshot, action)
            self._progress(job, 'dns_repair_recreating', {'repair': {'phase': 'create_dispatched', 'old_record_id': old['id']}})
            dispatched = True
            raw = adapter.write(snapshot['zone_id'], wanted, marker, existing_records=fresh)
            write_returned = True
            row, adapter, records = self._capture(snapshot)
            current = [r for r in records if r['type'] == 'MX' and r['name'] == wanted['name']]
            record_id = str(raw.get('id') or raw.get('record_id') or '')
            if (not self._others_unchanged(snapshot, records) or len(current) != 1
                    or current[0]['id'] != record_id or record_id == old['id']
                    or not matches(current[0], wanted) or current[0]['ttl'] != wanted['ttl']):
                raise ProviderError('dns_recreation_verification_failed', uncertain=True)
            self.m.dns.confirm(row, snapshot['zone_id'], op_id, wanted, current[0], marker)
            completed.append({'name': wanted['name'], 'role': 'wildcard_mx', 'action': 'create'})
            op_id, dispatched = None, False
            result = {'completed': completed, 'repair': {
                'phase': 'recreated', 'old_record_id': old['id'], 'record_id': record_id,
                'deadline': time.time() + self.WAIT_SECONDS, 'attempts': 0,
            }}
            self._progress(job, 'dns_repair_validating', result)
        except Exception as exc:
            code = exc.code if isinstance(exc, ProviderError) else 'dns_repair_preflight_or_persistence_failed'
            # Once dispatched, a readback/config/persistence failure may conceal a write.
            uncertain = bool(op_id) and dispatched and (write_returned or not isinstance(exc, ProviderError) or exc.uncertain)
            if op_id:
                self.m.dns.set_operation_error(op_id, code, uncertain)
            self.m.jobs.finish(job['id'], 'unknown' if uncertain else 'partial' if completed else 'failed',
                               step='dns_repair_interrupted', result={'completed': completed, 'operation_id': op_id,
                               'next_action': 'fresh_dns_preview', **self.m.jobs.provider_backoff(job['scope'], exc)}, error=code)
            return
        self._validate(job, snapshot, result)

    def _validate(self, job, snapshot, result):
        repair = dict(result['repair'])
        try:
            row = self.m.domain(snapshot['domain'])
            if row['dns_credential_ref'] != snapshot['credential_ref'] or self.m.dns.plan_for(row)['plan_hash'] != snapshot['plan_hash']:
                raise JobConflict('DNS configuration changed while waiting for publication')
            validation = self.m.validate_domain(row['domain'], build_plan(row, self.m.key_root),
                refresh_smtp_submission=True, activate_on_success=bool(job['request']['activate_on_success']))
        except Exception:
            self.m.jobs.finish(job['id'], 'partial', step='dns_repaired_validation_error',
                               result={**result, 'validation_status': 'error', 'next_action': 'dns_validate'}, error='dns_validation_failed')
            return
        repair['attempts'] = repair.get('attempts', 0) + 1
        passed = all(check.get('status') in {'passed', 'not_required'} for check in validation['checks'].values())
        result = {**validation, 'repair': repair, 'completed': result.get('completed', []),
                  'validation_status': 'passed' if passed else 'failed',
                  'next_action': 'wait_for_routing' if validation.get('activation', {}).get('status') == 'routing_pending'
                  else 'none' if passed else 'dns_validate'}
        if not passed and repair['phase'] in {'recreated', 'publication_wait'} and time.time() < repair['deadline']:
            result.update(validation_status='pending', next_action='wait_for_dns', retry_at=time.time() + self.RETRY_SECONDS)
            self.m.jobs.defer(job['id'], step='dns_repair_waiting_for_dns', result=result)
            return
        self.m.jobs.finish(job['id'], 'succeeded' if passed else 'partial', step='dns_repaired_and_validated', result=result)

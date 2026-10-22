"""Immutable DNS previews, ownership journal and non-replaying apply worker.

No delete or implicit adoption. Only locally journaled writes can be recovered
from a Cloudflare marker. DigitalPlat reconciliation observes matching records
without adopting them or repeating the original write.
"""
from __future__ import annotations
import json
import hashlib
import re
import threading
import time
import uuid
from api.providers.http import ProviderError
from api.repositories.domain_jobs import JobConflict
from api.services.dns_inventory import identifier, scoped_inventory, fingerprint, inventory_hash, matches, semantic
from api.services.dns_plan import build_plan
from api.providers.dns.dynv6 import DYNV6_TTL
from api.services.routing import normalize_domain


def _cname_boundary_applies(cname_name, target_name):
    """Whether a CNAME node owns the target's DNS namespace."""
    boundary = str(cname_name or "").removeprefix("*.").rstrip(".").lower()
    target = str(target_name or "").removeprefix("*.").rstrip(".").lower()
    return bool(boundary and target and (target == boundary or target.endswith("." + boundary)))


def _owned_txt_values(owner):
    saved = json.loads(owner['last_content'])
    return saved.get('owned_records') or [{'target': saved, 'fingerprint': owner['fingerprint']}]


class DNSReconciler:
    def __init__(self, manager):
        self.m = manager
        self.preview_slots = threading.BoundedSemaphore(3)

    def plan_for(self, row, *, plan=None):
        plan = plan if plan is not None else build_plan(row, self.m.key_root)
        extras = self.m.brevo_dns_targets(row)
        if extras:
            plan = dict(plan)
            plan["records"] = list(plan["records"]) + extras
            plan["plan_hash"] = hashlib.sha256(
                json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        if row["dns_provider"] == "dynv6":
            plan = {**plan, "records": [{**r, "ttl": DYNV6_TTL} for r in plan["records"]],
                    "warnings": [*plan["warnings"], "dynv6_ttl_fixed_60"]}
            plan["plan_hash"] = hashlib.sha256(
                json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        return plan

    def capture(self, domain):
        row = self.m.domain(domain)
        if row['source_status'] in {'released', 'revoked', 'expired'}:
            raise JobConflict('domain ownership is inactive')
        adapter = self.m.dns_adapter(row)
        try:
            inventory = adapter.inventory(row['domain'])
        except ProviderError:
            raise
        except Exception:
            raise ProviderError('invalid_provider_inventory_response') from None
        inventory['zone_id'] = identifier(inventory['zone_id'])
        records = scoped_inventory(inventory, row['domain'], row['dns_provider'])
        if any(r['type'] == 'NS' and r['name'] != inventory['zone_name'] and
               (r['name'] == row['domain'] or row['domain'].endswith('.' + r['name'])) for r in records):
            raise ProviderError('domain_delegated_outside_accessible_zone')
        return row, adapter, inventory, records

    def targets(self, row, inventory, records, *, plan=None):
        plan = plan if plan is not None else self.plan_for(row)
        plan = dict(plan)
        plan["notices"] = list(plan.get("notices") or [])
        targets = list(plan['records'])
        blockers = []
        if (row["dns_provider"] == "dynv6" and row["receive_subdomains"]
                and row["max_subdomain_depth"] > 1):
            blockers.append({
                "role": "wildcard_mx", "name": row["domain"],
                "code": "dynv6_multilevel_wildcard_not_supported",
                "message": "dynv6 实测仅匹配一层随机子域；请将最大子域层数设为 1，或选择支持多层 wildcard 的 DNS provider。",
            })
        cname_boundaries = [r for r in records if r['type'] == 'CNAME']
        if 'dkim_public_key_pending' in plan['warnings']:
            blockers.append({'role': 'dkim', 'name': row['domain'], 'code': 'dkim_public_key_pending'})
        for target in targets:
            if target['type'] == 'TXT':
                prefix = {'spf': 'v=spf1', 'dmarc': 'v=dmarc1', 'dkim': 'v=dkim1'}.get(target['role'])
                if (prefix and not target['content'].lower().startswith(prefix)) or not target['content'].strip():
                    blockers.append({'role': target['role'], 'name': target['name'], 'code': 'invalid_mail_dns_policy'})
        if not row['receive_subdomains'] or not row['max_subdomain_depth']:
            return plan, targets, blockers
        domain = row['domain']
        c = self.m.db()
        try:
            children = [r[0] for r in c.execute('SELECT domain FROM mail_domains WHERE domain!=?', (domain,)) if r[0].endswith('.' + domain)]
        finally:
            c.close()
        excluded = lambda node: any(node == child or node.endswith('.' + child) for child in children)
        nodes = set()
        for record in records:
            node = record['name'].removeprefix('*.')
            if excluded(node):
                continue
            if record['type'] == 'NS' and node != inventory['zone_name']:
                blockers.append({'role': 'wildcard_mx', 'name': node, 'code': 'delegation_requires_separate_management'})
            labels = node.split('.')
            while node != domain and node.endswith('.' + domain):
                if all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in node.split('.')):
                    depth = len(node.split('.')) - len(domain.split('.'))
                    if depth <= row['max_subdomain_depth'] and not excluded(node):
                        nodes.add((node, depth))
                labels = labels[1:]; node = '.'.join(labels)
        if len(nodes) > 128:
            blockers.append({'role': 'wildcard_mx', 'name': domain, 'code': 'existing_node_plan_too_large'})
            return plan, targets, blockers
        # DNS empty non-terminals are enclosers too. Never merely add root '*'
        # when existing A/TXT nodes would suppress its matching at/below them.
        ttl = DYNV6_TTL if row['dns_provider'] == 'dynv6' else 300
        for node, depth in sorted(nodes):
            # Third-party CNAMEs are external namespace boundaries. Do not
            # synthesize MX records at the boundary or below it.
            boundary = next((item for item in cname_boundaries
                             if _cname_boundary_applies(item['name'], node)), None)
            if boundary:
                skipped = [node]
                if depth < row['max_subdomain_depth']:
                    skipped.append('*.' + node)
                for name in skipped:
                    plan['notices'].append({
                        'role': 'wildcard_mx',
                        'name': name,
                        'boundary': boundary['name'],
                        'code': 'external_cname_boundary_skipped',
                        'message': f"保留外部 CNAME {boundary['name']}，跳过 wildcard MX {name}",
                    })
                continue
            targets.append({'role': 'wildcard_mx', 'type': 'MX', 'name': node, 'content': row['mx'], 'priority': 10, 'ttl': ttl})
            if depth < row['max_subdomain_depth']:
                targets.append({'role': 'wildcard_mx', 'type': 'MX', 'name': '*.' + node, 'content': row['mx'], 'priority': 10, 'ttl': ttl})
        # Keep distinct TXT records at the same owner.  SPF and a provider
        # verification token can legitimately share the zone apex; collapsing
        # by only (type, name) silently drops whichever target was added first.
        unique = {}
        for target in targets:
            key = (
                target['type'],
                target['name'],
                target.get('content', ''),
                target.get('priority'),
            )
            unique[key] = target
        return plan, list(unique.values()), blockers

    def pending(self, row, zone_id):
        c = self.m.db()
        try:
            return [dict(r) for r in c.execute("SELECT * FROM domain_dns_operations WHERE domain=? AND credential_ref=? AND zone_id=? AND status IN ('dispatched','unknown')",
                                               (row['domain'], row['dns_credential_ref'], zone_id))]
        finally:
            c.close()

    def owned(self, row, zone_id):
        c = self.m.db()
        try:
            return {r['provider_record_id']: dict(r) for r in c.execute('SELECT * FROM managed_dns_records WHERE domain=? AND credential_ref=? AND zone_id=?',
                    (row['domain'], row['dns_credential_ref'], zone_id))}
        finally:
            c.close()

    def reconcile_operation(self, domain, operation_id):
        """Settle a terminal ambiguous write by observing its exact desired state.

        DigitalPlat has no ownership marker. A matching record is accepted as
        existing, never adopted as our write. Missing/changed records remain
        unresolved and cannot be blindly retried.
        """
        with self.m.lock:
            row = self.m.domain(domain)
            c = self.m.db()
            try:
                operation = c.execute(
                    'SELECT * FROM domain_dns_operations WHERE id=? AND domain=?',
                    (operation_id, row['domain'])).fetchone()
                if not operation:
                    raise JobConflict('DNS operation not found for this domain')
                operation = dict(operation)
                if (row['dns_provider'] not in {'digitalplat', 'dynv6'} or
                    operation['credential_ref'] != row['dns_credential_ref']):
                    raise JobConflict('DNS operation binding changed; manual review required')
                if operation['status'] == 'observed':
                    return {'domain': row['domain'], 'operation_id': operation_id,
                            'status': 'observed', 'dns_writes': 0, 'ownership_adopted': False}
                job = c.execute('SELECT status,kind,request_json FROM domain_jobs WHERE id=?',
                                (operation['job_id'],)).fetchone()
                if operation['status'] not in {'unknown', 'dispatched'} or not job or job['status'] in {'queued', 'running'}:
                    raise JobConflict('DNS operation is not an interrupted terminal write')
            finally:
                c.close()
            row, _, inventory, records = self.capture(row['domain'])
            if operation['zone_id'] != inventory['zone_id']:
                raise JobConflict('DNS operation zone changed; manual review required')
            target = json.loads(operation['target_json'])
            _, targets, blockers = self.targets(row, inventory, records)
            if blockers or target not in targets:
                raise JobConflict('DNS operation target changed; manual review required')
            candidates = [record for record in records if semantic(record, target)]
            deleted = False
            if operation['action'] == 'delete' and job['kind'] == 'dns_repair':
                snapshot = self.plan(json.loads(job['request_json'])['plan_id'])
                saved = snapshot.get('repair', {}).get('record', {})
                others = [record for record in records if not semantic(record, target)]
                if (saved.get('id') != operation['provider_record_id'] or fingerprint(saved) != operation['before_hash'] or
                    inventory_hash(others, row['dns_provider'], inventory['zone_name']) != snapshot['repair']['other_inventory_hash']):
                    raise JobConflict('DNS repair backup no longer matches current inventory')
                deleted = not candidates
            if not deleted and (len(candidates) != 1 or not matches(candidates[0], target) or
                (operation['provider_record_id'] and operation['provider_record_id'] != candidates[0]['id'])):
                raise JobConflict('DNS write remains unresolved: current record is missing, ambiguous or changed')
            current = saved if deleted else candidates[0]
            c = self.m.db()
            try:
                c.execute('BEGIN IMMEDIATE')
                if c.execute("""SELECT 1 FROM domain_jobs WHERE scope=? AND kind IN ('dns_apply','dns_repair')
                    AND status IN ('queued','running')""", (row['domain'],)).fetchone():
                    raise JobConflict('DNS apply is active; wait before reconciliation')
                changed = c.execute("""UPDATE domain_dns_operations SET status='observed',
                    provider_record_id=?,updated_at=? WHERE id=? AND status IN ('unknown','dispatched')""",
                    (current['id'], time.time(), operation_id)).rowcount
                if changed != 1:
                    raise JobConflict('DNS operation changed during reconciliation; retry')
                old_job = c.execute('SELECT * FROM domain_jobs WHERE id=?', (operation['job_id'],)).fetchone()
                if old_job['status'] == 'unknown' and not c.execute("""SELECT 1 FROM domain_dns_operations
                    WHERE job_id=? AND status IN ('unknown','dispatched')""", (operation['job_id'],)).fetchone():
                    result = json.loads(old_job['result_json'])
                    result['reconciliation'] = {
                        'operation_id': operation_id, 'status': 'observed_deleted_without_replay' if deleted else 'observed_existing_without_adoption',
                        'record_id': current['id'], 'record_hash': fingerprint(current),
                        'previous_error': old_job['error_code'], 'next_action': 'fresh_dns_preview',
                    }
                    c.execute("""UPDATE domain_jobs SET status='partial',step='dns_write_observed_repreview_required',
                        result_json=?,updated_at=? WHERE id=? AND status='unknown'""",
                        (json.dumps(result), time.time(), operation['job_id']))
                c.commit()
            finally:
                c.close()
            return {'domain': row['domain'], 'operation_id': operation_id,
                    'status': 'observed', 'dns_writes': 0, 'ownership_adopted': False}

    def preview(self, domain):
        # Upstream reads and lazy Brevo registration must not monopolize the
        # domain configuration lock. Bound concurrency across all API callers.
        with self.preview_slots:
            row, _, inventory, records = self.capture(domain)
            local_plan = build_plan(row, self.m.key_root)
            plan = self.plan_for(row, plan=local_plan)
            with self.m.lock:
                current = self.m.domain(domain)
                if (current['dns_credential_ref'] != row['dns_credential_ref'] or
                    current['dns_provider'] != row['dns_provider'] or
                    current['source_status'] != row['source_status'] or
                    build_plan(current, self.m.key_root)['plan_hash'] != local_plan['plan_hash']):
                    raise JobConflict('DNS configuration changed during preview; prepare a fresh preview')
                return self._preview(row, inventory, records, plan)

    def _preview(self, row, inventory, records, plan):
        plan, targets, blockers = self.targets(row, inventory, records, plan=plan)
        zone_id = inventory['zone_id']
        owned = self.owned(row, zone_id)
        pending = self.pending(row, zone_id)
        cname_boundaries = [r for r in records if r['type'] == 'CNAME']
        actions, recovered = [], set()
        for target in targets:
            candidates = [r for r in records if semantic(r, target)]
            cname = [r for r in records if (r['name'] == target['name'] or target['name'].endswith('.' + r['name'])) and
                     ((target['type'] != 'CNAME' and r['type'] == 'CNAME') or
                      (r['type'] == 'NS' and r['name'] != inventory['zone_name']))]
            if target['role'] == 'wildcard_mx':
                boundary = next((r for r in cname_boundaries
                                 if _cname_boundary_applies(r['name'], target['name'])), None)
                if boundary:
                    notice = {
                        'role': target['role'],
                        'name': target['name'],
                        'boundary': boundary['name'],
                        'code': 'external_cname_boundary_skipped',
                        'message': f"保留外部 CNAME {boundary['name']}，跳过 wildcard MX {target['name']}",
                    }
                    if notice not in plan['notices']:
                        plan['notices'].append(notice)
                    continue
            if cname or len(candidates) > 1:
                blockers.append({'role': target['role'], 'name': target['name'], 'code': 'cname_or_multiple_semantic_records'})
                continue
            current = candidates[0] if candidates else None
            operation = next((p for p in pending if row['dns_provider'] == 'cloudflare' and current and
                              current['comment'] == p['ownership_marker'] and matches(current, json.loads(p['target_json'])) and
                              matches(current, target)), None)
            if operation:
                actions.append({'action': 'recover', 'target': target, 'record_id': current['id'],
                                'before_hash': fingerprint(current), 'operation_id': operation['id'], 'marker': current['comment']})
                recovered.add(operation['id'])
                continue
            owner = owned.get(current['id']) if current else None
            owner_fingerprint = owner['fingerprint'] if owner else ''
            if owner and row['dns_provider'] == 'digitalplat' and current['type'] == 'TXT':
                # A DigitalPlat TXT ID identifies an RRset. SPF and provider
                # verification values share it but retain independent ownership.
                proof = next((proof for proof in _owned_txt_values(owner)
                              if semantic(current, proof['target'])), None)
                if proof:
                    owner_fingerprint = proof['fingerprint']
                else:
                    owner = None
            if owner and (not owner_fingerprint or owner_fingerprint != fingerprint(current) or
                          (row['dns_provider'] == 'cloudflare' and current['comment'] != owner['ownership_marker'])):
                blockers.append({'role': target['role'], 'name': target['name'], 'code': 'owned_record_changed_externally'})
                continue
            if current and matches(current, target):
                actions.append({'action': 'exists', 'target': target, 'record_id': current['id'],
                                'before_hash': fingerprint(current), 'owned': bool(owner)})
            elif current:
                if not owner:
                    blockers.append({'role': target['role'], 'name': target['name'], 'code': 'foreign_record_conflict'})
                elif current['locked']:
                    blockers.append({'role': target['role'], 'name': target['name'], 'code': 'provider_record_locked'})
                else:
                    actions.append({'action': 'update', 'target': target, 'record_id': current['id'],
                                    'before_hash': fingerprint(current), 'marker': owner['ownership_marker']})
            else:
                actions.append({'action': 'create', 'target': target, 'before_hash': ''})
        for p in pending:
            if p['id'] not in recovered:
                blockers.append({'role': 'operation', 'name': row['domain'], 'code': 'unresolved_dns_write', 'operation_id': p['id']})
        snapshot = {'id': uuid.uuid4().hex, 'domain': row['domain'], 'credential_ref': row['dns_credential_ref'],
                    'provider': row['dns_provider'], 'zone_id': zone_id, 'zone_name': inventory['zone_name'],
                    'config_hash': plan['config_hash'], 'plan_hash': plan['plan_hash'],
                    'inventory_hash': inventory_hash(records, row['dns_provider'], inventory['zone_name']),
                    'actions': actions, 'conflicts': blockers, 'notices': plan.get('notices', []),
                    'executable': not blockers,
                    'created_at': time.time(), 'expires_at': time.time() + 600,
                    'wildcard_readiness': 'pending_until_resolver_and_boundary_validation'}
        c = self.m.db()
        try:
            with c:
                c.execute('INSERT INTO domain_dns_plans VALUES(?,?,?,?,?,?,?,?,?)',
                    (snapshot['id'], row['domain'], row['dns_credential_ref'], plan['config_hash'], plan['plan_hash'],
                     snapshot['inventory_hash'], json.dumps(snapshot), snapshot['created_at'], snapshot['expires_at']))
        finally:
            c.close()
        return snapshot

    def plan(self, plan_id):
        c = self.m.db()
        try:
            row = c.execute('SELECT snapshot_json FROM domain_dns_plans WHERE id=?', (plan_id,)).fetchone()
            if not row:
                raise ValueError('DNS preview not found')
            return json.loads(row['snapshot_json'])
        finally:
            c.close()

    def enqueue(self, domain, plan_id, key, *, activate_on_success=False):
        request = {"plan_id": plan_id}
        if activate_on_success:
            request["activate_on_success"] = True
        snapshot = self.plan(plan_id)
        if snapshot['domain'] != normalize_domain(domain):
            raise JobConflict('DNS preview belongs to another domain')
        c = self.m.db()
        try:
            prior = c.execute("SELECT 1 FROM domain_jobs WHERE kind='dns_apply' AND scope=? AND idempotency_key=?", (snapshot['domain'], key)).fetchone()
        finally:
            c.close()
        if prior:
            return self.m.jobs.enqueue('dns_apply', snapshot['domain'], key, request)
        if not snapshot['executable'] or snapshot['expires_at'] < time.time():
            raise JobConflict('DNS preview has conflicts or expired; prepare a fresh preview')
        return self.m.jobs.enqueue('dns_apply', snapshot['domain'], key, request)

    def operation(self, job, snapshot, action):
        op_id = uuid.uuid4().hex
        marker = action.get('marker') or 'mail-stack:operation:' + op_id
        c = self.m.db()
        try:
            with c:
                c.execute("""INSERT INTO domain_dns_operations(id,job_id,domain,credential_ref,zone_id,action,target_json,
                    before_hash,ownership_marker,provider_record_id,status,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (op_id, job['id'], snapshot['domain'], snapshot['credential_ref'], snapshot['zone_id'], action['action'],
                     json.dumps(action['target']), action['before_hash'], marker, action.get('record_id'), 'dispatched', time.time()))
        finally:
            c.close()
        return op_id, marker

    def confirm(self, row, zone_id, op_id, target, current, marker):
        c = self.m.db()
        try:
            with c:
                saved = target
                if row['dns_provider'] == 'digitalplat' and current['type'] == 'TXT':
                    previous = c.execute("""SELECT * FROM managed_dns_records
                        WHERE domain=? AND credential_ref=? AND zone_id=? AND provider_record_id=?""",
                        (row['domain'], row['dns_credential_ref'], zone_id, current['id'])).fetchone()
                    proofs = _owned_txt_values(previous) if previous else []
                    proofs = [proof for proof in proofs if not semantic(current, proof['target'])]
                    proofs.append({'target': target, 'fingerprint': fingerprint(current)})
                    saved = {**target, 'owned_records': proofs}
                c.execute("""INSERT INTO managed_dns_records(domain,credential_ref,zone_id,provider_record_id,record_type,
                    record_name,role,last_content,updated_at,fingerprint,ownership_marker) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(domain,credential_ref,zone_id,provider_record_id) DO UPDATE SET
                    last_content=excluded.last_content,fingerprint=excluded.fingerprint,ownership_marker=excluded.ownership_marker,
                    updated_at=excluded.updated_at""", (row['domain'], row['dns_credential_ref'], zone_id, current['id'], target['type'],
                      target['name'], target['role'], json.dumps(saved), time.time(), fingerprint(current), marker))
                c.execute("UPDATE domain_dns_operations SET status='confirmed',provider_record_id=?,updated_at=? WHERE id=?",
                          (current['id'], time.time(), op_id))
        finally:
            c.close()

    def set_operation_error(self, op_id, code, uncertain):
        c = self.m.db()
        try:
            with c:
                c.execute('UPDATE domain_dns_operations SET status=?,error_code=?,updated_at=? WHERE id=?',
                          ('unknown' if uncertain else 'failed', code, time.time(), op_id))
        finally:
            c.close()

    def _assert_apply_revision(self, row, plan):
        current = self.m.domain(row["domain"])
        if (current["dns_credential_ref"] != row["dns_credential_ref"] or
            current["dns_provider"] != row["dns_provider"] or
            current["source_status"] != row["source_status"] or
            build_plan(current, self.m.key_root)["plan_hash"] != plan["plan_hash"]):
            raise JobConflict("DNS configuration changed during apply")

    def _interrupt_apply(self, job, completed, op_id, write_returned, exc):
        code = exc.code if isinstance(exc, ProviderError) else 'dns_write_or_persistence_failed'
        uncertain = bool(op_id) and (write_returned or not isinstance(exc, ProviderError) or exc.uncertain)
        if op_id:
            self.set_operation_error(op_id, code, uncertain)
        self.m.jobs.finish(job['id'], 'unknown' if uncertain else ('partial' if completed else 'failed'),
            step='dns_apply_interrupted', result={'completed': completed, 'operation_id': op_id,
            **self.m.jobs.provider_backoff(job['scope'], exc)}, error=code)

    def apply(self, job):
        completed, op_id, write_returned = [], None, False
        snapshot = self.plan(job['request']['plan_id'])
        if snapshot['domain'] != job['scope']:
            raise JobConflict('DNS preview belongs to another domain')
        if (not snapshot['executable'] or not
                snapshot['created_at'] <= job['created_at'] <= snapshot['expires_at']):
            raise JobConflict('DNS preview expired or conflicted')
        # Admission excludes overlapping namespaces. Configuration writers also
        # reject edits to an active namespace, including its parents/children.
        # Slow upstream reads therefore need not hold the global config lock.
        try:
            row, adapter, inventory, records = self.capture(snapshot['domain'])
        except ProviderError as exc:
            raise ProviderError(exc.code, uncertain=False, retry_after=exc.retry_after,
                                rate_limit=exc.rate_limit) from None
        validation_plan = build_plan(row, self.m.key_root)
        current_plan = self.plan_for(row)
        with self.m.lock:
            self._assert_apply_revision(row, validation_plan)
            if (row['dns_credential_ref'] != snapshot['credential_ref'] or inventory['zone_id'] != snapshot['zone_id'] or
                inventory['zone_name'] != snapshot['zone_name'] or current_plan['plan_hash'] != snapshot['plan_hash'] or
                inventory_hash(records, row['dns_provider'], inventory['zone_name']) != snapshot['inventory_hash']):
                raise JobConflict('DNS configuration or inventory changed; fresh preview required')
            c = self.m.db()
            try:
                with c:
                    c.execute('DELETE FROM domain_checks WHERE domain=?', (row['domain'],))
            finally:
                c.close()
        expected_records = records
        try:
            for action in snapshot['actions']:
                target = action['target']
                if action['action'] == 'exists':
                    completed.append({'name': target['name'], 'role': target['role'], 'action': 'exists'})
                    continue
                # Re-read inventory before every write; there is no claim of
                # server-side CAS against an unrelated DNS writer.
                fresh_inventory = adapter.inventory(row['domain'])
                if (identifier(fresh_inventory['zone_id']) != snapshot['zone_id'] or
                    fresh_inventory['zone_name'] != snapshot['zone_name']):
                    raise ProviderError('dns_zone_changed_before_write')
                fresh = scoped_inventory(fresh_inventory, row['domain'], row['dns_provider'])
                if inventory_hash(fresh, row['dns_provider'], snapshot['zone_name']) != inventory_hash(expected_records, row['dns_provider'], snapshot['zone_name']):
                    raise ProviderError('dns_changed_before_write')
                candidates = [r for r in fresh if semantic(r, target)]
                if action['action'] == 'create':
                    if candidates or any(r['name'] == target['name'] and r['type'] == 'CNAME' for r in fresh):
                        raise ProviderError('dns_changed_before_write')
                else:
                    if len(candidates) != 1 or candidates[0]['id'] != action['record_id'] or fingerprint(candidates[0]) != action['before_hash']:
                        raise ProviderError('dns_changed_before_write')
                if action['action'] == 'recover':
                    with self.m.lock:
                        self._assert_apply_revision(row, validation_plan)
                        self.confirm(row, snapshot['zone_id'], action['operation_id'], target, candidates[0], action['marker'])
                else:
                    write_returned = False
                    # Serialize only dispatch, not inventory or validation.
                    # Persist a 429 before releasing this gate, so the other
                    # active task cannot issue another provider write.
                    with self.m.lock:
                        self._assert_apply_revision(row, validation_plan)
                        self.m.jobs.check_provider_backoff(row['dns_provider'])
                        op_id, marker = self.operation(job, snapshot, action)
                        try:
                            if row['dns_provider'] == 'digitalplat':
                                raw = adapter.write(snapshot['zone_id'], target, marker, action.get('record_id'),
                                                    existing_records=fresh)
                            else:
                                raw = adapter.write(snapshot['zone_id'], target, marker, action.get('record_id'))
                        except Exception as exc:
                            self._interrupt_apply(job, completed, op_id, False, exc)
                            return
                    write_returned = True
                    record_id = identifier(raw.get('id') or raw.get('record_id'))
                    verified_inventory = adapter.inventory(row['domain'])
                    if (identifier(verified_inventory['zone_id']) != snapshot['zone_id'] or
                        verified_inventory['zone_name'] != snapshot['zone_name']):
                        raise ProviderError('dns_zone_changed_after_write', uncertain=True)
                    verified = scoped_inventory(verified_inventory, row['domain'], row['dns_provider'])
                    exact = [r for r in verified if r['id'] == record_id and matches(r, target)]
                    if len(exact) != 1 or (row['dns_provider'] == 'cloudflare' and exact[0]['comment'] != marker):
                        raise ProviderError('dns_write_verification_failed', uncertain=True)
                    # Only the intended logical value may change, including
                    # when a physical RRset ID holds several TXT values.
                    is_written = lambda r: r['id'] == record_id and semantic(r, target)
                    untouched_before = [r for r in fresh if not is_written(r)]
                    untouched_after = [r for r in verified if not is_written(r)]
                    if inventory_hash(untouched_before, row['dns_provider'], snapshot['zone_name']) != inventory_hash(untouched_after, row['dns_provider'], snapshot['zone_name']):
                        raise ProviderError('dns_inventory_changed_during_write', uncertain=True)
                    with self.m.lock:
                        self.confirm(row, snapshot['zone_id'], op_id, target, exact[0], marker)
                    expected_records = verified
                    op_id = None
                completed.append({'name': target['name'], 'role': target['role'], 'action': action['action']})
        except Exception as exc:
            with self.m.lock:
                self._interrupt_apply(job, completed, op_id, write_returned, exc)
            return
        c = self.m.db()
        try:
            with c:
                c.execute("UPDATE domain_jobs SET step='dns_validating',updated_at=? WHERE id=? AND status='running'",
                          (time.time(), job['id']))
        finally:
            c.close()
        if row['dns_provider'] == 'dynv6' and job['request'].get('activate_on_success'):
            try:
                child = self.m.dns_completion.enqueue(row['domain'], 'dns-complete:' + job['id'])
            except Exception:
                self.m.jobs.finish(job['id'], 'partial', step='dns_applied_completion_error',
                    result={'domain': row['domain'], 'completed': completed, 'next_action': 'retry_completion'},
                    error='dns_completion_not_queued')
                return
            self.m.jobs.finish(job['id'], 'succeeded', step='dns_applied_completion_queued',
                result={'domain': row['domain'], 'completed': completed, 'completion_job': child,
                        'next_action': 'wait_for_dns'})
            return
        # Keep the same job running until resolver/SMTP evidence is saved.
        # The UI therefore holds its row lock and refreshes only at completion.
        try:
            validation = self.m.validate_domain(
                row['domain'], validation_plan,
                refresh_smtp_submission=True,
                activate_on_success=bool(job["request"].get("activate_on_success")),
            )
        except Exception:
            # DNS writes are already confirmed. A read-only validation error
            # must never reclassify them as unknown or replay those writes.
            self.m.jobs.finish(job['id'], 'partial', step='dns_applied_validation_error',
                result={'completed': completed, 'validation_status': 'error', 'next_action': 'dns_validate'},
                error='dns_validation_failed')
            return
        passed = all(check.get('status') in {'passed', 'not_required'}
                     for check in validation['checks'].values())
        self.m.jobs.finish(job['id'], 'succeeded', step='dns_applied_and_validated', result={
            **validation, 'completed': completed,
            'validation_status': 'passed' if passed else 'failed',
            'next_action': ('wait_for_routing' if validation.get('activation', {}).get('status') == 'routing_pending'
                            else 'none' if passed else 'wait_for_dns')})

"""Durable dynv6 delegation and activation; uncertain writes are read back, never replayed."""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import secrets
import time

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

from api.providers.dns.digitalplat import DigitalPlatDNS
from api.providers.http import ProviderError
from api.repositories.credentials import CredentialError
from api.repositories.domain_jobs import JobConflict
from api.services.dns_inventory import matches
from api.services.routing import normalize_domain

TARGET_NS = ('ns1.dynv6.com', 'ns2.dynv6.com', 'ns3.dynv6.com')
HOSTED_NS = frozenset(('dns1.digitalplat.org', 'dns2.digitalplat.org'))


class DelegationProbe:
    """Check every target authority and the actual parent, without recursive NS caches."""
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout, self.resolver.lifetime = 2, 4

    def query(self, host, name, kind, *, authoritative=True):
        addresses = []
        for family in ('A', 'AAAA'):
            try:
                addresses.extend(str(r) for r in self.resolver.resolve(host, family, search=False))
            except dns.exception.DNSException:
                pass
            if addresses:
                break
        if not addresses:
            return None
        query = dns.message.make_query(name, kind)
        query.flags &= ~dns.flags.RD
        for address in addresses[:2]:
            try:
                try:
                    response = dns.query.tcp(query, address, timeout=2)
                except (OSError, dns.exception.DNSException):
                    response = dns.query.udp(query, address, timeout=2)
                    if response.flags & dns.flags.TC:
                        response = dns.query.tcp(query, address, timeout=2)
                if response.rcode() or (authoritative and not response.flags & dns.flags.AA):
                    continue
                values = set()
                sections = list(response.answer) + (list(response.authority) if kind == 'NS' else [])
                for rrset in sections:
                    if (rrset.name.to_text().lower().rstrip('.') != name.lower().rstrip('.')
                            or rrset.rdtype != dns.rdatatype.from_text(kind)):
                        continue
                    for record in rrset:
                        if kind == 'TXT':
                            values.add(b''.join(record.strings).decode('ascii'))
                        elif kind == 'MX':
                            values.add(str(record.preference) + ' ' + str(record.exchange).lower().rstrip('.'))
                        else:
                            values.add(record.to_text().lower().rstrip('.'))
                return values
            except (OSError, ValueError, dns.exception.DNSException):
                continue
        return None

    def targets(self, row, targets):
        expected = {}
        for record in targets:
            value = record['content']
            if record['type'] == 'MX':
                value = str(record['priority']) + ' ' + value.lower().rstrip('.')
            elif record['type'] == 'CNAME':
                value = value.lower().rstrip('.')
            expected.setdefault((record['name'], record['type']), set()).add(value)
        expected[(row['domain'], 'NS')] = set(TARGET_NS)
        if row['receive_subdomains'] and row['max_subdomain_depth']:
            expected[('ns-check-' + secrets.token_hex(5) + '.' + row['domain'], 'MX')] = {
                '10 ' + row['mx'].lower().rstrip('.')}
        tasks = [(host, name, kind, wanted) for host in TARGET_NS
                 for (name, kind), wanted in expected.items()]
        def check(task):
            host, name, kind, wanted = task
            found = self.query(host, name, kind)
            passed = found is not None and (wanted <= found if kind == 'TXT' else wanted == found)
            # Never expose TXT contents or provider credentials in job diagnostics.
            return {'host': host, 'name': name, 'type': kind, 'passed': passed}
        with ThreadPoolExecutor(max_workers=3) as pool:
            checks = list(pool.map(check, tasks))
        return {'passed': bool(checks) and all(c['passed'] for c in checks), 'checks': checks}

    def parents(self, domain):
        parent = dns.resolver.zone_for_name(dns.name.from_text(domain).parent(), resolver=self.resolver)
        hosts = sorted({str(r.target).lower().rstrip('.') for r in
                        self.resolver.resolve(parent, 'NS', search=False)})
        if not hosts or len(hosts) > 8:
            raise ProviderError('dns_parent_authorities_unavailable')
        def check(host):
            values = self.query(host, domain, 'NS', authoritative=False)
            return {'host': host, 'nameservers': sorted(values) if values is not None else [],
                    'passed': values == set(TARGET_NS)}
        with ThreadPoolExecutor(max_workers=3) as pool:
            checks = list(pool.map(check, hosts))
        return {'passed': all(c['passed'] for c in checks), 'checks': checks}


class DNSCompletion:
    WAIT_SECONDS = 2 * 3600

    def __init__(self, manager):
        self.m = manager
        self.probe = DelegationProbe()

    def enqueue(self, domain, key):
        domain = normalize_domain(domain)
        with self.m.lock:
            c = self.m.db()
            try:
                prior = c.execute("SELECT * FROM domain_jobs WHERE kind='dns_complete' AND scope=? AND idempotency_key=?",
                                  (domain, key)).fetchone()
                if prior:
                    return self.m.jobs.public(prior)
                row = self.m.domain(domain)
                if row['dns_provider'] != 'dynv6':
                    raise ValueError('DNS completion requires a selected dynv6 binding')
                if row['source_status'] in {'released', 'revoked', 'expired', 'releasing'}:
                    raise ValueError('domain ownership is inactive')
                self.m.credentials().require_writer()
                plan = self.m.plan(domain)
                claim = self.m.claim_row(row['claim_id']) if row['claim_id'] else {}
                request = {'claim_job_id': claim.get('job_id'), 'registrar_credential_ref': claim.get('dns_credential_ref'),
                           'config_hash': plan['config_hash'], 'plan_hash': plan['plan_hash'],
                           'credential_ref': row['dns_credential_ref'], 'claim_id': row['claim_id'],
                           'activate_on_success': True}
                # One pending completion per revision, including double clicks with new keys.
                active = c.execute("SELECT * FROM domain_jobs WHERE kind='dns_complete' AND scope=? AND status IN ('queued','running')",
                                   (domain,)).fetchall()
                for existing in active:
                    if json.loads(existing['request_json']) == request:
                        return self.m.jobs.public(existing)
                return self.m.jobs.enqueue('dns_complete', domain, key, request)
            finally:
                c.close()

    def context(self, job):
        row = self.m.domain(job['scope'])
        plan = self.m.plan(job['scope'])
        expected = job['request']
        claim = self.m.claim_row(row['claim_id']) if row['claim_id'] else {}
        if (claim.get('job_id') != expected['claim_job_id']
                or claim.get('dns_credential_ref') != expected['registrar_credential_ref']
                or row['dns_provider'] != 'dynv6' or row['dns_credential_ref'] != expected['credential_ref']
                or row['claim_id'] != expected['claim_id']
                or row['source_status'] in {'released', 'revoked', 'expired', 'releasing'}
                or plan['config_hash'] != expected['config_hash'] or plan['plan_hash'] != expected['plan_hash']):
            raise JobConflict('domain ownership or configuration changed during completion')
        return row

    def registrar(self, row):
        if not row['claim_id']:
            return None
        claim = self.m.claim_row(row['claim_id'])
        if claim['domain'] != row['domain'] or not claim['dns_credential_ref']:
            return None
        c = self.m.db()
        try:
            credential = c.execute('SELECT provider FROM dns_credentials WHERE id=?',
                                   (claim['dns_credential_ref'],)).fetchone()
            if not credential or credential['provider'] != 'digitalplat':
                return None
            secret = self.m.credentials().get(c, claim['dns_credential_ref'], provider='digitalplat', domain=row['domain'])
        finally:
            c.close()
        return DigitalPlatDNS(self.m.http, secret, row['domain'])

    def progress(self, job, result, step):
        self.m.jobs.progress(job['id'], step=step, result=result)

    def wait(self, job, result, phase, *, error=None):
        now = time.time()
        if now >= result['deadline']:
            result.update(next_action='retry_completion', validation_status='pending')
            self.m.jobs.finish(job['id'], 'partial', step='dns_completion_timed_out', result=result,
                               error=error or 'dns_publication_timeout')
            return
        result['attempts'] = result.get('attempts', 0) + 1
        delay = min(300, 15 * (2 ** min(result['attempts'] - 1, 5)))
        until = now + delay
        if phase == 'dns_completion_waiting_upstream':
            until = max(until, result.get('provider_backoff', {}).get('until', 0))
        result.update(retry_at=min(until, result['deadline']), next_action='wait_for_dns')
        self.m.jobs.defer(job['id'], step=phase, result=result)

    def unresolved(self, job):
        c = self.m.db()
        try:
            rows = c.execute("""SELECT id,result_json FROM domain_jobs WHERE kind='dns_complete'
                AND scope=? AND id!=? AND status IN ('unknown','partial','failed') ORDER BY created_at DESC""",
                (job['scope'], job['id'])).fetchall()
            for row in rows:
                delegation = json.loads(row['result_json']).get('delegation', {})
                if delegation.get('phase') != 'confirmed' and any(a.get('phase') in {'dispatched', 'accepted', 'uncertain'} for a in delegation.get('writes', [])):
                    return row['id']
        finally:
            c.close()
        return None

    def execute(self, job):
        result = copy.deepcopy(job['result'])
        result.setdefault('domain', job['scope'])
        result.setdefault('deadline', time.time() + self.WAIT_SECONDS)
        result.pop('retry_at', None)
        delegation = result.setdefault('delegation', {'phase': 'checking', 'nameservers': list(TARGET_NS), 'writes': []})
        provider = 'dynv6'
        try:
            row = self.context(job)
            if delegation['phase'] != 'confirmed':
                # Prove all intended mail and Brevo records exist before any delegation change.
                captured, _, inventory, records = self.m.dns.capture(row['domain'])
                if captured['dns_credential_ref'] != row['dns_credential_ref'] or inventory['zone_name'] != row['domain']:
                    raise ProviderError('dns_completion_requires_exact_zone')
                targets = self.m.dns.plan_for(row)['records']
                if not all(any(matches(record, target) for record in records) for target in targets):
                    raise ProviderError('dns_completion_records_missing')
                self.context(job)
                provider = 'digitalplat'
                registrar = self.registrar(row)
                current_ns = registrar.delegation_status() if registrar else None
                result['parent_authorities'] = self.probe.parents(row['domain'])
                if result['parent_authorities']['passed'] and (current_ns is None or set(current_ns) == set(TARGET_NS)):
                    delegation['phase'] = 'confirmed'
                elif current_ns is not None and set(current_ns) == set(TARGET_NS):
                    delegation['phase'] = 'accepted'
                    self.wait(job, result, 'dns_completion_waiting_delegation')
                    return
                else:
                    writes = delegation['writes']
                    if any(a['phase'] in {'dispatched', 'accepted', 'uncertain'} for a in writes) or self.unresolved(job):
                        # A stale API read cannot prove that an earlier POST was rejected.
                        delegation['phase'] = 'readback_pending'
                        self.wait(job, result, 'dns_completion_readback_pending', error='dns_delegation_unconfirmed')
                        return
                    if registrar is None:
                        raise ProviderError('digitalplat_delegation_credential_required')
                    if set(current_ns) != HOSTED_NS:
                        raise ProviderError('dns_delegation_external_provider_conflict')
                    if row['enabled']:
                        raise ProviderError('dns_delegation_requires_disabled_domain')
                    # A partially changed parent must not be overwritten based on a stale API view.
                    observed = result['parent_authorities']['checks']
                    if not all(c['nameservers'] for c in observed):
                        self.wait(job, result, 'dns_completion_waiting_authorities')
                        return
                    if any(set(c['nameservers']) == set(TARGET_NS) for c in observed):
                        self.wait(job, result, 'dns_completion_readback_pending')
                        return
                    if any(c['nameservers'] and set(c['nameservers']) not in (HOSTED_NS, set(TARGET_NS)) for c in observed):
                        raise ProviderError('dns_delegation_parent_conflict')
                    delegation.setdefault('before_nameservers', current_ns)
                    for force in (False, True):
                        previous = writes[-1] if writes else None
                        if force and (not previous or previous.get('error_code') != 'external_nameserver_precheck_failed'):
                            break
                        if not force and previous:
                            # Only the explicit precheck rejection permits a separate confirmation POST.
                            if previous.get('error_code') == 'external_nameserver_precheck_failed':
                                continue
                            raise ProviderError('dns_delegation_request_rejected')
                        result['target_authorities'] = self.probe.targets(row, targets)
                        if not result['target_authorities']['passed']:
                            self.wait(job, result, 'dns_completion_waiting_authorities')
                            return
                        with self.m.lock:
                            self.context(job)
                            if set(registrar.delegation_status()) != HOSTED_NS:
                                self.wait(job, result, 'dns_completion_readback_pending')
                                return
                            self.m.jobs.check_provider_backoff('digitalplat')
                            attempt = {'force': force, 'phase': 'dispatched', 'at': time.time(),
                                       'idempotency_key': 'mail-stack-ns:' + job['id'] + (':confirm' if force else ':precheck')}
                            writes.append(attempt)
                            self.progress(job, result, 'dns_completion_switch_dispatched')
                            try:
                                operation = registrar.switch_external(TARGET_NS, attempt['idempotency_key'], force=force)
                            except ProviderError as exc:
                                if exc.upstream_code == 'external_nameserver_precheck_failed' and not force:
                                    attempt.update(phase='rejected', error_code=exc.upstream_code)
                                    self.progress(job, result, 'dns_completion_precheck_rejected')
                                    continue
                                attempt.update(phase='uncertain' if exc.uncertain else 'rejected', error_code=exc.code)
                                result.update(self.m.jobs.provider_backoff(row['domain'], exc, provider='digitalplat'))
                                self.progress(job, result, 'dns_completion_switch_readback')
                                if not exc.uncertain:
                                    raise
                            else:
                                attempt.update(phase='accepted', operation_id=operation)
                                self.progress(job, result, 'dns_completion_switch_accepted')
                        # Always read back on the next pass; accepted does not mean delegated.
                        self.wait(job, result, 'dns_completion_waiting_delegation', error='dns_delegation_unconfirmed')
                        return
            delegation.setdefault('confirmed_at', time.time())
            self.progress(job, result, 'dns_completion_validating')
            validation = self.m.validate_domain(row['domain'], job['request'],
                                                refresh_smtp_submission=True, activate_on_success=True)
            result.update(validation)
            passed = all(c.get('status') in {'passed', 'not_required'} for c in validation['checks'].values())
            result['validation_status'] = 'passed' if passed else 'pending'
            if not passed:
                self.wait(job, result, 'dns_completion_waiting_dns')
                return
            result['next_action'] = 'wait_for_routing' if validation.get('activation', {}).get('status') == 'routing_pending' else 'none'
            self.m.jobs.finish(job['id'], 'succeeded', step='dns_completion_validated', result=result)
        except JobConflict:
            self.m.jobs.finish(job['id'], 'failed', step='dns_completion_configuration_changed', result=result,
                               error='dns_completion_configuration_changed')
        except (ProviderError, CredentialError) as exc:
            code = exc.code if isinstance(exc, ProviderError) else 'digitalplat_delegation_credential_required'
            # Only GET/probe failures reach here without a recorded POST; retry reads with a deadline.
            if isinstance(exc, ProviderError) and (code in {'provider_http_429', 'provider_http_502', 'provider_http_503',
                    'provider_http_504', 'provider_transport_or_json_error', 'dns_parent_authorities_unavailable'}):
                result.update(self.m.jobs.provider_backoff(row['domain'], exc, provider=provider))
                self.wait(job, result, 'dns_completion_waiting_upstream', error=code)
                return
            self.m.jobs.finish(job['id'], 'partial', step='dns_completion_blocked', result=result, error=code)
        except dns.exception.DNSException:
            self.wait(job, result, 'dns_completion_waiting_authorities', error='dns_parent_authorities_unavailable')
        except Exception:
            # Preserve dispatch evidence even when a local fault follows an external write.
            uncertain = any(a['phase'] in {'dispatched', 'accepted', 'uncertain'} for a in delegation['writes'])
            self.m.jobs.finish(job['id'], 'unknown' if uncertain else 'partial', step='dns_completion_error',
                               result=result, error='dns_completion_check_persisted_state')

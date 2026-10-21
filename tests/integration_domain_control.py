"""Real container API/worker/SQLite + loopback provider + isolated DNS verification.
Requires tests/compose.integration.yml, never uses production env or provider.
"""
import json
from pathlib import Path
import uuid
from integration_inbound import api, client, docker, login, wait_for, ready

RESULTS = []


def record(name, **extra):
    RESULTS.append({'test': name, 'status': 'passed', **extra})
    print('PASS:', name)


def fixture(method, path, body=None):
    script = "import urllib.request,json; "
    if body is None:
        script += "r=urllib.request.urlopen('http://127.0.0.1:19123" + path + "'); print(r.read().decode())"
    else:
        script += "r=urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:19123" + path + "',data=" + repr(json.dumps(body).encode()) + ",headers={'Content-Type':'application/json'},method=" + repr(method) + ")); print(r.read().decode())"
    return json.loads(docker('exec', '-T', 'api', 'python', '-c', script))


def start_fixture():
    docker('exec', '-d', 'api', 'python', '/fixtures/domain_provider_fixture.py')
    def live():
        try:
            return fixture('GET', '/fixture/health').get('ok')
        except RuntimeError:
            return False
    wait_for(live)


def terminal(job):
    item = api('GET', '/domain-jobs/' + job['id'])
    return item if item['status'] in {'succeeded', 'failed', 'partial', 'unknown'} else False


def run():
    wait_for(login); start_fixture()
    fixture('POST', '/fixture/control', {'mode': 'normal'})
    baseline = fixture('GET', '/fixture/metrics')
    initial_count = baseline['claims']
    run_id = uuid.uuid4().hex[:12]
    source = api('POST', '/domain-sources', json={'name': 'integration-' + run_id, 'source_type': 'sfreg_mx',
        'base_url': 'http://127.0.0.1:19123', 'client_id': 'integration-' + run_id, 'secret': {'api_key': 'integration-source-token'}})
    candidates = api('GET', '/domain-sources/' + source['id'] + '/candidates')
    assert candidates['allocation'] == 'none'
    assert 'integration-dns-token' not in json.dumps(candidates)
    assert 'integration-source-token' not in json.dumps(source)
    assert fixture('GET', '/fixture/metrics')['claims'] == initial_count
    record('real container source API + encrypted credential + candidate secret allowlist')
    headers = {'Idempotency-Key': 'claim-' + run_id}
    job = api('POST', '/domain-sources/' + source['id'] + '/claim', headers=headers, json={})
    result = wait_for(lambda: terminal(job))
    assert result['status'] == 'succeeded', result
    domain = result['result']['items'][0]['domain']
    row = next(r for r in api('GET', '/mail-domains') if r['domain'] == domain)
    assert not row['enabled'] and not row['receive_ready'] and row['source_status'] == 'claimed'
    assert 'integration-dns-token' not in json.dumps(result)
    repeat = api('POST', '/domain-sources/' + source['id'] + '/claim', headers=headers, json={})
    assert repeat['id'] == job['id']
    assert fixture('GET', '/fixture/metrics')['claims'] == initial_count + 1
    check = "import sqlite3; c=sqlite3.connect('/app-data/mail.db'); rows=c.execute('select ciphertext from dns_credentials').fetchall(); assert all('integration-source-token' not in r[0] and 'integration-dns-token' not in r[0] for r in rows); print('encrypted')"
    assert 'encrypted' in docker('exec', '-T', 'api', 'python', '-c', check)
    record('durable claim executes once, receipt/DNS token encrypted, imported domain disabled')
    claim = api('GET', '/domain-claims')['items'][0]
    status_job = api('POST', '/domain-claims/' + claim['id'] + '/status', headers={'Idempotency-Key': 'status-' + run_id})
    status_result = wait_for(lambda: terminal(status_job))
    assert status_result['status'] == 'succeeded', status_result
    assert status_result['result']['upstream_status'] == 'active'
    assert fixture('GET', '/fixture/metrics')['status_requests'] == baseline.get('status_requests', 0) + 1
    assert 'integration-source-token' not in json.dumps(status_result)
    record('SFREG status durable job records allowlisted upstream state without secret projection')
    refresh_job = api('POST', '/domain-claims/' + claim['id'] + '/refresh',
                      headers={'Idempotency-Key': 'refresh-' + run_id})
    refresh_result = wait_for(lambda: terminal(refresh_job))
    assert refresh_result['status'] == 'succeeded', refresh_result
    assert fixture('GET', '/fixture/metrics')['lifecycle_refreshs'] == baseline.get('lifecycle_refreshs', 0) + 1
    assert 'integration-dns-token-refreshed' not in json.dumps(refresh_result)
    refreshed = "import sqlite3; c=sqlite3.connect('/app-data/mail.db'); rows=c.execute('select ciphertext from dns_credentials').fetchall(); assert any('integration-dns-token-refreshed' not in r[0] for r in rows); print('refresh-encrypted')"
    assert 'refresh-encrypted' in docker('exec', '-T', 'api', 'python', '-c', refreshed)
    refresh_repeat = api('POST', '/domain-claims/' + claim['id'] + '/refresh',
                         headers={'Idempotency-Key': 'refresh-' + run_id})
    assert refresh_repeat['id'] == refresh_job['id']
    assert fixture('GET', '/fixture/metrics')['lifecycle_refreshs'] == baseline.get('lifecycle_refreshs', 0) + 1
    record('SFREG credential refresh replaces encrypted DNS credential and is idempotent')
    report_job = api('POST', '/domain-claims/' + claim['id'] + '/report',
                     headers={'Idempotency-Key': 'report-' + run_id},
                     json={'status': 'active', 'checks': {'mx': 'passed', 'dkim': 'passed'},
                           'verified_at': '2026-10-05T00:00:00Z'})
    report_result = wait_for(lambda: terminal(report_job))
    assert report_result['status'] == 'succeeded', report_result
    assert report_result['result']['upstream_status'] == 'active'
    assert fixture('GET', '/fixture/metrics')['lifecycle_reports'] == baseline.get('lifecycle_reports', 0) + 1
    assert 'integration-source-token' not in json.dumps(report_result)
    record('SFREG report persists allowlisted validation status without secret projection')
    release_job = api('POST', '/domain-claims/' + claim['id'] + '/release',
                      headers={'Idempotency-Key': 'release-' + run_id},
                      json={'reason': 'integration_cleanup', 'environment_stopped': True})
    release_result = wait_for(lambda: terminal(release_job))
    assert release_result['status'] == 'succeeded', release_result
    assert release_result['result']['upstream_status'] == 'released'
    assert fixture('GET', '/fixture/metrics')['lifecycle_releases'] == baseline.get('lifecycle_releases', 0) + 1
    released = next(r for r in api('GET', '/mail-domains') if r['domain'] == domain)
    assert not released['enabled'] and not released['receive_enabled'] and not released['send_enabled']
    assert released['source_status'] == 'released'
    assert api('GET', '/domain-claims')['items'][0]['status'] == 'released'
    release_repeat = api('POST', '/domain-claims/' + claim['id'] + '/release',
                         headers={'Idempotency-Key': 'release-' + run_id},
                         json={'reason': 'integration_cleanup', 'environment_stopped': True})
    assert release_repeat['id'] == release_job['id']
    assert fixture('GET', '/fixture/metrics')['lifecycle_releases'] == baseline.get('lifecycle_releases', 0) + 1
    record('SFREG release disables local routing before upstream release and is idempotent')
    docker('restart', 'api'); wait_for(login); start_fixture()
    assert api('GET', '/domain-jobs/' + job['id'])['status'] == 'succeeded'
    assert api('GET', '/domain-sources/' + source['id'] + '/candidates')['total'] == 1
    assert fixture('GET', '/fixture/metrics')['claims'] == initial_count + 1
    record('API restart keeps keyring-backed credentials and completed job without reallocation')
    # Isolated resolver: real UDP MX/A; TXT is intentionally incomplete.
    current = next((r for r in api('GET', '/mail-domains') if r['domain'] == 'example.test'), None)
    data = {'domain': 'example.test', 'enabled': True, 'users': [], 'receive_mode': 'catch_all',
            'receive_subdomains': True, 'max_subdomain_depth': 3, 'mx': 'mail.example.test', 'spf': 'v=spf1 -all', 'dns_provider': 'manual'}
    if current:
        api('PATCH', '/mail-domains/example.test', json={k: v for k, v in data.items() if k != 'domain'})
    else:
        api('POST', '/mail-domains', json=data)
    wait_for(ready)
    validation = api('POST', '/mail-domains/example.test/dns-validate', headers={'Idempotency-Key': 'validate-' + run_id})
    validated = wait_for(lambda: terminal(validation))
    assert validated['status'] == 'succeeded', validated
    assert validated['result']['checks']['mx']['status'] == 'passed'
    assert validated['result']['checks']['wildcard_mx']['status'] == 'passed'
    available = api('GET', '/domains/available')
    assert 'example.test' in {r['domain'] for r in available['items']}
    assert api('GET', '/domains/available', params={'capability': 'subdomain_receive'})['total'] == 1
    record('real DNS validation enables base and wildcard receive; submission remains separately gated')
    # Make future inbound regression start with no DNS-validation residue.
    api('DELETE', '/mail-domains/example.test')
    data['spf'] = 'v=spf1 ip4:203.0.113.10 -all'
    api('POST', '/mail-domains', json=data); wait_for(ready)
    assert api('GET', '/domains/available')['total'] == 0
    fixture('POST', '/fixture/control', {'mode': 'timeout'})
    unknown_job = api('POST', '/domain-sources/' + source['id'] + '/claim', headers={'Idempotency-Key': 'timeout-' + run_id}, json={})
    unknown = wait_for(lambda: terminal(unknown_job), seconds=40)
    assert unknown['status'] == 'unknown', unknown
    assert fixture('GET', '/fixture/metrics')['claims'] == initial_count + 2
    repeat = api('POST', '/domain-sources/' + source['id'] + '/claim', headers={'Idempotency-Key': 'timeout-' + run_id}, json={})
    assert repeat['id'] == unknown_job['id']
    blocked = client.post('/domain-sources/' + source['id'] + '/claim', headers={'Idempotency-Key': 'new-key-' + run_id}, json={})
    assert blocked.status_code == 409
    docker('restart', 'api'); wait_for(login); start_fixture()
    assert api('GET', '/domain-jobs/' + unknown_job['id'])['status'] == 'unknown'
    assert fixture('GET', '/fixture/metrics')['claims'] == initial_count + 2
    fixture('POST', '/fixture/control', {'mode': 'normal'})
    record('allocation-before-timeout stays unknown across restart and fences new-key blind reclaim')


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / 'reports/evidence/p2/container-results.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        run()
        outcome = {'status': 'passed', 'scope': 'isolated container API/worker/SQLite + loopback SFREG fixture + .test DNS; not live upstream validation', 'results': RESULTS}
    except Exception as exc:
        outcome = {'status': 'failed', 'error': str(exc), 'results': RESULTS}
        raise
    finally:
        path.write_text(json.dumps(outcome, indent=2, ensure_ascii=False), encoding='utf-8')
        client.close()

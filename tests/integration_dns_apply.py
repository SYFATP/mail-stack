"""Real isolated workers, OpenDKIM and loopback HTTP DNS writes; not live providers."""
import hashlib
import json
from pathlib import Path
import uuid
from integration_inbound import api, client, docker, login, wait_for, ready, rejected
from integration_domain_control import fixture, start_fixture, terminal

RESULTS = []


def record(name, **extra):
    RESULTS.append({'test': name, 'status': 'passed', **extra})
    print('PASS:', name)


def apply(domain, preview, key):
    job = api('POST', '/mail-domains/' + domain + '/dns-apply',
              headers={'Idempotency-Key': key}, json={'plan_id': preview['id']})
    return job, wait_for(lambda: terminal(job), seconds=45)


def key_digest(domain):
    script = "import hashlib; print(hashlib.sha256(open('/dkim/keys/" + domain + "/default.private','rb').read()).hexdigest())"
    return docker('exec', '-T', 'api', 'python', '-c', script).strip()


def run():
    wait_for(login); start_fixture()
    fixture('POST', '/fixture/dns-control', {'mode': 'normal'})
    run_id = uuid.uuid4().hex[:12]
    domain = 'dns-' + run_id + '.test'
    path = '/mail-domains/' + domain
    api('POST', '/mail-domains', json={'domain': domain, 'enabled': False, 'receive_mode': 'catch_all',
        'receive_subdomains': False, 'users': [], 'mx': 'mail.example.test',
        'spf': 'v=spf1 ip4:203.0.113.10 -all', 'dmarc': 'v=DMARC1; p=none'})
    wait_for(ready)
    plan = wait_for(lambda: (p if 'dkim_public_key_pending' not in (p := api('GET', path + '/dns-plan'))['warnings'] else False))
    dkim = next(r for r in plan['records'] if r['role'] == 'dkim')['content']
    script = "import base64; from cryptography.hazmat.primitives.serialization import load_der_public_key; p=" + repr(dkim.split('p=')[1].split(';')[0]) + "; assert load_der_public_key(base64.b64decode(p)).key_size == 2048; print('2048')"
    assert '2048' in docker('exec', '-T', 'api', 'python', '-c', script)
    original_key = key_digest(domain)
    record('disabled domain prepares real 2048-bit DKIM but rejects SMTP RCPT', smtp_code=rejected('user@' + domain))
    credential = api('POST', '/dns-credentials', json={'provider': 'cloudflare', 'domain': None,
        'label': 'fixture-' + run_id, 'secret': {'api_token': 'fixture-only-token'}})
    api('POST', path + '/dns-binding', json={'credential_ref': credential['id']})
    preview = api('POST', path + '/dns-preview')
    assert preview['executable'] and len(preview['actions']) == 4
    start_posts = fixture('GET', '/fixture/metrics').get('dns_posts', 0)
    job, result = apply(domain, preview, 'create-' + run_id)
    assert result['status'] == 'succeeded', result
    assert not result['result']['receive_ready'] and not result['result']['send_ready']
    script = "import sqlite3; c=sqlite3.connect('/app-data/mail.db'); d=" + repr(domain) + "; assert c.execute('select count(*) from managed_dns_records where domain=?',(d,)).fetchone()[0]==4; assert c.execute(\"select count(*) from domain_dns_operations where domain=? and status='confirmed'\",(d,)).fetchone()[0]==4; assert c.execute('select count(*) from domain_checks where domain=?',(d,)).fetchone()[0]==0; print('journal-confirmed')"
    assert 'journal-confirmed' in docker('exec', '-T', 'api', 'python', '-c', script)
    record('preview/apply executes real worker + HTTP writes and atomic ownership journal; not ready')
    repeat = api('POST', path + '/dns-apply', headers={'Idempotency-Key': 'create-' + run_id}, json={'plan_id': preview['id']})
    assert repeat['id'] == job['id']
    assert fixture('GET', '/fixture/metrics')['dns_posts'] == start_posts + 4
    record('same Idempotency-Key returns persisted job without duplicate DNS POST')
    zone = preview['zone_id']
    foreign = fixture('POST', '/cloudflare/client/v4/zones/' + zone + '/dns_records',
        {'type': 'TXT', 'name': domain, 'content': 'fixture-verification=unchanged', 'ttl': 900})['result']
    initial_patches = fixture('GET', '/fixture/metrics').get('dns_patches', 0)
    api('PATCH', path, json={'spf': 'v=spf1 ip4:203.0.113.20 -all'})
    preview = api('POST', path + '/dns-preview')
    assert preview['executable'] and [a['action'] for a in preview['actions']].count('update') == 1
    _, result = apply(domain, preview, 'update-' + run_id)
    assert result['status'] == 'succeeded', result
    rows = fixture('GET', '/fixture/metrics')['records'][zone]
    assert next(r for r in rows if r['id'] == foreign['id']) == foreign
    assert fixture('GET', '/fixture/metrics')['dns_patches'] == initial_patches + 1
    record('owned SPF changes via PATCH; unrelated verification TXT remains byte-for-byte unchanged')
    # Timeout on an owned update; provider commits before client loses its ACK.
    api('PATCH', path, json={'spf': 'v=spf1 ip4:203.0.113.30 -all'})
    preview = api('POST', path + '/dns-preview')
    fixture('POST', '/fixture/dns-control', {'mode': 'timeout'})
    job, result = apply(domain, preview, 'timeout-' + run_id)
    assert result['status'] == 'unknown', result
    posts_before_recovery = fixture('GET', '/fixture/metrics')['dns_posts']
    patches_before_recovery = fixture('GET', '/fixture/metrics')['dns_patches']
    docker('restart', 'api'); wait_for(login); start_fixture()
    assert api('GET', '/domain-jobs/' + job['id'])['status'] == 'unknown'
    record('HTTP timeout after remote commit stays unknown across API restart')
    fresh = api('POST', path + '/dns-preview')
    assert fresh['executable'] and sum(a['action'] == 'recover' for a in fresh['actions']) == 1
    _, result = apply(domain, fresh, 'recover-' + run_id)
    assert result['status'] == 'succeeded', result
    metrics = fixture('GET', '/fixture/metrics')
    assert metrics['dns_posts'] == posts_before_recovery and metrics['dns_patches'] == patches_before_recovery
    record('persisted marker + exact target recover ownership without replaying POST or PATCH')
    docker('exec', '-T', 'opendkim', 'rm', '-f', '/etc/opendkim/keys/' + domain + '/default.txt')
    docker('up', '-d', '--no-deps', '--force-recreate', '--pull', 'never', 'opendkim')
    regenerated = wait_for(lambda: (p if 'dkim_public_key_pending' not in (p := api('GET', path + '/dns-plan'))['warnings'] else False))
    assert key_digest(domain) == original_key
    assert next(r for r in regenerated['records'] if r['role'] == 'dkim')['content'] == dkim
    record('OpenDKIM force-recreate retains private-key hash and reconstructs missing public TXT')
    response = client.post(path + '/dns/provision')
    assert response.status_code == 409, response.text
    assert not next(r for r in api('GET', '/mail-domains') if r['domain'] == domain)['enabled']
    assert domain not in {r['domain'] for r in api('GET', '/domains/available')['items']}
    record('legacy provision cannot bypass bound-domain ownership; disabled domain never available')


if __name__ == '__main__':
    output = Path(__file__).resolve().parents[1] / 'reports/evidence/p2/dns-apply-results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    outcome = {'status': 'failed', 'results': RESULTS}
    try:
        run()
        outcome = {'status': 'passed', 'scope': 'isolated containers + loopback Cloudflare-shaped fixture; not live Cloudflare/DigitalPlat acceptance', 'results': RESULTS}
    except Exception as exc:
        outcome['error'] = str(exc)
        raise
    finally:
        output.write_text(json.dumps(outcome, ensure_ascii=False, indent=2), encoding='utf-8')
        client.close()

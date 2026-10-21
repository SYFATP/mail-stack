"""Loopback-only SFREG fixture inside the isolated API container.

No external DNS/provider calls. Public fixture tokens, never production secrets.
Counters survive API recreation solely for timeout/idempotency assertions.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import hashlib
from urllib.parse import urlsplit, parse_qs
from pathlib import Path
import threading
import time

STATE = Path('/app-data/domain-provider-fixture.json')
LOCK = threading.Lock()


def state():
    return json.loads(STATE.read_text()) if STATE.exists() else {
        'claims': 0, 'mode': 'normal', 'lifecycle_mode': 'normal', 'keys': [],
        'lifecycle_keys': {}, 'received_webhooks': [],
    }


def write(value):
    temporary = STATE.with_suffix('.tmp')
    temporary.write_text(json.dumps(value))
    temporary.replace(STATE)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, value, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        try:
            self.wfile.write(json.dumps(value).encode())
        except (BrokenPipeError, ConnectionResetError):
            pass

    def cloudflare(self, method, body=None):
        parsed = urlsplit(self.path)
        path = parsed.path.removeprefix('/cloudflare/client/v4')
        if path == '/zones' and method == 'GET':
            domain = parse_qs(parsed.query).get('name', [''])[0]
            if not domain.endswith('.test'):
                return self.respond({'success': True, 'result': []})
            zone_id = 'fixture_' + hashlib.sha256(domain.encode()).hexdigest()[:16]
            return self.respond({'success': True, 'result': [{'id': zone_id, 'name': domain, 'status': 'active'}]})
        parts = path.strip('/').split('/')
        if len(parts) < 3 or parts[0] != 'zones' or parts[2] != 'dns_records':
            return self.respond({'success': False}, 404)
        zone_id = parts[1]
        with LOCK:
            current = state()
            rows = current.setdefault('records', {}).setdefault(zone_id, [])
            if method == 'GET':
                return self.respond({'success': True, 'result': rows, 'result_info': {'total_pages': 1}})
            if method == 'POST':
                current['dns_posts'] = current.get('dns_posts', 0) + 1
                current['dns_sequence'] = current.get('dns_sequence', 0) + 1
                row = {'id': 'dns_' + str(current['dns_sequence']), **body}
                rows.append(row)
            elif method == 'PATCH':
                row = next((r for r in rows if r['id'] == parts[-1]), None)
                if not row:
                    return self.respond({'success': False}, 404)
                row.update(body)
                current['dns_patches'] = current.get('dns_patches', 0) + 1
            else:
                return self.respond({'success': False}, 405)
            mode = current.get('dns_mode', 'normal')
            current['dns_mode'] = 'normal'
            write(current)
        if mode == 'timeout':
            time.sleep(23)
        return self.respond({'success': True, 'result': row})

    def do_GET(self):
        if self.path.startswith('/cloudflare/client/v4/'):
            return self.cloudflare('GET')
        if self.path == '/fixture/health':
            return self.respond({'ok': True})
        if self.path == '/fixture/metrics':
            with LOCK:
                current = state()
            return self.respond(current)
        if self.path.startswith('/api/digitalplat-dns/domains/available'):
            return self.respond({'domains': [{'domain': 'candidate.test', 'status': 'available', 'dns': {'api_token': 'integration-dns-token'}, 'secret_alias': 'integration-dns-token'}]})
        status_prefix = '/api/digitalplat-dns/domains/'
        if self.path.startswith(status_prefix) and self.path.endswith('/status'):
            claim_id = self.path[len(status_prefix):-len('/status')]
            if self.headers.get('X-Domain-API-Key') != 'integration-source-token' or self.headers.get('X-SFREG-Client-ID', '').startswith('integration-') is False:
                return self.respond({'ok': False}, 401)
            with LOCK:
                current = state(); current['status_requests'] = current.get('status_requests', 0) + 1; write(current)
            return self.respond({'claim_id': claim_id, 'status': 'active'})
        self.respond({'ok': False}, 404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        if self.path.startswith('/cloudflare/client/v4/'):
            return self.cloudflare('POST', body)
        if self.path == '/fixture/dns-control':
            with LOCK:
                current = state(); current['dns_mode'] = body['mode']; write(current)
            return self.respond({'ok': True})
        if self.path == '/fixture/control':
            with LOCK:
                current = state(); current['mode'] = body['mode']; write(current)
            return self.respond({'ok': True})
        if self.path == '/fixture/reset':
            with LOCK:
                write({'claims': 0, 'mode': 'normal', 'lifecycle_mode': 'normal',
                       'keys': [], 'lifecycle_keys': {}, 'received_webhooks': []})
            return self.respond({'ok': True})
        if self.path == '/fixture/webhook':
            with LOCK:
                current = state()
                current.setdefault('received_webhooks', []).append({
                    'body': body,
                    'signature': self.headers.get('X-Webhook-Signature', ''),
                    'event_id': body.get('event_id', ''),
                })
                write(current)
            return self.respond({'ok': True}, 204)
        if self.path == '/fixture/lifecycle-control':
            with LOCK:
                current = state(); current['lifecycle_mode'] = body['mode']; write(current)
            return self.respond({'ok': True})
        lifecycle_prefix = '/api/digitalplat-dns/domains/'
        if self.path.startswith(lifecycle_prefix):
            suffix = self.path[len(lifecycle_prefix):]
            parts = suffix.split('/')
            if len(parts) == 3 and parts[1] == 'credentials' and parts[2] == 'refresh':
                return self.lifecycle(body, 'refresh', parts[0])
            if len(parts) == 2 and parts[1] == 'release':
                return self.lifecycle(body, 'release', parts[0])
        if self.path != '/api/digitalplat-dns/domains/claim':
            return self.respond({'ok': False}, 404)
        if self.headers.get('X-Domain-API-Key') != 'integration-source-token':
            return self.respond({'ok': False}, 401)
        key = self.headers.get('Idempotency-Key')
        if key != body.get('idempotency_key') or self.headers.get('X-SFREG-Client-ID') != body.get('client_id'):
            return self.respond({'ok': False}, 422)
        with LOCK:
            current = state()
            if key in current['keys']:
                index = current['keys'].index(key) + 1
            else:
                current['claims'] += 1; current['keys'].append(key); index = current['claims']; write(current)
            mode = current['mode']
        if mode == 'timeout':
            # Commit allocation before client timeout. Do not replay this request.
            time.sleep(23)
        self.respond({'domains': [{'domain': 'allocated' + str(index) + '.test', 'claim_id': 'fixture-' + str(index),
            'status': 'active', 'dns': {'api_token': 'integration-dns-token', 'api_base': 'https://dns.fixture.test/api/v1'}}]})

    def do_PATCH(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        prefix = '/api/digitalplat-dns/domains/'
        if self.path.startswith(prefix) and self.path.endswith('/status'):
            claim_id = self.path[len(prefix):-len('/status')]
            return self.lifecycle(body, 'report', claim_id)
        return self.cloudflare('PATCH', body)

    def lifecycle(self, body, operation, claim_id):
        if self.headers.get('X-Domain-API-Key') != 'integration-source-token' or not self.headers.get('X-SFREG-Client-ID', '').startswith('integration-'):
            return self.respond({'ok': False}, 401)
        key = self.headers.get('Idempotency-Key')
        if not key:
            return self.respond({'ok': False}, 422)
        with LOCK:
            current = state()
            lifecycle_keys = current.setdefault('lifecycle_keys', {})
            identity = operation + ':' + claim_id + ':' + key
            if identity in lifecycle_keys:
                response = lifecycle_keys[identity]
            else:
                current['lifecycle_' + operation + 's'] = current.get('lifecycle_' + operation + 's', 0) + 1
                if operation == 'refresh':
                    response = {'claim_id': claim_id, 'status': 'active',
                                'api_token': 'integration-dns-token-refreshed',
                                'api_base': 'https://dns.fixture.test/api/v1'}
                elif operation == 'release':
                    response = {'claim_id': claim_id, 'status': 'released'}
                else:
                    response = {'claim_id': claim_id, 'status': str(body.get('status') or 'active')}
                lifecycle_keys[identity] = response
                write(current)
        if current.get('lifecycle_mode') == 'timeout':
            time.sleep(23)
        return self.respond(response)


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 19123), Handler).serve_forever()

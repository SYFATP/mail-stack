"""Isolated deterministic fixture: no provider network, production DB or mail writes."""
import inspect
import json
import time
from unittest.mock import patch
import test_domain_control as fixture
from api.services import routing

case = fixture.P2Tests('test_batch_sfreg_count_forwarded_and_each_domain_recorded')
case.setUp()
app = fixture.app
try:
    manager = case.manager
    if 'publish_runtime' in inspect.signature(app._save_domain).parameters:
        manager.bulk_save_domain = lambda data, domain: app._save_domain(
            data, domain, publish_runtime=False, return_public=False)
        manager.publish_domains = app._write_runtime_files
    source = case.source()
    case.http.payload = case.batch_payload(200)
    job = manager.create_claim_job(source['id'], 'benchmark-200-claim', count=200,
                                   status='registered', sync_provider='none')
    with patch.object(manager, 'brevo_sync_enabled', return_value=True), \
         patch.object(manager, 'ensure_brevo_domain', return_value={'created': True}) as brevo, \
         patch.object(app, 'publish', wraps=app.publish) as publish:
        start = time.perf_counter()
        manager.run_once()
        claim_seconds = time.perf_counter() - start
        publications = publish.call_count
        inline_brevo_calls = brevo.call_count
    parent = manager.jobs.get(job['id'])
    assert parent['status'] == 'succeeded'
    assert parent['result']['recorded_count'] == 200
    assert len(manager.claims()) == 200
    assert len(case.http.calls) == 1
    generation = (app.RUNTIME_DIR / 'routing.current').read_text().strip()
    (app.RUNTIME_DIR / 'postfix-applied.json').write_text(json.dumps({
        'generation': generation, 'status': 'applied', 'applied_at': time.time()}))
    app._save_domain({'domain': 'unrelated.test', 'enabled': False, 'users': []})
    with patch.object(app, 'key_ok', return_value=True), \
         patch.object(app, 'db', wraps=app.db) as connections, \
         patch.object(routing, '_generation_domains', wraps=routing._generation_domains) as reads:
        start = time.perf_counter()
        domains = app.list_mail_domains(False, 'fixture')
        list_seconds = time.perf_counter() - start
    assert len(domains) == 201
    print(json.dumps({
        'fixture_domains': 200, 'claim_import_seconds': round(claim_seconds, 4),
        'routing_publications': publications, 'inline_brevo_calls': inline_brevo_calls,
        'upstream_allocations': len(case.http.calls), 'list_domains': len(domains),
        'list_seconds': round(list_seconds, 4), 'list_db_connections': connections.call_count,
        'list_manifest_reads': reads.call_count, 'provider_network_calls': 0,
        'production_database_access': False}))
finally:
    case.tearDown()

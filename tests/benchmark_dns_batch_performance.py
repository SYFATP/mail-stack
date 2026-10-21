"""Compare fixture-only DNS previews and validation; no upstream network or writes."""
import argparse
import collections
import importlib.util
import json
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import test_dns_reconcile as fixture
import test_domain_control as base
from api.services.dns_reconcile import DNSReconciler
from api.services.dns_plan import DNSValidator


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def measure(reconciler_class, validator_class, concurrency):
    case = fixture.DNSWriteTests(methodName='runTest')
    case.setUp()
    try:
        manager = case.m
        manager.dns = reconciler_class(manager)
        capture = manager.dns.capture
        def delayed(domain):
            time.sleep(0.03)  # One fixed inventory latency per preview.
            return capture(domain)
        start = time.perf_counter()
        with patch.object(manager.dns, 'capture', side_effect=delayed):
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                plans = list(pool.map(manager.dns.preview, ['example.test'] * 200))
        preview_seconds = time.perf_counter() - start
        assert len(plans) == 200 and all(plan['executable'] for plan in plans)
        assert not case.writes()
        case.edit(receive_subdomains=True, max_subdomain_depth=3)
        class Resolver(base.FakeResolver):
            def __init__(self):
                self.calls = collections.Counter()
            def resolve(self, name, kind, **kwargs):
                self.calls[(name, kind)] += 1
                time.sleep(0.01)
                return super().resolve(name, kind, **kwargs)
        resolver = Resolver()
        validator = validator_class(resolver)
        row = manager.domain('example.test')
        start = time.perf_counter()
        for _ in range(20):
            result = validator.validate(row, manager.key_root)
            assert all(check['status'] == 'passed' for check in result['checks'].values())
        validation_seconds = time.perf_counter() - start
        return {'preview_operations': 200, 'preview_concurrency': concurrency,
                'preview_seconds': round(preview_seconds, 4), 'validation_runs': 20,
                'validation_seconds': round(validation_seconds, 4),
                'queries_per_validation': sum(resolver.calls.values()) // 20,
                'dns_writes': len(case.writes()), 'provider_network_calls': 0,
                'production_database_access': False}
    finally:
        case.tearDown()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline-root', type=Path, required=True)
    args = parser.parse_args()
    old_reconcile = load(args.baseline_root / 'api/services/dns_reconcile.py', 'baseline_dns_reconcile')
    old_plan = load(args.baseline_root / 'api/services/dns_plan.py', 'baseline_dns_plan')
    print(json.dumps({'baseline': measure(old_reconcile.DNSReconciler, old_plan.DNSValidator, 1),
                      'candidate': measure(DNSReconciler, DNSValidator, 3)}))

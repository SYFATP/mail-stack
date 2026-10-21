import copy
import unittest

from api.providers.dns.digitalplat import (
    DIGITALPLAT_DNS_UPSTREAM_UNAVAILABLE,
    DIGITALPLAT_DNS_ZONE_UNAVAILABLE,
    DigitalPlatDNS,
)
from api.services.dns_inventory import canonical, inventory_hash
from api.providers.http import ProviderError


class DigitalPlatInventoryTests(unittest.TestCase):
    def test_apex_ns_fence_preserves_all_changes_except_digitalplat_ids(self):
        records = [
            canonical({'id': str(i), 'type': 'NS', 'name': '@',
                       'value': f'ns{i}.example.test.', 'ttl': 86400},
                      'example.test', 'digitalplat')[0]
            for i in (1, 2)
        ]
        expected = inventory_hash(records, 'digitalplat', 'example.test')
        rotated = copy.deepcopy(records)[::-1]
        for i, record in enumerate(rotated):
            record['id'] = 'regenerated-' + str(i)
        self.assertEqual(inventory_hash(rotated, 'digitalplat', 'example.test'), expected)
        for field, value in [('content', 'ns.other.test.'), ('ttl', 300),
                             ('locked', True), ('settings', {'disabled': True})]:
            with self.subTest(field=field):
                changed = copy.deepcopy(rotated)
                changed[0][field] = value
                self.assertNotEqual(inventory_hash(changed, 'digitalplat', 'example.test'), expected)
        self.assertNotEqual(inventory_hash(rotated[:1], 'digitalplat', 'example.test'), expected)
        self.assertNotEqual(inventory_hash(rotated + [rotated[0]], 'digitalplat', 'example.test'), expected)
        for provider, zone in [('cloudflare', 'example.test'), ('digitalplat', 'test')]:
            with self.subTest(provider=provider, zone=zone):
                self.assertNotEqual(inventory_hash(rotated, provider, zone),
                                    inventory_hash(records, provider, zone))

    def test_hosted_status_normalizes_nameservers(self):
        class HostedTransport:
            def request(self, method, base, path, **kwargs):
                self.call = (method, path, kwargs)
                return {"data": {"mode": "hosted", "status": "active",
                                 "nameservers": ["NS1.DIGITALPLAT.ORG.", "ns2.digitalplat.org"]}}

        transport = HostedTransport()
        adapter = DigitalPlatDNS(
            transport,
            {"api_base": "https://dns.fixture.test", "api_token": "fixture-token"},
            "example.test",
        )
        self.assertEqual(adapter.hosted_status(), {
            "mode": "hosted",
            "status": "active",
            "nameservers": ["ns1.digitalplat.org", "ns2.digitalplat.org"],
            "operation_id": "",
        })
        self.assertEqual(transport.call[0:2], ("GET", "/domains/example.test/dns"))

    def test_hosted_502_has_retryable_domain_error(self):
        class BrokenTransport:
            def request(self, method, base, path, **kwargs):
                raise ProviderError("provider_http_502", uncertain=True)

        adapter = DigitalPlatDNS(
            BrokenTransport(),
            {"api_base": "https://dns.fixture.test", "api_token": "fixture-token"},
            "example.test",
        )
        with self.assertRaises(ProviderError) as raised:
            adapter.hosted_status()
        self.assertEqual(raised.exception.code, DIGITALPLAT_DNS_UPSTREAM_UNAVAILABLE)
        self.assertTrue(raised.exception.uncertain)

    def test_missing_dns_zone_is_reported_as_a_recoverable_state(self):
        class MissingZoneTransport:
            def request(self, method, base, path, **kwargs):
                raise ProviderError("provider_http_404")

        adapter = DigitalPlatDNS(
            MissingZoneTransport(),
            {"api_base": "https://dns.fixture.test", "api_token": "fixture-token"},
            "example.test",
        )
        with self.assertRaises(ProviderError) as raised:
            adapter.inventory("example.test")
        self.assertEqual(raised.exception.code, DIGITALPLAT_DNS_ZONE_UNAVAILABLE)

    def test_singular_value_field_is_accepted_for_mx_records(self):
        rows = canonical(
            {
                "id": "record-1",
                "name": "@",
                "type": "MX",
                "value": "10 mx.example.test.",
                "ttl": 300,
            },
            "example.test",
            "digitalplat",
        )
        self.assertEqual(rows[0]["name"], "example.test")
        self.assertEqual(rows[0]["content"], "mx.example.test")
        self.assertEqual(rows[0]["priority"], 10)


class DigitalPlatRecordEndpointTests(unittest.TestCase):
    """Real API shape: one concrete record ID per TXT value in an RRset."""
    def setUp(self):
        self.rows = [
            {'id': 'spf-member', 'rrset_id': 'apex-rrset', 'type': 'TXT', 'name': '@', 'value': '"v=spf1 -all"', 'ttl': 300},
            {'id': 'verification-member', 'rrset_id': 'apex-rrset', 'type': 'TXT', 'name': '@', 'value': '"foreign-verification"', 'ttl': 300},
            {'id': 'dmarc-member', 'rrset_id': 'dmarc-rrset', 'type': 'TXT', 'name': '_dmarc', 'value': '"v=DMARC1; p=none"', 'ttl': 300},
        ]
        self.calls = []
        case = self
        class Transport:
            def request(self, method, base, path, **kwargs):
                case.calls.append((method, path, copy.deepcopy(kwargs)))
                if method == 'GET': return {'data': copy.deepcopy(case.rows)}
                selected = next((r for r in case.rows if r['id'] == path.rsplit('/', 1)[-1]), None)
                if selected is None: raise ProviderError('provider_http_404')
                if method == 'PATCH':
                    selected.update(kwargs['body'])
                    return {'data': copy.deepcopy(selected)}
                if method == 'DELETE':
                    case.rows.remove(selected)
                    return {}
                raise AssertionError(method)
        self.adapter = DigitalPlatDNS(Transport(), {'api_base': 'https://dns.fixture.test', 'api_token': 'fixture-token'}, 'example.test')

    def records(self):
        from api.services.dns_inventory import scoped_inventory
        return scoped_inventory(self.adapter.inventory('example.test'), 'example.test', 'digitalplat')

    def test_member_update_retains_logical_identity_and_foreign_txt(self):
        before = self.records()
        wanted = {'role': 'spf', 'type': 'TXT', 'name': 'example.test', 'content': 'v=spf1 ip4:203.0.113.10 -all', 'ttl': 300}
        result = self.adapter.write('example.test', wanted, 'marker', 'apex-rrset', existing_records=before)
        self.assertEqual(result['id'], 'apex-rrset')
        write = next(c for c in self.calls if c[0] == 'PATCH')
        self.assertTrue(write[1].endswith('/spf-member'))
        self.assertNotIn('values', write[2]['body'])
        after = self.records()
        self.assertEqual({r['id'] for r in after if r['name'] == 'example.test'}, {'apex-rrset'})
        self.assertEqual({r['content'] for r in after if r['name'] == 'example.test'}, {'foreign-verification', wanted['content']})
        self.assertEqual(next(r for r in after if r['id'] == 'dmarc-rrset'), next(r for r in before if r['id'] == 'dmarc-rrset'))

    def test_single_txt_update_and_delete_use_member_id(self):
        wanted = {'role': 'dmarc', 'type': 'TXT', 'name': '_dmarc.example.test', 'content': 'v=DMARC1; p=quarantine', 'ttl': 300}
        self.adapter.write('example.test', wanted, 'marker', 'dmarc-rrset', existing_records=self.records())
        self.assertTrue(next(c for c in self.calls if c[0] == 'PATCH')[1].endswith('/dmarc-member'))
        self.adapter.delete('dmarc-rrset', 'delete-fixture')
        self.assertTrue(next(c for c in self.calls if c[0] == 'DELETE')[1].endswith('/dmarc-member'))
        self.assertEqual(len(self.rows), 2)

    def test_shared_rrset_delete_and_ambiguous_member_never_dispatch(self):
        with self.assertRaises(ProviderError) as exc: self.adapter.delete('apex-rrset', 'delete-fixture')
        self.assertEqual(exc.exception.code, 'digitalplat_txt_rrset_member_ambiguous')
        self.rows.append({**self.rows[0], 'id': 'second-spf-member'})
        wanted = {'role': 'spf', 'type': 'TXT', 'name': 'example.test', 'content': 'v=spf1 ip4:203.0.113.10 -all', 'ttl': 300}
        with self.assertRaises(ProviderError): self.adapter.write('example.test', wanted, 'marker', 'apex-rrset', existing_records=self.records())
        self.assertFalse(any(c[0] in {'PATCH', 'DELETE'} for c in self.calls))

    def test_dkim_patch_keeps_chunks_within_one_member(self):
        self.rows.append({'id': 'dkim-member', 'rrset_id': 'dkim-rrset', 'type': 'TXT', 'name': 'default._domainkey', 'value': '"v=DKIM1; p=old"', 'ttl': 300})
        value = 'v=DKIM1; p=' + 'A' * 500
        wanted = {'role': 'dkim', 'type': 'TXT', 'name': 'default._domainkey.example.test', 'content': value, 'ttl': 300}
        self.adapter.write('example.test', wanted, 'marker', 'dkim-rrset', existing_records=self.records())
        self.assertEqual(next(r['content'] for r in self.records() if r['id'] == 'dkim-rrset'), value)
        self.assertEqual(len([r for r in self.rows if r.get('rrset_id') == 'dkim-rrset']), 1)
        self.assertIn('" "', next(c for c in self.calls if c[0] == 'PATCH')[2]['body']['value'])

"""Canonical scoped DNS inventory. No raw provider content enters public results."""
import hashlib
import json
import re
from api.providers.http import ProviderError


def _txt_join(value):
    value = str(value).strip()
    pieces = re.findall(r'"([^"\r\n]*)"', value)
    return ''.join(pieces) if pieces else value.strip('"')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def identifier(value):
    value = str(value or '')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value) or value in {'.', '..'}:
        raise ProviderError('invalid_provider_record_identifier')
    return value


def name(value, zone):
    value = str(value or '').lower().rstrip('.')
    if value in {'@', ''}:
        value = zone
    elif value != zone and not value.endswith('.' + zone):
        value += '.' + zone
    labels = value.split('.')
    if len(value) > 253 or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?|\*', label) for label in labels):
        raise ProviderError('invalid_provider_record_name')
    if '*' in labels[1:]:
        raise ProviderError('invalid_provider_wildcard_name')
    return value


def canonical(raw, zone, provider):
    kind = str(raw.get('type', '')).upper()
    contents = raw.get('values') if provider == 'digitalplat' else None
    if provider == 'digitalplat' and kind == 'TXT' and isinstance(contents, list):
        # DigitalPlat returns one TXT RRset as several quoted DNS
        # character-strings. They form one logical value for SPF/DKIM/DMARC
        # matching; treating each chunk as a separate record creates a false
        # multiple-semantic-record conflict.
        contents = [_txt_join(content) for content in contents]
    if contents is None:
        # DigitalPlat inventory currently returns a singular `value` field
        # while its write contract uses `values`. Accept both shapes.
        contents = [raw.get('content', raw.get('value', ''))]
    if not isinstance(contents, list) or not contents:
        raise ProviderError('invalid_provider_record_values')
    out = []
    for content in contents:
        value = _txt_join(content) if kind == "TXT" else str(content).strip()
        priority = raw.get('priority')
        if kind in {'MX', 'CNAME'}:
            match = re.fullmatch(r'(\d{1,5})\s+(\S+)', value)
            if kind == 'MX' and match:
                priority, value = int(match[1]), match[2]
            if kind == 'MX' and priority is None:
                raise ProviderError('digitalplat_mx_priority_contract_unverified')
            value = value.lower().rstrip('.')
        if kind == 'TXT':
            value = value.strip('"')
        out.append({'id': identifier(raw.get('id') or raw.get('record_id')), 'type': kind,
                    'name': name(raw.get('name'), zone), 'content': value,
                    'priority': int(priority or 0), 'ttl': int(raw.get('ttl') or 300),
                    'proxied': bool(raw.get('proxied', False)), 'comment': str(raw.get('comment') or ''),
                    'locked': bool(raw.get('locked', False)), 'settings': raw.get('settings') or {},
                    'tags': sorted(raw.get('tags') or [])})
    return out


def scoped_inventory(inventory, domain, provider):
    if not inventory.get('complete'):
        raise ProviderError('dns_inventory_incomplete')
    try:
        records = [r for raw in inventory['records'] for r in canonical(raw, inventory['zone_name'], provider)]
        # Parent-zone delegation/alias nodes govern a managed subdomain too.
        # Include only these relevant ancestors, not unrelated zone TXT values.
        records = [r for r in records if r['name'] == domain or r['name'].endswith('.' + domain) or
                   (r['type'] in {'NS', 'CNAME'} and domain.endswith('.' + r['name']))]
        if len(records) > 10000:
            raise ProviderError('dns_inventory_too_large')
        return sorted(records, key=lambda r: (r['name'], r['type'], r['id'], r['content']))
    except ProviderError:
        raise
    except Exception:
        raise ProviderError('invalid_provider_inventory_response') from None


def fingerprint(record):
    return digest(record)


def inventory_hash(records, provider, zone_name):
    """Fence DNS content while tolerating DigitalPlat's regenerated apex NS IDs.

    The provider rebuilds these two system records during ordinary DNS writes.
    Retain every other field, record multiplicity and all non-apex record IDs.
    """
    if provider != 'digitalplat':
        return digest(records)
    normalized = [
        {**record, 'id': 'digitalplat-apex-ns'}
        if record['type'] == 'NS' and record['name'] == zone_name else record
        for record in records
    ]
    return digest(sorted(normalized, key=lambda record: (
        record['name'], record['type'], record['id'], digest(record))))


def matches(record, wanted):
    return record['type'] == wanted['type'] and record['name'] == wanted['name'] and record['content'] == wanted['content'] and (
        wanted['type'] != 'MX' or record['priority'] == wanted['priority']) and not record['proxied']


def semantic(record, wanted):
    if record['name'] != wanted['name'] or record['type'] != wanted['type']:
        return False
    if wanted['type'] != 'TXT':
        return True
    prefix = {'spf': 'v=spf1', 'dmarc': 'v=dmarc1', 'dkim': 'v=dkim1'}.get(wanted['role'])
    if prefix:
        return record['content'].lower().startswith(prefix)
    return record['content'] == wanted['content']

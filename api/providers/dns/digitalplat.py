"""DigitalPlat per-domain DNS is distinct from the Admin Key domain pool.

The per-domain API exposes the same record contract used by SFREG:
``POST /domains/{domain}/dns/records`` creates a record and
``PATCH /domains/{domain}/dns/records/{id}`` updates its value/TTL.
"""
from urllib.parse import quote
import re
from api.providers.http import ProviderError, validate_base_url


DIGITALPLAT_DNS_ZONE_UNAVAILABLE = "digitalplat_dns_zone_unavailable"
DIGITALPLAT_DNS_UPSTREAM_UNAVAILABLE = "digitalplat_dns_upstream_unavailable"
DIGITALPLAT_DNS_NOT_ENABLED = "digitalplat_dns_not_enabled"


def digitalplat_dns_zone_message(domain):
    return (
        f"DigitalPlat 当前没有返回 {domain} 的可读取 DNS zone；"
        "请稍后重试或检查该域名绑定的 DigitalPlat credential。"
    )

def digitalplat_dns_hosting_message(domain):
    return f"{domain} 尚未启用 DigitalPlat DNS 托管；执行配置预览时会自动准备托管后继续。"


def digitalplat_dns_upstream_message(domain):
    return (
        f"DigitalPlat DNS 上游暂时不可用（{domain}，HTTP 502），"
        "请稍后重试；本次操作未写入本地 DNS。"
    )


def _txt_join(value):
    value = str(value).strip()
    pieces = re.findall(r'"([^"\r\n]*)"', value)
    return ''.join(pieces) if pieces else value.strip('"')


def _txt_chunks(value, size=250):
    """Split a TXT RR value into provider-sized DNS character-strings."""
    return [value[i:i + size] for i in range(0, len(value), size)] or [""]


def _join_txt_rows(rows):
    """Collapse DigitalPlat's multi-row TXT RRset representation."""
    grouped = []
    by_rrset = {}
    for row in rows:
        if str(row.get("type", "")).upper() != "TXT" or not row.get("rrset_id"):
            grouped.append(row)
            continue
        key = (str(row["rrset_id"]), str(row.get("name") or row.get("fqdn") or ""))
        current = by_rrset.get(key)
        chunk = _txt_join(row.get("value", row.get("content", "")))
        if current is None:
            current = dict(row)
            current["id"] = str(row.get("rrset_id"))
            current["values"] = []
            by_rrset[key] = current
            grouped.append(current)
        current["values"].append(chunk)
    return grouped


class DigitalPlatDNS:
    def __init__(self, transport, secret, domain):
        self.http, self.domain = transport, domain
        self.base = validate_base_url(secret["api_base"])
        self.headers = {"Authorization": "Bearer " + secret["api_token"]}

    @staticmethod
    def _status_fields(payload):
        """Extract the safe Hosted DNS state from DigitalPlat envelopes."""
        data = payload.get("data") if isinstance(payload, dict) else payload
        if not isinstance(data, dict):
            data = {}
        zone = data.get("zone") if isinstance(data.get("zone"), dict) else {}
        operation = data.get("operation") if isinstance(data.get("operation"), dict) else {}
        dns = data.get("dns") if isinstance(data.get("dns"), dict) else {}
        mode = str(
            data.get("mode") or data.get("dns_mode")
            or zone.get("mode") or dns.get("mode") or ""
        ).strip().lower()
        status = str(
            data.get("status") or data.get("dns_status")
            or zone.get("status") or dns.get("status")
            or operation.get("status") or ""
        ).strip().lower()
        raw_nameservers = (
            data.get("nameservers") or data.get("name_servers")
            or data.get("authoritative_nameservers")
            or zone.get("nameservers") or dns.get("nameservers")
        )
        if isinstance(raw_nameservers, str):
            raw_nameservers = [raw_nameservers]
        nameservers = []
        for item in raw_nameservers if isinstance(raw_nameservers, list) else []:
            if isinstance(item, dict):
                item = item.get("host") or item.get("name") or item.get("nameserver") or item.get("value")
            value = str(item or "").strip().rstrip(".").lower()
            if value and value not in nameservers:
                nameservers.append(value)
        operation_id = str(
            data.get("operation_id") or operation.get("id") or ""
        ).strip()
        return {
            "mode": mode,
            "status": status,
            "nameservers": nameservers,
            "operation_id": operation_id,
        }

    def hosted_status(self, domain=None):
        """Read Hosted DNS state without changing records or delegation."""
        domain = domain or self.domain
        if domain != self.domain:
            raise ValueError("DigitalPlat credential is bound to one domain")
        path = "/domains/" + quote(domain, safe="") + "/dns"
        try:
            payload = self.http.request("GET", self.base, path, headers=self.headers)
        except ProviderError as exc:
            if exc.code == "provider_http_404" and exc.upstream_code == "hosted_dns_zone_not_found":
                return {"mode": "", "status": "missing", "nameservers": [], "operation_id": ""}
            if exc.code == "provider_http_502":
                raise ProviderError(DIGITALPLAT_DNS_UPSTREAM_UNAVAILABLE, uncertain=True) from None
            raise
        return self._status_fields(payload)

    def enable_hosted(self, idempotency_key, domain=None):
        """Initialize Hosted DNS; callers must persist the dispatch first."""
        domain = domain or self.domain
        if domain != self.domain:
            raise ValueError("DigitalPlat credential is bound to one domain")
        path = "/domains/" + quote(domain, safe="") + "/dns/enable"
        headers = {**self.headers, "Idempotency-Key": idempotency_key}
        try:
            payload = self.http.request("POST", self.base, path, headers=headers, body={})
        except ProviderError as exc:
            if exc.code == "provider_http_502":
                raise ProviderError(DIGITALPLAT_DNS_UPSTREAM_UNAVAILABLE, uncertain=True) from None
            raise
        return self._status_fields(payload)

    def hosting_preflight(self):
        """Verify ownership and avoid replacing a custom external delegation."""
        payload = self.http.request(
            "GET", self.base, "/domains/" + quote(self.domain, safe=""), headers=self.headers)
        data = payload.get("data") if isinstance(payload, dict) else None
        if (not isinstance(data, dict) or data.get("domain") != self.domain
                or data.get("status") not in {"ok", "active", "registered"}):
            raise ProviderError("digitalplat_domain_not_ready")
        nameservers = data.get("nameservers") or []
        if not isinstance(nameservers, list):
            raise ProviderError("invalid_digitalplat_domain_response")
        for item in nameservers:
            name = item.get("host") or item.get("name") if isinstance(item, dict) else item
            if not str(name or "").lower().rstrip(".").endswith(".digitalplat.org"):
                raise ProviderError("digitalplat_external_dns_in_use")

    def inventory(self, domain):
        if domain != self.domain:
            raise ValueError("DigitalPlat credential is bound to one domain")
        path = "/domains/" + quote(domain, safe="") + "/dns/records"
        try:
            data = self.http.request("GET", self.base, path, headers=self.headers)
        except ProviderError as exc:
            # Keep a missing provider zone distinct from transport or auth
            # failures so the UI can explain that the credential/zone needs
            # checking without dispatching a Nameserver operation.
            if exc.code == "provider_http_404":
                if exc.upstream_code == "hosted_dns_zone_not_found":
                    raise ProviderError(DIGITALPLAT_DNS_NOT_ENABLED) from None
                raise ProviderError(DIGITALPLAT_DNS_ZONE_UNAVAILABLE) from None
            if exc.code == "provider_http_502":
                raise ProviderError(DIGITALPLAT_DNS_UPSTREAM_UNAVAILABLE, uncertain=True) from None
            raise
        rows = data.get("data", data.get("records", [])) if isinstance(data, dict) else data
        if isinstance(rows, dict):
            rows = rows.get("records", [])
        if not isinstance(rows, list):
            raise ProviderError("invalid_digitalplat_inventory")
        return {"zone_id": domain, "zone_name": domain, "records": _join_txt_rows(rows), "complete": True}

    def _txt_endpoint_member(self, record_id, wanted=None):
        """RRset inventory IDs and record mutation IDs are different upstream.

        Keep RRset IDs as the internal identity used by plans and ownership.
        Resolve the concrete member only at the wire boundary, and never turn
        a member update/delete into a shared RRset replacement.
        """
        payload = self.http.request(
            'GET', self.base, '/domains/' + quote(self.domain, safe='') + '/dns/records',
            headers=self.headers)
        rows = payload.get('data', payload.get('records', [])) if isinstance(payload, dict) else payload
        if isinstance(rows, dict):
            rows = rows.get('records', [])
        if not isinstance(rows, list):
            raise ProviderError('invalid_digitalplat_inventory')
        members = [r for r in rows if str(r.get('type', '')).upper() == 'TXT'
                   and str(r.get('rrset_id') or '') == str(record_id)]
        # Older flat inventories expose a single ID. Preserve that contract,
        # including explicit whole-RRset values updates when all IDs coincide.
        if not members or all(str(r.get('id') or '') == str(record_id) for r in members):
            return str(record_id), False
        from api.services.dns_inventory import canonical, semantic, identifier
        if wanted is not None:
            members = [r for r in members
                       if any(semantic(value, wanted) for value in canonical(r, self.domain, 'digitalplat'))]
        if len(members) != 1:
            raise ProviderError('digitalplat_txt_rrset_member_ambiguous')
        return identifier(members[0].get('id')), True

    def delete(self, record_id, idempotency_key):
        """Delete one explicit record; the repair ledger owns dispatch/readback."""
        endpoint_id, _ = self._txt_endpoint_member(record_id)
        return self.http.request(
            'DELETE', self.base,
            '/domains/' + quote(self.domain, safe='') + '/dns/records/' + quote(endpoint_id, safe=''),
            headers={**self.headers, 'Idempotency-Key': idempotency_key},
        )

    def write(self, zone_id, wanted, marker, record_id=None, *, existing_records=None):
        from api.providers.http import ProviderError
        relative = '@' if wanted['name'] == self.domain else wanted['name'][:-len(self.domain)-1]
        value = wanted['content']
        if wanted['type'] == 'MX':
            value = f"{wanted['priority']} {value}."
        elif wanted['type'] == 'CNAME':
            # DigitalPlat treats an unqualified CNAME target as relative to
            # the managed zone.  Brevo returns an absolute target, so retain
            # the terminal dot on the provider wire format.
            value = value.rstrip('.') + '.'
        if record_id:
            endpoint_id, member_endpoint = (self._txt_endpoint_member(record_id, wanted)
                                            if wanted['type'] == 'TXT' else (str(record_id), False))
            body = {'value': value, 'ttl': wanted['ttl'], 'disabled': False}
            if member_endpoint:
                body['value'] = ' '.join(f'"{chunk}"' for chunk in _txt_chunks(value))
            if wanted['type'] == 'TXT':
                from api.services.dns_inventory import scoped_inventory, semantic
                if existing_records is None:
                    existing_records = scoped_inventory(self.inventory(self.domain), self.domain, 'digitalplat')
                peers = [r for r in existing_records if r['id'] == str(record_id)]
                selected = [r for r in peers if semantic(r, wanted)]
                if len(selected) != 1:
                    raise ProviderError('digitalplat_txt_rrset_member_ambiguous')
                if len(peers) > 1 and member_endpoint:
                    body['ttl'] = peers[0]['ttl']
                if len(peers) > 1 and not member_endpoint:
                    # Each values entry is a complete TXT RR; DKIM chunks must
                    # remain character-strings within that single entry.
                    values = [wanted['content'] if r is selected[0] else r['content'] for r in peers]
                    body.pop('value')
                    body['ttl'] = peers[0]['ttl']
                    body['values'] = [' '.join(f'"{chunk}"' for chunk in _txt_chunks(v)) for v in values]
            payload = self.http.request(
                'PATCH', self.base,
                '/domains/' + quote(self.domain, safe='') + '/dns/records/' + quote(endpoint_id, safe=''),
                headers=self.headers,
                body=body,
            )
            raw = payload.get('data', payload.get('record')) if isinstance(payload, dict) else None
            # DigitalPlat PATCH responses may omit the record identifier even
            # though the requested record was updated successfully.
            if not isinstance(raw, dict):
                raw = {}
            if member_endpoint:
                if raw.get('id') and str(raw['id']) not in {endpoint_id, str(record_id)}:
                    raise ProviderError('invalid_dns_write_response', uncertain=True)
                raw['id'] = str(record_id)
            else:
                raw.setdefault('id', str(record_id))
        else:
            # DigitalPlat's TXT create contract uses ``values`` (a list),
            # while MX create uses the singular ``value`` field.
            payload_body = {
                'type': wanted['type'],
                'name': relative,
                'ttl': wanted['ttl'],
            }
            if wanted['type'] == 'TXT':
                chunks = _txt_chunks(value)
                # Live DigitalPlat behavior accepts one quoted `value`
                # containing multiple DNS character-strings. Sending chunks
                # as separate `values` items creates separate TXT RRs and
                # breaks DKIM reconstruction.
                payload_body['value'] = ' '.join(f'"{chunk}"' for chunk in chunks)
            else:
                payload_body['value'] = value
            payload = self.http.request(
                'POST', self.base,
                '/domains/' + quote(self.domain, safe='') + '/dns/records',
                headers=self.headers,
                body=payload_body,
            )
            raw = payload.get('data', payload.get('record')) if isinstance(payload, dict) else None
            if isinstance(raw, dict) and isinstance(raw.get('records'), list) and raw['records']:
                records = _join_txt_rows(raw['records'])
                if len(records) == 1:
                    raw = records[0]
            if not isinstance(raw, dict):
                raw = {}
            if not (raw.get('id') or raw.get('record_id')):
                # Re-read after a successful POST and bind the response to the
                # exact semantic record. This handles providers that return a
                # success envelope without the newly allocated record id.
                inventory = self.inventory(self.domain)
                rows = inventory.get('records', [])
                candidates = []
                for item in rows:
                    item_type = str(item.get('type') or '').upper()
                    item_name = str(item.get('name') or item.get('host') or '@').rstrip('.').lower()
                    if item_type != wanted['type'] or item_name not in {relative.rstrip('.').lower(), wanted['name'].rstrip('.').lower()}:
                        continue
                    item_values = item.get('values')
                    if isinstance(item_values, list):
                        item_value = ''.join(_txt_join(v) for v in item_values)
                    else:
                        item_value = _txt_join(item.get('value', item.get('content', '')))
                    if item_type == 'MX':
                        item_value = item_value.rstrip('.')
                    if item_value == value.rstrip('.'):
                        candidates.append(item)
                if len(candidates) == 1:
                    raw = candidates[0]
                else:
                    raise ProviderError('invalid_dns_write_response', uncertain=True)
        return raw

"""Cloudflare inventory with exact zone-boundary lookup and complete pagination."""
from api.providers.http import ProviderError


def cloudflare_headers(secret):
    if secret.get("api_token"):
        return {"Authorization": "Bearer " + secret["api_token"]}
    if secret.get("api_email") and secret.get("api_key"):
        return {"X-Auth-Email": secret["api_email"], "X-Auth-Key": secret["api_key"]}
    raise ValueError("Cloudflare credential is incomplete")


class CloudflareDNS:
    def __init__(self, transport, secret):
        self.http = transport
        self.base = "https://api.cloudflare.com/client/v4"
        self.headers = cloudflare_headers(secret)

    def _get(self, path, query=None):
        return self.http.request("GET", self.base, path, headers=self.headers, query=query)

    def zone(self, domain):
        labels = domain.split(".")
        # Never infer the zone as the final two labels (co.uk/delegated zones).
        for start in range(len(labels) - 1):
            candidate = ".".join(labels[start:])
            payload = self._get("/zones", {"name": candidate, "status": "active", "per_page": 50})
            zones = [r for r in payload.get("result", []) if r.get("name", "").rstrip(".").lower() == candidate and r.get("status") == "active"]
            if len(zones) > 1:
                raise ProviderError("ambiguous_cloudflare_zone")
            if zones:
                from api.services.dns_inventory import identifier
                return identifier(zones[0]["id"]), candidate
        raise ProviderError("cloudflare_zone_not_accessible")

    def inventory(self, domain):
        zone_id, zone_name = self.zone(domain)
        rows, page = [], 1
        while True:
            payload = self._get(f"/zones/{zone_id}/dns_records", {"page": page, "per_page": 100})
            batch = payload.get("result", [])
            rows.extend(batch)
            if page >= int(payload.get("result_info", {}).get("total_pages", 1)):
                break
            if not batch or page >= 100:
                raise ProviderError("incomplete_cloudflare_inventory")
            page += 1
        return {"zone_id": zone_id, "zone_name": zone_name, "records": rows, "complete": True}

    def write(self, zone_id, wanted, marker, record_id=None):
        from api.services.dns_inventory import identifier
        zone_id = identifier(zone_id)
        body = {k: wanted[k] for k in ('type', 'name', 'content', 'ttl')}
        body['comment'] = marker
        if wanted['type'] == 'MX':
            body['priority'] = wanted['priority']
        path = f'/zones/{zone_id}/dns_records'
        method = 'POST'
        if record_id:
            path += '/' + identifier(record_id)
            method = 'PATCH'  # Preserve provider fields unrelated to this plan.
        payload = self.http.request(method, self.base, path, headers=self.headers, body=body)
        if not isinstance(payload, dict) or not isinstance(payload.get('result'), dict):
            raise ProviderError('invalid_dns_write_response', uncertain=True)
        return payload['result']

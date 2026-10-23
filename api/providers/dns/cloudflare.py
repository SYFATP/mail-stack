"""Cloudflare inventory with exact zone-boundary lookup and complete pagination."""
import re
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
        self.account_id = secret.get("account_id")

    def _get(self, path, query=None):
        return self.http.request("GET", self.base, path, headers=self.headers, query=query)

    @staticmethod
    def nameservers(zone):
        values = zone.get("name_servers") or []
        if not isinstance(values, list) or not 1 <= len(values) <= 8:
            raise ProviderError("cloudflare_nameservers_unavailable")
        names = sorted({str(v).lower().rstrip(".") for v in values})
        if any(len(v) > 253 or "." not in v or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in v.split(".")) for v in names):
            raise ProviderError("cloudflare_nameservers_unavailable")
        return names

    def zone_info(self, domain, *, pending=False, exact=False):
        from api.services.dns_inventory import identifier
        labels = domain.split(".")
        for start in range(1 if exact else len(labels) - 1):
            candidate = ".".join(labels[start:])
            query = {"name": candidate, "per_page": 50}
            if not pending or start:
                query["status"] = "active"
            if self.account_id:
                query["account.id"] = self.account_id
            payload = self._get("/zones", query)
            if not isinstance(payload, dict) or not isinstance(payload.get("result"), list):
                raise ProviderError("invalid_cloudflare_zone_response")
            allowed = {"active", "pending", "initializing"} if pending and not start else {"active"}
            zones = [r for r in payload["result"] if r.get("name", "").rstrip(".").lower() == candidate
                     and r.get("status") in allowed]
            if len(zones) > 1:
                raise ProviderError("ambiguous_cloudflare_zone")
            if zones:
                zone = dict(zones[0]);zone["id"] = identifier(zone.get("id"));zone["name"] = candidate
                if zone.get("type", "full") != "full":
                    raise ProviderError("cloudflare_full_zone_required")
                if self.account_id and zone.get("account", {}).get("id") != self.account_id:
                    raise ProviderError("cloudflare_zone_account_mismatch")
                return zone
        return None

    def zone(self, domain):
        zone = self.zone_info(domain)
        if not zone:
            raise ProviderError("cloudflare_zone_not_accessible")
        return zone["id"], zone["name"]

    def creation_account(self):
        if self.account_id:
            return self.account_id
        found = set()
        for page in range(1, 101):
            payload = self._get("/accounts", {"page": page, "per_page": 50})
            if not isinstance(payload, dict) or not isinstance(payload.get("result"), list):
                raise ProviderError("cloudflare_account_id_required")
            for account in payload["result"]:
                value = str(account.get("id") or "")
                if not re.fullmatch(r"[0-9a-fA-F]{32}", value):
                    raise ProviderError("invalid_cloudflare_account_response")
                found.add(value)
            if len(found) > 1:
                raise ProviderError("cloudflare_account_id_required")
            if page >= int(payload.get("result_info", {}).get("total_pages", 1)):
                break
        else:
            raise ProviderError("incomplete_cloudflare_account_inventory")
        if len(found) != 1:
            raise ProviderError("cloudflare_account_id_required")
        return found.pop()

    def create_zone(self, domain, account_id):
        payload = self.http.request("POST", self.base, "/zones", headers=self.headers,
                                    body={"name": domain, "account": {"id": account_id}, "type": "full"})
        zone = payload.get("result") if isinstance(payload, dict) else None
        if not isinstance(zone, dict) or zone.get("name", "").lower().rstrip(".") != domain:
            raise ProviderError("invalid_cloudflare_zone_response", uncertain=True)
        from api.services.dns_inventory import identifier
        try:
            identifier(zone.get("id"))
            self.nameservers(zone)
        except ProviderError:
            raise ProviderError("invalid_cloudflare_zone_response", uncertain=True) from None
        return zone

    def inventory(self, domain):
        zone = self.zone_info(domain, pending=True)
        if not zone:
            raise ProviderError("cloudflare_zone_not_accessible")
        zone_id, zone_name = zone["id"], zone["name"]
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
        return {"zone_id": zone_id, "zone_name": zone_name, "records": rows, "complete": True,
                "zone_status": zone["status"], "name_servers": zone.get("name_servers", [])}

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

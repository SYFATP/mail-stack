"""dynv6 REST v2 DNS for zones registered under the user's My Domains.

The custom-domain registration and parent delegation are separate from this
record API. No zone is created implicitly and no NS is changed here.
"""
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import re
from api.providers.http import ProviderError
from api.services.dns_inventory import name as record_name


DYNV6_TTL = 60


def numeric_id(value):
    text = str(value)
    if not re.fullmatch(r"[1-9][0-9]{0,18}", text) or int(text) > 9223372036854775807:
        raise ProviderError("invalid_dynv6_identifier")
    return text


class Dynv6DNS:
    def __init__(self, transport, secret, domain):
        self.http, self.domain = transport, domain
        self.base = "https://dynv6.com"
        self.headers = {"Authorization": "Bearer " + secret["api_token"]}
        self._zone_names = {}
        self._exact_zone_id = None

    def zone(self, domain):
        zones = self.http.request("GET", self.base, "/api/v2/zones", headers=self.headers)
        if not isinstance(zones, list) or len(zones) > 10000:
            raise ProviderError("invalid_dynv6_zone_inventory")
        matches = []
        for zone in zones:
            if not isinstance(zone, dict) or not isinstance(zone.get("name"), str):
                raise ProviderError("invalid_dynv6_zone_inventory")
            name = zone["name"].lower().rstrip(".")
            if domain == name or domain.endswith("." + name):
                matches.append((name, numeric_id(zone.get("id")), zone))
        if not matches:
            raise ProviderError("dynv6_zone_not_accessible")
        matches.sort(key=lambda item: len(item[0]), reverse=True)
        chosen = matches[0]
        if sum(item[0] == chosen[0] for item in matches) != 1:
            raise ProviderError("ambiguous_dynv6_zone")
        self._zone_names[chosen[1]] = chosen[0]
        if chosen[0] == self.domain:
            self._exact_zone_id = chosen[1]
        return chosen[1], chosen[0], chosen[2]

    def _exact_zone(self):
        # Keep only the ID for this short-lived adapter, never DNS contents.
        # Refresh mutable primary addresses alongside every record inventory.
        zone = self.http.request("GET", self.base, "/api/v2/zones/" + self._exact_zone_id,
                                 headers=self.headers)
        if (not isinstance(zone, dict) or numeric_id(zone.get("id")) != self._exact_zone_id
                or not isinstance(zone.get("name"), str)
                or zone["name"].lower().rstrip(".") != self.domain):
            raise ProviderError("dynv6_zone_changed")
        return zone

    @staticmethod
    def _record(raw, zone_id, zone_name):
        if (not isinstance(raw, dict) or numeric_id(raw.get("zoneID")) != zone_id
                or not isinstance(raw.get("data"), str)
                or not isinstance(raw.get("name"), str)):
            raise ProviderError("invalid_dynv6_record")
        kind = str(raw.get("type") or "").upper()
        if kind not in {"A", "AAAA", "CAA", "CNAME", "MX", "SPF", "SRV", "TXT"}:
            raise ProviderError("invalid_dynv6_record")
        value = raw["data"]
        if kind in {"CNAME", "MX", "SRV"}:
            if raw.get("expandedData") is not None:
                value = str(raw["expandedData"])
            elif not value.endswith("."):
                value = zone_name if value in {"", "@"} else value + "." + zone_name
        if kind == "MX" and (type(raw.get("priority")) is not int
                             or not 0 <= raw["priority"] <= 65535):
            raise ProviderError("invalid_dynv6_mx_priority")
        return {"id": numeric_id(raw.get("id")), "type": kind,
                "name": record_name(raw["name"], zone_name), "content": value,
                "ttl": DYNV6_TTL, "priority": raw.get("priority", 0)}

    def inventory(self, domain):
        if domain != self.domain:
            raise ValueError("dynv6 adapter is scoped to one managed domain")
        if self._exact_zone_id:
            zone_id, zone_name = self._exact_zone_id, self.domain
            # Both are fresh reads. Independent reads can overlap without
            # weakening write-before/write-after inventory comparisons.
            with ThreadPoolExecutor(max_workers=2) as pool:
                metadata = pool.submit(self._exact_zone)
                records_read = pool.submit(self.http.request, "GET", self.base,
                    "/api/v2/zones/" + zone_id + "/records", headers=self.headers)
                zone, records = metadata.result(), records_read.result()
        else:
            # Inherited zones must rediscover the longest matching suffix on
            # every read, so a newly created child zone cannot be overlooked.
            zone_id, zone_name, zone = self.zone(domain)
            records = self.http.request("GET", self.base, "/api/v2/zones/" + zone_id + "/records",
                                        headers=self.headers)
        if not isinstance(records, list) or len(records) > 10000:
            raise ProviderError("invalid_dynv6_record_inventory")
        normalized = [self._record(raw, zone_id, zone_name) for raw in records]
        if len({r["id"] for r in normalized}) != len(normalized):
            raise ProviderError("ambiguous_dynv6_record_inventory")
        # Primary zone addresses are served too, but absent from /records.
        # Include them in the snapshot so DNS previews see the whole zone.
        for field, kind in (("ipv4address", "A"), ("ipv6prefix", "AAAA")):
            if zone.get(field):
                try:
                    address = ipaddress.ip_interface(str(zone[field])).ip
                    if address.version != (4 if kind == "A" else 6):
                        raise ValueError()
                except ValueError:
                    raise ProviderError("invalid_dynv6_primary_address") from None
                normalized.append({"id": "dynv6-zone-" + field, "type": kind,
                                   "name": zone_name, "content": str(address), "ttl": DYNV6_TTL})
        return {"zone_id": zone_id, "zone_name": zone_name,
                "records": normalized, "complete": True}

    def write(self, zone_id, wanted, marker, record_id=None):
        zone_id = numeric_id(zone_id)
        zone_name = self._zone_names.get(zone_id)
        if not zone_name:
            raise ProviderError("dynv6_zone_not_captured")
        name = wanted["name"]
        if name != zone_name and not name.endswith("." + zone_name):
            raise ProviderError("dynv6_record_outside_zone")
        kind = wanted["type"]
        if kind not in {"MX", "TXT", "CNAME"}:
            raise ProviderError("unsupported_dynv6_mail_record")
        data = wanted["content"]
        if kind in {"MX", "CNAME"}:
            data = data.rstrip(".") + "."
        body = {"name": "" if name == zone_name else name[:-len(zone_name)-1],
                "data": data}
        if kind == "MX":
            body["priority"] = wanted["priority"]
        endpoint = "/api/v2/zones/" + zone_id + "/records"
        method = "POST"
        if record_id is not None:
            endpoint += "/" + numeric_id(record_id)
            method = "PATCH"  # Record type is immutable; preserve unrelated fields.
        else:
            body["type"] = kind
        raw = self.http.request(method, self.base, endpoint, headers=self.headers, body=body)
        try:
            record = self._record(raw, zone_id, zone_name)
            if record_id is not None and record["id"] != str(record_id):
                raise ProviderError("invalid_dynv6_write_response")
        except (ProviderError, TypeError, ValueError, KeyError):
            raise ProviderError("invalid_dynv6_write_response", uncertain=True) from None
        return record

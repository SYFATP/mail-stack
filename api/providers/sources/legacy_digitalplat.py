from api.providers.http import ProviderError
from api.providers.projections import public_items


class LegacyDigitalPlat:
    def __init__(self, transport, base_url, secret, client_id=""):
        self.http, self.base = transport, base_url
        key = secret["admin_key"]
        self.headers = {"Authorization": "Bearer " + key, "X-Admin-Key": key, "X-API-Key": key}

    def candidates(self, count):
        try:
            data = self.http.request("GET", self.base, "/api/domains/available", headers=self.headers, query={"count": count})
        except ProviderError as exc:
            if exc.code != "provider_http_404":
                raise
            data = self.http.request("GET", self.base, "/api/domains/list-available", headers=self.headers, query={"count": count})
        return public_items(data)[:count]

    def claim(self, request, key):
        # This legacy GET has SIDE EFFECTS. It is dispatched only from a durable
        # POST job, never retried automatically and never called as a lookup.
        return self.http.request("GET", self.base, "/api/domains/claim-by-ids", headers=self.headers,
                                 query={"ids": ",".join(request["external_ids"])})

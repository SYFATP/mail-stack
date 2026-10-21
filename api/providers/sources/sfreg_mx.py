from urllib.parse import quote
from api.providers.projections import public_items


class SFRegMX:
    def __init__(self, transport, base_url, secret, client_id):
        self.http, self.base, self.client_id = transport, base_url, client_id
        key = secret["api_key"]
        self.headers = {"X-Domain-API-Key": key, "Authorization": "Bearer " + key}

    def candidates(self, count, *, status=None, sync_provider=None):
        path = "/api/digitalplat-dns/domains/available"
        query = {"count": count}
        if status is not None:
            path = "/api/domains/available"
            query.update(status=status, sync_provider=sync_provider)
        return public_items(self.http.request("GET", self.base, path, headers=self.headers, query=query))[:count]

    def claim(self, request, key):
        headers = {**self.headers, "X-SFREG-Client-ID": self.client_id, "Idempotency-Key": key}
        if "status" in request:
            # These GET endpoints allocate records. Only the durable claim job
            # calls them; an ambiguous result must never trigger another claim.
            query = {"status": request["status"], "sync_provider": request["sync_provider"]}
            ids = request.get("external_ids")
            if ids:
                path = "/api/domains/claim-by-ids"
                query["ids"] = ",".join(ids)
            else:
                path = "/api/domains/claim"
                query["count"] = request.get("count", 1)
            return self.http.request("GET", self.base, path, headers=headers, query=query)
        return self.http.request("POST", self.base, "/api/digitalplat-dns/domains/claim",
            headers=headers,
            body={"count": request.get("count", 1), "provider": "digitalplat", "local_part": request["local_part"],
                  "include_dns_credentials": True, "client_id": self.client_id, "idempotency_key": key})

    def status(self, claim_id):
        return self.http.request("GET", self.base, "/api/digitalplat-dns/domains/" + quote(claim_id, safe="") + "/status",
                                 headers={**self.headers, "X-SFREG-Client-ID": self.client_id})

    def report_status(self, claim_id, body, key):
        return self.http.request("PATCH", self.base, "/api/digitalplat-dns/domains/" + quote(claim_id, safe="") + "/status",
            headers={**self.headers, "X-SFREG-Client-ID": self.client_id, "Idempotency-Key": key}, body=body)

    def refresh_credential(self, claim_id, key):
        return self.http.request("POST", self.base, "/api/digitalplat-dns/domains/" + quote(claim_id, safe="") + "/credentials/refresh",
            headers={**self.headers, "X-SFREG-Client-ID": self.client_id, "Idempotency-Key": key}, body={})

    def release(self, claim_id, body, key):
        return self.http.request("POST", self.base, "/api/digitalplat-dns/domains/" + quote(claim_id, safe="") + "/release",
            headers={**self.headers, "X-SFREG-Client-ID": self.client_id, "Idempotency-Key": key}, body=body)

    def provision_plan(self, claim_id, body, key):
        # Upstream plan, not proof of actual DNS application or local readiness.
        return self.http.request("POST", self.base, "/api/digitalplat-dns/domains/" + quote(claim_id, safe="") + "/provision",
            headers={**self.headers, "X-SFREG-Client-ID": self.client_id, "Idempotency-Key": key}, body=body)

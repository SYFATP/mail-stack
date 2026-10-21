from api.providers.http import ProviderError


class CloudflareInventory:
    def __init__(self, transport, base_url, secret, client_id=""):
        self.http, self.base = transport, base_url
        self.headers = {"Authorization": "Bearer " + secret["api_token"]}

    def candidates(self, count):
        out = []
        page = 1
        while len(out) < count:
            data = self.http.request("GET", self.base, "/zones", headers=self.headers,
                                     query={"page": page, "per_page": min(50, count), "status": "active"})
            rows = data.get("result", []) if isinstance(data, dict) else []
            from api.providers.projections import public_item
            for row in rows:
                if row.get("status") == "active":
                    out.append(public_item(row))
            pages = int(data.get("result_info", {}).get("total_pages", 1))
            if page >= pages or not rows:
                break
            page += 1
        return out[:count]

    def claim(self, request, key):
        raise ProviderError("cloudflare_inventory_requires_import_not_claim")

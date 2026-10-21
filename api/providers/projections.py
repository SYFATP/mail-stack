"""Allowlisted projections. Raw provider objects never become public API objects."""
from api.services.routing import normalize_domain


def items(payload):
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = payload.get("items") or payload.get("domains") or payload.get("data") or payload.get("result") or []
        if not rows and (payload.get("domain") or payload.get("name")):
            rows = [payload]
        if isinstance(rows, dict):
            if any(k in rows for k in ("items", "domains", "data", "result")):
                return items(rows)
            rows = [rows]
    else:
        rows = []
    return [r if isinstance(r, dict) else {"domain": r} for r in rows if isinstance(r, (str, dict))]


def public_item(row):
    domain = normalize_domain(row.get("domain") or row.get("name") or "")
    # Do not expose status/error/message strings from an upstream response.
    # They can echo credentials; only structured, bounded identifiers leave here.
    import re
    identifier = lambda value: str(value or "") if re.fullmatch(r"[A-Za-z0-9_.:-]{0,128}", str(value or "")) else ""
    status = str(row.get("status") or "").lower()
    return {"domain": domain,
            "external_id": identifier(row.get("id") or row.get("external_id")),
            "claim_id": identifier(row.get("claim_id") or (row.get("dns", {}).get("claim_id") if isinstance(row.get("dns"), dict) else "")),
            "status": status if status in {"available", "registered", "synced", "sync_failed", "used", "reserved", "claimed", "active", "pending", "released", "expired", "revoked"} else "unknown"}


def public_items(payload):
    result, seen = [], set()
    for row in items(payload):
        try:
            item = public_item(row)
        except ValueError:
            continue
        if item["domain"] not in seen:
            seen.add(item["domain"])
            result.append(item)
    return result

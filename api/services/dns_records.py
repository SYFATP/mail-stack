"""Find the owned/semantic DNS record, never overwrite arbitrary root TXT."""
from __future__ import annotations


def record_content(record: dict) -> str:
    return str(record.get("content") or "").strip().strip('"')


def select_record(existing: list[dict], wanted: dict) -> dict | None:
    if len(existing) == 0:
        return None
    kind = wanted["type"].upper()
    content = record_content(wanted)
    exact = [r for r in existing if record_content(r) == content and
             (kind != "MX" or int(r.get("priority") or 0) == int(wanted.get("priority") or 0))]
    if exact:
        return exact[0]
    if kind == "TXT":
        prefix = next((p for p in ("v=spf1", "v=DMARC1", "v=DKIM1") if content.lower().startswith(p.lower())), None)
        candidates = [r for r in existing if prefix and record_content(r).lower().startswith(prefix.lower())]
    else:
        candidates = existing
    if len(candidates) > 1:
        raise ValueError("multiple conflicting DNS records; reconcile explicitly")
    return candidates[0] if candidates else None

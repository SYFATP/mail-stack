"""Read-only DNS plan and conservative resolver validation.

Wildcard readiness is deliberately fail-closed.  It is promoted only when the
authoritative wildcard owner itself and one freshly-randomized probe at every
configured depth resolve to the exact managed MX target.  A failed or
incomplete probe never extends an older successful revision.
"""
from __future__ import annotations
import hashlib
import json
import re
import secrets
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
import dns.resolver
from api.services.routing import config_hash, normalize_domain


def _txt(value):
    return str(value).strip().strip('"')


def dkim_value(row, key_root=Path("/dkim/keys")):
    path = key_root / row["domain"] / (row["dkim_selector"] + ".txt")
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8")
    pieces = re.findall(r'"([^"\r\n]*)"', raw)
    value = "".join(pieces)
    if not value:
        value = raw.strip()
    if not re.match(r"v=DKIM1\s*;", value, re.I) or not re.search(r"(?:^|;)\s*p=[A-Za-z0-9+/=]+\s*(?:;|$)", value):
        return None
    return value


def build_plan(row, key_root=Path("/dkim/keys")):
    domain = normalize_domain(row["domain"])
    mx = normalize_domain(row["mx"])
    records = [
        {"role": "mx", "type": "MX", "name": domain, "content": mx, "priority": 10, "ttl": 300},
        {"role": "spf", "type": "TXT", "name": domain, "content": row["spf"], "ttl": 300},
        {"role": "dmarc", "type": "TXT", "name": "_dmarc." + domain, "content": row["dmarc"], "ttl": 300},
    ]
    warnings = []
    value = dkim_value(row, key_root)
    if value:
        records.append({"role": "dkim", "type": "TXT", "name": row["dkim_selector"] + "._domainkey." + domain, "content": value, "ttl": 300})
    else:
        warnings.append("dkim_public_key_pending")
    if row["receive_subdomains"] and row["max_subdomain_depth"]:
        records.append({"role": "wildcard_mx", "type": "MX", "name": "*." + domain, "content": mx, "priority": 10, "ttl": 300})
        warnings.append("wildcard_requires_existing_node_and_delegation_reconciliation")
    warnings.append("mx_host_address_and_ptr_are_infrastructure_checks_not_implicit_zone_writes")
    plan = {"domain": domain, "config_hash": config_hash(row), "records": records, "warnings": warnings,
            "write_policy": "plan_only", "transport": "local_smtp"}
    plan["plan_hash"] = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return plan


class DNSValidator:
    def __init__(self, resolver=None):
        self.resolver = resolver or dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 5

    def values(self, name, kind):
        try:
            answer = self.resolver.resolve(name, kind, search=False)
            if kind == "TXT":
                return [b"".join(r.strings).decode("ascii", errors="strict") for r in answer]
            if kind == "MX":
                return [str(r.exchange).rstrip(".").lower() for r in answer]
            return [str(r).rstrip(".") for r in answer]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []

    def validate(self, row, key_root=Path("/dkim/keys")):
        plan = build_plan(row, key_root)
        domain = row["domain"]
        # Per-validation single-flight cache only: root/wildcard probes share
        # one observation of the MX host, never evidence from an earlier run.
        observations, observation_lock = {}, threading.Lock()
        def observed_values(name, kind):
            with observation_lock:
                key = (name, kind)
                first = key not in observations
                if first:
                    observations[key] = Future()
                future = observations[key]
            if first:
                try:
                    future.set_result(self.values(name, kind))
                except Exception as exc:
                    future.set_exception(exc)
            return future.result()
        def run(name, fn):
            try:
                passed, code = fn()
                return {"status": "passed" if passed else "failed", "detail": code}
            except Exception:
                return {"status": "failed", "detail": "dns_query_failed"}
        def mx_check(name):
            values = observed_values(name, "MX")
            expected = normalize_domain(row["mx"])
            if not values or set(values) != {expected}:
                return False, "mx_missing_or_unexpected_target"
            if observed_values(expected, "CNAME"):
                return False, "mx_target_is_cname"
            ips = observed_values(expected, "A") + observed_values(expected, "AAAA")
            return bool(ips), "mx_target_resolves" if ips else "mx_target_address_missing"
        tasks = [("mx", lambda: mx_check(domain))]
        for role, name, expected, prefix in (
            ("spf", domain, row["spf"], "v=spf1"),
            ("dmarc", "_dmarc." + domain, row["dmarc"], "v=DMARC1"),
            ("dkim", row["dkim_selector"] + "._domainkey." + domain, dkim_value(row, key_root), "v=DKIM1"),
        ):
            def txt_check(name=name, expected=expected, prefix=prefix):
                values = [v.strip() for v in observed_values(name, "TXT") if v.strip().lower().startswith(prefix.lower())]
                valid = bool(expected) and len(values) == 1 and values[0] == expected
                return valid, "txt_matches" if valid else "txt_missing_conflicting_or_mismatched"
            tasks.append((role, txt_check))
        probe_tasks = []
        if row["receive_subdomains"] and row["max_subdomain_depth"]:
            probe_tasks.append({"depth": 0, "name": "*." + domain, "kind": "wildcard_owner"})
            for depth in range(1, int(row["max_subdomain_depth"]) + 1):
                name = ".".join("ms-" + secrets.token_hex(5) for _ in range(depth)) + "." + domain
                probe_tasks.append({"depth": depth, "name": name, "kind": "random_depth_probe"})
        # Keep resolver load bounded even for deep wildcard configurations.
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = [(name, pool.submit(run, name, fn)) for name, fn in tasks]
            probe_results = [(probe, pool.submit(run, "wildcard_mx", lambda name=probe["name"]: mx_check(name)))
                             for probe in probe_tasks]
            checks = {name: future.result() for name, future in results}
            probes = []
            for probe, future in probe_results:
                check = future.result()
                probes.append({**probe, "passed": check["status"] == "passed", "detail": check["detail"]})
        if probes:
            passed = all(p["passed"] for p in probes)
            checks["wildcard_mx"] = {
                "status": "passed" if passed else "failed",
                "detail": "wildcard_owner_and_depth_probes_passed" if passed else "wildcard_owner_or_depth_probe_failed",
            }
        else:
            checks["wildcard_mx"] = {"status": "not_required", "detail": "subdomain_receive_disabled"}
        # No smtp_submission pass inferred from DNS. P4 owns that actual test.
        return {"domain": domain, "config_hash": plan["config_hash"], "checks": checks,
                "wildcard_probes": probes, "plan_hash": plan["plan_hash"], "validation_scope": "resolver_observed_not_authoritative_ownership"}

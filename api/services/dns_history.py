"""Observe ambiguous DNS apply history without replaying or adopting writes."""
from __future__ import annotations

import json
import os
import time

from api.services.dns_inventory import fingerprint, matches, semantic
from api.services.dns_plan import build_plan

EVIDENCE_KINDS = {"dns_validate", "dns_apply", "dns_complete"}
ACTIVE_KINDS = ("dns_apply", "dns_validate", "dns_repair", "dns_hosting",
                "claim_setup", "dynv6_register", "dns_complete")


class DNSHistoryReconciler:
    def __init__(self, manager):
        self.m = manager

    @staticmethod
    def _active(c, domain):
        return any(domain == r[0] or domain.endswith("." + r[0]) or r[0].endswith("." + domain)
                   for r in c.execute("SELECT scope FROM domain_jobs WHERE status IN ('queued','running') "
                                      "AND kind IN (" + ",".join("?" for _ in ACTIVE_KINDS) + ")", ACTIVE_KINDS))

    @staticmethod
    def _binding(row, plan):
        return row["dns_provider"], row["dns_credential_ref"], row["source_status"], plan["plan_hash"]

    @staticmethod
    def _evidence(job, row, plan, now):
        if not job or job["status"] != "succeeded" or job["kind"] not in EVIDENCE_KINDS or job["scope"] != row["domain"]:
            return False
        try:
            max_age = max(60, int(os.getenv("DNS_CHECK_MAX_AGE_SECONDS", "3600")))
        except ValueError:
            max_age = 3600
        result = json.loads(job["result_json"])
        if (not 0 <= now - job["updated_at"] <= max_age or
            result.get("config_hash") != plan["config_hash"] or result.get("plan_hash") != plan["plan_hash"]):
            return False
        checks = result.get("checks") or {}
        required = {"mx", "spf", "dkim", "dmarc"}
        if row["receive_subdomains"] and row["max_subdomain_depth"]:
            required.add("wildcard_mx")
        return (all(checks.get(name, {}).get("status") == "passed" for name in required)
                and all(check.get("status") in {"passed", "not_required"} for check in checks.values()))

    def reconcile(self, domain, evidence_job_id):
        """Resolve only exact, current observations; original tasks stay partial.

        This acknowledges present DNS state, not who performed an ambiguous
        write. Original errors, confirmed record IDs and ownership stay intact.
        No DNS/Brevo/claim mutation or automatic write retry is performed.
        """
        c = self.m.db()
        try:
            jobs = [dict(r) for r in c.execute("SELECT * FROM domain_jobs WHERE kind='dns_apply' "
                    "AND scope=? AND status='unknown' ORDER BY created_at,id LIMIT 50", (domain,))]
            if not jobs:
                return []
            row = self.m.domain(domain)
            plan = build_plan(row, self.m.key_root)
            evidence = c.execute("SELECT * FROM domain_jobs WHERE id=?", (evidence_job_id,)).fetchone()
            if (row["dns_provider"] not in {"digitalplat", "dynv6", "cloudflare"} or
                row["source_status"] in {"released", "revoked", "expired", "releasing"} or
                not self._evidence(evidence, row, plan, time.time()) or self._active(c, domain)):
                return []
            evidence = dict(evidence)
            operations = {job["id"]: [dict(r) for r in c.execute(
                "SELECT * FROM domain_dns_operations WHERE job_id=? ORDER BY id", (job["id"],))] for job in jobs}
        finally:
            c.close()
        # capture() only reads provider inventory. Do not call plan_for(),
        # preview() or targets() without a supplied plan: they can register Brevo.
        captured, _, inventory, records = self.m.dns.capture(domain)
        if self._binding(captured, build_plan(captured, self.m.key_root)) != self._binding(row, plan):
            return []
        _, targets, blockers = self.m.dns.targets(row, inventory, records, plan=plan)
        if blockers or any(len([r for r in records if semantic(r, target)]) != 1 or
                           not any(matches(r, target) for r in records) for target in targets):
            return []
        eligible = []
        for job in jobs:
            ops = operations[job["id"]]
            if not ops or job["updated_at"] > evidence["updated_at"] or job["created_at"] >= evidence["created_at"]:
                continue
            observed = []
            for op in ops:
                target = json.loads(op["target_json"])
                name = target.get("name", "")
                if (op["domain"] != domain or op["credential_ref"] != row["dns_credential_ref"] or
                    op["zone_id"] != inventory["zone_id"] or op["action"] not in {"create", "update"} or
                    op["status"] not in {"confirmed", "observed", "unknown", "dispatched"} or
                    not (name == domain or name.endswith("." + domain))):
                    break
                candidates = [r for r in records if semantic(r, target)]
                if len(candidates) != 1 or not matches(candidates[0], target):
                    break
                record = candidates[0]
                if (op["status"] in {"unknown", "dispatched"} and op["provider_record_id"] and
                    op["provider_record_id"] != record["id"]):
                    break
                observed.append({"operation_id": op["id"], "previous_status": op["status"],
                                 "record_id": record["id"], "record_hash": fingerprint(record)})
            else:
                eligible.append((job, ops, observed))
        if not eligible:
            return []
        resolved = []
        with self.m.lock:
            c = self.m.db()
            try:
                c.execute("BEGIN IMMEDIATE")
                current = self.m.domain(domain)
                fresh_evidence = c.execute("SELECT * FROM domain_jobs WHERE id=?", (evidence_job_id,)).fetchone()
                if (self._binding(current, build_plan(current, self.m.key_root)) != self._binding(row, plan) or
                    not self._evidence(fresh_evidence, current, plan, time.time()) or
                    dict(fresh_evidence) != evidence or self._active(c, domain)):
                    return []
                now = time.time()
                for job, ops, observed in eligible:
                    saved = c.execute("SELECT * FROM domain_jobs WHERE id=?", (job["id"],)).fetchone()
                    saved_ops = [dict(r) for r in c.execute("SELECT * FROM domain_dns_operations WHERE job_id=? ORDER BY id", (job["id"],))]
                    if dict(saved) != job or saved_ops != ops:
                        continue
                    for op, observation in zip(ops, observed):
                        if op["status"] in {"unknown", "dispatched"}:
                            c.execute("UPDATE domain_dns_operations SET status='observed',provider_record_id=?,updated_at=? WHERE id=?",
                                      (observation["record_id"], now, op["id"]))
                    result = json.loads(job["result_json"])
                    result["reconciliation"] = {"status": "observed_current_state_without_replay", "at": now,
                        "evidence_job_id": evidence_job_id, "config_hash": plan["config_hash"],
                        "operations": observed, "previous_error": job["error_code"], "dns_writes": 0,
                        "ownership_adopted": False, "next_action": "none"}
                    c.execute("UPDATE domain_jobs SET status='partial',step='dns_history_reconciled',result_json=?,updated_at=? "
                              "WHERE id=? AND status='unknown'", (json.dumps(result), now, job["id"]))
                    resolved.append(job["id"])
                c.commit()
            finally:
                c.close()
        return resolved

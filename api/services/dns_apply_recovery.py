"""Bounded apply continuation. Ambiguous writes receive reads, never replay."""
from __future__ import annotations
import copy
import time
from api.providers.http import ProviderError
from api.repositories.domain_jobs import JobConflict
from api.services.dns_inventory import inventory_hash, matches, semantic


class DNSApplyRecovery:
    WAIT_SECONDS = 30 * 60
    TRANSIENT = {
        "provider_transport_or_json_error", "provider_http_429",
        "provider_http_502", "provider_http_503", "provider_http_504",
    }

    def __init__(self, reconciler, job, snapshot):
        self.dns, self.m, self.job, self.snapshot = reconciler, reconciler.m, job, snapshot
        self.result = copy.deepcopy(job.get("result") or {})
        self.result.pop("retry_at", None)
        self.state = self.result.setdefault("apply_recovery", {
            "deadline": time.time() + self.WAIT_SECONDS,
            "index": 0, "inventory_hash": snapshot["inventory_hash"],
            "pending": None,
        })
        self.result.setdefault("completed", [])

    def expired(self):
        if time.time() < self.state["deadline"]:
            return False
        pending = self.state.get("pending")
        self.result.update(operation_id=pending["id"] if pending else None,
                           next_action="reconcile_dns_write" if pending else "fresh_dns_preview")
        self.m.jobs.finish(self.job["id"], "unknown" if pending else "partial",
                           step="dns_apply_recovery_timed_out", result=self.result,
                           error="dns_write_unconfirmed" if pending else "dns_apply_retry_timeout")
        return True

    def wait(self, exc=None):
        if self.expired():
            return
        self.state["attempts"] = self.state.get("attempts", 0) + 1
        delay = min(300, 15 * 2 ** min(self.state["attempts"] - 1, 5))
        if exc is not None:
            self.result["last_error"] = exc.code
            self.result.update(self.m.jobs.provider_backoff(self.job["scope"], exc))
        retry_at = max(time.time() + delay,
                       self.result.get("provider_backoff", {}).get("until", 0))
        self.result.update(retry_at=min(retry_at, self.state["deadline"]),
                           operation_id=(self.state.get("pending") or {}).get("id"),
                           next_action="wait_for_dns_readback" if self.state.get("pending") else "retry_dns_read")
        self.m.jobs.defer(self.job["id"], result=self.result,
                          step="dns_apply_readback_pending" if self.state.get("pending") else "dns_apply_waiting_upstream")

    def save(self, step="dns_apply_continuing"):
        self.m.jobs.progress(self.job["id"], step=step, result=self.result)

    def prepare(self, row, inventory, records):
        revision = [row["source_status"], row["claim_id"]]
        if self.state.setdefault("ownership_revision", revision) != revision:
            raise JobConflict("Domain ownership changed during DNS continuation")
        pending = self.state.get("pending")
        if pending:
            action = self.snapshot["actions"][self.state["index"]]
            target = action["target"]
            c = self.m.db()
            try:
                op = c.execute("SELECT * FROM domain_dns_operations WHERE id=? AND job_id=?",
                               (pending["id"], self.job["id"])).fetchone()
            finally:
                c.close()
            if not op or op["status"] not in {"dispatched", "unknown", "confirmed", "observed"}:
                raise JobConflict("DNS continuation journal changed")
            candidates = [r for r in records if semantic(r, target)]
            if not candidates:
                # Absence does not prove that an uncertain request was rejected.
                self.wait()
                return False
            if (len(candidates) != 1 or not matches(candidates[0], target)
                    or (action.get("record_id") and candidates[0]["id"] != action["record_id"])
                    or (row["dns_provider"] == "cloudflare" and candidates[0]["comment"] != op["ownership_marker"])):
                raise ProviderError("dns_readback_conflict", uncertain=True)
            unaffected = [r for r in records if not semantic(r, target)]
            if inventory_hash(unaffected, row["dns_provider"], inventory["zone_name"]) != pending["unaffected_hash"]:
                raise ProviderError("dns_inventory_changed_during_write", uncertain=True)
            if row["dns_provider"] == "cloudflare":
                self.dns.confirm(row, inventory["zone_id"], op["id"], target,
                                 candidates[0], op["ownership_marker"])
            elif op["status"] != "confirmed":
                # Markerless providers cannot prove ownership. Observe presence
                # without adopting an external record or replaying the POST.
                c = self.m.db()
                try:
                    with c:
                        c.execute("""UPDATE domain_dns_operations SET status='observed',
                            provider_record_id=?,updated_at=? WHERE id=? AND status IN ('dispatched','unknown')""",
                            (candidates[0]["id"], time.time(), op["id"]))
                finally:
                    c.close()
            self.result["completed"].append({"name": target["name"], "role": target["role"],
                                              "action": "observed"})
            self.advance(self.state["index"], inventory, records)
        elif inventory_hash(records, row["dns_provider"], inventory["zone_name"]) != self.state["inventory_hash"]:
            raise ProviderError("dns_changed_before_write")
        return True

    def dispatched(self, row, inventory, records, op_id):
        action = self.snapshot["actions"][self.state["index"]]
        self.state["pending"] = {
            "id": op_id,
            "unaffected_hash": inventory_hash(
                [r for r in records if not semantic(r, action["target"])],
                row["dns_provider"], inventory["zone_name"]),
        }
        self.save("dns_write_dispatched")

    def advance(self, index, inventory, records):
        self.state.update(index=index + 1, pending=None,
                          inventory_hash=inventory_hash(records, self.snapshot["provider"], inventory["zone_name"]))
        self.result["operation_id"] = None
        self.save()

    def interrupt(self, completed, op_id, uncertain, exc):
        self.result["completed"] = completed
        if not op_id or not uncertain:
            self.state["pending"] = None
        if isinstance(exc, ProviderError) and (exc.code in self.TRANSIENT
                or (self.state.get("pending") and exc.code == "dns_write_verification_failed")):
            self.wait(exc)
            return True
        return False

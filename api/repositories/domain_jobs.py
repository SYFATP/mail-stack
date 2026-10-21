"""Durable operation ledger. Unknown external side effects are never auto-replayed."""
from __future__ import annotations
import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
import json
import math
import os
import re
import time
import uuid

_executing_job = ContextVar("domain_executing_job", default=None)
PARALLEL_KINDS = ("dns_apply", "dns_validate")
WRITE_KINDS = ("dns_apply", "dns_hosting", "dns_repair", "claim_setup", "claim_provision")


def job_concurrency():
    """Bound the I/O pool for small hosts, including invalid configuration."""
    try:
        return max(1, min(2, int(os.getenv("DOMAIN_JOB_CONCURRENCY", "2"))))
    except (TypeError, ValueError):
        return 2


class JobConflict(ValueError):
    pass


def assert_domain_mutable(db, domain):
    """Called under the configuration lock; active namespaces stay immutable."""
    c = db()
    try:
        active = c.execute("""SELECT id,scope FROM domain_jobs WHERE status='running'
            AND kind IN ('dns_apply','dns_validate','dns_hosting','dns_repair','claim_setup')""").fetchall()
    finally:
        c.close()
    for row in active:
        other = row["scope"]
        if row["id"] != _executing_job.get() and (
            domain == other or domain.endswith("." + other) or other.endswith("." + domain)
        ):
            raise JobConflict("Domain operation is running; wait before changing this domain")


class DomainJobs:
    def __init__(self, db):
        self.db = db

    @contextmanager
    def execution(self, job):
        token = _executing_job.set(job["id"])
        try:
            yield
        finally:
            _executing_job.reset(token)

    def check_provider_backoff(self, provider):
        """Fence writes from jobs already running when another job hits 429."""
        from api.providers.http import ProviderError
        c = self.db()
        try:
            row = c.execute("""SELECT result_json FROM domain_jobs
                WHERE json_extract(result_json,'$.provider_backoff.provider')=?
                AND json_extract(result_json,'$.provider_backoff.until')>?
                ORDER BY json_extract(result_json,'$.provider_backoff.until') DESC LIMIT 1""",
                (provider, time.time())).fetchone()
        finally:
            c.close()
        if row:
            backoff = json.loads(row[0])["provider_backoff"]
            raise ProviderError("provider_http_429", uncertain=False,
                                retry_after=max(1, math.ceil(backoff["until"] - time.time())),
                                rate_limit=backoff.get("rate_limit", {}),
                                provider_backoff=backoff)

    @staticmethod
    def cooldowns(c, now):
        return {row[0]: row[1] for row in c.execute("""SELECT
            json_extract(result_json,'$.provider_backoff.provider'),
            max(json_extract(result_json,'$.provider_backoff.until')) FROM domain_jobs
            WHERE json_extract(result_json,'$.provider_backoff.until')>?
            AND json_extract(result_json,'$.provider_backoff.provider') IN ('digitalplat','cloudflare')
            GROUP BY json_extract(result_json,'$.provider_backoff.provider')""", (now,))}

    @staticmethod
    def queued_eligibility(alias, now, cooldowns):
        """Share admission rules with queue dependencies and readiness refresh."""
        params = {"now": now}
        clause = (f"COALESCE(json_extract({alias}.result_json,'$.incident_hold'),'')=''"
                  f" AND COALESCE(json_extract({alias}.result_json,'$.retry_at'),0)<=:now")
        if cooldowns:
            params.update({f"cooldown_{i}": name for i, name in enumerate(sorted(cooldowns))})
            providers = ",".join(":" + name for name in params if name != "now")
            clause += (f" AND ({alias}.kind NOT IN {WRITE_KINDS} OR NOT EXISTS"
                       f" (SELECT 1 FROM mail_domains limited_domain WHERE limited_domain.domain={alias}.scope"
                       f" AND limited_domain.dns_provider IN ({providers})))")
        return clause, params

    def public_rows(self, c, rows):
        now = time.time()
        needs_cooldown = any(row["status"] == "queued" and row["kind"] in WRITE_KINDS
                             and not json.loads(row["result_json"]).get("incident_hold") for row in rows)
        cooldowns = self.cooldowns(c, now) if needs_cooldown else {}
        providers = {r[0]: r[1] for r in c.execute("SELECT domain,dns_provider FROM mail_domains")} if cooldowns else {}
        return [self.public(row, now=now, cooldown_until=cooldowns.get(providers.get(row["scope"]), 0)) for row in rows]

    @staticmethod
    def public(row, *, now=None, cooldown_until=0):
        if not row:
            return None
        result = dict(row)
        result["request"] = json.loads(result.pop("request_json"))
        result["result"] = json.loads(result.pop("result_json"))
        result.pop("request_hash", None)
        now = time.time() if now is None else now
        result["automatic"] = result["idempotency_key"].startswith("auto-readiness:")
        result["read_only"] = result["kind"] == "dns_validate"
        result["wait_reason"] = ""
        result["wait_until"] = None
        if result["status"] == "queued":
            if result["result"].get("incident_hold"):
                result["wait_reason"] = "incident_hold"
            else:
                retry_at = result["result"].get("retry_at", 0) or 0
                cooldown = cooldown_until if result["kind"] in WRITE_KINDS else 0
                if max(retry_at, cooldown) > now:
                    result["wait_reason"] = "provider_cooldown" if cooldown >= retry_at else "retry_at"
                    result["wait_until"] = max(retry_at, cooldown)
                else:
                    result["wait_reason"] = "queue"
        if result["kind"] == "claim":
            result["upstream_idempotency_key"] = "mail-stack-" + result["id"]
        return result

    def enqueue(self, kind, scope, key, request):
        if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", key):
            raise ValueError("Idempotency-Key must be 8-128 ASCII identifier characters")
        body = json.dumps(request, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(body.encode()).hexdigest()
        c = self.db()
        try:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT * FROM domain_jobs WHERE kind=? AND scope=? AND idempotency_key=?", (kind, scope, key)).fetchone()
            if row:
                if row["request_hash"] != digest:
                    raise JobConflict("idempotency key reused with a different request")
            else:
                if kind in {'dns_apply', 'dns_hosting', 'dns_repair'}:
                    active = c.execute("""SELECT kind FROM domain_jobs WHERE scope=?
                        AND kind IN ('dns_apply','dns_hosting','dns_repair') AND status IN ('queued','running')""", (scope,)).fetchall()
                    if any(kind == 'dns_repair' or r['kind'] == 'dns_repair' for r in active):
                        raise JobConflict('DNS repair is active; wait for completion before another DNS write')
                if kind == "claim":
                    prior = c.execute("SELECT status,result_json FROM domain_jobs WHERE kind='claim' AND scope=? AND status IN ('unknown','partial')", (scope,)).fetchall()
                    if any(r["status"] == "unknown" or any(i.get("status") == "unknown" for i in json.loads(r["result_json"]).get("items", [])) for r in prior):
                        raise JobConflict("unresolved allocation exists; reconcile it before claiming again")
                job_id = uuid.uuid4().hex
                now = time.time()
                c.execute("""INSERT INTO domain_jobs(id,kind,scope,idempotency_key,request_hash,request_json,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?)""", (job_id, kind, scope, key, digest, body, now, now))
                row = c.execute("SELECT * FROM domain_jobs WHERE id=?", (job_id,)).fetchone()
            c.commit()
            return self.public(row)
        finally:
            c.close()

    def get(self, job_id):
        c = self.db()
        try:
            row = c.execute("SELECT * FROM domain_jobs WHERE id=?", (job_id,)).fetchone()
            return self.public_rows(c, [row])[0] if row else None
        finally:
            c.close()

    def get_many(self, ids):
        """One bounded snapshot for a browser tracking a large batch."""
        if not ids or len(ids) > 200 or any(
                not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value)
                for value in ids):
            raise ValueError("provide between 1 and 200 valid job ids")
        ids = list(dict.fromkeys(ids))
        c = self.db()
        try:
            rows = c.execute("SELECT * FROM domain_jobs WHERE id IN (" +
                             ",".join("?" for _ in ids) + ")", ids).fetchall()
            found = {row["id"]: row for row in self.public_rows(c, rows)}
            return {"items": [found[value] for value in ids if value in found]}
        finally:
            c.close()

    def progress(self, job_id, *, step, result):
        """Persist progress without changing dispatch state or replaying a write."""
        c = self.db()
        try:
            with c:
                c.execute("""UPDATE domain_jobs SET step=?,result_json=?,updated_at=?
                    WHERE id=? AND status='running'""",
                    (step, json.dumps(result), time.time(), job_id))
        finally:
            c.close()

    def list(self, limit=100, offset=0, *, q="", status=""):
        if status not in {"", "queued", "running", "succeeded", "failed", "partial", "unknown"}:
            raise ValueError("invalid job status filter")
        where, params = [], []
        if q.strip():
            pattern = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            fields = ("id", "kind", "scope", "status", "step", "error_code", "result_json")
            where.append("(" + " OR ".join(f"{field} LIKE ? ESCAPE '\\'" for field in fields) + ")")
            params.extend([pattern] * len(fields))
        if status:
            where.append("status=?")
            params.append(status)
        clause = " WHERE " + " AND ".join(where) if where else ""
        c = self.db()
        try:
            # Read rows/counts from one SQLite snapshot while workers update jobs.
            c.execute("BEGIN")
            rows = c.execute("SELECT * FROM domain_jobs" + clause + " ORDER BY created_at DESC,id LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
            total = c.execute("SELECT count(*) FROM domain_jobs" + clause, params).fetchone()[0]
            counts = {r[0]: r[1] for r in c.execute("SELECT status,count(*) FROM domain_jobs GROUP BY status")}
            blocked = set()
            for row in c.execute("SELECT scope,status,result_json FROM domain_jobs WHERE kind='claim' AND status IN ('queued','running','unknown','partial')"):
                if row["status"] != "partial" or any(i.get("status") == "unknown" for i in json.loads(row["result_json"]).get("items", [])):
                    blocked.add(row["scope"])
            active_rows = c.execute("""SELECT * FROM domain_jobs
                WHERE kind IN ('dns_apply','dns_validate','dns_hosting','dns_repair','claim_setup','claim')
                AND status IN ('queued','running') ORDER BY created_at,id""").fetchall()
            projected = self.public_rows(c, [*rows, *active_rows])
            active = projected[len(rows):]
            summary_fields = ("id", "kind", "scope", "status", "step", "automatic", "read_only", "wait_reason", "wait_until")
            active_dns = [{key: r[key] for key in summary_fields} for r in active if r["kind"] != "claim"]
            active_claims = [r for r in active if r["kind"] == "claim"]
            return {"items": projected[:len(rows)], "total": total,
                    "active_domain_jobs": active_dns, "active_claim_jobs": active_claims,
                    "status_counts": counts, "blocked_claim_sources": sorted(blocked)}
        finally:
            c.close()

    def provider_backoff(self, scope, error):
        """Persist rate limiting with the terminal job; never replay that job."""
        if getattr(error, "code", "") != "provider_http_429":
            return {}
        c = self.db()
        try:
            row = c.execute("SELECT dns_provider FROM mail_domains WHERE domain=?", (scope,)).fetchone()
        finally:
            c.close()
        if not row or row[0] not in {"digitalplat", "cloudflare"}:
            return {}
        now = time.time()
        inherited = getattr(error, "provider_backoff", None)
        if inherited and inherited.get("provider") == row[0]:
            return {"provider_backoff": dict(inherited)}
        metadata = getattr(error, "rate_limit", {}) or {}
        explicit_delay = getattr(error, "retry_after", 0)
        daily = metadata.get("window") == "day" or metadata.get("code") == "hosted_dns_daily_limit"
        if row[0] == "digitalplat" and daily and not explicit_delay:
            # Trial default, not a provider-confirmed reset. Unix days are UTC,
            # including when the host timezone differs or midnight is imminent.
            until = (math.floor(now / 86400) + 1) * 86400
            return {"provider_backoff": {"provider": row[0], "until": until,
                    "retry_after_seconds": math.ceil(until - now), "rate_limit": metadata,
                    "reset_time_source": "assumed_utc_midnight"}}
        fallback = {"day": 86400, "hour": 3600}.get(metadata.get("window"), 300)
        delay = max(300, min(604800, explicit_delay or fallback))
        return {"provider_backoff": {"provider": row[0], "until": now + delay,
                                     "retry_after_seconds": delay,
                                     "rate_limit": metadata}}

    def take(self, *, capacity=2):
        c = self.db()
        try:
            c.execute("BEGIN IMMEDIATE")
            running = c.execute("SELECT kind FROM domain_jobs WHERE status='running'").fetchall()
            if len(running) >= max(1, min(2, capacity)) or any(
                row["kind"] not in PARALLEL_KINDS for row in running
            ):
                c.commit()
                return None
            now = time.time()
            cooldowns = self.cooldowns(c, now)
            eligible, params = self.queued_eligibility("pending", now, cooldowns)
            writer_eligible, _ = self.queued_eligibility("writer", now, cooldowns)
            params.update(running=len(running), aged=now - 120)
            # Drain only for runnable exclusive work, never for held writers.
            if running and c.execute(f"""SELECT 1 FROM domain_jobs AS pending
                WHERE pending.status='queued' AND {eligible}
                AND pending.kind NOT IN ('dns_apply','dns_validate') LIMIT 1""", params).fetchone():
                c.commit()
                return None
            # Deferred writers must not expire a usable domain's read evidence.
            # Runnable earlier writers and every running namespace keep priority.
            row = c.execute(f"""SELECT pending.* FROM domain_jobs AS pending WHERE pending.status='queued'
                AND {eligible}
                AND (:running=0 OR pending.kind IN ('dns_apply','dns_validate'))
                AND NOT EXISTS (SELECT 1 FROM domain_jobs AS active WHERE active.status='running'
                    AND (active.scope=pending.scope
                         OR substr(active.scope,-length(pending.scope)-1)='.'||pending.scope
                         OR substr(pending.scope,-length(active.scope)-1)='.'||active.scope))
                AND (pending.kind<>'dns_validate' OR NOT EXISTS (
                    SELECT 1 FROM domain_jobs AS writer
                    WHERE (writer.scope=pending.scope
                           OR substr(writer.scope,-length(pending.scope)-1)='.'||pending.scope
                           OR substr(pending.scope,-length(writer.scope)-1)='.'||writer.scope)
                    AND (writer.status='running' OR (writer.status='queued' AND {writer_eligible}))
                    AND (writer.kind IN ('dns_apply','dns_hosting') OR
                         (writer.kind='dns_repair' AND COALESCE(
                          json_extract(writer.result_json,'$.repair.phase'),'')
                          NOT IN ('recreated','publication_wait')))
                    AND writer.created_at<=pending.created_at))
                ORDER BY CASE
                    WHEN pending.kind='dns_validate' AND pending.created_at<=:aged THEN -1
                    WHEN pending.kind IN ('claim','import','claim_recover') THEN 0
                    WHEN pending.kind='dns_hosting' THEN 3
                    WHEN pending.kind='claim_setup' THEN 4
                    WHEN pending.kind='dns_validate' AND pending.idempotency_key LIKE 'auto-readiness:%' THEN 2
                    ELSE 1 END,pending.created_at,pending.id LIMIT 1""", params).fetchone()
            if row:
                c.execute("UPDATE domain_jobs SET status='running',step='dispatching',updated_at=? WHERE id=?", (time.time(), row["id"]))
            c.commit()
            return self.get(row["id"]) if row else None
        finally:
            c.close()

    def defer(self, job_id, *, step, result):
        """Release the single worker while a read-only propagation retry waits."""
        c = self.db()
        try:
            with c:
                c.execute("""UPDATE domain_jobs SET status='queued',step=?,result_json=?,updated_at=?
                    WHERE id=? AND status='running'""", (step, json.dumps(result), time.time(), job_id))
        finally:
            c.close()

    def finish(self, job_id, status, *, step, result=None, error=""):
        if status not in {"succeeded", "failed", "partial", "unknown"}:
            raise ValueError("invalid job terminal status")
        c = self.db()
        try:
            c.execute("UPDATE domain_jobs SET status=?,step=?,result_json=?,error_code=?,updated_at=? WHERE id=? AND status='running'",
                      (status, step, json.dumps(result or {}), error, time.time(), job_id))
            c.commit()
        finally:
            c.close()

    def recover_interrupted(self):
        # Called once on startup in the supported single-process deployment.
        # Even read-only jobs are conservatively left for explicit new requests.
        c = self.db()
        try:
            c.execute("UPDATE domain_jobs SET status='unknown',error_code='worker_interrupted',updated_at=? WHERE status='running'", (time.time(),))
            c.commit()
        finally:
            c.close()

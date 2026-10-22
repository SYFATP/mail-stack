"""Periodic read-only readiness validation; never apply DNS or replay claims."""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import smtplib
import threading
import time

from api.services.dns_plan import build_plan

logger = logging.getLogger("domain-readiness")
PREFIX = "auto-readiness:"


def _seconds(name, default, minimum=1):
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, value)


def smtp_submission_check(row, *, smtp_factory=None):
    """Check the actual trusted submission path, without ever issuing DATA.

    An envelope addressed to the reserved .invalid namespace tests relay
    permission. RSET discards it: no message, outbound API request or recipient
    delivery is created. This is readiness, not proof of downstream delivery.
    """
    smtp_factory = smtp_factory or smtplib.SMTP
    try:
        host = os.getenv("SMTP_SUBMISSION_HOST", "mail-postfix")
        port = int(os.getenv("SMTP_SUBMISSION_PORT", "25"))
        if not host or not 1 <= port <= 65535:
            raise ValueError("invalid SMTP endpoint")
        with smtp_factory(host, port, timeout=10) as smtp:
            for operation, args in (
                (smtp.ehlo, ()),
                (smtp.mail, ("postmaster@" + row["domain"],)),
                (smtp.rcpt, ("readiness-probe@example.invalid",)),
                (smtp.rset, ()),
            ):
                code, _ = operation(*args)
                if code != 250:
                    return {"status": "failed", "detail": "smtp_submission_envelope_rejected"}
        return {"status": "passed", "detail": "smtp_submission_envelope_accepted_no_data"}
    except Exception:
        # Never persist exception text, SMTP banners or credentials.
        return {"status": "failed", "detail": "smtp_submission_probe_failed"}


class ReadinessRefresh:
    """Bounded scheduler sharing the existing single-process domain worker."""

    def __init__(self, manager, *, clock=None, monotonic=None):
        self.manager = manager
        self.clock = clock or time.time
        self.monotonic = monotonic or time.monotonic
        self._next_scan = 0
        self._lock = threading.Lock()

    def tick(self):
        if os.getenv("DNS_READINESS_REFRESH_ENABLED", "1").strip().lower() not in {"1", "true", "yes", "on"}:
            return []
        if not self._lock.acquire(blocking=False):
            return []
        try:
            age = _seconds("DNS_CHECK_MAX_AGE_SECONDS", 3600, 60)
            interval = min(_seconds("DNS_READINESS_SCAN_SECONDS", 30), max(1, age // 4))
            mono = self.monotonic()
            if mono < self._next_scan:
                return []
            self._next_scan = mono + interval
            now = self.clock()
            retry = min(_seconds("DNS_READINESS_RETRY_SECONDS", 60), max(1, age // 4))
            batch = min(_seconds("DNS_READINESS_BATCH_SIZE", 16), 100)
            c = self.manager.db()
            try:
                domains = [dict(row) for row in c.execute(
                    """SELECT * FROM mail_domains WHERE enabled=1 AND
                       (receive_enabled=1 OR send_enabled=1) AND
                       source_status NOT IN ('released','revoked','expired','releasing')
                       ORDER BY domain""")]
                checks = {}
                for check in c.execute("SELECT * FROM domain_checks"):
                    checks.setdefault(check["domain"], {})[check["check_name"]] = dict(check)
                eligible, eligibility_params = self.manager.jobs.queued_eligibility(
                    "pending", now, self.manager.jobs.cooldowns(c, now))
                active = {row["scope"] for row in c.execute(f"""SELECT scope FROM domain_jobs pending
                    WHERE kind IN ('dns_validate','dns_apply','dns_repair','dns_hosting','claim_setup','dynv6_register','dns_complete')
                    AND (status='running' OR (status='queued' AND
                         (kind='dns_validate' OR ({eligible}))))""", eligibility_params)}
                attempts = {row["scope"]: row["updated_at"] for row in c.execute(
                    """SELECT scope,max(updated_at) AS updated_at FROM domain_jobs
                       WHERE kind='dns_validate' AND idempotency_key LIKE 'auto-readiness:%'
                       GROUP BY scope""")}
            finally:
                c.close()
            due = []
            for row in domains:
                domain = row["domain"]
                if domain in active or now - attempts.get(domain, 0) < retry:
                    continue
                try:
                    plan = build_plan(row, self.manager.key_root)
                    required = set()
                    if row["receive_enabled"]:
                        required.add("mx")
                        if row["receive_subdomains"] and row["max_subdomain_depth"]:
                            required.add("wildcard_mx")
                    if row["send_enabled"]:
                        required.update(("spf", "dkim", "dmarc", "smtp_submission"))
                    observed = checks.get(domain, {})
                    deadlines = []
                    for name in required:
                        check = observed.get(name, {})
                        timestamp = float(check.get("checked_at", 0))
                        if (check.get("status") != "passed" or
                            check.get("config_hash") != plan["config_hash"] or
                            not math.isfinite(timestamp) or timestamp > now):
                            deadlines.append(0)
                        else:
                            deadlines.append(timestamp + age / 2)
                    if deadlines and min(deadlines) <= now:
                        due.append((min(deadlines), domain, plan))
                except Exception:
                    logger.error("readiness plan unavailable")  # No domain/credential exception data.
            # Oldest/missing evidence first; one broken domain cannot starve
            # other domains when the batch size is smaller than the inventory.
            due.sort(key=lambda item: (item[0], attempts.get(item[1], 0), item[1]))
            scheduled = []
            for _, domain, plan in due[:batch]:
                key = PREFIX + hashlib.sha256(
                    (domain + ":" + plan["plan_hash"]).encode()).hexdigest()[:32] + ":" + str(int(now // retry))
                try:
                    job = self.manager.jobs.enqueue("dns_validate", domain, key, {
                        "config_hash": plan["config_hash"], "plan_hash": plan["plan_hash"],
                        "refresh_smtp_submission": True,
                    })
                    scheduled.append(job["id"])
                except Exception:
                    logger.error("readiness validation enqueue failed")
            return scheduled
        finally:
            self._lock.release()

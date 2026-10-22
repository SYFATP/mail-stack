"""P2 domain control-plane. All writes require administrator authentication.

Supported execution model: one API process and a bounded domain I/O pool. No upstream
claim is automatically replayed after timeout, ambiguous response or restart.
"""
from __future__ import annotations
import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from pathlib import Path
from api.providers.http import JsonTransport, ProviderError, validate_base_url
from api.providers.projections import items, public_item
from api.providers.sources.sfreg_mx import SFRegMX
from api.providers.sources.legacy_digitalplat import LegacyDigitalPlat
from api.providers.sources.cloudflare_inventory import CloudflareInventory
from api.providers.dns.cloudflare import CloudflareDNS
from api.providers.dns.dynv6 import Dynv6DNS
from api.providers.dns.digitalplat import DigitalPlatDNS, DIGITALPLAT_DNS_NOT_ENABLED
from api.providers.brevo import BrevoAPI
from api.repositories.credentials import CredentialStore, CredentialError
from api.repositories.domain_jobs import DomainJobs, JobConflict, assert_domain_mutable, job_concurrency
from api.services.routing import normalize_domain, normalize_local, config_hash
from api.services.dns_plan import build_plan, DNSValidator, dkim_value

SOURCE_ADAPTERS = {"sfreg_mx": SFRegMX, "legacy_digitalplat_pool": LegacyDigitalPlat,
                   "cloudflare_import": CloudflareInventory}
SECRET_FIELDS = {"sfreg_mx": {"api_key"}, "legacy_digitalplat_pool": {"admin_key"},
                 "cloudflare_import": {"api_token"}, "cloudflare": {"api_token"},
                 "digitalplat": {"api_token", "api_base"}, "dynv6": {"api_token"}}


def clean_secret(provider, secret):
    allowed = [SECRET_FIELDS[provider]]
    if provider == "cloudflare":
        allowed.append({"api_email", "api_key"})
    if set(secret) not in allowed:
        raise ValueError("credential fields do not match provider contract")
    result = {}
    for name, value in secret.items():
        if not isinstance(value, str) or not value or len(value) > 8192 or "\r" in value or "\n" in value:
            raise ValueError("invalid credential field")
        result[name] = value
    if provider == "digitalplat":
        result["api_base"] = validate_base_url(result["api_base"])
    return result


def _policy_value(value, prefix, default):
    text = str(value or "").strip()
    match = re.search(rf"(?i)(?:^|[;\s]){re.escape(prefix)}\s*=\s*([^\s;]+)", text)
    return match.group(1).lower() if match else default


def _dkim_public_key(value):
    match = re.search(r"(?i)(?:^|;)\s*p\s*=\s*([A-Za-z0-9+/=]+)", str(value or ""))
    if not match:
        raise ValueError("DKIM public key is not ready")
    return match.group(1)


def _spf_policy(value):
    match = re.search(r"(?i)(?:^|\s)(-all|~all|\?all)\s*$", str(value or "").strip())
    return match.group(1).lower() if match else "-all"


class DomainManager:
    def __init__(self, db, save_domain, domain_lock, *, transport=None, credential_factory=CredentialStore,
                 validator=None, key_root=Path("/dkim/keys"), global_cloudflare_secret=None, domain_public=None,
                 bulk_save_domain=None, publish_domains=None):
        self.db, self.save_domain, self.lock = db, save_domain, domain_lock
        self.bulk_save_domain = bulk_save_domain or save_domain
        self.publish_domains = publish_domains
        self.http = transport or JsonTransport()
        self.credentials = credential_factory
        self.validator = validator or DNSValidator()
        self.key_root = key_root
        self.global_cloudflare_secret = global_cloudflare_secret
        self.domain_public = domain_public
        self.jobs = DomainJobs(db)
        self.worker_lock = threading.Lock()
        self.job_concurrency = job_concurrency()
        from api.services.dns_reconcile import DNSReconciler
        self.dns = DNSReconciler(self)
        from api.services.dns_history import DNSHistoryReconciler
        self.dns_history = DNSHistoryReconciler(self)
        from api.services.dns_repair import DNSRepair
        self.dns_repair = DNSRepair(self)
        from api.services.dns_completion import DNSCompletion
        self.dns_completion = DNSCompletion(self)
        from api.services.dynv6_registration import Dynv6Registration
        self.dynv6_registration = Dynv6Registration(self)
        from api.services.dynv6_accounts import Dynv6Accounts
        self.dynv6_accounts = Dynv6Accounts(self)

    def source(self, source_id):
        c = self.db()
        try:
            row = c.execute("SELECT * FROM domain_sources WHERE id=?", (source_id,)).fetchone()
            if not row:
                raise ValueError("domain source not found")
            return dict(row)
        finally:
            c.close()

    def sources(self):
        c = self.db()
        try:
            return [dict(r) for r in c.execute("SELECT * FROM domain_sources ORDER BY created_at,id")]
        finally:
            c.close()

    def create_source(self, name, source_type, base_url, client_id, secret):
        if source_type not in SOURCE_ADAPTERS:
            raise ValueError("unsupported domain source")
        base_url = validate_base_url(base_url)
        if source_type == "cloudflare_import" and base_url != "https://api.cloudflare.com/client/v4":
            raise ValueError("Cloudflare source requires the official API base")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", client_id):
            raise ValueError("invalid immutable source client_id")
        secret = clean_secret(source_type, secret)
        source_id = uuid.uuid4().hex
        c = self.db()
        try:
            with c:
                ref = self.credentials().put(c, source_type, secret, label=name)
                c.execute("INSERT INTO domain_sources VALUES(?,?,?,?,?,?,?,?)",
                          (source_id, name, source_type, base_url, client_id, ref, 1, time.time()))
        finally:
            c.close()
        return self.source(source_id)

    def adapter(self, source):
        if not source["enabled"]:
            raise ValueError("domain source is disabled")
        c = self.db()
        try:
            secret = self.credentials().get(c, source["credential_ref"], provider=source["source_type"])
        finally:
            c.close()
        return SOURCE_ADAPTERS[source["source_type"]](self.http, source["base_url"], secret, source["client_id"])

    @staticmethod
    def source_pool(source, status=None, sync_provider=None):
        if status is None and sync_provider is None:
            return {}  # Keep existing requests and persisted MX jobs unchanged.
        if source["source_type"] != "sfreg_mx":
            raise ValueError("pool filters are only available for SFREG sources")
        status = status if status is not None else "synced"
        sync_provider = sync_provider if sync_provider is not None else "cloudflare"
        if status not in {"registered", "synced", "sync_failed", "all"}:
            raise ValueError("invalid source pool status")
        if sync_provider not in {"none", "cloudflare", "all", "digitalplat_dns"}:
            raise ValueError("invalid source pool sync_provider")
        if sync_provider == "digitalplat_dns":
            if status != "synced":
                raise ValueError("DigitalPlat MX pool only supports synced status")
            return {}
        return {"status": status, "sync_provider": sync_provider}

    def candidates(self, source_id, count, *, status=None, sync_provider=None):
        source = self.source(source_id)
        pool = self.source_pool(source, status, sync_provider)
        adapter = self.adapter(source)
        try:
            return adapter.candidates(count, **pool)
        except ProviderError:
            raise
        except Exception:
            raise ProviderError("invalid_provider_inventory_response") from None

    def create_claim_job(self, source_id, key, local_part="support", external_ids=None, count=1,
                         status=None, sync_provider=None, configure_on_success=False):
        if type(count) is not int or not 1 <= count <= 200:
            raise ValueError("claim count must be an integer from 1 to 200")
        source = self.source(source_id)
        if not source["enabled"]:
            raise ValueError("domain source is disabled")
        if source["source_type"] == "cloudflare_import":
            raise ValueError("Cloudflare inventory requires import, not claim")
        pool = self.source_pool(source, status, sync_provider)
        local_part = normalize_local(local_part)
        external_ids = external_ids or []
        if source["source_type"] == "legacy_digitalplat_pool":
            if (len(external_ids) != count or len(set(external_ids)) != len(external_ids)
                    or any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", item) for item in external_ids)):
                raise ValueError("legacy pool claim requires distinct external_ids matching count")
        elif pool and external_ids:
            if (len(external_ids) != count or len(set(external_ids)) != count
                    or any(not re.fullmatch(r"[1-9][0-9]{0,18}", item) for item in external_ids)):
                raise ValueError("registered pool requires distinct numeric external_ids matching count")
        elif external_ids:
            raise ValueError("SFREG claim does not accept candidate external_ids")
        self.credentials().require_writer()  # Fail BEFORE any external side effect.
        request = {"local_part": local_part, "external_ids": external_ids, "client_id": source["client_id"]}
        request.update(pool)
        if configure_on_success:
            request["configure_on_success"] = True
        # Preserve the canonical payload of existing single-domain retry keys.
        if count != 1:
            request["count"] = count
        return self.jobs.enqueue("claim", source_id, key, request)

    def create_import_job(self, source_id, domain, key):
        source = self.source(source_id)
        if not source["enabled"] or source["source_type"] != "cloudflare_import":
            raise ValueError("source is not enabled Cloudflare inventory")
        self.credentials().require_writer()
        return self.jobs.enqueue("import", source_id, key, {"domain": normalize_domain(domain), "client_id": source["client_id"]})

    def domain(self, domain):
        domain = normalize_domain(domain)
        c = self.db()
        try:
            row = c.execute("SELECT * FROM mail_domains WHERE domain=?", (domain,)).fetchone()
            if not row:
                raise ValueError("managed domain not found")
            return dict(row)
        finally:
            c.close()

    def plan(self, domain):
        return build_plan(self.domain(domain), self.key_root)

    def provision_payload(self, domain):
        row = self.domain(domain)
        plan = self.plan(domain)
        dkim = next((item for item in plan["records"] if item["role"] == "dkim"), None)
        if not dkim:
            raise ValueError("DKIM public key is not ready")
        dmarc = str(row.get("dmarc") or "")
        return {
            "mail_host": row["mx"],
            "server_ipv4": os.getenv("PUBLIC_SERVER_IP", "203.0.113.10"),
            "mx_priority": 10,
            "ttl": 300,
            "dkim": {
                "selector": row.get("dkim_selector") or "default",
                "public_key": _dkim_public_key(dkim["content"]),
            },
            "spf": {"policy": _spf_policy(row.get("spf"))},
            "dmarc": {
                "policy": _policy_value(dmarc, "p", "none"),
                "rua": _policy_value(dmarc, "rua", f"mailto:dmarc@{row['domain']}"),
                "adkim": _policy_value(dmarc, "adkim", "r"),
                "aspf": _policy_value(dmarc, "aspf", "r"),
            },
            # The local plan owns MX/SPF/DKIM/DMARC. Bounce records are
            # intentionally disabled until the local plan exposes them too.
            "bounce": {"enabled": False, "prefix": "bounce"},
            "requested_records": {
                "root_mx": True,
                "spf": True,
                "dkim": True,
                "dmarc": True,
            },
        }

    def create_validate_job(self, domain, key, *, activate_on_success=False):
        domain = normalize_domain(domain)
        if activate_on_success:
            c = self.db()
            try:
                prior = c.execute("SELECT * FROM domain_jobs WHERE kind='dns_validate' AND scope=? AND idempotency_key=?",
                                  (domain, key)).fetchone()
                prior = self.jobs.public(prior)
            finally:
                c.close()
            if prior and prior["request"].get("activate_on_success"):
                # The activation itself changes config_hash. A retry still
                # refers to that original durable operation, never a new one.
                return self.jobs.enqueue("dns_validate", domain, key, prior["request"])
            if self.domain(domain)["dns_provider"] == "dynv6":
                return self.dns_completion.enqueue(domain, key)
        plan = self.plan(domain)
        request = {"config_hash": plan["config_hash"], "plan_hash": plan["plan_hash"]}
        if activate_on_success:
            request.update(activate_on_success=True, refresh_smtp_submission=True)
        return self.jobs.enqueue("dns_validate", plan["domain"], key, request)

    def add_dns_credential(self, provider, domain, label, secret):
        secret = clean_secret(provider, secret)
        domain = normalize_domain(domain) if domain else None
        if provider == "digitalplat" and not domain:
            raise ValueError("DigitalPlat credential must be bound to one domain")
        c = self.db()
        try:
            with c:
                ref = self.credentials().put(c, provider, secret, domain=domain, label=label)
            return next(r for r in CredentialStore.public(c) if r["id"] == ref)
        finally:
            c.close()

    def global_cloudflare_status(self):
        secret = self.global_cloudflare_secret() if self.global_cloudflare_secret else {}
        return {"configured": bool(secret), "auth_mode": (
            "api_token" if secret.get("api_token") else "global_api_key" if secret else "")}

    def bind_global_cloudflare(self, domain):
        """Explicitly import the existing global credential for one legacy domain."""
        with self.lock:
            row = self.domain(domain)
            assert_domain_mutable(self.db, row["domain"])
            if row["dns_provider"] != "cloudflare":
                raise ValueError("global Cloudflare binding requires a Cloudflare domain")
            ref = "global-cloudflare-" + hashlib.sha256(row["domain"].encode()).hexdigest()[:32]
            if row["dns_credential_ref"]:
                if row["dns_credential_ref"] == ref:
                    return {"domain": row["domain"], "dns_provider": "cloudflare", "dns_credential_ref": ref}
                raise JobConflict("domain already has a DNS credential binding")
            secret = self.global_cloudflare_secret() if self.global_cloudflare_secret else {}
            if not secret:
                raise CredentialError("global Cloudflare credential is not configured")
            secret = clean_secret("cloudflare", secret)
            self.credentials().require_writer()
            inventory = CloudflareDNS(self.http, secret).inventory(row["domain"])
            if not inventory.get("complete"):
                raise ProviderError("dns_inventory_incomplete")
            c = self.db()
            try:
                with c:
                    self.credentials().put(c, "cloudflare", secret, domain=row["domain"],
                                           label="Cloudflare · 全局凭据导入", credential_id=ref)
                    c.execute("UPDATE mail_domains SET dns_credential_ref=?,updated_at=? WHERE domain=?",
                              (ref, time.time(), row["domain"]))
            finally:
                c.close()
            # This changes credential metadata only. Provider, DNS policy and
            # config_hash stay identical, so existing validation remains valid.
            return {"domain": row["domain"], "dns_provider": "cloudflare", "dns_credential_ref": ref}

    def bind_dns_credential(self, domain, ref):
        with self.lock:
            row = self.domain(domain)
            assert_domain_mutable(self.db, row["domain"])
            c = self.db()
            try:
                credential = c.execute("SELECT provider FROM dns_credentials WHERE id=?", (ref,)).fetchone()
                if not credential or credential["provider"] not in {"cloudflare", "digitalplat", "dynv6"}:
                    raise ValueError("DNS credential reference not found")
                secret = self.credentials().get(c, ref, domain=row["domain"])
                if credential["provider"] == "dynv6":
                    if row["enabled"] and row["dns_provider"] != "dynv6":
                        raise ValueError("Disable this domain before changing DNS provider")
                    Dynv6DNS(self.http, secret, row["domain"]).inventory(row["domain"])
                with c:
                    c.execute("UPDATE mail_domains SET dns_credential_ref=?,dns_provider=?,updated_at=? WHERE domain=?",
                              (ref, credential["provider"], time.time(), row["domain"]))
                    c.execute("DELETE FROM domain_checks WHERE domain=?", (row["domain"],))
            finally:
                c.close()
            # Same publication path and lock as the existing domain controls.
            updated = self.domain(domain)
            updated["users"] = json.loads(updated["users"])
            return self.save_domain(updated, domain)

    def dns_adapter(self, row):
        if not row["dns_credential_ref"] or row["dns_provider"] not in {"cloudflare", "digitalplat", "dynv6"}:
            raise ValueError("domain has no supported DNS credential binding")
        c = self.db()
        try:
            secret = self.credentials().get(c, row["dns_credential_ref"], provider=row["dns_provider"], domain=row["domain"])
        finally:
            c.close()
        if row["dns_provider"] == "cloudflare":
            return CloudflareDNS(self.http, secret)
        if row["dns_provider"] == "dynv6":
            return Dynv6DNS(self.http, secret, row["domain"])
        return DigitalPlatDNS(self.http, secret, row["domain"])

    def dns_inventory(self, domain):
        row = self.domain(domain)
        try:
            inventory = self.dns_adapter(row).inventory(row["domain"])
        except (ProviderError, ValueError):
            raise
        except Exception:
            raise ProviderError("invalid_provider_inventory_response") from None
        return {"domain": row["domain"], "zone_name": inventory["zone_name"], "complete": inventory["complete"],
                "record_count": len(inventory["records"]), "write_policy": "explicit_preview_apply_only"}

    def create_dns_hosting_job(self, domain, key, *, completion=None):
        if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", key):
            raise ValueError("Idempotency-Key must be 8-128 ASCII identifier characters")
        with self.lock:
            row = self.domain(domain)
            if (row["dns_provider"] != "digitalplat" or not row["dns_credential_ref"]
                    or row["source_status"] in {"released", "revoked", "expired", "releasing"}):
                raise ValueError("domain requires an active DigitalPlat credential binding")
            self.dns_adapter(row)  # Validate encrypted credential scope before enqueue.
            request = {"credential_ref": row["dns_credential_ref"]}
            if completion:
                request["completion"] = completion
            c = self.db()
            try:
                same = c.execute(
                    "SELECT id FROM domain_jobs WHERE kind='dns_hosting' AND scope=? AND idempotency_key=?",
                    (row["domain"], key)).fetchone()
                active = c.execute(
                    "SELECT * FROM domain_jobs WHERE kind='dns_hosting' AND scope=? AND status IN ('queued','running')",
                    (row["domain"],)).fetchone()
            finally:
                c.close()
            if same:
                return self.jobs.enqueue("dns_hosting", row["domain"], key, request)
            if active:
                if json.loads(active["request_json"]) != request:
                    raise JobConflict("DNS hosting preparation uses a different credential; wait for it to finish")
                return self.jobs.public(active)
            return self.jobs.enqueue("dns_hosting", row["domain"], key, request)

    def _execute_dns_hosting(self, job):
        """Initialize a missing Hosted DNS service once, with durable fencing."""
        dispatched = accepted = False
        try:
            with self.lock:
                row = self.domain(job["scope"])
                if (row["dns_provider"] != "digitalplat"
                        or row["dns_credential_ref"] != job["request"].get("credential_ref")
                        or row["source_status"] in {"released", "revoked", "expired", "releasing"}):
                    raise ValueError("DNS binding changed before hosting preparation")
                adapter = self.dns_adapter(row)
                try:
                    inventory = adapter.inventory(row["domain"])
                except ProviderError as exc:
                    if exc.code != DIGITALPLAT_DNS_NOT_ENABLED:
                        raise
                    inventory = None
                if inventory is None:
                    c = self.db()
                    try:
                        prior = c.execute(
                            """SELECT status,result_json FROM domain_jobs
                               WHERE kind='dns_hosting' AND scope=? AND id!=?
                               AND status IN ('unknown','partial')""", (row["domain"], job["id"])).fetchall()
                    finally:
                        c.close()
                    if any(r["status"] == "unknown" or json.loads(r["result_json"]).get("enable_dispatched") for r in prior):
                        self.jobs.finish(job["id"], "partial", step="dns_hosting_pending",
                                         result={"domain": row["domain"], "hosting_status": "pending",
                                                 "enable_dispatched": False, "next_action": "dns_hosting"},
                                         error="dns_hosting_enable_unconfirmed")
                        return
                    adapter.hosting_preflight()
                    c = self.db()
                    try:
                        with c:
                            c.execute(
                                "UPDATE domain_jobs SET step='dns_hosting_enabling',result_json=?,updated_at=? WHERE id=? AND status='running'",
                                (json.dumps({"enable_dispatched": True}), time.time(), job["id"]))
                    finally:
                        c.close()
                    dispatched = True
                    adapter.enable_hosted("mail-stack-dns-hosting-" + job["id"])
                    accepted = True
                    # A successful enable ACK is not proof that record CRUD is ready.
                    for attempt in range(3):
                        try:
                            inventory = adapter.inventory(row["domain"])
                            break
                        except ProviderError as exc:
                            if exc.code != DIGITALPLAT_DNS_NOT_ENABLED:
                                raise
                            if attempt < 2:
                                time.sleep(1)
                    if inventory is None:
                        self.jobs.finish(job["id"], "partial", step="dns_hosting_pending",
                                         result={"domain": row["domain"], "hosting_status": "pending",
                                                 "enable_dispatched": True, "next_action": "dns_hosting"},
                                         error="dns_hosting_enable_unconfirmed")
                        return
                observed = []
                c = self.db()
                try:
                    with c:
                        for prior in c.execute(
                            """SELECT * FROM domain_jobs WHERE kind='dns_hosting' AND scope=? AND id!=?
                               AND status IN ('unknown','partial')""", (row["domain"], job["id"])).fetchall():
                            if json.loads(prior["request_json"]) != job["request"]:
                                continue
                            result = json.loads(prior["result_json"])
                            result.update(hosting_status="ready", reconciled_by=job["id"],
                                          original_error=prior["error_code"])
                            c.execute(
                                """UPDATE domain_jobs SET status='succeeded',step='dns_hosting_observed',
                                   result_json=?,error_code='',updated_at=? WHERE id=?""",
                                (json.dumps(result), time.time(), prior["id"]))
                            observed.append(prior["id"])
                finally:
                    c.close()
                result = {"domain": row["domain"], "hosting_status": "ready",
                          "enable_dispatched": dispatched, "record_count": len(inventory["records"]),
                          "observed_jobs": observed, "next_action": "dns_preview"}
            # Network preview work must not hold the configuration lock.
            if job["request"].get("completion"):
                result.update(self._queue_claim_completion(job["request"]["completion"]))
            self.jobs.finish(job["id"], "partial" if result.get("configuration_status") in {"pending", "blocked"} else "succeeded",
                             step="dns_hosting_ready", result=result)
        except Exception as exc:
            uncertain = dispatched and (accepted or not isinstance(exc, ProviderError) or exc.uncertain)
            self.jobs.finish(job["id"], "unknown" if uncertain else "failed",
                             step="dns_hosting_unconfirmed" if uncertain else "dns_hosting_failed",
                             result={"domain": job["scope"], "enable_dispatched": dispatched,
                                     "hosting_status": "unknown" if uncertain else "failed",
                                     **self.jobs.provider_backoff(job["scope"], exc)},
                             error=exc.code if isinstance(exc, ProviderError) else "dns_hosting_preparation_failed")

    def brevo(self):
        api_key = os.getenv("BREVO_API_KEY", "").strip()
        if not api_key:
            raise CredentialError("Brevo API key is not configured")
        return BrevoAPI(self.http, api_key, os.getenv("BREVO_API_BASE", "https://api.brevo.com").strip())

    def brevo_domains(self):
        return {"domains": self.brevo().list_domains()}

    @staticmethod
    def brevo_sync_enabled():
        return os.getenv("BREVO_DNS_SYNC_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}

    def brevo_create_domain(self, domain):
        domain = normalize_domain(domain)
        existing = self.brevo().get_domain(domain)
        if existing:
            return {"domain": existing, "created": False}
        return {"domain": self.brevo().create_domain(domain), "created": True}

    def brevo_authenticate_domain(self, domain):
        domain = normalize_domain(domain)
        return self.brevo().authenticate_domain(domain)

    def brevo_authentication_result(self, domain):
        """Attempt Brevo authentication without making DNS validation fail.

        DNS propagation and Brevo's verification edge are eventually
        consistent.  A DNS validation job must keep its authoritative result
        even when Brevo is temporarily unavailable; the next validation will
        retry this idempotent call.
        """
        if not self.brevo_sync_enabled():
            return {"status": "disabled"}
        try:
            setup = self.ensure_brevo_domain(domain)
            api = self.brevo()
            before = setup.get("domain") if isinstance(setup, dict) else {}
            before = before if isinstance(before, dict) else {}
            if bool(before.get("authenticated")) and bool(before.get("verified")):
                detail = before
            else:
                response = api.authenticate_domain(normalize_domain(domain))
                # Brevo's authenticate endpoint may acknowledge the request
                # with a message only. Read the domain resource again so the
                # result reflects the provider's durable authentication state.
                try:
                    detail = api.get_domain(normalize_domain(domain)) or response
                except ProviderError:
                    # The authentication request itself was accepted; retain a
                    # retryable requested state if the follow-up read is
                    # temporarily unavailable.
                    detail = response
        except ProviderError as exc:
            return {"status": "pending", "error_code": exc.code}
        except Exception:
            return {"status": "pending", "error_code": "brevo_authentication_failed"}
        if isinstance(detail, dict) and isinstance(detail.get("domain"), dict):
            detail = detail["domain"]
        detail = detail if isinstance(detail, dict) else {}
        authenticated = bool(detail.get("authenticated"))
        verified = bool(detail.get("verified"))
        return {
            "status": "authenticated" if authenticated and verified else "requested",
            "authenticated": authenticated,
            "verified": verified,
        }

    def ensure_brevo_domain(self, domain):
        """Ensure the domain exists in Brevo before building DNS targets.

        SFREG claims arrive with a DigitalPlat DNS credential, but Brevo keeps
        its own sender-domain registry.  Registration is idempotent and is
        performed lazily from the DNS preview path as a repair for older
        claims that predate automatic Brevo setup.
        """
        domain = normalize_domain(domain)
        api = self.brevo()
        existing = api.get_domain(domain)
        if existing:
            return {"domain": existing, "created": False}
        try:
            created = api.create_domain(domain)
        except ProviderError as exc:
            # A concurrent preview may have created the domain between the
            # GET and POST.  Re-read only for a conflict-style response.
            if exc.code not in {"provider_http_400", "provider_http_409"}:
                raise
            existing = api.get_domain(domain)
            if not existing:
                raise
            return {"domain": existing, "created": False}
        return {"domain": created, "created": True}

    def brevo_dns_targets(self, row):
        """Return Brevo verification records for DNS preview/apply.

        Brevo's DMARC recommendation is intentionally excluded: mail-stack
        owns the single DMARC record in the normal domain plan.  Verification
        code and DKIM records are safe additive records.
        """
        if not self.brevo_sync_enabled():
            return []
        detail = self.ensure_brevo_domain(row["domain"])["domain"]
        dns_records = detail.get("dns_records") if isinstance(detail, dict) else {}
        if not isinstance(dns_records, dict):
            raise ProviderError("invalid_brevo_domain_response")
        targets = []
        for key in ("dkim1Record", "dkim2Record", "dkim_record", "brevo_code"):
            item = dns_records.get(key)
            if not isinstance(item, dict):
                continue
            host = str(item.get("host_name") or "").strip().rstrip(".")
            value = str(item.get("value") or "").strip()
            kind = str(item.get("type") or "").upper()
            if not host or not value or kind not in {"TXT", "CNAME"}:
                continue
            domain_labels = row["domain"].split(".")
            root_label = domain_labels[0]
            if host in {"@", "", root_label}:
                name = row["domain"]
            elif host.endswith("." + row["domain"]):
                # Some Brevo responses already return an absolute owner name.
                name = host
            elif host.endswith("." + root_label):
                # Brevo returns e.g. ``_dmarc.sender`` for a domain
                # ``sender.example.test``.  The record belongs at
                # ``_dmarc.sender.example.test``, not below the managed subdomain.
                name = host[:-(len(root_label))] + row["domain"]
            else:
                name = host + "." + row["domain"]
            targets.append({"role": "brevo_auth", "type": kind, "name": name,
                            "content": value, "ttl": 300})
        return targets

    def _record_claim(self, source, job, raw):
        public = public_item(raw)
        # Persist known allocation metadata first. Saving credentials/receipt is
        # a separate explicit step, so failure never erases an allocated claim.
        claim_id = uuid.uuid4().hex
        c = self.db()
        try:
            with c:
                existing = c.execute("SELECT * FROM domain_claims WHERE source_id=? AND domain=?", (source["id"], public["domain"])).fetchone()
                if existing:
                    reclaimable = (
                        source["source_type"] == "sfreg_mx"
                        and existing["status"] == "awaiting_dns"
                        and existing["upstream_status"] in {"", "reserved", "available", "released", "expired", "revoked"}
                    )
                    if existing["job_id"] != job["id"] and source["source_type"] != "cloudflare_import" and not reclaimable:
                        raise ValueError("domain already has an allocation from another job")
                    claim_id = existing["id"]
                    if existing["job_id"] != job["id"]:
                        c.execute(
                            """UPDATE domain_claims
                               SET upstream_claim_id=?,external_id=?,client_id=?,upstream_status=?,
                                   status='credential_pending',job_id=?,receipt_ref=NULL
                               WHERE id=?""",
                            (public["claim_id"], public["external_id"], source["client_id"],
                             public["status"], job["id"], claim_id),
                        )
                else:
                    c.execute("""INSERT INTO domain_claims(id,source_id,domain,upstream_claim_id,external_id,client_id,
                        upstream_status,status,job_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        (claim_id, source["id"], public["domain"], public["claim_id"], public["external_id"],
                         source["client_id"], public["status"], "credential_pending", job["id"], time.time()))
            with c:
                receipt_ref = self.credentials().put(c, "claim_receipt", {"payload": raw}, domain=public["domain"], label="claim receipt")
                c.execute("UPDATE domain_claims SET receipt_ref=? WHERE id=?", (receipt_ref, claim_id))
        finally:
            c.close()
        return claim_id

    def claim_row(self, claim_id):
        c = self.db()
        try:
            row = c.execute("SELECT * FROM domain_claims WHERE id=?", (claim_id,)).fetchone()
            if not row:
                raise ValueError("local claim not found")
            return dict(row)
        finally:
            c.close()

    def claims(self):
        c = self.db()
        try:
            rows = [dict(r) for r in c.execute("SELECT * FROM domain_claims ORDER BY created_at DESC")]
            for row in rows:
                try:
                    row["nameservers"] = json.loads(row.pop("nameservers_json", "[]") or "[]")
                except (TypeError, ValueError):
                    row["nameservers"] = []
                row["dns_mode"] = "direct_dns"
                # SFREG allocations already belong to the provider that
                # issued their DNS credential.  DNS records are managed
                # through that credential; there is no separate NS
                # provisioning step for any suffix or source.
                row["nameserver_required"] = False
            return rows
        finally:
            c.close()

    def _claim_sfreg_job(self, claim_id, key, kind, request=None, *, allow_registered_pool=False):
        row = self.claim_row(claim_id)
        source = self.source(row["source_id"])
        if source["source_type"] != "sfreg_mx":
            raise ValueError("claim lifecycle contract is only available for SFREG MX")
        if "status" in self.jobs.get(row["job_id"])["request"] and not allow_registered_pool:
            raise ValueError("registered pool claims require local DNS binding, not MX lifecycle operations")
        if not row["upstream_claim_id"]:
            raise ValueError("claim has no upstream claim_id")
        self.credentials().require_writer()
        body = {"claim_id": claim_id, "upstream_claim_id": row["upstream_claim_id"],
                "source_id": source["id"], "client_id": source["client_id"]}
        if request:
            body.update(request)
        return self.jobs.enqueue(kind, claim_id, key, body)

    def create_claim_status_job(self, claim_id, key):
        return self._claim_sfreg_job(claim_id, key, "claim_status", allow_registered_pool=True)

    def create_claim_report_job(self, claim_id, key, status, checks=None, verified_at=None, error=None):
        if status not in {"validating", "active", "partial", "failed"}:
            raise ValueError("invalid claim report status")
        return self._claim_sfreg_job(claim_id, key, "claim_report", {
            "status": status, "checks": checks or {}, "verified_at": verified_at, "error": error})

    def create_claim_refresh_job(self, claim_id, key):
        return self._claim_sfreg_job(claim_id, key, "claim_refresh")

    def create_claim_provision_job(self, claim_id, key):
        row = self.claim_row(claim_id)
        # Keep the endpoint for older clients, but never dispatch an
        # upstream Nameserver operation.  The next action is the normal DNS
        # credential binding/preview flow.
        return {
            "id": None,
            "claim_id": row["id"],
            "domain": row["domain"],
            "status": "not_required",
            "step": "nameserver_sync_not_required",
            "message": "无需同步 Nameserver，请直接绑定凭据并配置 DNS",
        }

    def create_claim_release_job(self, claim_id, key, reason="mailbox_deleted", environment_stopped=False):
        return self._claim_sfreg_job(claim_id, key, "claim_release", {
            "reason": reason, "environment_stopped": bool(environment_stopped)})

    def create_recover_job(self, claim_id, key):
        row = self.claim_row(claim_id)
        if not row["receipt_ref"]:
            raise ValueError("claim receipt missing; upstream status reconciliation required, do not repeat claim")
        return self.jobs.enqueue("claim_recover", claim_id, key, {})

    def _attach_claim(self, claim_id, *, defer_setup=False, defer_runtime=False):
        row = self.claim_row(claim_id)
        source = self.source(row["source_id"])
        c = self.db()
        try:
            raw = self.credentials().get(c, row["receipt_ref"], provider="claim_receipt", domain=row["domain"])["payload"]
            dns = raw.get("dns") if isinstance(raw.get("dns"), dict) else {}
            ref = row["dns_credential_ref"]
            allocation = c.execute("SELECT request_json FROM domain_jobs WHERE id=?", (row["job_id"],)).fetchone()
            registered_pool = source["source_type"] == "sfreg_mx" and "status" in json.loads(allocation["request_json"])
            if source["source_type"] == "sfreg_mx":
                token = dns.get("api_token") or dns.get("token")
                if token:
                    credential_id = ref
                    if credential_id:
                        prior = c.execute("SELECT provider,domain FROM dns_credentials WHERE id=?", (credential_id,)).fetchone()
                        if not prior or prior["provider"] != "digitalplat" or prior["domain"] != row["domain"]:
                            credential_id = None
                    if not row["upstream_claim_id"]:
                        raise CredentialError("claim has no upstream claim_id; reconciliation required")
                    secret = clean_secret("digitalplat", {"api_token": token, "api_base": dns.get("api_base") or "https://domain-api.digitalplat.org/api/v1"})
                    label = "claimed DNS"
                    if dns.get("account_name"):
                        label = "claimed DNS · " + str(dns["account_name"])[:60]
                    with c:
                        ref = self.credentials().put(c, "digitalplat", secret, domain=row["domain"],
                                                      label=label, credential_id=credential_id)
                        c.execute("UPDATE domain_claims SET dns_credential_ref=?,status='credential_ready' WHERE id=?", (ref, claim_id))
                elif not registered_pool:
                    token = dns.get("api_token") or dns.get("token")
                    if not token:
                        raise CredentialError("claim has no DNS credential; refresh requires upstream reconciliation")
                    if not row["upstream_claim_id"]:
                        raise CredentialError("claim has no upstream claim_id; reconciliation required")
                    secret = clean_secret("digitalplat", {"api_token": token, "api_base": dns.get("api_base") or "https://domain-api.digitalplat.org/api/v1"})
                    with c:
                        ref = self.credentials().put(c, "digitalplat", secret, domain=row["domain"], label="claimed DNS", credential_id=ref)
                        c.execute("UPDATE domain_claims SET dns_credential_ref=?,status='credential_ready' WHERE id=?", (ref, claim_id))
            elif source["source_type"] == "cloudflare_import":
                secret = self.credentials().get(c, source["credential_ref"], provider="cloudflare_import")
                with c:
                    ref = self.credentials().put(c, "cloudflare", secret, label="imported Cloudflare account", credential_id=ref)
                    c.execute("UPDATE domain_claims SET dns_credential_ref=?,status='credential_ready' WHERE id=?", (ref, claim_id))
            else:
                # Registered and legacy pools allocate ownership without DNS
                # credentials. Bind a separate DNS credential after importing.
                with c:
                    c.execute("UPDATE domain_claims SET status='awaiting_dns' WHERE id=?", (claim_id,))
        finally:
            c.close()
        with self.lock:
            c = self.db()
            try:
                existing = c.execute("SELECT * FROM mail_domains WHERE domain=?", (row["domain"],)).fetchone()
                if existing and existing["claim_id"] != claim_id:
                    raise ValueError("managed domain exists with different ownership; explicit migration required")
                data = dict(existing) if existing else {"domain": row["domain"], "enabled": False, "users": [], "receive_mode": "catch_all", "mx": os.getenv("MAIL_HOST")}
                if registered_pool and existing and not ref:
                    ref = existing["dns_credential_ref"]
            finally:
                c.close()
            provider = "cloudflare" if source["source_type"] == "cloudflare_import" else (
                "digitalplat" if ref and (not registered_pool or data.get("dns_provider") == "digitalplat" or dns.get("api_token") or dns.get("token"))
                else (data.get("dns_provider", "manual") if registered_pool else "manual"))
            data.update(source_type=source["source_type"], source_status="imported" if source["source_type"] == "cloudflare_import" else "claimed",
                        source_id=source["id"], claim_id=claim_id, dns_provider=provider, dns_credential_ref=ref)
            # _save_domain expects parsed users, not its persisted JSON representation.
            if isinstance(data["users"], str):
                data["users"] = json.loads(data["users"])
            save = self.bulk_save_domain if defer_runtime else self.save_domain
            save(data, row["domain"])
        c = self.db()
        try:
            with c:
                c.execute("UPDATE domain_claims SET status=?,dns_credential_ref=? WHERE id=?", ("imported" if ref else "awaiting_dns", ref, claim_id))
        finally:
            c.close()
        result = {"claim_id": claim_id, "domain": row["domain"],
                  "status": "imported" if ref else "awaiting_dns", "enabled": bool(data["enabled"])}
        auto = bool(json.loads(allocation["request_json"]).get("configure_on_success"))
        prepare_hosting = bool(registered_pool and provider == "digitalplat" and ref)
        completion = {"claim_id": claim_id, "allocation_job_id": row["job_id"],
                      "credential_ref": ref}
        if (defer_setup or auto) and (self.brevo_sync_enabled() or prepare_hosting or auto):
            try:
                request = {**completion, "prepare_hosting": prepare_hosting}
                if auto:
                    request["configure_on_success"] = True
                result["claim_setup_job"] = self.jobs.enqueue(
                    "claim_setup", row["domain"], "claim-setup:" + claim_id + ":" + row["job_id"],
                    request)
                result["brevo_registration"] = {"status": "queued" if self.brevo_sync_enabled() else "disabled"}
            except Exception:
                # Ownership/credentials are durable even if background enqueue fails.
                result["setup_error"] = "claim_setup_not_queued"
            return result
        return self._prepare_claim_services(result, prepare_hosting)

    def _prepare_claim_services(self, result, prepare_hosting, expected=None, configure_on_success=False):
        """Slow provider work runs independently of bulk allocation/import."""
        result = dict(result)
        result["brevo_registration"] = {"status": "disabled"}
        if self.brevo_sync_enabled() and configure_on_success:
            # DNS preview performs registration and reads the exact records.
            result["brevo_registration"] = {"status": "deferred_to_dns_preview"}
        elif self.brevo_sync_enabled():
            try:
                setup = self.ensure_brevo_domain(result["domain"])
                result["brevo_registration"] = {"status": "registered", "created": bool(setup.get("created"))}
            except ProviderError as exc:
                result["brevo_registration"] = {"status": "pending", "error_code": exc.code}
            except Exception:
                result["brevo_registration"] = {"status": "pending", "error_code": "brevo_registration_failed"}
        if prepare_hosting:
            try:
                with self.lock:
                    if expected is not None:
                        current = self.domain(result["domain"])
                        claim = self.claim_row(expected["claim_id"])
                        if (current["claim_id"] != expected["claim_id"]
                                or current["dns_credential_ref"] != expected["credential_ref"]
                                or claim["job_id"] != expected["allocation_job_id"]
                                or current["source_status"] in {"released", "revoked", "expired", "releasing"}):
                            raise ValueError("claim DNS binding changed during setup")
                    result["dns_hosting_job"] = self.create_dns_hosting_job(
                        result["domain"], "claim-dns-hosting:" + result["claim_id"],
                        completion=expected if configure_on_success else None)
            except Exception:
                result["dns_hosting_error"] = "dns_hosting_prepare_not_queued"
        elif configure_on_success:
            result.update(self._queue_claim_completion(expected))
        return result

    def _queue_claim_completion(self, expected):
        """Persist a previewed apply/validate child; no dependence on an open UI."""
        result = {"next_action": "dns_preview"}
        try:
            claim = self.claim_row(expected["claim_id"])
            row = self.domain(claim["domain"])
            if (row["claim_id"] != claim["id"] or claim["job_id"] != expected["allocation_job_id"]
                    or row["dns_credential_ref"] != expected["credential_ref"]
                    or row["source_status"] in {"released", "revoked", "expired", "releasing"}):
                raise ValueError("claim DNS binding changed before configuration")
            key = "claim-complete:" + expected["allocation_job_id"] + ":" + claim["id"]
            c = self.db()
            try:
                prior = c.execute("""SELECT * FROM domain_jobs WHERE scope=? AND idempotency_key=?
                                  AND kind IN ('dns_apply','dns_validate','dns_complete')""", (row["domain"], key)).fetchone()
                if prior:
                    return {"dns_apply_job": self.jobs.public(prior), "next_action": "wait_for_dns"}
            finally:
                c.close()
            preview = self.dns.preview(row["domain"])
            if not preview["executable"]:
                return {**result, "configuration_status": "blocked",
                        "configuration_conflicts": preview["conflicts"]}
            # Existing records need fresh validation, not a second apply task.
            if all(action["action"] == "exists" for action in preview["actions"]):
                child = self.create_validate_job(row["domain"], key, activate_on_success=True)
            else:
                child = self.dns.enqueue(row["domain"], preview["id"], key, activate_on_success=True)
            return {"dns_apply_job": child, "configuration_status": "queued", "next_action": "wait_for_dns"}
        except Exception as exc:
            return {**result, "configuration_status": "pending",
                    "configuration_error": exc.code if isinstance(exc, ProviderError) else "dns_configuration_not_queued"}

    def _execute_claim_setup(self, job):
        claim = self.claim_row(job["request"]["claim_id"])
        row = self.domain(job["scope"])
        if (row["claim_id"] != claim["id"] or row["domain"] != claim["domain"]
                or claim["job_id"] != job["request"].get("allocation_job_id")
                or row["dns_credential_ref"] != job["request"].get("credential_ref")
                or row["source_status"] in {"released", "revoked", "expired", "releasing"}):
            raise ValueError("claim ownership or DNS binding changed before setup")
        result = self._prepare_claim_services({"claim_id": claim["id"], "domain": row["domain"],
                  "status": claim["status"], "enabled": bool(row["enabled"])},
                  job["request"].get("prepare_hosting", False), expected=job["request"],
                  configure_on_success=job["request"].get("configure_on_success", False))
        pending = (result["brevo_registration"]["status"] == "pending" or bool(result.get("dns_hosting_error"))
                   or result.get("configuration_status") in {"pending", "blocked"})
        self.jobs.finish(job["id"], "partial" if pending else "succeeded", step="claim_services_prepared", result=result)

    def _claim_job_context(self, job):
        claim = self.claim_row(job["scope"])
        if claim["id"] != job["request"].get("claim_id") or claim["upstream_claim_id"] != job["request"].get("upstream_claim_id"):
            raise ValueError("claim lifecycle identity changed")
        source = self.source(claim["source_id"])
        if source["source_type"] != "sfreg_mx" or source["client_id"] != job["request"].get("client_id"):
            raise ValueError("claim lifecycle source changed")
        return claim, source, self.adapter(source)

    def _is_registered_pool_claim(self, claim):
        """Return whether this claim came from the registered SFREG pool."""
        allocation = self.jobs.get(claim["job_id"]) if claim.get("job_id") else None
        request = allocation.get("request", {}) if allocation else {}
        return request.get("sync_provider") == "none" and request.get("status") in {
            "registered", "sync_failed", "all"
        }

    def _upstream_key(self, job):
        return "mail-stack-" + job["id"]

    @staticmethod
    def _upstream_data(response):
        if not isinstance(response, dict):
            return {}
        nested = response.get("data")
        return nested if isinstance(nested, dict) else response

    def _record_claim_upstream(self, claim_id, response, *, fallback_status=""):
        data = self._upstream_data(response)
        status = str(
            response.get("status")
            if isinstance(response, dict)
            else ""
        ).strip().lower() or str(
            data.get("status") or data.get("state") or data.get("upstream_status") or fallback_status
        ).strip().lower()
        containers = [data]
        if isinstance(data.get("dns"), dict):
            containers.append(data["dns"])
        if isinstance(response, dict) and response is not data:
            containers.append(response)
        raw_nameservers = []
        for container in containers:
            raw_nameservers = (container.get("nameservers") or container.get("name_servers")
                               or container.get("nameServers") or container.get("nameserver") or [])
            if raw_nameservers:
                break
        if isinstance(raw_nameservers, str):
            raw_nameservers = [raw_nameservers]
        nameservers = []
        for item in raw_nameservers if isinstance(raw_nameservers, list) else []:
            if isinstance(item, dict):
                item = item.get("host") or item.get("name") or item.get("nameserver") or item.get("value") or ""
            value = str(item).strip().rstrip(".").lower()
            if value and value not in nameservers:
                nameservers.append(value)
        c = self.db()
        try:
            with c:
                if nameservers:
                    c.execute(
                        "UPDATE domain_claims SET upstream_status=?,nameservers_json=? WHERE id=?",
                        (status, json.dumps(nameservers, ensure_ascii=False), claim_id),
                    )
                elif status:
                    c.execute("UPDATE domain_claims SET upstream_status=? WHERE id=?", (status, claim_id))
        finally:
            c.close()
        return status, nameservers

    def _execute_claim_report(self, job):
        claim, source, adapter = self._claim_job_context(job)
        body = {k: job["request"].get(k) for k in ("status", "checks", "verified_at", "error") if job["request"].get(k) is not None}
        response = adapter.report_status(claim["upstream_claim_id"], body, self._upstream_key(job))
        if not isinstance(response, dict):
            raise ProviderError("invalid_claim_report_response", uncertain=True)
        nested = response.get("data") if isinstance(response.get("data"), dict) else {}
        status = str(response.get("status") or nested.get("status") or body["status"]).lower()
        allowed = {"validating", "active", "partial", "failed", "released", "expired", "revoked"}
        if status not in allowed:
            raise ProviderError("invalid_claim_report_status", uncertain=False)
        c = self.db()
        try:
            with c:
                c.execute("UPDATE domain_claims SET upstream_status=? WHERE id=?", (status, claim["id"]))
        finally:
            c.close()
        self.jobs.finish(job["id"], "succeeded", step="upstream_report_recorded", result={"claim_id": claim["id"], "domain": claim["domain"], "upstream_status": status})

    def _execute_claim_refresh(self, job):
        claim, source, adapter = self._claim_job_context(job)
        response = adapter.refresh_credential(claim["upstream_claim_id"], self._upstream_key(job))
        data = response.get("data") if isinstance(response, dict) and isinstance(response.get("data"), dict) else response
        if not isinstance(data, dict):
            raise ProviderError("invalid_claim_refresh_response", uncertain=True)
        token = data.get("api_token") or data.get("token")
        if not isinstance(token, str) or not token:
            raise ProviderError("claim_refresh_missing_dns_token", uncertain=True)
        secret = clean_secret("digitalplat", {"api_token": token, "api_base": data.get("api_base") or "https://domain-api.digitalplat.org/api/v1"})
        c = self.db()
        try:
            with c:
                ref = self.credentials().put(c, "digitalplat", secret, domain=claim["domain"], label="refreshed claimed DNS", credential_id=claim["dns_credential_ref"])
                c.execute("UPDATE domain_claims SET dns_credential_ref=?,status='credential_ready' WHERE id=?", (ref, claim["id"]))
        finally:
            c.close()
        self.jobs.finish(job["id"], "succeeded", step="credential_refreshed", result={"claim_id": claim["id"], "domain": claim["domain"], "credential_ref": ref})

    def _execute_claim_provision(self, job):
        claim = self.claim_row(job["scope"])
        self.jobs.finish(
            job["id"],
            "succeeded",
            step="nameserver_sync_not_required",
            result={
                "claim_id": claim["id"],
                "domain": claim["domain"],
                "nameservers": [],
                "nameservers_assigned": False,
                "next_action": "dns_preview",
                "message": "无需同步 Nameserver，请直接绑定凭据并配置 DNS",
            },
        )

    def _execute_claim_release(self, job):
        claim, source, adapter = self._claim_job_context(job)
        # Stop local acceptance before an upstream release request. An unknown
        # release stays fenced and never auto-retries.
        with self.lock:
            row = self.domain(claim["domain"])
            row["users"] = json.loads(row["users"])
            row.update(enabled=False, receive_enabled=False, send_enabled=False, source_status="releasing")
            self.save_domain(row, claim["domain"])
        response = adapter.release(claim["upstream_claim_id"], {"reason": job["request"].get("reason") or "mailbox_deleted", "environment_stopped": bool(job["request"].get("environment_stopped"))}, self._upstream_key(job))
        if not isinstance(response, dict):
            raise ProviderError("invalid_claim_release_response", uncertain=True)
        nested = response.get("data") if isinstance(response.get("data"), dict) else {}
        status = str(response.get("status") or nested.get("status") or "releasing").lower()
        if status not in {"releasing", "released", "pending"}:
            raise ProviderError("invalid_claim_release_status", uncertain=False)
        c = self.db()
        try:
            with c:
                c.execute("UPDATE domain_claims SET upstream_status=?,status=? WHERE id=?", (status, status, claim["id"]))
        finally:
            c.close()
        if status == "released":
            with self.lock:
                row = self.domain(claim["domain"]); row["users"] = json.loads(row["users"]); row.update(enabled=False, receive_enabled=False, send_enabled=False, source_status="released"); self.save_domain(row, claim["domain"])
        self.jobs.finish(job["id"], "succeeded", step="upstream_release_recorded", result={"claim_id": claim["id"], "domain": claim["domain"], "upstream_status": status})

    def _execute_claim_status(self, job):
        claim, source, adapter = self._claim_job_context(job)
        response = adapter.status(claim["upstream_claim_id"])
        if not isinstance(response, dict):
            raise ProviderError("invalid_claim_status_response", uncertain=True)
        raw_status = str(response.get("status") or response.get("state") or response.get("upstream_status") or "").lower()
        allowed = {"available", "reserved", "claimed", "provisioning", "validating", "synced", "active", "pending", "ready", "released", "expired", "revoked"}
        status = raw_status if raw_status in allowed else "unknown"
        if status == "unknown":
            raise ProviderError("invalid_claim_status_value", uncertain=False)
        _, nameservers = self._record_claim_upstream(claim["id"], response, fallback_status=status)
        self.jobs.finish(job["id"], "succeeded", step="upstream_status_recorded", result={"claim_id": claim["id"],
                         "domain": claim["domain"], "upstream_claim_id": claim["upstream_claim_id"],
                         "upstream_status": status, "nameservers": nameservers,
                         "nameservers_assigned": bool(nameservers)})

    def _execute_claim(self, job):
        source = self.source(job["scope"])
        c = self.db()
        try:
            prior = c.execute("SELECT status,result_json FROM domain_jobs WHERE kind='claim' AND scope=? AND id!=? AND status IN ('unknown','partial')", (job["scope"], job["id"])).fetchall()
            if any(r["status"] == "unknown" or any(i.get("status") == "unknown" for i in json.loads(r["result_json"]).get("items", [])) for r in prior):
                self.jobs.finish(job["id"], "failed", step="not_dispatched", error="unresolved_prior_allocation")
                return
        finally:
            c.close()
        try:
            if source["client_id"] != job["request"]["client_id"]:
                raise ValueError("source ownership changed")
            self.credentials().require_writer()
            adapter = self.adapter(source)
        except (CredentialError, ValueError):
            self.jobs.finish(job["id"], "failed", step="not_dispatched", error="source_or_credential_preflight_failed")
            return
        requested_count = job["request"].get("count", 1)
        self.jobs.progress(job["id"], step="claim_dispatched", result={"requested_count": requested_count})
        raw = adapter.claim(job["request"], job["upstream_idempotency_key"])
        rows = items(raw)
        if not rows:
            raise ProviderError("claim_response_missing_domains", uncertain=True)
        results, partial, seen = [], False, set()
        processed = 0

        def snapshot():
            return {"items": results, "requested_count": requested_count,
                    "received_count": len(rows), "processed_count": processed,
                    "recorded_count": sum(bool(r.get("claim_id")) for r in results),
                    "warnings": ["claim_count_mismatch"] if len(rows) != requested_count else []}

        # Save every encrypted allocation receipt before any slow Brevo/network
        # setup. Interruption must not strand the tail of a large upstream batch.
        for raw_item in rows:
            try:
                domain = public_item(raw_item)["domain"]
                if domain in seen:
                    partial = True
                    results.append({"status": "unknown", "error_code": "duplicate_domain_in_claim_response"})
                    continue
                seen.add(domain)
                claim_id = self._record_claim(source, job, raw_item)
                results.append({"claim_id": claim_id, "domain": domain, "status": "credential_pending"})
            except Exception:
                partial = True
                results.append({"status": "unknown", "error_code": "claim_metadata_or_receipt_persistence_failed"})
            if len(results) % 10 == 0:
                self.jobs.progress(job["id"], step="saving_claim_receipts", result=snapshot())
        self.jobs.progress(job["id"], step="importing_domains", result=snapshot())
        bulk = requested_count > 1
        # Unpublished local rows stay disabled. One generation at the end avoids
        # 200 Postfix reloads/key scans and leaves the API free between writes.
        defer_runtime = bulk and self.publish_domains is not None
        try:
            for index, item in enumerate(results):
                if item.get("claim_id"):
                    try:
                        if bulk:
                            results[index] = self._attach_claim(item["claim_id"], defer_setup=True, defer_runtime=defer_runtime)
                        else:
                            results[index] = self._attach_claim(item["claim_id"])
                    except Exception:
                        results[index] = {**item, "status": "partial", "error_code": "credential_or_import_pending"}
                        partial = True
                processed += 1
                self.jobs.progress(job["id"], step="importing_domains", result=snapshot())
        finally:
            if defer_runtime:
                self.publish_domains()
        self.jobs.finish(job["id"], "partial" if partial or len(rows) != requested_count else "succeeded",
                         step="allocation_recorded", result=snapshot())

    def _execute_import(self, job):
        source = self.source(job["scope"])
        if source["source_type"] != "cloudflare_import" or not source["enabled"] or source["client_id"] != job["request"]["client_id"]:
            raise ValueError("invalid import source")
        c = self.db()
        try:
            secret = self.credentials().get(c, source["credential_ref"], provider="cloudflare_import")
        finally:
            c.close()
        zone_id, _ = CloudflareDNS(self.http, secret).zone(job["request"]["domain"])
        local_claim = self._record_claim(source, job, {"domain": job["request"]["domain"], "id": zone_id, "status": "active"})
        result = self._attach_claim(local_claim)
        self.jobs.finish(job["id"], "succeeded", step="inventory_imported", result=result)

    def _activate_validated_domain(self, row, result):
        """Explicit user intent only; periodic readiness jobs never enable domains."""
        required = set()
        if row["receive_enabled"]:
            required.add("mx")
            if row["receive_subdomains"] and row["max_subdomain_depth"]:
                required.add("wildcard_mx")
        if row["send_enabled"]:
            required.update(("spf", "dkim", "dmarc", "smtp_submission"))
        pending = sorted(name for name in required
                         if result["checks"].get(name, {}).get("status") != "passed")
        if row["send_enabled"] and not (self.key_root / row["domain"] /
                                        ((row.get("dkim_selector") or "default") + ".private")).is_file():
            pending.append("dkim_private_key")
        if row["receive_enabled"] and row["receive_mode"] != "catch_all" and not json.loads(row["users"]):
            pending.append("recipients")
        if not required:
            pending.append("capabilities_disabled")
        if pending:
            result["activation"] = {"status": "blocked", "enabled": bool(row["enabled"]),
                                    "pending_checks": pending}
            return
        changed = not row["enabled"]
        if changed:
            data = {**row, "enabled": True, "users": json.loads(row["users"])}
            self.save_domain(data, row["domain"])
            activated = build_plan(self.domain(row["domain"]), self.key_root)
            # Enabling changes the policy revision, but no DNS target or key.
            # Bind only these freshly obtained checks to that new revision.
            result["validated_config_hash"] = result["config_hash"]
            result.update(config_hash=activated["config_hash"], plan_hash=activated["plan_hash"])
        result["activation"] = {"status": "enabled", "enabled": True, "changed": changed}

    def _wait_activation_ready(self, domain, result):
        if not self.domain_public or result.get("activation", {}).get("status") != "enabled":
            return
        activation = result["activation"]
        activation["status"] = "routing_pending"
        for attempt in range(21):
            row = self.domain(domain)
            if config_hash(row) != result["config_hash"]:
                activation.update(status="configuration_changed", enabled=bool(row["enabled"]))
                return
            public = self.domain_public(row)
            receive, send = bool(row["receive_enabled"]), bool(row["send_enabled"])
            subdomains = row["receive_subdomains"] and row["max_subdomain_depth"] > 0
            ready = bool(public["enabled"] and (receive or send)
                         and (not receive or (public["receive_ready"] and
                              (not subdomains or public["subdomain_receive_ready"])))
                         and (not send or (public["send_ready"] and
                              (not subdomains or public["subdomain_send_ready"]))))
            if ready:
                activation["status"] = "ready"
                return
            if attempt < 20:
                time.sleep(0.5)

    def validate_domain(self, domain, expected, *, refresh_smtp_submission=False, activate_on_success=False):
        """Validate and persist one configuration revision, also after DNS apply."""
        row = self.domain(domain)
        if activate_on_success and row["source_status"] in {"released", "revoked", "expired", "releasing"}:
            raise ValueError("domain ownership is inactive")
        plan = build_plan(row, self.key_root)
        if plan["config_hash"] != expected["config_hash"] or plan["plan_hash"] != expected["plan_hash"]:
            raise ValueError("domain configuration or DKIM key changed")
        result = self.validator.validate(row, self.key_root)
        if result["config_hash"] != expected["config_hash"]:
            raise ValueError("validation revision mismatch")
        if (refresh_smtp_submission or activate_on_success) and row["send_enabled"]:
            from api.services.readiness_refresh import smtp_submission_check
            result["checks"]["smtp_submission"] = smtp_submission_check(row)
        dns_ready = all(
            check.get("status") in {"passed", "not_required"}
            for name, check in result["checks"].items()
            if name != "smtp_submission"
        )
        result["brevo_authentication"] = (
            self.brevo_authentication_result(row["domain"])
            if dns_ready else
            {"status": "waiting_for_dns"}
        )
        with self.lock:
            current = build_plan(self.domain(row["domain"]), self.key_root)
            if current["plan_hash"] != expected["plan_hash"]:
                raise ValueError("domain configuration changed during validation")
            if activate_on_success:
                self._activate_validated_domain(self.domain(row["domain"]), result)
            c = self.db()
            try:
                with c:
                    for name, check in result["checks"].items():
                        c.execute("INSERT OR REPLACE INTO domain_checks VALUES(?,?,?,?,?,?)",
                                  (row["domain"], name, check["status"], result["config_hash"], time.time(), check["detail"]))
            finally:
                c.close()
        self._wait_activation_ready(row["domain"], result)
        return result

    def _execute_validate(self, job):
        result = self.validate_domain(
            job["scope"], job["request"],
            refresh_smtp_submission=bool(job["request"].get("refresh_smtp_submission")),
            activate_on_success=bool(job["request"].get("activate_on_success")),
        )
        self.jobs.finish(job["id"], "succeeded", step="dns_checks_recorded", result=result)

    def run_once(self):
        job = None
        try:
            with self.worker_lock:
                job = self.jobs.take(capacity=self.job_concurrency)
            if not job:
                return False
            with self.jobs.execution(job):
                self._run_job(job)
                if job["kind"] in {"dns_validate", "dns_apply", "dns_complete"}:
                    try:
                        self.dns_history.reconcile(job["scope"], job["id"])
                    except Exception:
                        # History observation must not change a completed job's
                        # outcome or retry external writes after read failures.
                        logging.getLogger("domain-jobs").warning("DNS history reconciliation deferred")
            return True
        except JobConflict:
            self.jobs.finish(job["id"], "failed", step="not_dispatched", error="dns_preview_stale_or_conflicted")
            return True
        except ProviderError as exc:
            self.jobs.finish(job["id"], "unknown" if exc.uncertain else "failed", step="provider_request",
                             result=self.jobs.provider_backoff(job["scope"], exc), error=exc.code)
            return True
        except Exception:
            if job:
                # Allocation/DNS writes may already have side effects. Do not replay.
                self.jobs.finish(job["id"], "unknown" if job["kind"] in {"claim", "import", "dns_apply", "dns_hosting", "dns_repair", "dynv6_register", "dns_complete"} else "failed",
                                 step="local_processing", error="operation_failed_check_persisted_state")
                return True
            raise

    def _run_job(self, job):
        handlers = {
            "claim": self._execute_claim, "import": self._execute_import,
            "dns_apply": self.dns.apply, "dns_repair": self.dns_repair.execute,
            "dns_complete": self.dns_completion.execute,
            "dynv6_register": self.dynv6_registration.execute,
            "claim_setup": self._execute_claim_setup, "dns_hosting": self._execute_dns_hosting,
            "dns_validate": self._execute_validate, "claim_status": self._execute_claim_status,
            "claim_report": self._execute_claim_report, "claim_refresh": self._execute_claim_refresh,
            "claim_provision": self._execute_claim_provision, "claim_release": self._execute_claim_release,
        }
        if job["kind"] == "claim_recover":
            result = self._attach_claim(job["scope"])
            self.jobs.finish(job["id"], "succeeded", step="recovered_without_new_claim", result=result)
        elif job["kind"] in handlers:
            handlers[job["kind"]](job)
        else:
            raise ValueError("unsupported domain operation")

"""Durable Cloudflare Zone onboarding; ambiguous creates are only read back."""
import json
from api.providers.dns.cloudflare import CloudflareDNS
from api.providers.http import ProviderError
from api.repositories.domain_jobs import JobConflict, assert_domain_mutable
from api.services.routing import config_hash, normalize_domain


class CloudflareRegistration:
    def __init__(self, manager):
        self.m = manager

    def adapter(self, ref, domain):
        c = self.m.db()
        try:
            secret = self.m.credentials().get(c, ref, provider="cloudflare", domain=domain)
        finally:
            c.close()
        return CloudflareDNS(self.m.http, secret)

    def check(self, request, row):
        if (row["enabled"] or row["source_status"] in {"released", "revoked", "expired", "releasing"}
                or row["dns_provider"] != request["initial_provider"]
                or row["dns_credential_ref"] != request["initial_credential_ref"]
                or config_hash(row) != request["config_hash"] or row["claim_id"] != request["claim_id"]):
            raise JobConflict("domain ownership or configuration changed before Cloudflare setup")
        expected = request.get("completion")
        if expected:
            claim = self.m.claim_row(expected["claim_id"])
            if claim["id"] != row["claim_id"] or claim["domain"] != row["domain"] or claim["job_id"] != expected["allocation_job_id"]:
                raise JobConflict("claim changed before Cloudflare setup")

    def enqueue(self, domain, key, ref, *, completion=None):
        domain = normalize_domain(domain)
        with self.m.lock:
            row = self.m.domain(domain)
            self.adapter(ref, domain)
            self.m.credentials().require_writer()
            c = self.m.db()
            try:
                prior = c.execute("SELECT * FROM domain_jobs WHERE kind='dns_hosting' AND scope=? AND idempotency_key=?", (domain, key)).fetchone()
                if prior:
                    saved = self.m.jobs.public(prior)
                    if saved["request"].get("provider") != "cloudflare" or saved["request"].get("credential_ref") != ref or saved["request"].get("completion") != completion:
                        raise JobConflict("Cloudflare setup idempotency options changed")
                    return saved
                request = {"provider": "cloudflare", "credential_ref": ref,
                           "initial_provider": row["dns_provider"], "initial_credential_ref": row["dns_credential_ref"],
                           "config_hash": config_hash(row), "claim_id": row["claim_id"]}
                if completion:
                    request["completion"] = dict(completion)
                self.check(request, row)
                active = c.execute("SELECT * FROM domain_jobs WHERE kind='dns_hosting' AND scope=? AND status IN ('queued','running')", (domain,)).fetchone()
                if active:
                    if json.loads(active["request_json"]) != request:
                        raise JobConflict("DNS hosting preparation is active with different options")
                    return self.m.jobs.public(active)
            finally:
                c.close()
            assert_domain_mutable(self.m.db, domain)
            return self.m.jobs.enqueue("dns_hosting", domain, key, request)

    def execute(self, job):
        request = job["request"]
        name, ref = job["scope"], request["credential_ref"]
        result = {"domain": name, "provider": "cloudflare", "credential_ref": ref,
                  "registration_dispatched": False, "bound": False}
        dispatched = confirmed = False
        adapter = None
        try:
            self.check(request, self.m.domain(name))
            adapter = self.adapter(ref, name)
            zone = adapter.zone_info(name, pending=True)
            c = self.m.db()
            try:
                unresolved = c.execute("""SELECT 1 FROM domain_jobs WHERE kind='dns_hosting' AND scope=? AND id!=?
                    AND json_extract(request_json,'$.provider')='cloudflare'
                    AND json_extract(request_json,'$.credential_ref')=?
                    AND json_extract(result_json,'$.registration_dispatched')=1
                    AND (status='unknown' OR json_extract(result_json,'$.registration_status')='unknown') LIMIT 1""", (name, job["id"], ref)).fetchone()
            finally:
                c.close()
            if unresolved and (not zone or zone["name"] != name):
                raise ProviderError("cloudflare_zone_creation_unconfirmed", uncertain=True)
            if not zone:
                account = adapter.creation_account()
                with self.m.lock:
                    self.check(request, self.m.domain(name))
                    self.m.jobs.check_provider_backoff("cloudflare")
                    result["registration_dispatched"] = True
                    self.m.jobs.progress(job["id"], step="cloudflare_zone_create_dispatched", result=result)
                    dispatched = True
                adapter.create_zone(name, account)
                zone = adapter.zone_info(name, pending=True, exact=True)
                if not zone:
                    raise ProviderError("cloudflare_zone_creation_unconfirmed", uncertain=True)
            confirmed = True
            nameservers = adapter.nameservers(zone) if zone["name"] == name else []
            result.update(zone_id=zone["id"], zone_name=zone["name"], zone_status=zone["status"],
                          nameservers=nameservers, registration_status="registered", already_registered=not dispatched)
            self.m.jobs.progress(job["id"], step="cloudflare_zone_confirmed", result=result)
            with self.m.lock:
                self.check(request, self.m.domain(name))
                row = self.m.domain(name)
                if row["dns_provider"] != "cloudflare" or row["dns_credential_ref"] != ref:
                    self.m.bind_dns_credential(name, ref)
                result.update(bound=True, hosting_status="ready", next_action="dns_preview")
            if request.get("completion"):
                result.update(self.m._queue_claim_completion(request["completion"]))
            self.m.jobs.finish(job["id"], "partial" if result.get("configuration_status") in {"pending", "blocked"} else "succeeded",
                               step="cloudflare_hosting_ready", result=result)
        except Exception as exc:
            if dispatched and not confirmed and adapter:
                try:
                    zone = adapter.zone_info(name, pending=True, exact=True)
                    if zone:
                        confirmed = True
                        result.update(zone_id=zone["id"], zone_name=zone["name"], zone_status=zone["status"],
                                      nameservers=adapter.nameservers(zone), registration_status="registered")
                except Exception:
                    pass
            uncertain = not confirmed and (getattr(exc, "uncertain", False) or dispatched and not isinstance(exc, ProviderError))
            result.update(registration_status="registered" if confirmed else "unknown" if uncertain else "failed",
                          hosting_status="pending" if confirmed else "unknown" if uncertain else "failed",
                          next_action="retry_binding" if confirmed else "check_cloudflare_zone" if uncertain else "check_cloudflare_account")
            result.update(self.m.jobs.provider_backoff(name, exc, provider="cloudflare"))
            self.m.jobs.finish(job["id"], "partial" if confirmed else "unknown" if uncertain else "failed",
                               step="cloudflare_hosting_incomplete", result=result,
                               error=exc.code if isinstance(exc, ProviderError) else "cloudflare_setup_configuration_changed")

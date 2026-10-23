"""Durable custom-domain registration, kept separate from DNS record writes."""
import json
import re
import time
import uuid
from api.providers.dns.dynv6 import numeric_id
from api.providers.dynv6_session import Dynv6Session, session_cookie
from api.providers.http import ProviderError
from api.repositories.credentials import CredentialError, CredentialStore
from api.repositories.domain_jobs import JobConflict, assert_domain_mutable
from api.services.routing import normalize_domain


class Dynv6Registration:
    def __init__(self, manager):
        self.m = manager
        self.session_factory = Dynv6Session

    def secret(self, ref, domain=None):
        c = self.m.db()
        try:
            if domain is None:
                row = c.execute("SELECT domain FROM dns_credentials WHERE id=?", (ref,)).fetchone()
                if not row:
                    raise CredentialError("credential reference not found")
                domain = row["domain"]
            return self.m.credentials().get(c, ref, provider="dynv6", domain=domain)
        finally:
            c.close()

    def credentials(self):
        c = self.m.db()
        try:
            rows = CredentialStore.public(c)
            for row in rows:
                if row["provider"] != "dynv6":
                    continue
                try:
                    secret = self.m.credentials().get(c, row["id"], domain=row["domain"])
                    row["session"] = {
                        "configured": bool(secret.get("session_cookie")),
                        "status": secret.get("session_status", "missing"),
                        "checked_at": float(secret.get("session_checked_at", 0)),
                    }
                    row["login"] = {
                        "email": secret.get("login_email", ""),
                        "configured": bool(secret.get("login_password")),
                        "status": secret.get("login_status", "manual"),
                        "checked_at": float(secret.get("login_checked_at", 0)),
                        "retry_at": float(secret.get("login_retry_at", 0)),
                        "token_id": secret.get("account_token_id", ""),
                        "token_scope": secret.get("account_token_scope", ""),
                        "zone_count": int(secret.get("account_zone_count", 0)),
                    }
                except CredentialError:
                    row["session"] = {"configured": False, "status": "unavailable", "checked_at": 0}
            return rows
        finally:
            c.close()

    def zones(self, secret):
        zones = self.m.http.request("GET", "https://dynv6.com", "/api/v2/zones",
                                    headers={"Authorization": "Bearer " + secret["api_token"]})
        if not isinstance(zones, list) or len(zones) > 10000:
            raise ProviderError("invalid_dynv6_zone_inventory")
        for zone in zones:
            if not isinstance(zone, dict) or not isinstance(zone.get("name"), str):
                raise ProviderError("invalid_dynv6_zone_inventory")
            numeric_id(zone.get("id"))
        return zones

    @staticmethod
    def exact_zone(zones, name):
        matches = [z for z in zones if z["name"].lower().rstrip(".") == name]
        if len(matches) > 1:
            raise ProviderError("ambiguous_dynv6_zone")
        return matches[0] if matches else None

    def store_session(self, ref, secret, cookie, status, *, new=False):
        c = self.m.db()
        try:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT * FROM dns_credentials WHERE id=?", (ref,)).fetchone()
            if not row:
                raise CredentialError("credential reference not found")
            current = self.m.credentials().get(c, ref, provider="dynv6", domain=row["domain"])
            if (current.get("session_revision") != secret.get("session_revision")
                    or current["api_token"] != secret["api_token"]):
                raise CredentialError("dynv6 session changed; check the current session again")
            current.update(session_cookie=cookie, session_status=status,
                           session_checked_at=str(time.time()))
            if new:
                current["session_revision"] = uuid.uuid4().hex
            self.m.credentials().put(c, "dynv6", current, domain=row["domain"],
                                     label=row["label"], credential_id=ref)
            c.commit()
            return current
        finally:
            c.close()

    def save_session(self, ref, value):
        secret = self.secret(ref)
        cookie = session_cookie(value)
        client = self.session_factory(cookie)
        client.prepare(self.zones(secret))
        self.store_session(ref, secret, client.cookie(), "valid", new=True)
        return {"credential_ref": ref, "status": "valid"}

    def check_session(self, ref):
        secret = self.secret(ref)
        if secret.get("login_password"):
            self.m.dynv6_accounts.prepared(ref)
            return {"credential_ref": ref, "status": "valid"}
        if not secret.get("session_cookie"):
            raise ProviderError("dynv6_session_required")
        client = self.session_factory(secret["session_cookie"])
        try:
            client.prepare(self.zones(secret))
        except ProviderError as exc:
            if exc.code == "dynv6_session_expired":
                self.store_session(ref, secret, secret["session_cookie"], "expired")
            raise
        self.store_session(ref, secret, client.cookie(), "valid")
        return {"credential_ref": ref, "status": "valid"}

    def enqueue(self, domain, key, credential_ref, *, bind=True, max_subdomain_depth=1, completion=None):
        if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", key):
            raise ValueError("Idempotency-Key must be 8-128 ASCII identifier characters")
        domain = normalize_domain(domain)
        if type(max_subdomain_depth) is not int or max_subdomain_depth != 1:
            raise ValueError("dynv6 registration requires max_subdomain_depth=1")
        with self.m.lock:
            row = self.m.domain(domain)
            if row["enabled"] or row["source_status"] in {"released", "revoked", "expired", "releasing"}:
                raise ValueError("Disable this active domain before dynv6 registration or migration")
            self.secret(credential_ref, domain)
            self.m.credentials().require_writer()
            request = {"credential_ref": credential_ref, "bind": bind,
                       "max_subdomain_depth": max_subdomain_depth}
            if completion:
                request["completion"] = dict(completion)
                request["initial_credential_ref"] = row["dns_credential_ref"]
                request["initial_provider"] = row["dns_provider"]
                self.check_claim_context(request, row)
            c = self.m.db()
            try:
                active = c.execute("""SELECT * FROM domain_jobs WHERE kind='dynv6_register'
                    AND scope=? AND status IN ('queued','running')""", (domain,)).fetchone()
            finally:
                c.close()
            if active:
                if json.loads(active["request_json"]) != request:
                    raise JobConflict("dynv6 registration is active with different options")
                return self.m.jobs.enqueue("dynv6_register", domain, active["idempotency_key"], request)
            assert_domain_mutable(self.m.db, domain)
            return self.m.jobs.enqueue("dynv6_register", domain, key, request)

    def _bind(self, name, ref):
        with self.m.lock:
            row = self.m.domain(name)
            if row["enabled"]:
                raise ValueError("Disable this domain before changing DNS configuration")
            if row["dns_provider"] != "dynv6" or row["dns_credential_ref"] != ref:
                self.m.bind_dns_credential(name, ref)
            row = self.m.domain(name)
            if row["max_subdomain_depth"] != 1:
                row["users"] = json.loads(row["users"])
                row["max_subdomain_depth"] = 1
                self.m.save_domain(row, name)

    def check_claim_context(self, request, row):
        expected = request.get("completion")
        if not expected:
            return
        claim = self.m.claim_row(expected["claim_id"])
        if (row["claim_id"] != claim["id"] or row["domain"] != claim["domain"]
                or claim["job_id"] != expected["allocation_job_id"]
                or row["dns_credential_ref"] != request["initial_credential_ref"]
                or row["dns_provider"] != request["initial_provider"]
                or row["source_status"] in {"released", "revoked", "expired", "releasing"}):
            raise ValueError("claim ownership or DNS binding changed before dynv6 setup")

    def execute(self, job):
        name, ref = job["scope"], job["request"]["credential_ref"]
        result = {"domain": name, "credential_ref": ref, "registration_dispatched": False}
        dispatched = confirmed = False
        secret = None
        try:
            row = self.m.domain(name)
            if row["enabled"] or row["source_status"] in {"released", "revoked", "expired", "releasing"}:
                raise ValueError("domain changed before dynv6 registration")
            self.check_claim_context(job["request"], row)
            secret, zones = self.m.dynv6_accounts.zones(ref, name)
            zone = self.exact_zone(zones, name)
            if not zone:
                c = self.m.db()
                try:
                    unresolved = c.execute("""SELECT 1 FROM domain_jobs
                        WHERE kind='dynv6_register' AND scope=? AND id!=?
                        AND status IN ('unknown','partial')
                        AND COALESCE(json_extract(result_json,'$.registration_dispatched'),0)=1 LIMIT 1""",
                        (name, job["id"])).fetchone()
                finally:
                    c.close()
                if unresolved:
                    raise ProviderError("dynv6_registration_unconfirmed", uncertain=True)
                self.m.jobs.check_provider_backoff("dynv6")
                secret, client = self.m.dynv6_accounts.prepared(ref, name)
                # Registration overlaps other domains' reads, while all DNS
                # and registration dispatches retain one shared write gate.
                with self.m.lock:
                    current = self.m.domain(name)
                    self.check_claim_context(job["request"], current)
                    if current["enabled"] or current["dns_provider"] != row["dns_provider"]:
                        raise ValueError("domain changed before registration dispatch")
                    self.m.jobs.check_provider_backoff("dynv6")
                    result["registration_dispatched"] = True
                    self.m.jobs.progress(job["id"], step="dynv6_register_dispatched", result=result)
                    dispatched = True
                    try:
                        result.update(client.register(name))
                    except ProviderError as exc:
                        # Publish a 429 before a running peer can dispatch.
                        result.update(self.m.jobs.provider_backoff(name, exc, provider="dynv6"))
                        self.m.jobs.progress(job["id"], step="dynv6_registration_readback", result=result)
                        raise
                    finally:
                        # Persist rotated cookies even after an uncertain POST.
                        secret = self.store_session(ref, secret, client.cookie(), "valid")
                zone = self.exact_zone(self.zones(secret), name)
                if not zone:
                    raise ProviderError("dynv6_registration_unconfirmed", uncertain=True)
            confirmed = True
            result.update(zone_id=numeric_id(zone["id"]), registration_status="registered",
                          already_registered=not dispatched, bound=False)
            self.m.jobs.progress(job["id"], step="dynv6_zone_confirmed", result=result)
            # A readback may resolve a prior interrupted submission without repeating it.
            c = self.m.db()
            try:
                with c:
                    for previous in c.execute("""SELECT * FROM domain_jobs WHERE kind='dynv6_register'
                        AND scope=? AND id!=? AND status IN ('unknown','partial')""", (name, job["id"])).fetchall():
                        if json.loads(previous["request_json"]).get("credential_ref") != ref:
                            continue
                        saved = json.loads(previous["result_json"])
                        saved.update(zone_id=result["zone_id"], registration_status="registered", reconciled_by=job["id"])
                        c.execute("""UPDATE domain_jobs SET status='partial',step='dynv6_zone_observed',
                            result_json=?,error_code='',updated_at=? WHERE id=?""",
                            (json.dumps(saved), time.time(), previous["id"]))
            finally:
                c.close()
            if job["request"]["bind"]:
                self.check_claim_context(job["request"], self.m.domain(name))
                self._bind(name, ref)
                result.update(bound=True, max_subdomain_depth=1)
            result["next_action"] = "dns_preview" if result["bound"] else "dns_binding"
            if result["bound"] and job["request"].get("completion"):
                result.update(self.m._queue_claim_completion(job["request"]["completion"]))
            self.m.jobs.finish(job["id"], "partial" if result.get("configuration_status") in {"pending", "blocked"} else "succeeded",
                               step="dynv6_registration_ready", result=result)
        except Exception as exc:
            code = exc.code if isinstance(exc, ProviderError) else "dynv6_registration_local_error"
            # Read back after any dispatched write before declaring it unresolved.
            if dispatched and not confirmed and secret:
                try:
                    zone = self.exact_zone(self.zones(secret), name)
                    if zone:
                        confirmed = True
                        result.update(zone_id=numeric_id(zone["id"]), registration_status="registered")
                except Exception:
                    pass
            uncertain = not confirmed and (dispatched or getattr(exc, "uncertain", False))
            result.update(registration_status="registered" if confirmed else "unknown" if uncertain else "failed",
                          next_action="retry_binding" if confirmed else "check_registration" if uncertain else "update_session")
            result.update(self.m.jobs.provider_backoff(name, exc, provider="dynv6"))
            if code == "dynv6_session_expired" and secret:
                try:
                    self.store_session(ref, secret, secret["session_cookie"], "expired")
                except CredentialError:
                    pass
            self.m.jobs.finish(job["id"], "partial" if confirmed else "unknown" if uncertain else "failed",
                               step="dynv6_registration_incomplete", result=result, error=code)

"""Administrator-only P2 routes; provider secrets never have a read endpoint."""
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal
from api.providers.http import ProviderError
from api.providers.dns.digitalplat import (
    DIGITALPLAT_DNS_NOT_ENABLED,
    DIGITALPLAT_DNS_UPSTREAM_UNAVAILABLE,
    DIGITALPLAT_DNS_ZONE_UNAVAILABLE,
    digitalplat_dns_upstream_message,
    digitalplat_dns_zone_message,
    digitalplat_dns_hosting_message,
)
from api.repositories.credentials import CredentialError, CredentialStore
from api.repositories.domain_jobs import JobConflict


class RedactedValidationRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        async def redacted(request):
            try:
                return await handler(request)
            except RequestValidationError as exc:
                # FastAPI's default includes `input`, potentially echoing tokens.
                return JSONResponse(status_code=422, content={"detail": [
                    {"type": e["type"], "msg": "invalid request field"} for e in exc.errors()]})
        return redacted


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceInput(Input):
    name: str = Field(min_length=1, max_length=80)
    source_type: Literal["sfreg_mx", "legacy_digitalplat_pool", "cloudflare_import"]
    base_url: str = Field(min_length=1, max_length=1024)
    client_id: str = Field(default="mail-stack", min_length=1, max_length=80)
    secret: dict[str, str]


class ClaimInput(Input):
    count: int = Field(default=1, ge=1, le=200, strict=True)
    local_part: str = "support"
    external_ids: list[str] = Field(default_factory=list, max_length=200)
    status: Literal["registered", "synced", "sync_failed", "all"] | None = None
    sync_provider: Literal["none", "cloudflare", "all", "digitalplat_dns"] | None = None


class ImportInput(Input):
    domain: str


class ClaimReportInput(Input):
    status: Literal["validating", "active", "partial", "failed"]
    checks: dict[str, str] = Field(default_factory=dict, max_length=20)
    verified_at: str | None = Field(default=None, max_length=80)
    error: str | None = Field(default=None, max_length=500)


class ClaimReleaseInput(Input):
    reason: str = Field(default="mailbox_deleted", min_length=1, max_length=120)
    environment_stopped: bool = False


class CredentialInput(Input):
    provider: Literal["cloudflare", "digitalplat"]
    domain: str | None = None
    label: str = Field(default="DNS account", min_length=1, max_length=80)
    secret: dict[str, str]


class DNSApplyInput(Input):
    plan_id: str = Field(min_length=1, max_length=80)
    activate_on_success: bool = False


class DNSValidateInput(Input):
    activate_on_success: bool = False


class BindingInput(Input):
    credential_ref: str = Field(min_length=1, max_length=80)


class BrevoDomainInput(Input):
    domain: str = Field(min_length=1, max_length=253)


def build_router(manager, admin_ok):
    def require_admin(x_api_key: str | None = Header(default=None), x_admin_password: str | None = Header(default=None)):
        if not admin_ok(x_api_key, x_admin_password):
            raise HTTPException(401, "invalid administrator credentials")
    router = APIRouter(prefix="/api/v1", tags=["domain-control"], dependencies=[Depends(require_admin)], route_class=RedactedValidationRoute)
    def call(fn, *args, **kwargs):
        domain = kwargs.get("domain") or (args[0] if args and isinstance(args[0], str) else "")
        try:
            return fn(*args, **kwargs)
        except (JobConflict, CredentialError) as exc:
            raise HTTPException(409, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        except ProviderError as exc:
            if exc.code == DIGITALPLAT_DNS_NOT_ENABLED:
                raise HTTPException(409, {"code": exc.code, "message": digitalplat_dns_hosting_message(domain),
                                          "next_action": "dns_hosting"}) from None
            if exc.code == DIGITALPLAT_DNS_ZONE_UNAVAILABLE:
                raise HTTPException(409, digitalplat_dns_zone_message(domain)) from None
            if exc.code == DIGITALPLAT_DNS_UPSTREAM_UNAVAILABLE:
                raise HTTPException(502, digitalplat_dns_upstream_message(domain)) from None
            raise HTTPException(502, exc.code) from None

    @router.get("/domain-sources")
    def sources():
        return {"items": manager.sources()}

    @router.post("/domain-sources", status_code=201)
    def create_source(item: SourceInput):
        return call(manager.create_source, **item.model_dump())

    @router.post("/domain-sources/{source_id}/toggle")
    def toggle_source(source_id: str, enabled: bool):
        call(manager.source, source_id)
        c = manager.db()
        try:
            with c:
                c.execute("UPDATE domain_sources SET enabled=? WHERE id=?", (int(enabled), source_id))
        finally:
            c.close()
        return manager.source(source_id)

    @router.get("/domain-sources/{source_id}/candidates")
    def candidates(source_id: str, count: int = Query(default=10, ge=1, le=200),
                   status: Literal["registered", "synced", "sync_failed", "all"] | None = None,
                   sync_provider: Literal["none", "cloudflare", "all", "digitalplat_dns"] | None = None):
        items = call(manager.candidates, source_id, count, status=status, sync_provider=sync_provider)
        return {"items": items, "total": len(items), "allocation": "none"}

    @router.post("/domain-sources/{source_id}/claim", status_code=202)
    def claim(source_id: str, item: ClaimInput, idempotency_key: str = Header(alias="Idempotency-Key")):
        return call(manager.create_claim_job, source_id, idempotency_key, **item.model_dump())

    @router.post("/domain-sources/{source_id}/import", status_code=202)
    def import_domain(source_id: str, item: ImportInput, idempotency_key: str = Header(alias="Idempotency-Key")):
        return call(manager.create_import_job, source_id, item.domain, idempotency_key)

    @router.get("/dns-credentials")
    def credentials():
        c = manager.db()
        try:
            return {"items": CredentialStore.public(c), "global_cloudflare": manager.global_cloudflare_status()}
        finally:
            c.close()

    @router.post("/dns-credentials", status_code=201)
    def create_credential(item: CredentialInput):
        return call(manager.add_dns_credential, **item.model_dump())

    @router.post("/dns-credentials/{credential_id}/rewrap")
    def rewrap(credential_id: str):
        c = manager.db()
        try:
            with c:
                call(manager.credentials().rewrap, c, credential_id)
        finally:
            c.close()
        return {"id": credential_id, "status": "rewrapped"}

    @router.post("/mail-domains/{domain}/dns-binding")
    def binding(domain: str, item: BindingInput):
        return call(manager.bind_dns_credential, domain, item.credential_ref)

    @router.post("/mail-domains/{domain}/dns-binding/global-cloudflare")
    def bind_global_cloudflare(domain: str):
        return call(manager.bind_global_cloudflare, domain)

    @router.get("/mail-domains/{domain}/dns-plan")
    def plan(domain: str):
        return call(manager.plan, domain)

    @router.get("/mail-domains/{domain}/dns-inventory")
    def inventory(domain: str):
        return call(manager.dns_inventory, domain)

    @router.get("/brevo/domains")
    def brevo_domains():
        return call(manager.brevo_domains)

    @router.post("/brevo/domains", status_code=201)
    def brevo_create_domain(item: BrevoDomainInput):
        return call(manager.brevo_create_domain, item.domain)

    @router.post("/brevo/domains/{domain}/authenticate")
    def brevo_authenticate_domain(domain: str):
        return call(manager.brevo_authenticate_domain, domain)

    @router.post("/mail-domains/{domain}/dns-preview", status_code=201)
    def preview(domain: str):
        return call(manager.dns.preview, domain)

    @router.post("/mail-domains/{domain}/dns-operations/{operation_id}/reconcile")
    def reconcile_dns_operation(domain: str, operation_id: str):
        return call(manager.dns.reconcile_operation, domain, operation_id)

    @router.get("/dns-plans/{plan_id}")
    def dns_plan(plan_id: str):
        return call(manager.dns.plan, plan_id)

    @router.post("/mail-domains/{domain}/dns-apply", status_code=202)
    def apply_dns(domain: str, item: DNSApplyInput, idempotency_key: str = Header(alias="Idempotency-Key")):
        return call(manager.dns.enqueue, domain, item.plan_id, idempotency_key,
                    activate_on_success=item.activate_on_success)

    @router.post("/mail-domains/{domain}/dns-repair", status_code=202)
    def repair_dns(domain: str, item: DNSValidateInput | None = None,
                   idempotency_key: str = Header(alias="Idempotency-Key")):
        return call(manager.dns_repair.enqueue, domain, idempotency_key,
                    activate_on_success=bool(item and item.activate_on_success))

    @router.post("/mail-domains/{domain}/dns-hosting", status_code=202)
    def prepare_dns_hosting(domain: str, idempotency_key: str = Header(alias="Idempotency-Key")):
        return call(manager.create_dns_hosting_job, domain, idempotency_key)

    @router.post("/mail-domains/{domain}/dns-validate", status_code=202)
    def validate(domain: str, item: DNSValidateInput | None = None,
                 idempotency_key: str = Header(alias="Idempotency-Key")):
        return call(manager.create_validate_job, domain, idempotency_key,
                    activate_on_success=bool(item and item.activate_on_success))

    @router.get("/domain-claims")
    def claims():
        return {"items": manager.claims()}

    @router.post("/domain-claims/{claim_id}/report", status_code=202)
    def claim_report(claim_id: str, item: ClaimReportInput, idempotency_key: str = Header(alias="Idempotency-Key")):
        return call(manager.create_claim_report_job, claim_id, idempotency_key, **item.model_dump())

    @router.post("/domain-claims/{claim_id}/refresh", status_code=202)
    def claim_refresh(claim_id: str, idempotency_key: str = Header(alias="Idempotency-Key")):
        return call(manager.create_claim_refresh_job, claim_id, idempotency_key)

    @router.post("/domain-claims/{claim_id}/provision")
    def claim_provision(claim_id: str, idempotency_key: str = Header(alias="Idempotency-Key")):
        return call(manager.create_claim_provision_job, claim_id, idempotency_key)

    @router.post("/domain-claims/{claim_id}/release", status_code=202)
    def claim_release(claim_id: str, item: ClaimReleaseInput, idempotency_key: str = Header(alias="Idempotency-Key")):
        return call(manager.create_claim_release_job, claim_id, idempotency_key, **item.model_dump())

    @router.post("/domain-claims/{claim_id}/status", status_code=202)
    def claim_status(claim_id: str, idempotency_key: str = Header(alias="Idempotency-Key")):
        return call(manager.create_claim_status_job, claim_id, idempotency_key)

    @router.post("/domain-claims/{claim_id}/recover", status_code=202)
    def recover(claim_id: str, idempotency_key: str = Header(alias="Idempotency-Key")):
        return call(manager.create_recover_job, claim_id, idempotency_key)

    @router.get("/domain-jobs")
    def jobs(limit: int = Query(default=100, ge=1, le=200), offset: int = Query(default=0, ge=0),
             q: str = Query(default="", max_length=200),
             status: Literal["", "queued", "running", "succeeded", "failed", "partial", "unknown"] = ""):
        return manager.jobs.list(limit, offset, q=q, status=status)

    @router.get("/domain-jobs/status")
    def job_status(ids: str = Query(min_length=1, max_length=6600)):
        return call(manager.jobs.get_many, ids.split(","))

    @router.get("/domain-jobs/{job_id}")
    def job(job_id: str):
        result = manager.jobs.get(job_id)
        if not result:
            raise HTTPException(404, "domain job not found")
        return result

    return router

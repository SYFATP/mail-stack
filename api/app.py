import base64, hashlib, hmac, os, secrets, sqlite3, time, threading, email, json, urllib.request, urllib.parse, urllib.error, shutil, smtplib, re, queue, logging, html
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, getaddresses
import dkim
from email import policy
from email.parser import BytesParser, BytesHeaderParser
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, Field
from typing import Literal
from functools import wraps
from fastapi.responses import FileResponse, Response
from api.migrations.schema import migrate, maildir_identity
from api.services.routing import normalize_domain, normalize_address, normalize_local, publish, config_hash, applied_state, AppliedStateSnapshot, recipient_policy
from api.services.dns_records import select_record
from api.services.delivery_reports import parse_delivery_report
from api.providers.brevo import BrevoAPI
from api.providers.http import JsonTransport, ProviderError
from api.repositories.credentials import CredentialError
from api.services.auth_throttle import AuthenticationRateLimit
from api.services.global_credentials import load_cloudflare_secret, save_cloudflare_secret
from api.services.webhook_transport import send_webhook_request, validate_webhook_url, WebhookDeliveryError
from api.providers.dns.digitalplat import (
    DIGITALPLAT_DNS_NOT_ENABLED,
    DIGITALPLAT_DNS_UPSTREAM_UNAVAILABLE,
    DIGITALPLAT_DNS_ZONE_UNAVAILABLE,
    digitalplat_dns_upstream_message,
    digitalplat_dns_zone_message,
    digitalplat_dns_hosting_message,
)

DB = Path("/app-data/mail.db")
RUNTIME_DIR = Path("/app-data")
CF_API_BASE = "https://api.cloudflare.com/client/v4"
DEFAULT_RETENTION_DAYS = 3
DEFAULT_MAX_STORAGE_GB = 2.0
CLEANUP_INTERVAL_SECONDS = 3600
INGEST_INTERVAL_SECONDS = max(0.5, float(os.getenv("INGEST_INTERVAL_SECONDS", "2")))
WEBHOOK_WORKERS = max(1, min(16, int(os.getenv("WEBHOOK_WORKERS", "4"))))
WEBHOOK_RETRY_LIMIT = max(1, min(10, int(os.getenv("WEBHOOK_RETRY_LIMIT", "3"))))
WEBHOOK_LEASE_SECONDS = max(30, min(3600, int(os.getenv("WEBHOOK_LEASE_SECONDS", "120"))))
OUTBOUND_WORKERS = max(1, min(16, int(os.getenv("OUTBOUND_WORKERS", "2"))))
OUTBOUND_RETRY_LIMIT = max(1, min(10, int(os.getenv("OUTBOUND_RETRY_LIMIT", "3"))))
OUTBOUND_LEASE_SECONDS = max(30, min(3600, int(os.getenv("OUTBOUND_LEASE_SECONDS", "120"))))
OUTBOUND_API_FALLBACK_ENABLED = os.getenv("MAIL_OUTBOUND_API_FALLBACK", "1").strip().lower() in {
    "1", "true", "yes", "on"
}
# When an authenticated provider (for example Brevo) signs the message after
# SMTP submission, adding a second local DKIM signature can leave a stale or
# invalid signature in the final message. Keep local signing enabled by
# default for direct delivery and allow relay deployments to disable it.
OUTBOUND_DKIM_ENABLED = os.getenv("MAIL_OUTBOUND_DKIM_ENABLED", "1").strip().lower() not in {
    "0", "false", "no", "off"
}
CUR_SCAN_INTERVAL_SECONDS = max(10.0, float(os.getenv("CUR_SCAN_INTERVAL_SECONDS", "60")))
RECIPIENT_PARSE_VERSION = 1
SENDER_PARSE_VERSION = 1
SENDER_HEADER_SCAN_LIMIT = 64 * 1024
HME_BODY_SCAN_LIMIT = 1024 * 1024
API_SCOPES = frozenset({"mail.read", "mail.send", "webhook.manage", "domain.manage"})
DEFAULT_API_SCOPES = frozenset({"mail.read", "mail.send", "webhook.manage"})
logger = logging.getLogger("mail-api")
# Webhook jobs only keep a path to the raw message in memory, not the message
# bytes themselves. This keeps a slow/downstream webhook from blocking ingest.
webhook_queue = queue.SimpleQueue()
_schema_lock = threading.Lock()
_schema_initialized = False
_last_cur_scan = 0.0
_domain_mutation_lock = threading.RLock()
_mail_store_lock = threading.RLock()
app = FastAPI(title="mail-api")
app.add_middleware(AuthenticationRateLimit, database=lambda: db())
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

def _env_domains():
    raw = os.getenv("MAIL_DOMAINS", "").strip()
    if not raw:
        raw = os.getenv("MAIL_DOMAIN", "example.com")
    out = []
    for item in raw.replace(",", " ").split():
        domain = item.strip().lower().strip(".")
        if domain and domain not in out:
            out.append(domain)
    return out or ["example.com"]

def _normalize_domain(value: str) -> str:
    return normalize_domain(value)

def _default_users() -> list[str]:
    raw = os.getenv("MAILBOX_USERS", "test,postmaster,admin")
    return [x.strip().lower() for x in re.split(r"[\s,;]+", raw) if x.strip()]

def _default_spf() -> str:
    return f"v=spf1 ip4:{os.getenv('PUBLIC_SERVER_IP', '203.0.113.10')} -all"

def _domain_rows() -> list[dict]:
    c = db()
    rows = [dict(r) for r in c.execute(
        "select * "
        "from mail_domains order by domain"
    )]
    c.close()
    return rows

def configured_domains():
    # Empty/disabled is explicit policy, not a reason to restore environment grants.
    return [r["domain"] for r in _domain_rows()
            if r["enabled"] and r["send_enabled"] and r["source_status"] not in {"released", "revoked", "expired"}]

def _ensure_schema(c):
    global _schema_initialized
    if _schema_initialized:
        return
    with _schema_lock:
        if _schema_initialized:
            return
        # WAL lets the API read while the ingest thread commits another
        # message. Set it once instead of issuing the journal-mode transition
        # on every request/scan connection.
        c.execute("pragma journal_mode=WAL")
        c.execute("""create table if not exists messages(
          id integer primary key, received_at real not null, envelope_recipient text,
          to_header text, delivered_to text, original_to text, message_id text,
          subject text, sender text, raw_path text not null, source_path text,
          actual_recipient text, actual_recipient_source text,
          recipient_parse_version integer not null default 0,
          actual_sender text, actual_sender_source text,
          sender_parse_version integer not null default 0)""")
        try:
            c.execute("alter table messages add column source_path text")
        except sqlite3.OperationalError:
            pass
        columns = {row[1] for row in c.execute("pragma table_info(messages)")}
        for name, declaration in (
            ("actual_recipient", "text"),
            ("actual_recipient_source", "text"),
            ("recipient_parse_version", "integer not null default 0"),
            ("actual_sender", "text"),
            ("actual_sender_source", "text"),
            ("sender_parse_version", "integer not null default 0"),
        ):
            if name not in columns:
                c.execute(f"alter table messages add column {name} {declaration}")
        c.execute("""create table if not exists api_keys(
          id integer primary key, name text, key_hash text unique, created_at real)""")
        c.execute("""create table if not exists sessions(
          token_hash text primary key, expires_at real not null)""")
        c.execute("""create table if not exists settings(
          key text primary key, value text not null)""")
        c.execute("""create table if not exists webhooks(
          id integer primary key, url text, secret text, enabled integer default 1,
          created_at real)""")
        c.execute("""create table if not exists webhook_deliveries(
          id integer primary key, webhook_id integer, message_id integer,
          status text, attempts integer, last_error text, created_at real)""")
        c.execute("""create table if not exists mail_domains(
          domain text primary key, enabled integer not null default 1,
          users text not null, dkim_selector text not null default 'default',
          spf text not null, dmarc text not null, mx text not null,
          cf_zone_id text, cf_status text, created_at real not null, updated_at real not null)""")
        c.execute("create index if not exists idx_messages_source_path on messages(source_path)")
        c.execute("create index if not exists idx_messages_raw_path on messages(raw_path)")
        c.execute("create index if not exists idx_messages_received_at on messages(received_at)")
        migrate(c)
        c.commit()
        _schema_initialized = True

def db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    # The busy timeout avoids transient "database is locked" errors during a
    # burst of simultaneous API requests and Maildir ingestion.
    c.execute("pragma busy_timeout=30000")
    c.execute("pragma foreign_keys=ON")
    c.execute("pragma synchronous=NORMAL")
    _ensure_schema(c)
    return c

def _write_runtime_files(rows: list[dict] | None = None):
    with _domain_mutation_lock:
        return publish(rows if rows is not None else _domain_rows(), RUNTIME_DIR)


def _seed_domains():
    with _domain_mutation_lock:
        c = db()
        try:
            c.execute("BEGIN IMMEDIATE")
            initialized = c.execute("select 1 from settings where key='domains_initialized_v1'").fetchone()
            existing = c.execute("select count(*) from mail_domains").fetchone()[0]
            if not initialized:
                if not existing:
                    now = time.time()
                    for domain in _env_domains():
                        domain = _normalize_domain(domain)
                        c.execute(
                            "insert into mail_domains(domain,enabled,users,dkim_selector,spf,dmarc,mx,created_at,updated_at) values(?,?,?,?,?,?,?,?,?)",
                            (domain, 1, json.dumps(_default_users()), "default", _default_spf(),
                             f"v=DMARC1; p=none; rua=mailto:postmaster@{domain}", os.getenv("MAIL_HOST", "mail.example.com"), now, now),
                        )
                c.execute("insert into settings(key,value) values('domains_initialized_v1','1')")
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()
        _write_runtime_files()

def _serialized_mail_store(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with _mail_store_lock:
            return function(*args, **kwargs)
    return wrapped


@_serialized_mail_store
def ingest_once():
    global _last_cur_scan
    root = Path("/maildata")
    if not root.exists(): return 0
    if shutil.disk_usage("/app-data").free < 2 * 1024**3:
        return 0
    count = 0
    c = db()
    paths = list(root.glob("*/**/Maildir/new/*"))
    now = time.monotonic()
    if now - _last_cur_scan >= CUR_SCAN_INTERVAL_SECONDS:
        # New delivery stays in Maildir/new until a mail client moves it.
        # Check cur periodically for legacy/unusual delivery paths without
        # walking the entire historical mailbox on every fast scan.
        paths += list(root.glob("*/**/Maildir/cur/*"))
        _last_cur_scan = now
    # Maildir/cur contains every message forever. The previous implementation
    # reread and reparsed the whole mailbox on every polling pass, which made
    # ingest latency grow with total mailbox size. Filter already-indexed
    # source paths in batches before touching message bytes.
    indexed_sources = set()
    source_values = [str(p) for p in paths if p.is_file() and not p.name.startswith(".")]
    for start in range(0, len(source_values), 500):
        batch = source_values[start:start + 500]
        if not batch:
            continue
        placeholders = ",".join("?" for _ in batch)
        indexed_sources.update(
            str(row[0]) for row in c.execute(
                f"select source_path from messages where source_path in ({placeholders})",
                batch,
            ).fetchall()
        )
    for p in paths:
        if not p.is_file() or p.name.startswith("."): continue
        if str(p) in indexed_sources:
            continue
        identity = maildir_identity(p)
        if not identity:
            continue
        delivery_key, recipient = identity
        delivery = c.execute("select message_id from message_deliveries where delivery_key=?", (delivery_key,)).fetchone()
        if delivery:
            # A Maildir filename remains the same logical delivery after new -> cur.
            c.execute("update message_deliveries set source_path=? where delivery_key=?", (str(p), delivery_key))
            c.execute("update messages set source_path=? where id=?", (str(p), delivery["message_id"]))
            continue
        raw = p.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        out = Path("/app-data/raw") / f"{digest}.eml"
        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw)
            actual = _resolve_actual_recipient(msg, recipient)
            actual_sender = _resolve_actual_sender(msg)
            out.parent.mkdir(parents=True, exist_ok=True)
            if not out.exists():
                temporary = out.with_suffix("." + secrets.token_hex(8) + ".tmp")
                try:
                    with temporary.open("wb") as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, out)
                finally:
                    temporary.unlink(missing_ok=True)
            cur = c.execute("""insert into messages(received_at,envelope_recipient,to_header,delivered_to,
                         original_to,message_id,subject,sender,raw_path,source_path,
                         actual_recipient,actual_recipient_source,recipient_parse_version,
                         actual_sender,actual_sender_source,sender_parse_version)
                         values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (time.time(), recipient, _decoded_header(msg, "To"), _decoded_header(msg, "Delivered-To"),
                       _decoded_header(msg, "X-Original-To"), _decoded_header(msg, "Message-ID"),
                       _decoded_header(msg, "Subject"), _decoded_header(msg, "From"), str(out), str(p),
                       actual["actual_recipient"], actual["actual_recipient_source"], RECIPIENT_PARSE_VERSION,
                       actual_sender["actual_sender"], actual_sender["actual_sender_source"], SENDER_PARSE_VERSION))
            policy_result = recipient_policy(recipient, _domain_rows())
            managed_domain = policy_result.get("managed_domain")
            owner = c.execute("select project_id from mail_domains where domain=?", (managed_domain,)).fetchone()
            project_id = owner["project_id"] if owner else None
            c.execute("insert into message_deliveries(delivery_key,message_id,envelope_recipient,managed_domain,recipient_domain,source_path,received_at,project_id) values(?,?,?,?,?,?,?,?)",
                      (delivery_key, cur.lastrowid, recipient, managed_domain, recipient.split("@", 1)[1], str(p), time.time(), project_id))
            _record_delivery_report(c, msg, cur.lastrowid, recipient, digest)
            payload = {
                "id": cur.lastrowid, "event": "message.received",
                "schema_version": "1",
                "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "envelope_recipient": recipient, "to": _decoded_header(msg, "To"),
                "from": _decoded_header(msg, "From"), "subject": _decoded_header(msg, "Subject"),
                "message_id": _decoded_header(msg, "Message-ID"), **actual, **actual_sender}
            payload["data"] = dict(payload)
            payload["data"].pop("data", None)
            event_seed = delivery_key
            hooks = _inbound_webhooks(c, project_id)
            now = time.time()
            for hook in hooks:
                event_id = "evt_" + hashlib.sha256((event_seed + ":" + str(hook["id"])).encode()).hexdigest()[:32]
                payload_for_hook = dict(payload, event_id=event_id)
                payload_for_hook["data"] = dict(payload["data"], event_id=event_id)
                c.execute("""insert or ignore into webhook_outbox(
                    event_id,webhook_id,message_id,payload_json,raw_path,status,attempts,
                    next_attempt_at,last_error,created_at,updated_at)
                    values(?,?,?,?,?,'queued',0,?,'',?,?)""",
                          (event_id, hook["id"], cur.lastrowid, json.dumps(payload_for_hook, separators=(",", ":")),
                           str(out), now, now, now))
            c.commit()
            # The queue is retained as a low-latency wakeup/compatibility hook;
            # the outbox remains the source of truth across process restarts.
            webhook_queue.put((cur.lastrowid, payload, str(out)))
            indexed_sources.add(str(p))
            count += 1
        except Exception:
            c.rollback()
            logger.exception("failed to ingest Maildir delivery %s", p)
            continue
    c.commit(); c.close()
    return count

def _retention_days() -> int:
    raw = setting_get("retention_days")
    try:
        value = int(str(raw).strip()) if raw is not None else DEFAULT_RETENTION_DAYS
    except (TypeError, ValueError):
        value = DEFAULT_RETENTION_DAYS
    return max(1, min(value, 3650))

def _max_storage_gb() -> float:
    raw = setting_get("max_storage_gb")
    try:
        value = float(str(raw).strip()) if raw is not None else DEFAULT_MAX_STORAGE_GB
    except (TypeError, ValueError):
        value = DEFAULT_MAX_STORAGE_GB
    return max(0.1, min(value, 10000.0))

def _email_storage_bytes() -> int:
    """Return bytes occupied by indexed email copies on disk."""
    total = 0
    for root in (Path("/maildata"), Path("/app-data/raw")):
        if not root.exists():
            continue
        for p in root.rglob("*"):
            try:
                if p.is_file():
                    total += p.stat().st_size
            except OSError:
                pass
    return total

def _remove_message_files(row) -> tuple[int, int, int]:
    removed_raw = 0
    removed_maildir = 0
    removed_bytes = 0
    seen = set()
    c = db()
    shared_raw = c.execute("select count(*) from messages where raw_path=? and id<>?", (row["raw_path"], row["id"])).fetchone()[0]
    c.close()
    for raw_path in (None if shared_raw else row["raw_path"], row["source_path"]):
        if not raw_path or raw_path in seen:
            continue
        seen.add(raw_path)
        p = Path(raw_path)
        if p == Path("/app-data/raw") or p == Path("/maildata"):
            continue
        try:
            if p.is_file():
                size = p.stat().st_size
                p.unlink()
                removed_bytes += size
                if str(p).startswith("/app-data/raw/"):
                    removed_raw += 1
                elif str(p).startswith("/maildata/"):
                    removed_maildir += 1
        except OSError:
            pass
    return removed_raw, removed_maildir, removed_bytes

@_serialized_mail_store
def cleanup_expired_messages(days: int | None = None) -> dict:
    """Remove expired indexed messages, raw RFC822 files, and Maildir copies."""
    days = _retention_days() if days is None else max(1, min(int(days), 3650))
    cutoff = time.time() - days * 86400
    removed_messages = 0
    removed_raw = 0
    removed_maildir = 0
    removed_bytes = 0
    c = db()
    rows = c.execute(
        "select id,raw_path,source_path from messages where received_at < ?",
        (cutoff,),
    ).fetchall()
    if rows:
        c.execute("delete from webhook_outbox where message_id in (select id from messages where received_at < ?)", (cutoff,))
        c.execute("delete from message_deliveries where message_id in (select id from messages where received_at < ?)", (cutoff,))
        c.execute("delete from messages where received_at < ?", (cutoff,))
    c.commit()
    c.close()
    for row in rows:
        raw_count, maildir_count, byte_count = _remove_message_files(row)
        removed_raw += raw_count
        removed_maildir += maildir_count
        removed_bytes += byte_count
        removed_messages += 1

    # Existing rows predate source_path. Remove stale Maildir files by mtime
    # so they cannot be ingested again after their DB rows are deleted.
    mail_root = Path("/maildata")
    if mail_root.exists():
        for folder in ("new", "cur", "tmp"):
            for p in mail_root.glob(f"*/**/Maildir/{folder}/*"):
                try:
                    if p.is_file() and p.stat().st_mtime < cutoff:
                        size = p.stat().st_size
                        p.unlink()
                        removed_maildir += 1
                        removed_bytes += size
                except OSError:
                    pass
    storage_before = _email_storage_bytes()
    storage_limit = int(_max_storage_gb() * 1024**3)
    storage_target = storage_limit // 2
    size_removed_messages = 0
    size_removed_bytes = 0
    if storage_before > storage_limit:
        c = db()
        size_rows = c.execute(
            "select id,raw_path,source_path from messages order by received_at asc, id asc"
        ).fetchall()
        c.close()
        for row in size_rows:
            c = db()
            c.execute("delete from webhook_outbox where message_id=?", (row["id"],))
            c.execute("delete from message_deliveries where message_id=?", (row["id"],))
            c.execute("delete from messages where id=?", (row["id"],))
            c.commit()
            c.close()
            raw_count, maildir_count, byte_count = _remove_message_files(row)
            removed_raw += raw_count
            removed_maildir += maildir_count
            size_removed_bytes += byte_count
            size_removed_messages += 1
            if storage_before - size_removed_bytes <= storage_target:
                break
    storage_after = _email_storage_bytes()
    result = {
        "days": days,
        "cutoff": cutoff,
        "removed_messages": removed_messages,
        "removed_raw": removed_raw,
        "removed_maildir": removed_maildir,
        "removed_bytes": removed_bytes + size_removed_bytes,
        "size_removed_messages": size_removed_messages,
        "size_removed_bytes": size_removed_bytes,
        "storage_before_bytes": storage_before,
        "storage_after_bytes": storage_after,
        "storage_limit_bytes": storage_limit,
        "storage_target_bytes": storage_target,
    }
    setting_set("last_cleanup_at", str(time.time()))
    setting_set("last_cleanup_result", json.dumps(result, separators=(",", ":")))
    return result

def _record_delivery_report(c, message, inbound_id, envelope_recipient, raw_digest):
    """Persist correlated, unverified reports with events in the ingest transaction."""
    parsed = parse_delivery_report(message)
    if not parsed:
        return 0
    candidates = c.execute(
        "select * from outbound_outbox where rfc_message_id=? and attempts>0",
        (parsed["rfc_message_id"],),
    ).fetchall()
    if len(candidates) != 1:
        return 0
    outbound = candidates[0]
    if envelope_recipient != outbound["sender"]:
        return 0
    targets = set(json.loads(outbound["recipients_json"]))
    now = time.time()
    count = 0
    for report in parsed["reports"]:
        if report["recipient"] not in targets:
            continue
        report_key = hashlib.sha256(
            (str(outbound["id"]) + ":" + raw_digest + ":" + json.dumps(report, sort_keys=True)).encode()
        ).hexdigest()
        inserted = c.execute(
            """insert or ignore into outbound_delivery_reports(
                outbound_id,report_key,inbound_message_id,recipient,final_recipient,
                action,status_code,diagnostic,reporting_mta,trust,received_at)
                values(?,?,?,?,?,?,?,?,?,'unverified',?)""",
            (outbound["id"], report_key, inbound_id, report["recipient"], report["final_recipient"],
             report["action"], report["status_code"], report["diagnostic"], report["reporting_mta"], now),
        )
        if not inserted.rowcount:
            continue
        count += 1
        hooks = c.execute(
            """select w.id from webhooks w left join projects p on p.id=w.project_id
               where w.enabled=1
                 and (w.project_id is null or w.project_id = ?)
                 and (w.project_id is null or p.enabled=1)""",
            (outbound["project_id"],),
        ).fetchall()
        for hook in hooks:
            event_id = "evt_" + hashlib.sha256((report_key + ":" + str(hook["id"])).encode()).hexdigest()[:32]
            payload = {
                "event": "outbound.status_reported", "schema_version": "1", "event_id": event_id,
                "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "data": {"request_id": outbound["request_id"], **report, "trust": "unverified"},
            }
            c.execute(
                """insert or ignore into webhook_outbox(
                    event_id,webhook_id,message_id,payload_json,raw_path,status,attempts,
                    next_attempt_at,last_error,created_at,updated_at)
                    values(?,?,?, ?,NULL,'queued',0,?,'',?,?)""",
                (event_id, hook["id"], inbound_id, json.dumps(payload), now, now, now),
            )
    # A remote DSN is evidence about recipient delivery after MTA submission.
    # Keep the durable report rows and only downgrade the aggregate when a
    # recipient is explicitly reported failed; delayed/delivered reports do
    # not erase the fact that the MTA accepted the message.
    failed_count = c.execute(
        "select count(distinct recipient) from outbound_delivery_reports where outbound_id=? and action='failed'",
        (outbound["id"],),
    ).fetchone()[0]
    if failed_count:
        aggregate = "failed" if failed_count >= len(targets) else "partial"
        c.execute(
            """update outbound_outbox set status=?,last_error=?,updated_at=?
               where id=? and status in ('submitted_to_mta','partial')""",
            (aggregate, f"remote_dsn_failed={failed_count}/{len(targets)}", now, outbound["id"]),
        )
    return count


def _inbound_webhooks(c, project_id):
    return c.execute("""select w.id,w.url,w.secret from webhooks w
        left join projects p on p.id=w.project_id
        where w.enabled=1 and (w.project_id is null or w.project_id is ?)
          and (w.project_id is null or p.enabled=1)""", (project_id,)).fetchall()


def _webhook_job_allowed(c, row):
    hook = c.execute("select enabled,project_id from webhooks where id=?", (row["webhook_id"],)).fetchone()
    if not hook or not hook["enabled"]:
        return False
    project_id = hook["project_id"]
    if project_id and not c.execute("select 1 from projects where id=? and enabled=1", (project_id,)).fetchone():
        return False
    try:
        payload = json.loads(row["payload_json"])
        if payload.get("event") == "message.received":
            resource = c.execute("select project_id from message_deliveries where message_id=?",
                                 (row["message_id"],)).fetchone()
        elif payload.get("event") == "outbound.status_reported":
            resource = c.execute("select project_id from outbound_outbox where request_id=?",
                                 (payload.get("data", {}).get("request_id"),)).fetchone()
        else:
            return False
        return resource is not None and (project_id is None or resource["project_id"] == project_id)
    except (ValueError, TypeError, AttributeError):
        return False


def dispatch_webhooks(message_id, payload, raw_content: bytes | str | None = None,
                      raw_path: str | None = None):
    c = db()
    owner = c.execute("select project_id from message_deliveries where message_id=?", (message_id,)).fetchone()
    hooks = _inbound_webhooks(c, owner["project_id"] if owner else None)
    c.close()
    if not hooks:
        return
    if raw_path:
        try:
            raw_content = Path(raw_path).read_bytes()
        except OSError:
            raw_content = None
    payload = dict(payload or {})
    payload.setdefault("message_id", str(payload.get("message_id") or message_id))
    payload.setdefault("to_addr", payload.get("envelope_recipient") or payload.get("to") or "")
    if raw_content is not None:
        if isinstance(raw_content, bytes):
            raw_content = raw_content.decode("utf-8", errors="replace")
        payload["raw_content"] = str(raw_content)
    body=json.dumps(payload,separators=(",",":")).encode()
    stamp=str(int(time.time()))
    for hook in hooks:
        signature=hmac.new(hook["secret"].encode(), stamp.encode()+b"." + body, hashlib.sha256).hexdigest()
        req=urllib.request.Request(hook["url"], data=body, method="POST",
            headers={
                "Content-Type":"application/json",
                # Some reverse proxies/WAFs reject Python's default
                # ``urllib`` user agent before the webhook reaches the app.
                "User-Agent":"MailStack-Webhook/1.0",
                "X-Email-Webhook-Secret":hook["secret"],
                # SFReg consumes X-Email-Webhook-Secret; modern consumes
                # X-Webhook-Secret. Send both aliases with the same configured
                # secret so neither receiver requires weaker authentication.
                "X-Webhook-Secret":hook["secret"],
                "X-Webhook-Timestamp":stamp,
                "X-Webhook-Signature":"sha256="+signature,
            })
        status="failed"; err=""
        for attempt in range(1,4):
            try:
                send_webhook_request(req, timeout=float(os.getenv("WEBHOOK_TIMEOUT_SECONDS", "10")))
                status="delivered"; err=""; break
            except WebhookDeliveryError as exc:
                err = str(exc)
            except Exception:
                err = "webhook_transport_failed"
            time.sleep(2 ** (attempt-1))
        c=db(); c.execute("insert into webhook_deliveries(webhook_id,message_id,status,attempts,last_error,created_at) values(?,?,?,?,?,?)",(hook["id"],message_id,status,attempt,err,time.time())); c.commit(); c.close()

def _claim_webhook_outbox():
    now = time.time()
    c = db()
    try:
        c.execute("BEGIN IMMEDIATE")
        c.execute("""update webhook_outbox set status='queued',updated_at=?
                     where status='running' and updated_at < ?""",
                  (now, now - WEBHOOK_LEASE_SECONDS))
        row = c.execute("""select o.*,w.url,w.secret,w.enabled
                           from webhook_outbox o left join webhooks w on w.id=o.webhook_id
                           where o.status='queued' and o.next_attempt_at<=?
                           order by o.id limit 1""", (now,)).fetchone()
        if not row:
            c.commit()
            return None
        if not _webhook_job_allowed(c, row):
            c.execute("update webhook_outbox set status='cancelled',last_error='webhook_project_mismatch',updated_at=? where id=?", (now, row["id"]))
            c.commit()
            return None
        c.execute("""update webhook_outbox set status='running',attempts=attempts+1,
                     updated_at=? where id=? and status='queued'""", (now, row["id"]))
        c.commit()
        return dict(c.execute("""select o.*,w.url,w.secret,w.enabled
                                from webhook_outbox o join webhooks w on w.id=o.webhook_id
                                where o.id=?""", (row["id"],)).fetchone())
    finally:
        c.close()

def _deliver_webhook_outbox(row):
    now = time.time()
    c = db()
    try:
        if not _webhook_job_allowed(c, row):
            with c:
                c.execute("""update webhook_outbox set status='cancelled',
                             last_error='webhook_project_mismatch',updated_at=? where id=?""", (now, row["id"]))
            return
    finally:
        c.close()
    payload = json.loads(row["payload_json"])
    raw_path = row["raw_path"]
    if raw_path:
        try:
            raw_content = Path(raw_path).read_bytes().decode("utf-8", errors="replace")
            payload["raw_content"] = raw_content
            payload.setdefault("data", {})["raw_content"] = raw_content
        except OSError:
            pass
    body = json.dumps(payload, separators=(",", ":")).encode()
    stamp = str(int(now))
    signature = hmac.new(row["secret"].encode(), stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(row["url"], data=body, method="POST", headers={
        "Content-Type": "application/json",
        "User-Agent": "MailStack-Webhook/1.0",
        "X-Email-Webhook-Secret": row["secret"],
        "X-Webhook-Secret": row["secret"],
        "X-Webhook-Timestamp": stamp,
        "X-Webhook-Signature": "sha256=" + signature,
    })
    status, error = "failed", ""
    try:
        send_webhook_request(req, timeout=float(os.getenv("WEBHOOK_TIMEOUT_SECONDS", "10")))
        status, error = "delivered", ""
    except WebhookDeliveryError as exc:
        error = str(exc)
    except Exception:
        error = "webhook_transport_failed"
    c = db()
    try:
        with c:
            if status == "delivered":
                c.execute("""update webhook_outbox set status='delivered',last_error='',
                             next_attempt_at=?,updated_at=? where id=?""", (now, now, row["id"]))
                c.execute("""insert into webhook_deliveries(
                             webhook_id,message_id,status,attempts,last_error,created_at)
                             values(?,?,?,?,?,?)""",
                          (row["webhook_id"], row["message_id"], "delivered", row["attempts"], "", now))
            elif row["attempts"] >= WEBHOOK_RETRY_LIMIT:
                c.execute("""update webhook_outbox set status='failed',last_error=?,
                             next_attempt_at=?,updated_at=? where id=?""",
                          (error, now, now, row["id"]))
                c.execute("""insert into webhook_deliveries(
                             webhook_id,message_id,status,attempts,last_error,created_at)
                             values(?,?,?,?,?,?)""",
                          (row["webhook_id"], row["message_id"], "failed", row["attempts"], error, now))
            else:
                delay = 2 ** max(0, row["attempts"] - 1)
                c.execute("""update webhook_outbox set status='queued',last_error=?,
                             next_attempt_at=?,updated_at=? where id=?""",
                          (error, now + delay, now, row["id"]))
    finally:
        c.close()

def webhook_worker():
    """Durably deliver webhook outbox rows independently of Maildir ingest."""
    while True:
        try:
            row = _claim_webhook_outbox()
            if row:
                _deliver_webhook_outbox(row)
            else:
                time.sleep(0.5)
        except Exception:
            logger.exception("webhook outbox dispatch failed")
            time.sleep(1)

def _claim_outbound():
    now = time.time()
    c = db()
    try:
        c.execute("BEGIN IMMEDIATE")
        c.execute(
            """update outbound_outbox set status='submission_unknown',
               last_error='submission lease expired; MTA acceptance is uncertain',updated_at=?
               where status='running' and updated_at < ?""",
            (now, now - OUTBOUND_LEASE_SECONDS),
        )
        row = c.execute(
            """select * from outbound_outbox
               where status='queued' and next_attempt_at<=?
               order by id limit 1""",
            (now,),
        ).fetchone()
        if not row:
            c.commit()
            return None
        c.execute(
            """update outbound_outbox set status='running',attempts=attempts+1,
               updated_at=? where id=? and status='queued'""",
            (now, row["id"]),
        )
        c.commit()
        return dict(c.execute("select * from outbound_outbox where id=?", (row["id"],)).fetchone())
    finally:
        c.close()

def _brevo_api_fallback(row, recipients):
    """Submit only after an explicit SMTP non-acceptance.

    A connection drop or generic exception is deliberately excluded by the
    caller because the remote MTA may already have accepted DATA.  Brevo API
    errors are surfaced with their uncertainty flag so the outbox never
    blindly sends the same RFC822 message twice.
    """
    if not OUTBOUND_API_FALLBACK_ENABLED:
        return False
    api_key = os.getenv("BREVO_API_KEY", "").strip()
    if not api_key:
        return False
    api = BrevoAPI(
        JsonTransport(timeout=20),
        api_key,
        os.getenv("BREVO_API_BASE", "https://api.brevo.com").strip(),
    )
    api.send_transactional(bytes(row["raw_message"]), recipients)
    return True


def _deliver_outbound(row):
    now = time.time()
    recipients = json.loads(row["recipients_json"])
    status = "failed"
    error = ""
    accepted = []
    rejected = {}
    transport = row.get("transport") or "smtp"
    fallback_attempted = int(row.get("fallback_attempts") or 0)
    try:
        with smtplib.SMTP(
            os.getenv("SMTP_SUBMISSION_HOST", "mail-postfix"),
            int(os.getenv("SMTP_SUBMISSION_PORT", "25")),
            timeout=15,
        ) as smtp:
            refused = smtp.sendmail(row["sender"], recipients, bytes(row["raw_message"]))
        rejected = {
            address: {
                "code": code,
                "error": text.decode(errors="replace") if isinstance(text, bytes) else str(text),
            }
            for address, (code, text) in refused.items()
        }
        accepted = [address for address in recipients if address not in refused]
        status = "partial" if rejected else "submitted_to_mta"
    except smtplib.SMTPRecipientsRefused as exc:
        rejected = {
            address: {"code": code, "error": text.decode(errors="replace") if isinstance(text, bytes) else str(text)}
            for address, (code, text) in exc.recipients.items()
        }
        status = "failed"
        error = "all recipients refused"
    except smtplib.SMTPResponseException as exc:
        # Explicit negative acknowledgement: DATA was not accepted by the MTA.
        status = "failed" if exc.smtp_code >= 500 else "retry"
        error = f"smtp_{exc.smtp_code}"
        if not accepted and not rejected and fallback_attempted == 0:
            try:
                used = _brevo_api_fallback(row, recipients)
                if used:
                    fallback_attempted = 1
                    accepted = list(recipients)
                    rejected = {}
                    status = "submitted_to_mta"
                    transport = "brevo_api"
                    error = ""
            except ProviderError as fallback_error:
                fallback_attempted = 1
                status = "submission_unknown" if fallback_error.uncertain else "failed"
                error = f"brevo_api_{fallback_error.code}"
            except Exception as fallback_error:
                fallback_attempted = 1
                status = "submission_unknown"
                error = f"brevo_api_{str(fallback_error)[:200]}"
    except (ConnectionRefusedError, smtplib.SMTPConnectError) as exc:
        status = "retry"
        error = str(exc)[:240]
        if fallback_attempted == 0:
            try:
                used = _brevo_api_fallback(row, recipients)
                if used:
                    fallback_attempted = 1
                    accepted = list(recipients)
                    rejected = {}
                    status = "submitted_to_mta"
                    transport = "brevo_api"
                    error = ""
            except ProviderError as fallback_error:
                fallback_attempted = 1
                status = "submission_unknown" if fallback_error.uncertain else "failed"
                error = f"brevo_api_{fallback_error.code}"
            except Exception as fallback_error:
                fallback_attempted = 1
                status = "submission_unknown"
                error = f"brevo_api_{str(fallback_error)[:200]}"
    except Exception as exc:
        # A dropped connection may occur after DATA was accepted. Never blindly
        # resubmit that message, including after a process/lease restart.
        status = "submission_unknown"
        error = str(exc)[:240]

    c = db()
    try:
        with c:
            if status in {"submitted_to_mta", "partial"}:
                c.execute(
                    """update outbound_outbox set status=?,last_error='',
                       accepted_json=?,rejected_json=?,transport=?,fallback_attempts=?,
                       next_attempt_at=?,updated_at=?
                       where id=?""",
                    (
                        status,
                        json.dumps(accepted, separators=(",", ":")),
                        json.dumps(rejected, separators=(",", ":")),
                        transport,
                        fallback_attempted,
                        now,
                        now,
                        row["id"],
                    ),
                )
            elif status in {"submission_unknown", "failed"} or row["attempts"] >= OUTBOUND_RETRY_LIMIT:
                c.execute(
                    """update outbound_outbox set status=?,last_error=?,rejected_json=?,
                       transport=?,fallback_attempts=?,next_attempt_at=?,updated_at=?
                       where id=? and status='running'""",
                    (status if status in {"submission_unknown", "failed"} else "failed",
                     error, json.dumps(rejected), transport, fallback_attempted, now, now, row["id"]),
                )
            else:
                delay = 2 ** max(0, row["attempts"] - 1)
                c.execute(
                    """update outbound_outbox set status='queued',last_error=?,
                       transport=?,fallback_attempts=?,next_attempt_at=?,updated_at=? where id=?""",
                    (error, transport, fallback_attempted, now + delay, now, row["id"]),
                )
    finally:
        c.close()

def outbound_worker():
    """Durably deliver queued outbound messages independently of request latency."""
    while True:
        try:
            row = _claim_outbound()
            if row:
                _deliver_outbound(row)
            else:
                time.sleep(0.5)
        except Exception:
            logger.exception("outbound outbox dispatch failed")
            time.sleep(1)

def _decoded_header(message, name: str) -> str | None:
    value = message.get(name)
    return None if value is None else str(value)

def _decoded_part_text(part) -> str:
    try:
        value = part.get_content()
        if isinstance(value, str):
            return value
    except Exception:
        pass
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeError):
        return payload.decode("utf-8", errors="replace")

def _recipient_addresses(value) -> list[str]:
    """Extract ordinary mailbox addresses without changing local-part/+tag."""
    addresses = []
    for _, address in getaddresses([str(value or "")]):
        if len(address) <= 254 and re.fullmatch(
            r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", address
        ):
            local, domain = address.rsplit("@", 1)
            normalized = f"{local}@{domain.lower()}"
            if normalized not in addresses:
                addresses.append(normalized)
    return addresses

def _resolve_actual_sender(message) -> dict:
    """Infer original From address; HME s is metadata, not authentication."""
    candidates = []
    remaining = SENDER_HEADER_SCAN_LIMIT
    for header in message.get_all("X-ICLOUD-HME", []):
        text = str(header)
        if len(text) > remaining:
            candidates = []  # Never select a candidate from a truncated header.
            break
        remaining -= len(text)
        for item in text.split(";"):
            key, separator, value = item.partition("=")
            if separator and key.strip().lower() == "s":
                candidates.extend(_recipient_addresses(value.strip()))
    candidates = list(dict.fromkeys(candidates))
    if len(candidates) == 1:
        return {"actual_sender": candidates[0], "actual_sender_source": "hme_header"}
    # Missing/invalid/conflicting mappings use From, never Return-Path/Reply-To.
    addresses = _recipient_addresses(_decoded_header(message, "From"))
    return {"actual_sender": ", ".join(addresses) or None,
            "actual_sender_source": "from_header" if addresses else "unresolved"}


def _read_sender_headers(path):
    """Read only the bounded RFC header block, never a body or attachment."""
    chunks = []
    remaining = SENDER_HEADER_SCAN_LIMIT
    with Path(path).open("rb") as stream:
        while remaining > 0:
            line = stream.readline(remaining + 1)
            if len(line) > remaining:
                raise ValueError("Sender header block exceeds scan limit")
            chunks.append(line)
            remaining -= len(line)
            if not line or line in (b"\n", b"\r\n"):
                return BytesHeaderParser(policy=policy.default).parsebytes(b"".join(chunks))
    raise ValueError("Sender header block exceeds scan limit")


def backfill_actual_senders(batch_size=25, pause_seconds=1):
    """Cache sender metadata once per version; do not replay old webhooks."""
    processed = 0
    last_id = 2**63 - 1
    while True:
        c = db()
        rows = c.execute(
            "select id,raw_path,sender from messages "
            "where sender_parse_version < ? and id <= ? order by id desc limit ?",
            (SENDER_PARSE_VERSION, last_id, batch_size),
        ).fetchall()
        c.close()
        if not rows:
            return processed
        updates = []
        for row in rows:
            try:
                actual = _resolve_actual_sender(_read_sender_headers(row["raw_path"]))
            except (OSError, ValueError):
                # Preserve available From metadata even if history raw is gone.
                addresses = _recipient_addresses(row["sender"])
                actual = {"actual_sender": ", ".join(addresses) or None,
                          "actual_sender_source": "from_header" if addresses else "unresolved"}
            updates.append((actual["actual_sender"], actual["actual_sender_source"],
                            SENDER_PARSE_VERSION, row["id"], SENDER_PARSE_VERSION))
        c = db()
        c.executemany(
            "update messages set actual_sender=?,actual_sender_source=?,sender_parse_version=? "
            "where id=? and sender_parse_version < ?", updates,
        )
        c.commit()
        c.close()
        processed += len(updates)
        last_id = rows[-1]["id"] - 1
        if pause_seconds:
            time.sleep(pause_seconds)


def _hme_body_texts(message):
    """Scan bounded inline text only; never decode attachments/nested emails."""
    remaining = HME_BODY_SCAN_LIMIT
    pending = [message]
    visited = 0
    while pending and remaining > 0 and visited < 100:
        part = pending.pop()
        visited += 1
        if part.get_content_disposition() == "attachment" or part.get_filename():
            continue
        if part.get_content_maintype() == "message":
            continue
        if part.is_multipart():
            capacity = max(0, 100 - visited - len(pending))
            pending.extend(reversed(part.get_payload()[:capacity]))
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        payload = part.get_payload()
        if not isinstance(payload, str) or len(payload) > HME_BODY_SCAN_LIMIT * 2:
            continue
        text = _decoded_part_text(part)[:remaining]
        remaining -= len(text)
        yield html.unescape(text)

def _resolve_actual_recipient(message, envelope_recipient=None) -> dict:
    """Address inference only, not authentication. HME candidates must match p."""
    def result(address, source):
        return {"actual_recipient": address, "actual_recipient_source": source}

    aliases = []
    for header in message.get_all("X-ICLOUD-HME", []):
        for item in str(header).split(";"):
            key, separator, value = item.partition("=")
            if separator and key.strip().lower() == "p":
                aliases.extend(_recipient_addresses(value.strip()))
    aliases = list(dict.fromkeys(aliases))
    if len(aliases) == 1:
        alias = aliases[0]
        local, domain = alias.rsplit("@", 1)
        if "+" in local and local.split("+", 1)[1]:
            return result(alias, "hme_header")
        # SendGrid envelope-from embeds the destination using "=domain";
        # iCloud may further rewrite its outer sender as "_at_...".
        pattern = re.compile(
            r"(?<![A-Za-z0-9._])" + re.escape(local) +
            r"\+([A-Za-z0-9._+-]{1,128})(?:=|@)" + re.escape(domain) +
            r"(?=$|[\s<>;()\"'&/@]|_at_)", re.IGNORECASE
        )
        candidates = set()
        remaining = 64 * 1024
        for name in ("To", "Received-SPF", "Authentication-Results", "Return-Path"):
            for header in message.get_all(name, []):
                text = str(header)[:remaining]
                remaining -= len(text)
                for match in pattern.finditer(text):
                    candidate = f"{local}+{match[1]}@{domain}"
                    if len(candidate) <= 254:
                        candidates.add(candidate)
                if remaining <= 0:
                    break
            if remaining <= 0:
                break
        if len(candidates) == 1:
            return result(candidates.pop(), "hme_header")
        # Conflicting candidates are not resolved by choosing the first one.
        if len(candidates) > 1:
            return result(alias, "hme_alias")
        for text in _hme_body_texts(message):
            for match in re.finditer(r"\blogin_hint\s*=\s*([^&\s\"'<>]+)", text, re.IGNORECASE):
                hint = match[1]
                for _ in range(2):
                    hint = urllib.parse.unquote(hint)  # Preserve literal "+".
                for address in _recipient_addresses(hint):
                    candidate_local, candidate_domain = address.rsplit("@", 1)
                    base, separator, tag = candidate_local.partition("+")
                    if (separator and tag and base.casefold() == local.casefold()
                            and candidate_domain.casefold() == domain.casefold()):
                        candidates.add(address)
        if len(candidates) == 1:
            return result(candidates.pop(), "hme_login_hint")
        return result(alias, "hme_alias")
    # No mapping (or ambiguous mapping): do not guess a tag from arbitrary HTML.
    recipients = _recipient_addresses(_decoded_header(message, "To"))
    if recipients:
        return result(", ".join(recipients), "to_header")
    recipients = _recipient_addresses(envelope_recipient)
    return result(", ".join(recipients) or None, "envelope_recipient" if recipients else "unresolved")

def backfill_actual_recipients(batch_size=25, pause_seconds=1):
    """One-time, versioned history backfill; no parsing in list requests."""
    processed = 0
    last_id = 2**63 - 1
    while True:
        c = db()
        rows = c.execute(
            "select id,raw_path,envelope_recipient from messages "
            "where recipient_parse_version < ? and id <= ? order by id desc limit ?",
            (RECIPIENT_PARSE_VERSION, last_id, batch_size),
        ).fetchall()
        c.close()
        if not rows:
            return processed
        updates = []
        for row in rows:
            actual = {"actual_recipient": None, "actual_recipient_source": "unresolved"}
            try:
                message = BytesParser(policy=policy.default).parsebytes(Path(row["raw_path"]).read_bytes())
                actual = _resolve_actual_recipient(message, row["envelope_recipient"])
            except Exception:
                logger.exception("recipient backfill failed for message_id=%s", row["id"])
            updates.append((actual["actual_recipient"], actual["actual_recipient_source"],
                            RECIPIENT_PARSE_VERSION, row["id"], RECIPIENT_PARSE_VERSION))
        c = db()
        c.executemany(
            "update messages set actual_recipient=?,actual_recipient_source=?,recipient_parse_version=? "
            "where id=? and recipient_parse_version < ?", updates,
        )
        c.commit()
        c.close()
        processed += len(updates)
        last_id = rows[-1]["id"] - 1
        if pause_seconds:
            time.sleep(pause_seconds)

def _recipient_backfill_worker():
    try:
        count = backfill_actual_recipients()
        if count:
            logger.info("backfilled actual recipients for %d message(s)", count)
    except Exception:
        logger.exception("actual recipient backfill failed")
    try:
        count = backfill_actual_senders()
        if count:
            logger.info("backfilled actual senders for %d message(s)", count)
    except Exception:
        logger.exception("actual sender backfill failed")

def _sanitize_email_html(value: str) -> str:
    """保留邮件样式，同时移除脚本、事件属性和危险链接。"""
    value = re.sub(
        r"(?is)<\s*(script|iframe|object|embed|form|base|meta|link)\b[^>]*>.*?<\s*/\s*\1\s*>",
        "",
        value,
    )
    value = re.sub(
        r"(?is)<\s*/?\s*(script|iframe|object|embed|form|base|meta|link)\b[^>]*>",
        "",
        value,
    )
    value = re.sub(
        r"(?i)\s+on[a-z0-9_-]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)",
        "",
        value,
    )
    value = re.sub(
        r"(?i)(\s(?:href|src|action|formaction)\s*=\s*)([\"'])\s*(?:javascript|vbscript|data:text/html):[^\"']*\2",
        r"\1\2\2",
        value,
    )
    value = re.sub(r"(?i)(?:javascript|vbscript)\s*:", "", value)
    value = re.sub(r"(?i)expression\s*\(", "(", value)
    return value.strip()

def _message_content(message) -> dict:
    html_body = ""
    text_body = ""
    charset = None
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/html", "text/plain"}:
            continue
        text = _decoded_part_text(part)
        if not text:
            continue
        charset = charset or part.get_content_charset()
        if content_type == "text/html" and not html_body:
            html_body = text
        elif content_type == "text/plain" and not text_body:
            text_body = text
    return {
        "html": _sanitize_email_html(html_body) if html_body else "",
        "text": text_body,
        "charset": charset or "utf-8",
        "content_type": "text/html" if html_body else "text/plain",
    }

def scanner():
    while True:
        try:
            count = ingest_once()
            if count:
                logger.info("indexed %d new message(s)", count)
        except Exception:
            logger.exception("maildir ingest failed")
        time.sleep(INGEST_INTERVAL_SECONDS)

def cleanup_scanner():
    while True:
        try:
            cleanup_expired_messages()
        except Exception:
            logger.exception("retention cleanup failed")
        time.sleep(CLEANUP_INTERVAL_SECONDS)

@app.on_event("startup")
def startup():
    # Migrate legacy plaintext before any worker can use provider credentials.
    load_cloudflare_secret(db)
    _seed_domains()
    if os.getenv("DOMAIN_JOBS_ENABLED", "1") == "1":
        domain_worker.start()
    for _ in range(WEBHOOK_WORKERS):
        threading.Thread(target=webhook_worker, daemon=True, name="webhook-worker").start()
    for _ in range(OUTBOUND_WORKERS):
        threading.Thread(target=outbound_worker, daemon=True, name="outbound-worker").start()
    threading.Thread(target=scanner, daemon=True).start()
    threading.Thread(target=_recipient_backfill_worker, daemon=True, name="recipient-backfill").start()
    threading.Thread(target=cleanup_scanner, daemon=True).start()

def key_ok(value):
    return bool(key_scopes(value))

def key_scopes(value):
    if not value:
        return None
    digest = hashlib.sha256((value + os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
    c = db()
    try:
        row = c.execute("select scopes from api_keys where key_hash=?", (digest,)).fetchone()
        if row:
            raw = row["scopes"] or ""
            return frozenset(item for item in str(raw).split(",") if item in API_SCOPES)
        row = c.execute("select 1 from sessions where token_hash=? and expires_at>?", (digest, time.time())).fetchone()
        return DEFAULT_API_SCOPES if row else None
    finally:
        c.close()

def key_has_scope(value, scope):
    return scope in (key_scopes(value) or ())

def _key_row(value):
    if not value:
        return None
    digest = hashlib.sha256((value + os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
    c = db()
    try:
        return c.execute("select id,scopes,global_access from api_keys where key_hash=?",
                         (digest,)).fetchone()
    finally:
        c.close()

def key_has_global_scope(value, scope):
    if not key_has_scope(value, scope):
        return False
    if session_ok(value):
        return True
    row = _key_row(value)
    # global_access is the persisted representation of key_type=admin.
    # Project grants never downgrade an explicitly administrative key.
    return bool(row and row["global_access"])


def key_has_project_scope(value, scope, project_id):
    if not project_id:
        return key_has_global_scope(value, scope)
    if not key_has_scope(value, scope):
        return False
    # Administrator sessions and admin keys may access active projects
    # without grants. Normal service keys require an explicit project grant.
    digest = hashlib.sha256((value + os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest() if value else ""
    c = db()
    try:
        if key_has_global_scope(value, scope):
            return bool(c.execute("select 1 from projects where id=? and enabled=1", (project_id,)).fetchone())
        row = c.execute("""select g.scopes from api_key_grants g join projects p on p.id=g.project_id
                           join api_keys k on k.id=g.key_id
                           where k.key_hash=? and g.project_id=? and p.enabled=1""",
                        (digest, project_id)).fetchone()
        return bool(row and scope in str(row["scopes"] or "").split(","))
    finally:
        c.close()


def _require_mail_read(value, message_id=None):
    if not key_ok(value):
        raise HTTPException(401, "invalid api key")
    if not key_has_scope(value, "mail.read"):
        raise HTTPException(403, "missing mail.read scope")
    if message_id is None or key_has_global_scope(value, "mail.read"):
        return
    c = db()
    try:
        owner = c.execute("select project_id from message_deliveries where message_id=?", (message_id,)).fetchone()
    finally:
        c.close()
    if not owner:
        raise HTTPException(404, "message not found")
    if not key_has_project_scope(value, "mail.read", owner["project_id"]):
        raise HTTPException(403, "missing mail.read project grant")


def _visible_domains(rows, value):
    if admin_ok(value):
        return rows
    scopes = key_scopes(value) or ()
    if any(key_has_global_scope(value, scope) for scope in scopes):
        return rows
    key = _key_row(value)
    if not key:
        return []
    c = db()
    try:
        allowed = {row["project_id"] for row in c.execute(
            """select g.project_id,g.scopes from api_key_grants g join projects p on p.id=g.project_id
               where g.key_id=? and p.enabled=1""", (key["id"],))
            if scopes.intersection(str(row["scopes"]).split(","))}
    finally:
        c.close()
    return [row for row in rows if row.get("project_id") in allowed]


def _require_sender_project(sender, project_id, api_key=None):
    if project_id is None or key_has_global_scope(api_key, "mail.send"):
        return
    try:
        domain = normalize_address(sender).rsplit("@", 1)[1]
    except ValueError:
        raise HTTPException(400, "invalid sender") from None
    candidates = [row for row in _domain_rows()
                  if domain == row["domain"] or domain.endswith("." + row["domain"])]
    owner = max(candidates, key=lambda row: len(row["domain"])) if candidates else None
    if not owner or owner.get("project_id") != project_id:
        raise HTTPException(403, "sender domain does not belong to project")


def parse_project_id(value):
    if value is None:
        return None
    value = str(value).strip()
    if not re.fullmatch(r"prj_[A-Za-z0-9_-]{8,80}", value):
        raise HTTPException(400, "invalid project id")
    return value

def parse_scopes(value):
    scopes = frozenset(item.strip() for item in str(value or "").split(",") if item.strip())
    if not scopes or not scopes.issubset(API_SCOPES):
        raise HTTPException(400, "invalid API key scopes")
    return ",".join(sorted(scopes))

def session_ok(value):
    if not value: return False
    digest = hashlib.sha256((value + os.getenv("API_KEY_PEPPER","")).encode()).hexdigest()
    c=db()
    row=c.execute("select 1 from sessions where token_hash=? and expires_at>?", (digest,time.time())).fetchone()
    c.close()
    return bool(row)

def setting_get(name):
    c=db()
    row=c.execute("select value from settings where key=?", (name,)).fetchone()
    c.close()
    return row["value"] if row else None

def setting_set(name: str, value: str):
    c = db()
    c.execute("insert into settings(key,value) values(?,?) on conflict(key) do update set value=excluded.value",
              (name, value))
    c.commit()
    c.close()

def _global_cloudflare_secret():
    try:
        stored = load_cloudflare_secret(db)
    except CredentialError as exc:
        raise HTTPException(409, str(exc)) from None
    if stored:
        return stored
    token = os.getenv("CF_API_TOKEN", "").strip()
    if token:
        return {"api_token": token}
    email = os.getenv("CF_API_EMAIL", "").strip()
    key = os.getenv("CF_API_KEY", "").strip()
    if email and key:
        return {"api_email": email, "api_key": key}
    return {}


def _cloudflare_headers() -> tuple[dict[str, str] | None, str | None]:
    from api.providers.dns.cloudflare import cloudflare_headers
    secret = _global_cloudflare_secret()
    if secret:
        return {**cloudflare_headers(secret), "Content-Type": "application/json"}, None
    return None, "Cloudflare API Token 或 Global API Key 尚未配置"

def _cf_request(method: str, path: str, payload: dict | None = None, params: dict | None = None) -> tuple[int, dict]:
    url = CF_API_BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    body = json.dumps(payload).encode() if payload is not None else None
    headers, err = _cloudflare_headers()
    if err:
        return 0, {"success": False, "errors": [{"message": err}]}
    req = urllib.request.Request(url, data=body, method=method.upper(), headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try: data = json.loads(raw)
        except Exception: data = {"success": False, "errors": [{"message": raw[:500]}]}
        return exc.code, data
    except Exception as exc:
        return 0, {"success": False, "errors": [{"message": str(exc)[:500]}]}

def _cf_error(data: dict) -> str:
    return str(data.get("errors") or data.get("messages") or data)[:600]

def _dkim_txt(domain: str, selector: str) -> str:
    path = Path("/dkim/keys") / domain / f"{selector}.txt"
    if not path.exists():
        return ""
    chunks = re.findall(r'"([^"]*)"', path.read_text(errors="replace"))
    return "".join(chunks).strip()

def _cf_upsert_record(zone_id: str, record: dict) -> dict:
    status, data = _cf_request("GET", f"/zones/{zone_id}/dns_records", params={
        "type": record["type"], "name": record["name"], "per_page": 100,
    })
    if not data.get("success"):
        return {"ok": False, "record": record, "error": _cf_error(data)}
    existing = (data.get("result") or [])
    payload = {k: v for k, v in record.items() if k in {"type", "name", "content", "ttl", "proxied", "priority"}}
    if existing:
        try:
            current = select_record(existing, record)
        except ValueError as exc:
            return {"ok": False, "record": record, "error": str(exc)}
        if current is None:
            status, data = _cf_request("POST", f"/zones/{zone_id}/dns_records", payload)
            return {"ok": bool(data.get("success")), "action": "created", "record": record,
                    "error": "" if data.get("success") else _cf_error(data)}
        same = str(current.get("content", "")).strip('"') == str(payload.get("content", "")).strip('"')
        if record.get("type") == "MX":
            same = same and int(current.get("priority") or 0) == int(payload.get("priority") or 0)
        if same:
            return {"ok": True, "action": "exists", "record": record}
        status, data = _cf_request("PUT", f"/zones/{zone_id}/dns_records/{current['id']}", payload)
        return {"ok": bool(data.get("success")), "action": "updated", "record": record,
                "error": "" if data.get("success") else _cf_error(data)}
    status, data = _cf_request("POST", f"/zones/{zone_id}/dns_records", payload)
    return {"ok": bool(data.get("success")), "action": "created", "record": record,
            "error": "" if data.get("success") else _cf_error(data)}

def password_hash(password):
    salt = secrets.token_bytes(16)
    rounds = 210_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return f"pbkdf2_sha256${rounds}${salt.hex()}${digest.hex()}"

def password_matches(password):
    if not password:
        return False
    stored = setting_get("admin_password_hash") or os.getenv("ADMIN_PASSWORD_HASH", "")
    if stored:
        try:
            if stored.startswith("$argon2"):
                from passlib.hash import argon2
                return argon2.verify(password, stored)
            algorithm, rounds, salt_hex, digest_hex = stored.split("$", 3)
            if algorithm != "pbkdf2_sha256": return False
            expected = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
            return hmac.compare_digest(expected.hex(), digest_hex)
        except Exception:
            return False
    initial = os.getenv("ADMIN_PASSWORD", "")
    return bool(password and initial) and hmac.compare_digest(password, initial)

def admin_ok(api_key=None, admin_password=None):
    return session_ok(api_key) or password_matches(admin_password or "")

@app.get("/api/v1/health")
def health():
    free = shutil.disk_usage("/app-data").free
    return {"ok": free >= 2 * 1024**3, "service": "mail-api",
            "disk_free_bytes": free, "large_attachment_ingest": free >= 2 * 1024**3,
            "domain_jobs": domain_worker.status(),
            "routing": applied_state(RUNTIME_DIR)}

@app.get("/api/v1/domains")
def domains(x_api_key: str | None = Header(default=None)):
    if not key_ok(x_api_key): raise HTTPException(401, "invalid api key")
    out = []
    for row in _visible_domains(_domain_rows(), x_api_key):
        users = json.loads(row["users"]) if isinstance(row.get("users"), str) else []
        selector = row.get("dkim_selector") or "default"
        out.append({
            **row,
            "enabled": bool(row.get("enabled", 1)),
            "users": users,
            "dkim_ready": (Path("/dkim/keys") / row["domain"] / f"{selector}.private").exists(),
        })
    return out

class MailDomainInput(BaseModel):
    domain: str
    project_id: str | None = None
    users: list[str] | str | None = None
    dkim_selector: str = "default"
    spf: str = ""
    dmarc: str = ""
    mx: str = "mail.example.com"
    enabled: bool = True
    receive_mode: Literal["fixed", "catch_all"] = "catch_all"
    receive_enabled: bool = True
    send_enabled: bool = True
    receive_subdomains: bool = True
    max_subdomain_depth: int = Field(default=6, ge=0, le=7)
    registration_enabled: bool = True
    registration_random_subdomain_depth: bool = True
    dns_provider: Literal["cloudflare", "digitalplat", "manual"] = "cloudflare"


class MailDomainPatch(BaseModel):
    project_id: str | None = None
    users: list[str] | str | None = None
    dkim_selector: str | None = None
    spf: str | None = None
    dmarc: str | None = None
    mx: str | None = None
    enabled: bool | None = None
    receive_mode: Literal["fixed", "catch_all"] | None = None
    receive_enabled: bool | None = None
    send_enabled: bool | None = None
    receive_subdomains: bool | None = None
    max_subdomain_depth: int | None = Field(default=None, ge=0, le=7)
    registration_enabled: bool | None = None
    registration_random_subdomain_depth: bool | None = None
    dns_provider: Literal["cloudflare", "digitalplat", "manual"] | None = None

class CloudflareConfig(BaseModel):
    api_token: str = ""
    api_email: str = ""
    api_key: str = ""

def _clean_users(value: list[str] | str | None, domain: str) -> list[str]:
    values = _default_users() if value is None else (re.split(r"[\s,;]+", value) if isinstance(value, str) else value)
    out = []
    for item in values:
        if not str(item).strip():
            continue
        item = str(item).strip().lower()
        if "@" in item:
            local, item_domain = item.rsplit("@", 1)
            if _normalize_domain(item_domain) != domain:
                raise ValueError("mailbox user belongs to another domain")
            item = local
        user = normalize_local(item)
        if user not in out:
            out.append(user)
    return out


def _domain_public(row: dict, *, routing_snapshot=None, observed_checks=None) -> dict:
    selector = row.get("dkim_selector") or "default"
    users = json.loads(row["users"]) if isinstance(row.get("users"), str) else row.get("users", [])
    revision = config_hash(row)
    state = routing_snapshot.for_row(row) if routing_snapshot is not None else applied_state(RUNTIME_DIR, row=row)
    if observed_checks is None:
        c = db()
        try:
            checks = {r["check_name"]: dict(r) for r in c.execute("select * from domain_checks where domain=? and config_hash=?", (row["domain"], revision))}
        finally:
            c.close()
    else:
        checks = {r["check_name"]: r for r in observed_checks if r["config_hash"] == revision}
    max_age = max(60, int(os.getenv("DNS_CHECK_MAX_AGE_SECONDS", "3600")))
    passed = lambda name: (checks.get(name, {}).get("status") == "passed"
                           and 0 <= time.time() - checks[name]["checked_at"] <= max_age)
    enabled = bool(row["enabled"]) and row.get("source_status") not in {"released", "revoked", "expired"}
    routed = state.get("status") == "applied"
    dkim_ready = (Path("/dkim/keys") / row["domain"] / f"{selector}.private").exists()
    has_recipients = row["receive_mode"] == "catch_all" or bool(users)
    receive_ready = enabled and bool(row["receive_enabled"]) and has_recipients and routed and passed("mx")
    send_ready = enabled and bool(row["send_enabled"]) and dkim_ready and all(passed(x) for x in ("spf", "dkim", "dmarc", "smtp_submission"))
    subdomain_receive_ready = receive_ready and bool(row["receive_subdomains"]) and row["max_subdomain_depth"] > 0 and passed("wildcard_mx")
    registration_ready = (
        receive_ready
        and bool(row.get("registration_enabled", 1))
        and row.get("receive_mode") == "catch_all"
        and (
            not bool(row.get("registration_random_subdomain_depth", 0))
            or subdomain_receive_ready
        )
    )
    return {**row, "enabled": bool(row["enabled"]), "users": users,
            "receive_enabled": bool(row["receive_enabled"]), "send_enabled": bool(row["send_enabled"]),
            "receive_subdomains": bool(row["receive_subdomains"]), "dkim_ready": dkim_ready,
            "registration_enabled": bool(row.get("registration_enabled", 1)),
            "registration_random_subdomain_depth": bool(row.get("registration_random_subdomain_depth", 0)),
            "dkim_public_path": f"/opt/mail-stack/dkim/keys/{row['domain']}/{selector}.txt",
            "config_hash": revision, "generation": state.get("generation"),
            "routing_status": state.get("status", "pending"), "dns_checks": checks,
            "receive_ready": receive_ready, "send_ready": send_ready,
            "subdomain_receive_ready": subdomain_receive_ready,
            "subdomain_send_ready": send_ready and bool(row["receive_subdomains"]) and row["max_subdomain_depth"] > 0,
            "registration_ready": registration_ready}



def _domain_public_rows() -> list[dict]:
    # One database snapshot and routing evidence set for the complete list.
    c = db()
    try:
        c.execute("BEGIN")
        rows = [dict(row) for row in c.execute("SELECT * FROM mail_domains ORDER BY domain")]
        checks = {}
        for check in c.execute("SELECT * FROM domain_checks"):
            checks.setdefault(check["domain"], []).append(dict(check))
    finally:
        c.close()
    routing = AppliedStateSnapshot(RUNTIME_DIR)
    return [_domain_public(row, routing_snapshot=routing, observed_checks=checks.get(row["domain"], [])) for row in rows]


def _domain_management_ready(item: dict) -> bool:
    """Only expose claimed domains in the main management list once usable.

    Claimed domains are created early so the control page can finish
    background provider preparation, DNS apply, and validation. They should not appear
    in the user-facing domain management list while any required readiness
    check is still pending or failed.
    """
    if not item.get("claim_id"):
        return True
    return bool(item.get("enabled") and item.get("receive_ready") and item.get("send_ready"))


def _assert_domain_mutable(domain):
    from api.repositories.domain_jobs import assert_domain_mutable, JobConflict
    try:
        assert_domain_mutable(db, domain)
    except JobConflict as exc:
        raise HTTPException(409, str(exc)) from None


def _save_domain(data: dict, existing_domain: str | None = None, *, publish_runtime=True, return_public=True) -> dict:
    try:
        domain = _normalize_domain(data.get("domain") or existing_domain or "")
        selector = str(data.get("dkim_selector") or "default").strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,62}", selector):
            raise ValueError("invalid DKIM selector")
        users = _clean_users(data.get("users"), domain)
        mx = _normalize_domain(data.get("mx") or "mail.example.com")
        depth = int(data.get("max_subdomain_depth", 6))
        if depth < 0 or depth > 7 or data.get("receive_mode", "catch_all") not in {"fixed", "catch_all"}:
            raise ValueError("invalid receive policy")
        receive_subdomains = bool(data.get("receive_subdomains", True))
        project_id = parse_project_id(data.get("project_id"))
        # Random registration depth only has meaning when wildcard subdomain
        # delivery is enabled and there is at least one usable subdomain level.
        # Normalize stale/contradictory clients instead of persisting a state
        # that can advertise addresses the router cannot receive.
        random_registration_depth = bool(data.get("registration_random_subdomain_depth", True))
        if not receive_subdomains or depth <= 0:
            random_registration_depth = False
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    values = {
        "domain": domain, "enabled": int(bool(data.get("enabled", True))), "users": json.dumps(users),
        "dkim_selector": selector, "spf": str(data.get("spf") or _default_spf()).strip(),
        "dmarc": str(data.get("dmarc") or f"v=DMARC1; p=none; rua=mailto:postmaster@{domain}").strip(),
        "mx": mx, "created_at": data.get("created_at", time.time()), "updated_at": time.time(),
        "receive_mode": data.get("receive_mode", "catch_all"), "receive_enabled": int(bool(data.get("receive_enabled", True))),
        "send_enabled": int(bool(data.get("send_enabled", True))), "receive_subdomains": int(receive_subdomains),
        "max_subdomain_depth": depth,
        "registration_enabled": int(bool(data.get("registration_enabled", True))),
        "registration_random_subdomain_depth": int(random_registration_depth),
        "dns_provider": data.get("dns_provider", "cloudflare"),
        "source_type": data.get("source_type", "manual"), "source_status": data.get("source_status", "imported"),
        "source_id": data.get("source_id"), "claim_id": data.get("claim_id"),
        "dns_credential_ref": data.get("dns_credential_ref"),
        "project_id": project_id,
    }
    with _domain_mutation_lock:
        _assert_domain_mutable(domain)
        c = db()
        try:
            previous = c.execute("select project_id from mail_domains where domain=?", (domain,)).fetchone()
            if "project_id" not in data and previous:
                values["project_id"] = previous["project_id"]
            if values["project_id"] and (not previous or previous["project_id"] != values["project_id"]):
                if not c.execute("select 1 from projects where id=? and enabled=1", (values["project_id"],)).fetchone():
                    raise HTTPException(400, "project not found")
            fields = list(values)
            updates = ",".join(f"{x}=excluded.{x}" for x in fields if x not in {"domain", "created_at"})
            c.execute(f"insert into mail_domains({','.join(fields)}) values({','.join('?' for x in fields)}) on conflict(domain) do update set {updates}", list(values.values()))
            c.commit()
            row = dict(c.execute("select * from mail_domains where domain=?", (domain,)).fetchone())
        finally:
            c.close()
        if publish_runtime:
            _write_runtime_files()
        return _domain_public(row) if return_public else row


@app.get("/api/v1/domains/available")
def available_domains(capability: Literal["receive", "send", "subdomain_receive", "subdomain_send", "registration"] = "receive",
                      x_api_key: str | None = Header(default=None)):
    if not key_ok(x_api_key):
        raise HTTPException(401, "invalid api key")
    items = []
    for item in _visible_domains(_domain_public_rows(), x_api_key):
        capability_key = "registration_ready" if capability == "registration" else capability + "_ready"
        if item[capability_key]:
            items.append({k: item[k] for k in ("domain", "users", "receive_mode", "receive_subdomains", "max_subdomain_depth",
                                             "registration_enabled", "registration_random_subdomain_depth",
                                             "receive_ready", "send_ready", "subdomain_receive_ready", "subdomain_send_ready",
                                             "registration_ready", "generation")})
    return {"items": items, "total": len(items), "capability": capability}

@app.get("/api/v1/mail-domains")
def list_mail_domains(ready_only: bool = Query(default=False), x_api_key: str | None = Header(default=None)):
    if not key_ok(x_api_key): raise HTTPException(401, "invalid api key")
    items = _visible_domains(_domain_public_rows(), x_api_key)
    return [item for item in items if not ready_only or _domain_management_ready(item)]

@app.post("/api/v1/mail-domains")
def create_mail_domain(item: MailDomainInput, x_api_key: str | None = Header(default=None)):
    if not admin_ok(x_api_key): raise HTTPException(401, "invalid credentials")
    with _domain_mutation_lock:
        try:
            domain = _normalize_domain(item.domain)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        if any(r["domain"] == domain for r in _domain_rows()):
            raise HTTPException(409, "domain already exists")
        return _save_domain({**item.model_dump(), "domain": domain})

@app.patch("/api/v1/mail-domains/{domain}")
def patch_mail_domain(domain: str, item: MailDomainPatch, x_api_key: str | None = Header(default=None)):
    if not admin_ok(x_api_key): raise HTTPException(401, "invalid credentials")
    with _domain_mutation_lock:
        try:
            domain = _normalize_domain(domain)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        rows = {r["domain"]: r for r in _domain_rows()}
        if domain not in rows: raise HTTPException(404, "domain not found")
        current = rows[domain]
        current["users"] = json.loads(current["users"])
        updates = {k: v for k, v in item.model_dump(exclude_unset=True).items()
                   if v is not None or k == "project_id"}
        merged = {**current, **updates, "domain": domain}
        return _save_domain(merged, domain)

@app.delete("/api/v1/mail-domains/{domain}")
def delete_mail_domain(domain: str, x_api_key: str | None = Header(default=None)):
    if not admin_ok(x_api_key): raise HTTPException(401, "invalid credentials")
    with _domain_mutation_lock:
        try:
            domain = _normalize_domain(domain)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        _assert_domain_mutable(domain)
        c = db()
        c.execute("delete from domain_checks where domain=?", (domain,))
        cur = c.execute("delete from mail_domains where domain=?", (domain,))
        c.commit(); c.close()
        if not cur.rowcount: raise HTTPException(404, "domain not found")
        _write_runtime_files()
        return {"ok": True, "domain": domain}

@app.post("/api/v1/mail-domains/{domain}/toggle")
def toggle_mail_domain(domain: str, enabled: bool = Query(...), x_api_key: str | None = Header(default=None)):
    if not admin_ok(x_api_key): raise HTTPException(401, "invalid credentials")
    return patch_mail_domain(domain, MailDomainPatch(enabled=enabled), x_api_key)

@app.get("/api/v1/messages")
def messages(
    x_api_key: str | None = Header(default=None),
    q: str = Query(default="", max_length=120),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    meta: bool = Query(default=False),
    recipient: str | None = None,
    recipient_domain: str | None = None,
    managed_domain: str | None = None,
    since: float | None = None,
    before: float | None = None,
    project_id: str | None = None,
):
    _require_mail_read(x_api_key)
    project_id = parse_project_id(project_id)
    if not key_has_project_scope(x_api_key, "mail.read", project_id):
        raise HTTPException(403, "missing mail.read scope or project grant; project_id is required for project keys")
    q = q.strip().lower()
    like = f"%{q}%"
    clauses = ["(? = '' or lower(coalesce(m.subject,'')) like ? or lower(coalesce(m.sender,'')) like ? or lower(coalesce(m.to_header,'')) like ? or lower(coalesce(m.envelope_recipient,'')) like ? or lower(coalesce(m.actual_recipient,'')) like ? or lower(coalesce(m.actual_sender,'')) like ?)"]
    params = [q, like, like, like, like, like, like]
    if project_id:
        clauses.append("d.project_id=?")
        params.append(project_id)
    try:
        for value, column, normalizer in ((recipient, "m.envelope_recipient", normalize_address),
                                         (recipient_domain, "d.recipient_domain", normalize_domain),
                                         (managed_domain, "d.managed_domain", normalize_domain)):
            if value is not None:
                clauses.append(column + " = ?")
                params.append(normalizer(value))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    for value, operator in ((since, ">="), (before, "<")):
        if value is not None:
            clauses.append("m.received_at " + operator + " ?")
            params.append(value)
    where = " and ".join(clauses)
    source = "messages m left join message_deliveries d on d.message_id=m.id"
    c = db()
    try:
        total = c.execute(f"select count(*) from {source} where {where}", params).fetchone()[0]
        rows = [dict(r) for r in c.execute(f"""select m.id,m.received_at,m.envelope_recipient,m.to_header,m.subject,m.sender,m.message_id,
                    m.actual_recipient,m.actual_recipient_source,m.recipient_parse_version,
                    m.actual_sender,m.actual_sender_source,m.sender_parse_version,
                    d.id as delivery_id,d.managed_domain,d.recipient_domain
                    from {source} where {where} order by m.id desc limit ? offset ?""", params + [limit, offset])]
    finally:
        c.close()
    return {"items": rows, "total": total, "limit": limit, "offset": offset} if meta else rows

@app.get("/api/v1/messages/{message_id}/raw")
def raw(message_id: int, x_api_key: str | None = Header(default=None), download: bool = False,
        range_header: str | None = Header(default=None, alias="Range")):
    _require_mail_read(x_api_key, message_id)
    if isinstance(range_header, str):
        raise HTTPException(400, "Range requests are not supported")
    c=db(); row=c.execute("select raw_path from messages where id=?", (message_id,)).fetchone(); c.close()
    if not row: raise HTTPException(404)
    p=Path(row["raw_path"])
    if not p.exists(): raise HTTPException(404)
    if download:
        return FileResponse(p, media_type="message/rfc822", filename=f"message-{message_id}.eml",
                            headers={"Accept-Ranges": "none", "X-Content-Type-Options": "nosniff"})
    return {"raw": p.read_text(errors="replace")}

@app.get("/api/v1/messages/{message_id}")
def message_detail(message_id: int, x_api_key: str | None = Header(default=None)):
    _require_mail_read(x_api_key, message_id)
    c=db(); row=c.execute("select * from messages where id=?", (message_id,)).fetchone(); c.close()
    if not row: raise HTTPException(404)
    out = dict(row)
    p = Path(out["raw_path"])
    if p.exists():
        msg = BytesParser(policy=policy.default).parsebytes(p.read_bytes())
        for field, header in (("to_header", "To"), ("delivered_to", "Delivered-To"),
                              ("original_to", "X-Original-To"), ("message_id", "Message-ID"),
                              ("subject", "Subject"), ("sender", "From")):
            decoded = _decoded_header(msg, header)
            if decoded is not None:
                out[field] = decoded
    return out

@app.get("/api/v1/messages/{message_id}/content")
def message_content(message_id: int, x_api_key: str | None = Header(default=None)):
    _require_mail_read(x_api_key, message_id)
    c = db()
    row = c.execute("select raw_path from messages where id=?", (message_id,)).fetchone()
    c.close()
    if not row:
        raise HTTPException(404)
    p = Path(row["raw_path"])
    if not p.exists():
        raise HTTPException(404)
    msg = BytesParser(policy=policy.default).parsebytes(p.read_bytes())
    return _message_content(msg)

def _load_message(message_id: int):
    c = db()
    try:
        row = c.execute("select raw_path from messages where id=?", (message_id,)).fetchone()
    finally:
        c.close()
    if not row or not Path(row["raw_path"]).is_file():
        raise HTTPException(404, "message content not found")
    return BytesParser(policy=policy.default).parsebytes(Path(row["raw_path"]).read_bytes())


def _attachment_parts(message):
    for index, part in enumerate(message.walk()):
        if not part.is_multipart() and (part.get_filename() or part.get_content_disposition() == "attachment"):
            yield str(index), part


@app.get("/api/v1/messages/{message_id}/attachments")
def attachments(message_id: int, x_api_key: str | None = Header(default=None)):
    _require_mail_read(x_api_key, message_id)
    return [{"part_id": part_id, "filename": part.get_filename() or f"attachment-{part_id}",
             "content_type": part.get_content_type(), "size": len(part.get_payload(decode=True) or b""),
             "path": f"/api/v1/messages/{message_id}/attachments/{part_id}"}
            for part_id, part in _attachment_parts(_load_message(message_id))]


@app.get("/api/v1/messages/{message_id}/attachments/{part_id}")
def attachment_download(message_id: int, part_id: str, x_api_key: str | None = Header(default=None)):
    _require_mail_read(x_api_key, message_id)
    for index, part in _attachment_parts(_load_message(message_id)):
        if index == part_id:
            name = (part.get_filename() or f"attachment-{index}").replace("\\", "/").rsplit("/", 1)[-1]
            name = "".join(ch for ch in name if ord(ch) >= 32 and ord(ch) != 127)[:200] or "attachment"
            return Response(part.get_payload(decode=True) or b"", media_type="application/octet-stream",
                            headers={"Content-Disposition": "attachment; filename*=UTF-8''" + urllib.parse.quote(name, safe=""),
                                     "X-Content-Type-Options": "nosniff"})
    raise HTTPException(404, "attachment not found")

class Webhook(BaseModel):
    url: HttpUrl
    secret: str = Field(min_length=1, max_length=1024)
    project_id: str | None = None
    kind: Literal["mail_stack", "shared"] | None = None


class WebhookPatch(BaseModel):
    enabled: bool | None = None
    kind: Literal["mail_stack", "shared"] | None = None

class RetentionConfig(BaseModel):
    days: int
    max_storage_gb: float = DEFAULT_MAX_STORAGE_GB

class Login(BaseModel):
    password: str = Field(min_length=1, max_length=1024)

class ChangePassword(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=8, max_length=1024)

class OutboundAttachment(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"
    data_base64: str

class ReplyRequest(BaseModel):
    sender: str
    text: str = ""
    subject: str | None = None
    attachments: list[OutboundAttachment] = Field(default_factory=list, max_length=10)
    project_id: str | None = None

class OutboundMessage(BaseModel):
    sender: str
    recipients: list[str]
    subject: str = ""
    text: str = ""
    html: str | None = None
    reply_to: str | None = None
    in_reply_to: str | None = None
    references: list[str] = Field(default_factory=list, max_length=20)
    attachments: list[OutboundAttachment] = Field(default_factory=list, max_length=10)
    project_id: str | None = None


def _webhook_kind(url: str, requested: str | None = None) -> str:
    """Return the explicit webhook type or infer it from the receiver path."""
    kind = str(requested or "").strip().lower()
    if kind and kind not in {"mail_stack", "shared"}:
        raise HTTPException(400, "invalid webhook kind")
    path = urllib.parse.urlparse(url).path.rstrip("/").lower()
    inferred = "mail_stack" if path.endswith("/api/webhook/mail-stack") else "shared"
    if kind == "mail_stack" and inferred != "mail_stack":
        raise HTTPException(400, "mail_stack webhook must use /api/webhook/mail-stack")
    return kind or inferred

@app.get("/api/v1/retention")
def get_retention(x_api_key: str | None = Header(default=None)):
    if not admin_ok(x_api_key):
        raise HTTPException(401, "invalid credentials")
    last_at = setting_get("last_cleanup_at")
    raw_result = setting_get("last_cleanup_result")
    try:
        result = json.loads(raw_result) if raw_result else None
    except (TypeError, ValueError):
        result = None
    return {
        "days": _retention_days(),
        "default_days": DEFAULT_RETENTION_DAYS,
        "max_storage_gb": _max_storage_gb(),
        "default_max_storage_gb": DEFAULT_MAX_STORAGE_GB,
        "storage_used_gb": round(_email_storage_bytes() / 1024**3, 4),
        "storage_target_gb": round(_max_storage_gb() / 2, 4),
        "last_cleanup_at": float(last_at) if last_at else None,
        "last_cleanup": result,
    }

@app.put("/api/v1/retention")
def update_retention(item: RetentionConfig, x_api_key: str | None = Header(default=None)):
    if not admin_ok(x_api_key):
        raise HTTPException(401, "invalid credentials")
    if item.days < 1 or item.days > 3650:
        raise HTTPException(400, "retention days must be between 1 and 3650")
    if item.max_storage_gb < 0.1 or item.max_storage_gb > 10000:
        raise HTTPException(400, "max storage must be between 0.1 and 10000 GB")
    setting_set("retention_days", str(item.days))
    setting_set("max_storage_gb", str(item.max_storage_gb))
    return get_retention(x_api_key)

@app.post("/api/v1/retention/cleanup")
def run_retention_cleanup(x_api_key: str | None = Header(default=None)):
    if not admin_ok(x_api_key):
        raise HTTPException(401, "invalid credentials")
    return cleanup_expired_messages()

def _prepare_outbound(item: OutboundMessage):
    try:
        sender = normalize_address(item.sender.strip().lower())
        recipients = list(dict.fromkeys(normalize_address(r) for r in item.recipients))
        if not recipients:
            raise ValueError("no recipients")
    except ValueError:
        raise HTTPException(400, "invalid recipients or sender")
    sender_domain = sender.rsplit("@", 1)[1]
    rows = sorted(_domain_rows(), key=lambda row: len(row["domain"]), reverse=True)
    managed = None
    for row in rows:
        if not row.get("enabled", 1) or not row.get("send_enabled", 1):
            continue
        if row.get("source_status", "imported") in {"released", "revoked", "expired"}:
            continue
        root = row["domain"]
        if sender_domain == root:
            managed = row
            break
        suffix = "." + root
        if (
            sender_domain.endswith(suffix)
            and bool(row.get("receive_subdomains"))
            and sender_domain.count(".") - root.count(".") <= int(row.get("max_subdomain_depth", 0))
        ):
            managed = row
            break
    if managed is None:
        raise HTTPException(400, f"sender domain must be one of: {', '.join(configured_domains())}")
    signing_domain = managed["domain"]
    msg = EmailMessage()
    msg["Date"] = formatdate(localtime=False, usegmt=True)
    msg["Message-ID"] = make_msgid(domain=sender_domain)
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = item.subject
    if item.reply_to:
        msg["Reply-To"] = item.reply_to
    if item.in_reply_to:
        if "\r" in item.in_reply_to or "\n" in item.in_reply_to:
            raise HTTPException(400, "invalid in_reply_to")
        msg["In-Reply-To"] = item.in_reply_to[:998]
    if item.references:
        references = []
        for value in item.references:
            if "\r" in value or "\n" in value:
                raise HTTPException(400, "invalid references")
            references.append(value[:998])
        msg["References"] = " ".join(references)[:998]
    msg.set_content(item.text)
    if item.html is not None:
        msg.add_alternative(item.html, subtype="html")
    if len(item.attachments) > 10:
        raise HTTPException(400, "too many attachments")
    total_bytes = 0
    for attachment in item.attachments:
        filename = attachment.filename.replace("\\", "/").rsplit("/", 1)[-1]
        filename = "".join(ch for ch in filename if ord(ch) >= 32 and ord(ch) != 127)[:200]
        if not filename:
            raise HTTPException(400, "invalid attachment filename")
        content_type = attachment.content_type.strip().lower()
        if not re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", content_type):
            raise HTTPException(400, "invalid attachment content type")
        try:
            blob = base64.b64decode(attachment.data_base64, validate=True)
        except (ValueError, TypeError, base64.binascii.Error):
            raise HTTPException(400, "invalid attachment base64")
        total_bytes += len(blob)
        if len(blob) > 10 * 1024 * 1024 or total_bytes > 25 * 1024 * 1024:
            raise HTTPException(413, "attachment size limit exceeded")
        maintype, subtype = content_type.split("/", 1)
        msg.add_attachment(blob, maintype=maintype, subtype=subtype, filename=filename)
    raw = msg.as_bytes()
    if not OUTBOUND_DKIM_ENABLED:
        return sender, recipients, raw
    row = managed
    selector = row.get("dkim_selector") or "default"
    key_path = Path("/dkim/keys") / signing_domain / f"{selector}.private"
    if not key_path.exists():
        raise HTTPException(409, "DKIM key not ready")
    signature = dkim.sign(
        raw,
        selector=selector.encode(),
        domain=signing_domain.encode(),
        privkey=key_path.read_bytes(),
        canonicalize=(b"relaxed", b"relaxed"),
        include_headers=[b"from", b"to", b"subject"],
    )
    return sender, recipients, signature + raw

def _outbound_result(row):
    return {
        "request_id": row["request_id"],
        "status": row["status"],
        "sender": row["sender"],
        "recipients": json.loads(row["recipients_json"]),
        "accepted": json.loads(row["accepted_json"] or "[]"),
        "rejected": json.loads(row["rejected_json"] or "{}"),
        "attempts": row["attempts"],
        "transport": row["transport"] if "transport" in row.keys() else "smtp",
        "fallback_attempts": row["fallback_attempts"] if "fallback_attempts" in row.keys() else 0,
        "last_error": row["last_error"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }

@app.post("/api/v1/send/queue", status_code=202)
def queue_send(
    item: OutboundMessage,
    x_api_key: str | None = Header(default=None),
    x_idempotency_key: str | None = Header(default=None),
):
    project_id = parse_project_id(item.project_id)
    if not key_has_project_scope(x_api_key, "mail.send", project_id):
        raise HTTPException(403, "missing mail.send scope or project grant")
    _require_sender_project(item.sender, project_id, x_api_key)
    if project_id:
        c = db()
        try:
            if not c.execute("select 1 from projects where id=? and enabled=1", (project_id,)).fetchone():
                raise HTTPException(404, "project not found")
        finally:
            c.close()
    request_id = (x_idempotency_key or "").strip() or "send_" + secrets.token_urlsafe(18)
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,160}", request_id):
        raise HTTPException(400, "invalid idempotency key")
    # Hash caller-controlled inputs, not generated Date/Message-ID/DKIM/MIME boundaries.
    request_hash = hashlib.sha256(
        json.dumps(item.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    # Check the idempotency record before the expensive MIME/DKIM preparation.
    # The insert path rechecks under BEGIN IMMEDIATE, so concurrent callers
    # still converge on one durable row without holding a write transaction
    # while _prepare_outbound() opens its domain-read connection.
    c = db()
    try:
        existing = c.execute("select * from outbound_outbox where request_id=?", (request_id,)).fetchone()
    finally:
        c.close()
    if existing:
        if existing["request_hash"] != request_hash or existing["project_id"] != project_id:
            raise HTTPException(409, "idempotency key already used for a different message")
        return _outbound_result(existing)
    sender, recipients, raw = _prepare_outbound(item)
    rfc_message_id = str(BytesHeaderParser(policy=policy.default).parsebytes(raw).get("Message-ID") or "")
    now = time.time()
    c = db()
    try:
        c.execute("BEGIN IMMEDIATE")
        existing = c.execute("select * from outbound_outbox where request_id=?", (request_id,)).fetchone()
        if existing:
            if existing["request_hash"] != request_hash or existing["project_id"] != project_id:
                raise HTTPException(409, "idempotency key already used for a different message")
            return _outbound_result(existing)
        c.execute(
            """insert into outbound_outbox(
                request_id,project_id,sender,recipients_json,raw_message,status,attempts,
                next_attempt_at,last_error,accepted_json,rejected_json,created_at,updated_at,
                request_hash,rfc_message_id,transport,fallback_attempts)
                values(?,?,?,?,?,'queued',0,?,'','[]','{}',?,?,?,?,'smtp',0)""",
            (request_id, project_id, sender, json.dumps(recipients, separators=(",", ":")),
             raw, now, now, now, request_hash, rfc_message_id),
        )
        c.commit()
        row = c.execute("select * from outbound_outbox where request_id=?", (request_id,)).fetchone()
    finally:
        c.close()
    return _outbound_result(row)

@app.get("/api/v1/send")
def list_queued_sends(
    x_api_key: str | None = Header(default=None),
    q: str = Query(default="", max_length=120),
    status: str = Query(default="", max_length=40),
    project_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    if not key_ok(x_api_key):
        raise HTTPException(401, "invalid api key")
    project_id = parse_project_id(project_id)
    if project_id is None and not admin_ok(x_api_key):
        raise HTTPException(400, "project_id is required")
    if project_id and not key_has_project_scope(x_api_key, "mail.send", project_id):
        raise HTTPException(403, "missing mail.send scope or project grant")
    clauses = ["1=1"]
    params: list[object] = []
    if project_id:
        clauses.append("project_id=?")
        params.append(project_id)
    if status.strip():
        clauses.append("status=?")
        params.append(status.strip())
    if q.strip():
        like = f"%{q.strip().lower()}%"
        clauses.append("(lower(request_id) like ? or lower(sender) like ? or lower(recipients_json) like ?)")
        params.extend([like, like, like])
    where = " and ".join(clauses)
    c = db()
    try:
        total = c.execute(f"select count(*) from outbound_outbox where {where}", params).fetchone()[0]
        rows = c.execute(
            f"select * from outbound_outbox where {where} order by id desc limit ? offset ?",
            params + [limit, offset],
        ).fetchall()
        items = [_outbound_result(row) for row in rows]
    finally:
        c.close()
    return {"items": items, "total": total, "limit": limit, "offset": offset}

def _reply_outbound_item(message_id: int, item: ReplyRequest) -> OutboundMessage:
    c = db()
    try:
        row = c.execute("select raw_path from messages where id=?", (message_id,)).fetchone()
    finally:
        c.close()
    if not row or not Path(row["raw_path"]).is_file():
        raise HTTPException(404, "message content not found")
    try:
        original = BytesParser(policy=policy.default).parsebytes(Path(row["raw_path"]).read_bytes())
    except OSError:
        raise HTTPException(404, "message content not found")
    reply_target = _decoded_header(original, "Reply-To") or _decoded_header(original, "From") or ""
    addresses = [address for _, address in getaddresses([reply_target]) if address]
    try:
        recipients = [normalize_address(addresses[0])] if addresses else []
    except ValueError:
        recipients = []
    if not recipients:
        raise HTTPException(422, "original message has no replyable sender")
    original_subject = _decoded_header(original, "Subject") or ""
    subject = item.subject if item.subject is not None else (
        original_subject if original_subject.lower().startswith("re:") else "Re: " + original_subject
    )
    message_header = _decoded_header(original, "Message-ID")
    references = (_decoded_header(original, "References") or "").split()
    if message_header and message_header not in references:
        references.append(message_header)
    return OutboundMessage(
        sender=item.sender,
        recipients=recipients,
        subject=subject,
        text=item.text,
        in_reply_to=message_header,
        references=references[-20:],
        attachments=item.attachments,
        project_id=item.project_id,
    )

@app.post("/api/v1/messages/{message_id}/reply", status_code=202)
def reply_message(
    message_id: int,
    item: ReplyRequest,
    x_api_key: str | None = Header(default=None),
    x_idempotency_key: str | None = Header(default=None),
):
    _require_mail_read(x_api_key, message_id)
    if not key_has_project_scope(x_api_key, "mail.send", item.project_id):
        raise HTTPException(403, "missing mail.send scope or project grant")
    outbound = _reply_outbound_item(message_id, item)
    return queue_send(outbound, x_api_key, x_idempotency_key)

@app.get("/api/v1/send/{request_id}")
def get_queued_send(request_id: str, x_api_key: str | None = Header(default=None)):
    c = db()
    try:
        row = c.execute("select * from outbound_outbox where request_id=?", (request_id,)).fetchone()
        if not row:
            raise HTTPException(404, "outbound message not found")
        if not key_has_project_scope(x_api_key, "mail.send", row["project_id"]):
            raise HTTPException(403, "missing mail.send scope or project grant")
        result = _outbound_result(row)
        result["delivery_reports"] = [dict(report) for report in c.execute(
            """select recipient,final_recipient,action,status_code,diagnostic,reporting_mta,
                      trust,received_at from outbound_delivery_reports where outbound_id=?
               order by id desc limit 200""", (row["id"],))]
        return result
    finally:
        c.close()

@app.post("/api/v1/send/{request_id}/replay")
def replay_queued_send(request_id: str, x_api_key: str | None = Header(default=None)):
    now = time.time()
    c = db()
    try:
        row = c.execute("select * from outbound_outbox where request_id=?", (request_id,)).fetchone()
        if not row:
            raise HTTPException(404, "outbound message not found")
        if not key_has_project_scope(x_api_key, "mail.send", row["project_id"]):
            raise HTTPException(403, "missing mail.send scope or project grant")
        if row["status"] in {"failed", "cancelled", "submission_unknown"}:
            c.execute(
                """update outbound_outbox set status='queued',attempts=0,next_attempt_at=?,
                   last_error='',accepted_json='[]',rejected_json='{}',updated_at=? where id=?""",
                (now, now, row["id"]),
            )
            c.commit()
            row = c.execute("select * from outbound_outbox where id=?", (row["id"],)).fetchone()
        return _outbound_result(row)
    finally:
        c.close()

@app.post("/api/v1/send")
def send_message(item: OutboundMessage, x_api_key: str | None = Header(default=None)):
    project_id = parse_project_id(item.project_id)
    if not key_has_project_scope(x_api_key, "mail.send", project_id):
        raise HTTPException(403, "missing mail.send scope or project grant")
    _require_sender_project(item.sender, project_id, x_api_key)
    if project_id:
        c = db()
        try:
            if not c.execute("select 1 from projects where id=? and enabled=1", (project_id,)).fetchone():
                raise HTTPException(404, "project not found")
        finally:
            c.close()
    sender, recipients, raw = _prepare_outbound(item)
    try:
        with smtplib.SMTP(os.getenv("SMTP_SUBMISSION_HOST","mail-postfix"), int(os.getenv("SMTP_SUBMISSION_PORT", "25")), timeout=15) as smtp:
            refused = smtp.sendmail(sender, recipients, raw)
    except Exception as e:
        raise HTTPException(502, f"outbound smtp failed: {e}")
    rejected = {address: {"code": code, "error": text.decode(errors="replace") if isinstance(text, bytes) else str(text)}
                for address, (code, text) in refused.items()}
    accepted = [address for address in recipients if address not in refused]
    return {"ok": not bool(refused), "status": "partial" if refused else "submitted_to_mta",
            "sender": sender, "recipients": recipients, "accepted": accepted, "rejected": rejected}

@app.post("/api/v1/auth/login")
def login(item: Login):
    if not password_matches(item.password):
        raise HTTPException(401, "invalid credentials")
    token = "sess_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256((token + os.getenv("API_KEY_PEPPER","")).encode()).hexdigest()
    c=db(); c.execute("delete from sessions where expires_at<=?", (time.time(),)); c.execute(
        "insert into sessions(token_hash,expires_at) values(?,?)", (digest,time.time()+86400)); c.commit(); c.close()
    return {"token": token, "expires_in": 86400}

@app.post("/api/v1/auth/logout")
def logout(x_api_key: str | None = Header(default=None)):
    if not x_api_key:
        raise HTTPException(401, "invalid session")
    digest = hashlib.sha256((x_api_key + os.getenv("API_KEY_PEPPER", "")).encode()).hexdigest()
    c = db()
    try:
        with c:
            c.execute("delete from sessions where token_hash=?", (digest,))
    finally:
        c.close()
    return {"ok": True}

@app.post("/api/v1/auth/password")
def change_password(item: ChangePassword, x_api_key: str | None = Header(default=None)):
    if not password_matches(item.current_password):
        raise HTTPException(401, "invalid credentials")
    if len(item.new_password) < 8:
        raise HTTPException(400, "new password must be at least 8 characters")
    c=db()
    c.execute("insert into settings(key,value) values('admin_password_hash',?) "
              "on conflict(key) do update set value=excluded.value",
              (password_hash(item.new_password),))
    c.execute("delete from sessions")
    c.commit(); c.close()
    return {"ok": True, "message": "password updated; please login again"}

@app.get("/api/v1/dns/cloudflare")
def get_cloudflare_config(x_api_key: str | None = Header(default=None)):
    if not admin_ok(x_api_key): raise HTTPException(401, "invalid credentials")
    secret = _global_cloudflare_secret()
    token = secret.get("api_token", "")
    email = secret.get("api_email", "")
    key = secret.get("api_key", "")
    return {
        "configured": bool(token or (email and key)),
        "auth_mode": "api_token" if token else ("global_api_key" if email and key else ""),
        "api_email": email,
        "api_token_set": bool(token),
        "api_key_set": bool(key),
    }

@app.put("/api/v1/dns/cloudflare")
def save_cloudflare_config(item: CloudflareConfig, x_api_key: str | None = Header(default=None)):
    if not admin_ok(x_api_key): raise HTTPException(401, "invalid credentials")
    if item.api_token.strip():
        secret = {"api_token": item.api_token.strip()}
    else:
        if not item.api_email.strip() or not item.api_key.strip():
            raise HTTPException(400, "请填写 API Token，或同时填写 Email 和 Global API Key")
        secret = {"api_email": item.api_email.strip(), "api_key": item.api_key.strip()}
    try:
        save_cloudflare_secret(db, secret)
    except CredentialError as exc:
        raise HTTPException(409, str(exc)) from None
    return get_cloudflare_config(x_api_key)

@app.post("/api/v1/dns/cloudflare/test")
def test_cloudflare_config(x_api_key: str | None = Header(default=None)):
    if not admin_ok(x_api_key): raise HTTPException(401, "invalid credentials")
    status, data = _cf_request("GET", "/user/tokens/verify")
    if data.get("success"):
        return {"ok": True, "status": status, "result": data.get("result")}
    status, data = _cf_request("GET", "/accounts", params={"per_page": 20})
    return {"ok": bool(data.get("success")), "status": status,
            "accounts": [{"id": x.get("id"), "name": x.get("name")} for x in data.get("result", [])],
            "error": "" if data.get("success") else _cf_error(data)}

@app.post("/api/v1/mail-domains/{domain}/dns/provision")
def provision_domain_dns(domain: str, x_api_key: str | None = Header(default=None)):
    if not admin_ok(x_api_key): raise HTTPException(401, "invalid credentials")
    try:
        domain = _normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    rows = {r["domain"]: r for r in _domain_rows()}
    if domain not in rows: raise HTTPException(404, "domain not found")
    if rows[domain].get("dns_provider") != "cloudflare":
        raise HTTPException(409, "this DNS provider is pending P2 integration")
    if rows[domain].get("dns_credential_ref"):
        raise HTTPException(409, "bound DNS domains require dns-preview/dns-apply")
    headers, err = _cloudflare_headers()
    if err: raise HTTPException(400, err)
    status, data = _cf_request("GET", "/zones", params={"name": domain, "per_page": 1})
    if not data.get("success") or not data.get("result"):
        raise HTTPException(400, f"Cloudflare Zone 未找到，请先把 {domain} 添加到 Cloudflare：{_cf_error(data)}")
    zone = data["result"][0]
    zone_id = str(zone.get("id") or "")
    row = rows[domain]
    selector = row.get("dkim_selector") or "default"
    dkim = _dkim_txt(domain, selector)
    records = [
        {"type": "MX", "name": domain, "content": str(row.get("mx") or "mail.example.com").rstrip("."), "priority": 10, "ttl": 3600},
        {"type": "TXT", "name": domain, "content": str(row.get("spf") or _default_spf()), "ttl": 3600},
        {"type": "TXT", "name": f"{selector}._domainkey.{domain}", "content": dkim, "ttl": 3600},
        {"type": "TXT", "name": f"_dmarc.{domain}", "content": str(row.get("dmarc") or f"v=DMARC1; p=none; rua=mailto:postmaster@{domain}"), "ttl": 3600},
    ]
    if not dkim:
        raise HTTPException(400, f"DKIM 公钥尚未生成：/opt/mail-stack/dkim/keys/{domain}/{selector}.txt")
    results = [_cf_upsert_record(zone_id, record) for record in records]
    ok = all(item.get("ok") for item in results)
    c = db()
    c.execute("update mail_domains set cf_zone_id=?,cf_status=?,updated_at=? where domain=?",
              (zone_id, "provisioned" if ok else "error", time.time(), domain))
    c.commit(); c.close()
    return {"ok": ok, "domain": domain, "zone_id": zone_id, "records": results}

@app.get("/api/v1/mail-domains/{domain}/dns")
def list_domain_dns(domain: str, x_api_key: str | None = Header(default=None)):
    """Return provider-aware DNS records for a managed mail domain.

    The legacy endpoint used to assume every domain was a Cloudflare zone.
    Domains claimed through DigitalPlat have a per-domain credential and must
    be read through the domain-control adapter instead; manual domains return
    an explicit empty inventory rather than a misleading Cloudflare error.
    """
    if not admin_ok(x_api_key):
        raise HTTPException(401, "invalid credentials")
    try:
        domain = _normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    rows = {r["domain"]: r for r in _domain_rows()}
    if domain not in rows:
        raise HTTPException(404, "domain not found")
    row = rows[domain]
    provider = str(row.get("dns_provider") or "cloudflare").lower()
    if row.get("dns_credential_ref") and provider in {"cloudflare", "digitalplat"}:
        label = "DigitalPlat" if provider == "digitalplat" else "Cloudflare"
        try:
            inventory = domain_manager.dns_adapter(row).inventory(domain)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        except ProviderError as exc:
            if exc.code == DIGITALPLAT_DNS_NOT_ENABLED:
                return {
                    "ok": True, "domain": domain, "provider": provider,
                    "provider_label": "DigitalPlat DNS", "zone_id": domain,
                    "records": [], "complete": False, "status": "hosting_required",
                    "message": digitalplat_dns_hosting_message(domain),
                }
            if exc.code == DIGITALPLAT_DNS_ZONE_UNAVAILABLE:
                return {
                    "ok": True, "domain": domain, "provider": provider,
                    "provider_label": "DigitalPlat DNS", "zone_id": domain,
                    "records": [], "complete": False, "status": "unavailable",
                    "message": digitalplat_dns_zone_message(domain),
                }
            if exc.code == DIGITALPLAT_DNS_UPSTREAM_UNAVAILABLE:
                raise HTTPException(502, digitalplat_dns_upstream_message(domain)) from None
            raise HTTPException(502, f"读取 {label} DNS 记录失败：{exc.code}") from None
        except Exception:
            # Provider exceptions may include request headers or credential
            # values. Never echo their text to the browser or logs.
            raise HTTPException(502, "invalid_provider_inventory_response") from None
        records = []
        for item in inventory.get("records", []):
            rtype = str(item.get("type") or "").upper()
            name = str(item.get("name") or item.get("host") or "@").lower().rstrip(".")
            if name in {"", "@"}:
                fqdn = domain
            elif name == domain or name.endswith("." + domain):
                fqdn = name
            elif provider == "cloudflare":
                continue  # Bound credentials may cover a parent zone.
            else:
                fqdn = f"{name}.{domain}"
            values = item.get("values")
            content = item.get("content", item.get("value", ""))
            if rtype == "TXT":
                chunks = values if isinstance(values, list) else [content]
                content = "".join(
                    "".join(re.findall(r'"([^"\r\n]*)"', str(v))) if '"' in str(v)
                    else str(v) for v in chunks
                )
            elif isinstance(values, list):
                content = " ".join(str(v) for v in values)
            priority = item.get("priority")
            if rtype == "MX":
                match = re.fullmatch(r"(\d+)\s+(\S+)", str(content).strip())
                if match:
                    priority, content = int(match[1]), match[2]
            records.append({
                "id": item.get("id") or item.get("record_id") or item.get("rrset_id"),
                "type": rtype,
                "name": fqdn,
                "content": str(content),
                "ttl": item.get("ttl", 3600),
                "priority": priority,
                "proxied": bool(item.get("proxied", False)),
            })
        return {
            "ok": True,
            "domain": domain,
            "provider": provider,
            "provider_label": f"{label} DNS",
            "zone_id": inventory.get("zone_id") or domain,
            "records": records,
            "complete": bool(inventory.get("complete", True)),
        }
    if provider == "digitalplat":
        raise HTTPException(409, "DigitalPlat DNS credential is not bound")
    if provider == "manual":
        return {
            "ok": True,
            "domain": domain,
            "provider": "manual",
            "provider_label": "手工 DNS",
            "zone_id": None,
            "records": [],
            "complete": False,
            "message": "此域名由外部 DNS 服务商管理，mail-stack 不直接读取 DNS 记录。",
        }
    if provider != "cloudflare":
        raise HTTPException(409, f"unsupported DNS provider: {provider}")
    _, err = _cloudflare_headers()
    if err:
        raise HTTPException(400, err)
    zone_id = str(row.get("cf_zone_id") or "")
    if not zone_id:
        status, data = _cf_request("GET", "/zones", params={"name": domain, "per_page": 1})
        if not data.get("success") or not data.get("result"):
            raise HTTPException(400, f"Cloudflare Zone 未找到，请先把 {domain} 添加到 Cloudflare：{_cf_error(data)}")
        zone_id = str(data["result"][0].get("id") or "")
    status, data = _cf_request(
        "GET",
        f"/zones/{zone_id}/dns_records",
        params={"per_page": 100, "order": "name", "direction": "asc"},
    )
    if not data.get("success"):
        raise HTTPException(502, f"读取 Cloudflare DNS 记录失败：{_cf_error(data)}")
    records = []
    for item in data.get("result") or []:
        records.append({
            "id": item.get("id"),
            "type": item.get("type"),
            "name": item.get("name"),
            "content": item.get("content"),
            "ttl": item.get("ttl"),
            "priority": item.get("priority"),
            "proxied": item.get("proxied"),
        })
    c = db()
    c.execute(
        "update mail_domains set cf_zone_id=?,cf_status=?,updated_at=? where domain=?",
        (zone_id, "listed", time.time(), domain),
    )
    c.commit()
    c.close()
    return {"ok": True, "domain": domain, "provider": "cloudflare",
            "provider_label": "Cloudflare DNS", "zone_id": zone_id, "records": records}

@app.post("/api/v1/webhooks")
def create_webhook(item: Webhook, x_api_key: str | None = Header(default=None)):
    project_id = parse_project_id(item.project_id)
    if not key_has_project_scope(x_api_key, "webhook.manage", project_id):
        raise HTTPException(403, "missing webhook.manage scope or project grant")
    try:
        validate_webhook_url(item.url)
    except WebhookDeliveryError as exc:
        raise HTTPException(400, str(exc)) from None
    if "\r" in item.secret or "\n" in item.secret:
        raise HTTPException(400, "invalid webhook secret")
    kind = _webhook_kind(str(item.url), item.kind)
    c=db()
    if project_id and not c.execute("select 1 from projects where id=? and enabled=1", (project_id,)).fetchone():
        c.close()
        raise HTTPException(404, "project not found")
    cur=c.execute("insert into webhooks(url,secret,project_id,kind,created_at) values(?,?,?,?,?)",
                  (str(item.url),item.secret,project_id,kind,time.time()))
    c.commit(); out={"id":cur.lastrowid,"url":str(item.url),"project_id":project_id,
                     "kind":kind,"enabled":True}; c.close(); return out

@app.get("/api/v1/webhooks")
def list_webhooks(x_api_key: str | None = Header(default=None)):
    if not key_has_scope(x_api_key, "webhook.manage"): raise HTTPException(403, "missing webhook.manage scope")
    c=db(); rows=[dict(r) for r in c.execute(
        "select id,url,project_id,kind,enabled,created_at from webhooks order by id desc"
    )]; c.close()
    rows = [row for row in rows if key_has_project_scope(x_api_key, "webhook.manage", row["project_id"])]
    for row in rows:
        row["enabled"] = bool(row["enabled"])
        row["kind"] = row.get("kind") or _webhook_kind(row["url"])
    return rows


@app.patch("/api/v1/webhooks/{webhook_id}")
def patch_webhook(
    webhook_id: int,
    item: WebhookPatch,
    x_api_key: str | None = Header(default=None),
):
    c = db()
    try:
        row = c.execute("select id,url,project_id,kind,enabled from webhooks where id=?", (webhook_id,)).fetchone()
        if not row:
            raise HTTPException(404, "webhook not found")
        if not key_has_project_scope(x_api_key, "webhook.manage", row["project_id"]):
            raise HTTPException(403, "missing webhook.manage scope or project grant")
        updates = []
        values = []
        if item.enabled is not None:
            updates.append("enabled=?")
            values.append(int(item.enabled))
        if item.kind is not None:
            kind = _webhook_kind(row["url"], item.kind)
            updates.append("kind=?")
            values.append(kind)
        if updates:
            values.append(webhook_id)
            c.execute(f"update webhooks set {', '.join(updates)} where id=?", values)
            c.commit()
        updated = c.execute(
            "select id,url,project_id,kind,enabled,created_at from webhooks where id=?",
            (webhook_id,),
        ).fetchone()
    finally:
        c.close()
    result = dict(updated)
    result["enabled"] = bool(result["enabled"])
    result["kind"] = result.get("kind") or _webhook_kind(result["url"])
    return result

@app.get("/api/v1/webhooks/{webhook_id}/deliveries")
def list_webhook_deliveries(
    webhook_id: int,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    x_api_key: str | None = Header(default=None),
):
    c = db()
    try:
        hook = c.execute("select project_id from webhooks where id=?", (webhook_id,)).fetchone()
        if not hook:
            raise HTTPException(404, "webhook not found")
        if not key_has_project_scope(x_api_key, "webhook.manage", hook["project_id"]):
            raise HTTPException(403, "missing webhook.manage scope or project grant")
        rows = [dict(r) for r in c.execute(
            """select id,event_id,message_id,status,attempts,next_attempt_at,last_error,
                      created_at,updated_at
               from webhook_outbox where webhook_id=?
               order by id desc limit ? offset ?""",
            (webhook_id, limit, offset),
        )]
        total = c.execute("select count(*) from webhook_outbox where webhook_id=?", (webhook_id,)).fetchone()[0]
    finally:
        c.close()
    return {"items": rows, "total": total, "limit": limit, "offset": offset}

@app.post("/api/v1/webhooks/{webhook_id}/deliveries/{delivery_id}/replay")
def replay_webhook_delivery(
    webhook_id: int,
    delivery_id: int,
    x_api_key: str | None = Header(default=None),
):
    now = time.time()
    c = db()
    try:
        hook = c.execute("select project_id from webhooks where id=?", (webhook_id,)).fetchone()
        if not hook:
            raise HTTPException(404, "webhook not found")
        if not key_has_project_scope(x_api_key, "webhook.manage", hook["project_id"]):
            raise HTTPException(403, "missing webhook.manage scope or project grant")
        row = c.execute(
            "select status,attempts from webhook_outbox where id=? and webhook_id=?",
            (delivery_id, webhook_id),
        ).fetchone()
        if not row:
            raise HTTPException(404, "webhook delivery not found")
        if row["status"] not in {"failed", "cancelled"}:
            return {"id": delivery_id, "status": row["status"], "attempts": row["attempts"]}
        c.execute("""update webhook_outbox set status='queued',attempts=0,
                     next_attempt_at=?,last_error='',updated_at=?
                     where id=? and webhook_id=?""",
                  (now, now, delivery_id, webhook_id))
        c.commit()
    finally:
        c.close()
    return {"id": delivery_id, "status": "queued", "attempts": 0}

@app.get("/api/v1/webhooks/{webhook_id}/dead-letter")
def list_webhook_dead_letters(
    webhook_id: int,
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    x_api_key: str | None = Header(default=None),
):
    c = db()
    try:
        hook = c.execute("select project_id from webhooks where id=?", (webhook_id,)).fetchone()
        if not hook:
            raise HTTPException(404, "webhook not found")
        if not key_has_project_scope(x_api_key, "webhook.manage", hook["project_id"]):
            raise HTTPException(403, "missing webhook.manage scope or project grant")
        rows = [dict(r) for r in c.execute(
            """select id,event_id,message_id,status,attempts,last_error,created_at,updated_at
               from webhook_outbox where webhook_id=? and status='failed'
               order by updated_at desc,id desc limit ? offset ?""",
            (webhook_id, limit, offset),
        )]
        total = c.execute(
            "select count(*) from webhook_outbox where webhook_id=? and status='failed'",
            (webhook_id,),
        ).fetchone()[0]
    finally:
        c.close()
    return {"items": rows, "total": total, "limit": limit, "offset": offset}

@app.get("/api/v1/webhook-events/{event_id}")
def get_webhook_event(event_id: str, x_api_key: str | None = Header(default=None)):
    c = db()
    try:
        row = c.execute(
            """select o.id,o.event_id,o.webhook_id,o.message_id,o.status,o.attempts,
                      o.next_attempt_at,o.last_error,o.created_at,o.updated_at,w.project_id
               from webhook_outbox o join webhooks w on w.id=o.webhook_id
               where o.event_id=?""",
            (event_id,),
        ).fetchone()
        if not row:
            raise HTTPException(404, "webhook event not found")
        if not key_has_project_scope(x_api_key, "webhook.manage", row["project_id"]):
            raise HTTPException(403, "missing webhook.manage scope or project grant")
        result = dict(row)
        result.pop("project_id", None)
    finally:
        c.close()
    return result

@app.post("/api/v1/webhook-events/{event_id}/replay")
def replay_webhook_event(event_id: str, x_api_key: str | None = Header(default=None)):
    now = time.time()
    c = db()
    try:
        row = c.execute(
            """select o.id,o.status,o.attempts,w.project_id
               from webhook_outbox o join webhooks w on w.id=o.webhook_id
               where o.event_id=?""",
            (event_id,),
        ).fetchone()
        if not row:
            raise HTTPException(404, "webhook event not found")
        if not key_has_project_scope(x_api_key, "webhook.manage", row["project_id"]):
            raise HTTPException(403, "missing webhook.manage scope or project grant")
        if row["status"] in {"failed", "cancelled"}:
            c.execute("""update webhook_outbox set status='queued',attempts=0,
                         next_attempt_at=?,last_error='',updated_at=? where id=?""",
                      (now, now, row["id"]))
            c.commit()
            return {"event_id": event_id, "id": row["id"], "status": "queued", "attempts": 0}
        return {"event_id": event_id, "id": row["id"], "status": row["status"], "attempts": row["attempts"]}
    finally:
        c.close()

@app.delete("/api/v1/webhooks/{webhook_id}")
def delete_webhook(webhook_id: int, x_api_key: str | None = Header(default=None)):
    c=db()
    hook = c.execute("select project_id from webhooks where id=?", (webhook_id,)).fetchone()
    if not hook:
        c.close()
        raise HTTPException(404, "webhook not found")
    if not key_has_project_scope(x_api_key, "webhook.manage", hook["project_id"]):
        c.close()
        raise HTTPException(403, "missing webhook.manage scope or project grant")
    c.execute("delete from webhook_outbox where webhook_id=?", (webhook_id,))
    c.execute("delete from webhooks where id=?", (webhook_id,))
    c.commit(); c.close(); return {"ok": True}

class ProjectPatch(BaseModel):
    model_config = {"extra": "forbid"}
    name: str | None = Field(default=None, min_length=1, max_length=80)
    enabled: bool | None = Field(default=None, strict=True)


def _project_rows(c, project_id=None):
    sql = """select p.id,p.name,p.enabled,p.created_at,
        coalesce(d.n,0) as domain_count,coalesce(m.n,0) as message_count,
        coalesce(g.n,0) as key_count,coalesce(w.n,0) as webhook_count
        from projects p
        left join (select project_id,count(*) as n from mail_domains
                   where project_id is not null group by project_id) d on d.project_id=p.id
        left join (select project_id,count(distinct message_id) as n from message_deliveries
                   where project_id is not null group by project_id) m on m.project_id=p.id
        left join (select project_id,count(*) as n from api_key_grants
                   group by project_id) g on g.project_id=p.id
        left join (select project_id,count(*) as n from webhooks
                   where project_id is not null group by project_id) w on w.project_id=p.id"""
    params = ()
    if project_id is not None:
        sql += " where p.id=?"
        params = (project_id,)
    rows = [dict(row) for row in c.execute(sql + " order by p.created_at,p.id", params)]
    for row in rows:
        row["enabled"] = bool(row["enabled"])
    return rows


@app.post("/api/v1/projects")
def create_project(
    name: str = Query(min_length=1, max_length=80),
    x_api_key: str | None = Header(default=None),
    x_admin_password: str | None = Header(default=None),
):
    if not admin_ok(x_api_key, x_admin_password):
        raise HTTPException(401)
    name = name.strip()
    if not name:
        raise HTTPException(400, "project name must not be blank")
    project_id = "prj_" + secrets.token_urlsafe(12).replace("-", "_")
    c = db()
    try:
        with c:
            c.execute("insert into projects(id,name,created_at) values(?,?,?)", (project_id, name, time.time()))
            result = _project_rows(c, project_id)[0]
        return result
    except sqlite3.IntegrityError:
        raise HTTPException(409, "project name already exists") from None
    finally:
        c.close()


@app.get("/api/v1/projects")
def list_projects(
    x_api_key: str | None = Header(default=None),
    x_admin_password: str | None = Header(default=None),
):
    if not admin_ok(x_api_key, x_admin_password):
        raise HTTPException(401)
    c = db()
    try:
        return _project_rows(c)
    finally:
        c.close()


@app.patch("/api/v1/projects/{project_id}")
def update_project(
    project_id: str,
    item: ProjectPatch,
    x_api_key: str | None = Header(default=None),
    x_admin_password: str | None = Header(default=None),
):
    if not admin_ok(x_api_key, x_admin_password):
        raise HTTPException(401)
    project_id = parse_project_id(project_id)
    updates = item.model_dump(exclude_unset=True)
    if any(value is None for value in updates.values()):
        raise HTTPException(400, "project fields must not be null")
    if "name" in updates:
        updates["name"] = updates["name"].strip()
        if not updates["name"]:
            raise HTTPException(400, "project name must not be blank")
    c = db()
    try:
        with c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("select name,enabled from projects where id=?", (project_id,)).fetchone()
            if not row:
                raise HTTPException(404, "project not found")
            c.execute("update projects set name=?,enabled=? where id=?", (
                updates.get("name", row["name"]), int(updates.get("enabled", row["enabled"])), project_id))
            result = _project_rows(c, project_id)[0]
        return result
    except sqlite3.IntegrityError:
        raise HTTPException(409, "project name already exists") from None
    finally:
        c.close()


class ApiKeyGrantInput(BaseModel):
    model_config = {"extra": "forbid"}
    project_id: str
    scopes: list[Literal["mail.read", "mail.send", "webhook.manage", "domain.manage"]] = Field(min_length=1, max_length=4)


class ApiKeyPatch(BaseModel):
    model_config = {"extra": "forbid"}
    name: str | None = Field(default=None, min_length=1, max_length=80)
    key_type: Literal["normal", "admin"] | None = None
    scopes: list[Literal["mail.read", "mail.send", "webhook.manage", "domain.manage"]] | None = Field(default=None, min_length=1, max_length=4)
    grants: list[ApiKeyGrantInput] | None = Field(default=None, max_length=500)


def _api_key_metadata(c, key_id):
    row = c.execute("select id,name,scopes,global_access,created_at from api_keys where id=?", (key_id,)).fetchone()
    if not row:
        raise HTTPException(404, "API key not found")
    result = dict(row)
    result["scopes"] = [scope for scope in str(result["scopes"] or "").split(",") if scope]
    result["global_access"] = bool(result["global_access"])
    result["key_type"] = "admin" if result["global_access"] else "normal"
    result["grants"] = [dict(grant) for grant in c.execute(
        "select project_id,scopes,created_at from api_key_grants where key_id=? order by project_id", (key_id,))]
    for grant in result["grants"]:
        grant["scopes"] = [scope for scope in str(grant["scopes"] or "").split(",") if scope]
    return result


@app.get("/api/v1/api-keys/{key_id}")
def get_key(
    key_id: int,
    x_api_key: str | None = Header(default=None),
    x_admin_password: str | None = Header(default=None),
):
    if not admin_ok(x_api_key, x_admin_password):
        raise HTTPException(401)
    c = db()
    try:
        return _api_key_metadata(c, key_id)
    finally:
        c.close()


@app.patch("/api/v1/api-keys/{key_id}")
def update_key(
    key_id: int,
    item: ApiKeyPatch,
    x_api_key: str | None = Header(default=None),
    x_admin_password: str | None = Header(default=None),
):
    if not admin_ok(x_api_key, x_admin_password):
        raise HTTPException(401)
    updates = item.model_dump(exclude_unset=True)
    if any(value is None for value in updates.values()):
        raise HTTPException(400, "API key fields must not be null")
    if "name" in updates:
        updates["name"] = updates["name"].strip()
        if not updates["name"]:
            raise HTTPException(400, "API key name must not be blank")
    if "scopes" in updates:
        updates["scopes"] = parse_scopes(",".join(updates["scopes"]))
    c = db()
    try:
        with c:
            c.execute("BEGIN IMMEDIATE")
            current = _api_key_metadata(c, key_id)
            # Validate the whole replacement before changing any permissions.
            grants = []
            seen = set()
            existing = {grant["project_id"] for grant in current["grants"]}
            for grant in updates.get("grants", []):
                project = parse_project_id(grant["project_id"])
                if project in seen:
                    raise HTTPException(400, "duplicate project grant")
                seen.add(project)
                owner = c.execute("select enabled from projects where id=?", (project,)).fetchone()
                # Editing another field must not discard a previously disabled project's grant.
                if not owner or (not owner["enabled"] and project not in existing):
                    raise HTTPException(400, "project not found or disabled")
                grants.append((key_id, project, parse_scopes(",".join(grant["scopes"])), time.time()))
            c.execute("update api_keys set name=?,scopes=?,global_access=? where id=?", (
                updates.get("name", current["name"]), updates.get("scopes", ",".join(current["scopes"])),
                int(updates.get("key_type", current["key_type"]) == "admin"), key_id))
            if "grants" in updates:
                c.execute("delete from api_key_grants where key_id=?", (key_id,))
                c.executemany("insert into api_key_grants(key_id,project_id,scopes,created_at) values(?,?,?,?)", grants)
            result = _api_key_metadata(c, key_id)
        return result
    finally:
        c.close()


@app.post("/api/v1/api-keys")
def create_key(
    name: str = Query(default="default", min_length=1, max_length=80),
    scopes: str = Query(default="mail.read,mail.send,webhook.manage", max_length=300),
    x_api_key: str | None = Header(default=None),
    x_admin_password: str | None = Header(default=None),
    key_type: Literal["normal", "admin"] | None = None,
    global_access: bool | None = None,
    project_id: str | None = None,
):
    if not admin_ok(x_api_key, x_admin_password): raise HTTPException(401)
    scope_text = parse_scopes(scopes)
    project_id = parse_project_id(project_id)
    # Keep the previous global_access query as a compatibility alias. New
    # callers use key_type; omitting both always creates a normal key.
    if key_type is None:
        key_type = "admin" if global_access else "normal"
    elif global_access is not None and global_access != (key_type == "admin"):
        raise HTTPException(400, "key_type conflicts with global_access")
    global_access = key_type == "admin"
    raw="ms_"+secrets.token_urlsafe(32); digest=hashlib.sha256((raw+os.getenv("API_KEY_PEPPER","")).encode()).hexdigest()
    c = db()
    try:
        c.execute("BEGIN IMMEDIATE")
        if project_id and not c.execute("select 1 from projects where id=? and enabled=1", (project_id,)).fetchone():
            raise HTTPException(400, "project not found")
        cur = c.execute("insert into api_keys(name,key_hash,scopes,created_at,global_access) values(?,?,?,?,?)",
                        (name, digest, scope_text, time.time(), int(global_access)))
        key_id = cur.lastrowid
        if project_id:
            c.execute("insert into api_key_grants(key_id,project_id,scopes,created_at) values(?,?,?,?)",
                      (key_id, project_id, scope_text, time.time()))
        c.commit()
    finally:
        c.close()
    return {"id": key_id, "name":name,"scopes":scope_text.split(","),
            "key_type":key_type,"global_access":global_access,"project_id":project_id,"key":raw}

@app.get("/api/v1/api-keys")
def list_keys(
    x_api_key: str | None = Header(default=None),
    x_admin_password: str | None = Header(default=None),
):
    if not admin_ok(x_api_key, x_admin_password): raise HTTPException(401)
    c=db(); rows=[dict(r) for r in c.execute("select id,name,scopes,global_access,created_at from api_keys order by id desc")]; c.close()
    for row in rows:
        row["scopes"] = [scope for scope in str(row.get("scopes") or "").split(",") if scope]
        row["global_access"] = bool(row["global_access"])
        row["key_type"] = "admin" if row["global_access"] else "normal"
    return rows

@app.post("/api/v1/api-keys/{key_id}/grants")
def grant_api_key(
    key_id: int,
    project_id: str = Query(min_length=1, max_length=80),
    scopes: str = Query(default="webhook.manage", max_length=300),
    x_api_key: str | None = Header(default=None),
    x_admin_password: str | None = Header(default=None),
):
    if not admin_ok(x_api_key, x_admin_password):
        raise HTTPException(401)
    project_id = parse_project_id(project_id)
    scope_text = parse_scopes(scopes)
    c = db()
    try:
        if not c.execute("select 1 from api_keys where id=?", (key_id,)).fetchone():
            raise HTTPException(404, "API key not found")
        if not c.execute("select 1 from projects where id=? and enabled=1", (project_id,)).fetchone():
            raise HTTPException(404, "project not found")
        c.execute("""insert into api_key_grants(key_id,project_id,scopes,created_at)
                     values(?,?,?,?)
                     on conflict(key_id,project_id) do update set scopes=excluded.scopes""",
                  (key_id, project_id, scope_text, time.time()))
        c.commit()
    finally:
        c.close()
    return {"key_id": key_id, "project_id": project_id, "scopes": scope_text.split(",")}

@app.get("/api/v1/api-keys/{key_id}/grants")
def list_api_key_grants(
    key_id: int,
    x_api_key: str | None = Header(default=None),
    x_admin_password: str | None = Header(default=None),
):
    if not admin_ok(x_api_key, x_admin_password):
        raise HTTPException(401)
    c = db()
    try:
        if not c.execute("select 1 from api_keys where id=?", (key_id,)).fetchone():
            raise HTTPException(404, "API key not found")
        rows = [dict(r) for r in c.execute(
            "select project_id,scopes,created_at from api_key_grants where key_id=? order by project_id",
            (key_id,))]
    finally:
        c.close()
    for row in rows:
        row["scopes"] = [scope for scope in str(row["scopes"] or "").split(",") if scope]
    return rows

@app.delete("/api/v1/api-keys/{key_id}")
def delete_key(
    key_id: int,
    x_api_key: str | None = Header(default=None),
    x_admin_password: str | None = Header(default=None),
):
    if not admin_ok(x_api_key, x_admin_password): raise HTTPException(401)
    c = db()
    try:
        with c:
            c.execute("delete from api_key_grants where key_id=?", (key_id,))
            c.execute("delete from api_keys where id=?", (key_id,))
    finally:
        c.close()
    return {"ok": True}


# P2 control-plane is additive; no provider calls are made during app import.
from api.services.domain_manager import DomainManager
from api.routers.domain_control import build_router
from api.workers.domain_jobs import DomainWorker

domain_manager = DomainManager(db, _save_domain, _domain_mutation_lock,
                               global_cloudflare_secret=_global_cloudflare_secret,
                               domain_public=_domain_public,
                               bulk_save_domain=lambda data, domain: _save_domain(data, domain, publish_runtime=False, return_public=False),
                               publish_domains=_write_runtime_files)
domain_worker = DomainWorker(domain_manager)
app.include_router(build_router(domain_manager, admin_ok))

@app.on_event("shutdown")
def stop_domain_worker():
    domain_worker.stop()

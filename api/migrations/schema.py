"""Versioned, additive migrations; existing fixed mailboxes stay fixed."""
from __future__ import annotations
import hashlib
from email.parser import BytesHeaderParser
from pathlib import Path
import time

DOMAIN_COLUMNS = {
    "receive_mode": "TEXT NOT NULL DEFAULT 'fixed'",
    "receive_enabled": "INTEGER NOT NULL DEFAULT 1",
    "send_enabled": "INTEGER NOT NULL DEFAULT 1",
    "receive_subdomains": "INTEGER NOT NULL DEFAULT 0",
    "max_subdomain_depth": "INTEGER NOT NULL DEFAULT 3",
    "registration_enabled": "INTEGER NOT NULL DEFAULT 1",
    "registration_random_subdomain_depth": "INTEGER NOT NULL DEFAULT 0",
    "source_type": "TEXT NOT NULL DEFAULT 'manual'",
    "source_status": "TEXT NOT NULL DEFAULT 'imported'",
    "dns_provider": "TEXT NOT NULL DEFAULT 'cloudflare'",
}


def maildir_identity(path: Path) -> tuple[str, str] | None:
    parts = path.parts
    if len(parts) < 5 or parts[-3] != "Maildir" or parts[-2] not in {"new", "cur"}:
        return None
    recipient = parts[-4].lower() + "@" + parts[-5].lower()
    name = parts[-1].split(":2,", 1)[0]
    key = hashlib.sha256((recipient + "\0" + name).encode()).hexdigest()
    return key, recipient


def migrate(connection):
    # DDL and version markers are one transaction, including upgrade from v2.
    if not connection.in_transaction:
        connection.execute("BEGIN IMMEDIATE")
    connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at REAL NOT NULL)")
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=1").fetchone():
        _migrate_v2(connection)
        _migrate_v3(connection)
        _migrate_v4(connection)
        _migrate_v5(connection)
        _migrate_v6(connection)
        _migrate_v7(connection)
        _migrate_v8(connection)
        _migrate_v9(connection)
        _migrate_v10(connection)
        _migrate_v11(connection)
        _migrate_v12(connection)
        _migrate_v13(connection)
        _migrate_v14(connection)
        _migrate_v15(connection)
        _migrate_v16(connection)
        return
    columns = {x[1] for x in connection.execute("PRAGMA table_info(mail_domains)")}
    for name, declaration in DOMAIN_COLUMNS.items():
        if name not in columns:
            connection.execute(f"ALTER TABLE mail_domains ADD COLUMN {name} {declaration}")
    connection.execute("""CREATE TABLE IF NOT EXISTS message_deliveries(
        id INTEGER PRIMARY KEY, delivery_key TEXT NOT NULL UNIQUE,
        message_id INTEGER NOT NULL REFERENCES messages(id), envelope_recipient TEXT NOT NULL,
        managed_domain TEXT, recipient_domain TEXT NOT NULL, source_path TEXT,
        received_at REAL NOT NULL, source TEXT NOT NULL DEFAULT 'postfix')""")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_recipient ON message_deliveries(envelope_recipient, received_at)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_message ON message_deliveries(message_id)")
    connection.execute("""CREATE TABLE IF NOT EXISTS domain_checks(
        domain TEXT NOT NULL, check_name TEXT NOT NULL, status TEXT NOT NULL,
        config_hash TEXT NOT NULL, checked_at REAL NOT NULL, detail TEXT NOT NULL DEFAULT '',
        PRIMARY KEY(domain, check_name))""")
    # Preserve existing delivery identities. Never replay history as live events.
    for row in connection.execute("SELECT id,source_path,received_at FROM messages WHERE source_path IS NOT NULL").fetchall():
        identity = maildir_identity(Path(row["source_path"]))
        if identity:
            key, recipient = identity
            connection.execute("INSERT OR IGNORE INTO message_deliveries(delivery_key,message_id,envelope_recipient,recipient_domain,source_path,received_at) VALUES(?,?,?,?,?,?)",
                               (key, row["id"], recipient, recipient.split("@", 1)[1], row["source_path"], row["received_at"]))
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(1,?)", (time.time(),))
    _migrate_v2(connection)
    _migrate_v3(connection)
    _migrate_v4(connection)
    _migrate_v5(connection)
    _migrate_v6(connection)
    _migrate_v7(connection)
    _migrate_v8(connection)
    _migrate_v9(connection)
    _migrate_v10(connection)
    _migrate_v11(connection)
    _migrate_v12(connection)
    _migrate_v13(connection)
    _migrate_v14(connection)
    _migrate_v15(connection)
    _migrate_v16(connection)


def _migrate_v2(connection):
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=2").fetchone():
        return
    # Associate historic deliveries with the longest known management boundary,
    # independent of today's enable/disable state. Do not create live events.
    connection.execute("""UPDATE message_deliveries SET managed_domain=(
        SELECT d.domain FROM mail_domains d
        WHERE recipient_domain=d.domain OR substr(recipient_domain,-length(d.domain)-1)='.'||d.domain
        ORDER BY length(d.domain) DESC LIMIT 1
    ) WHERE managed_domain IS NULL""")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_managed ON message_deliveries(managed_domain,received_at)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_domain ON message_deliveries(recipient_domain,received_at)")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(2,?)", (time.time(),))


def _migrate_v3(connection):
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=3").fetchone():
        return
    columns = {x[1] for x in connection.execute("PRAGMA table_info(mail_domains)")}
    for name, declaration in {
        "source_id": "TEXT", "claim_id": "TEXT", "dns_credential_ref": "TEXT",
    }.items():
        if name not in columns:
            connection.execute(f"ALTER TABLE mail_domains ADD COLUMN {name} {declaration}")
    statements = [
        """CREATE TABLE dns_credentials(
            id TEXT PRIMARY KEY, provider TEXT NOT NULL, domain TEXT, label TEXT NOT NULL,
            key_id TEXT NOT NULL, ciphertext TEXT NOT NULL, created_at REAL NOT NULL,
            updated_at REAL NOT NULL)""",
        """CREATE TABLE domain_sources(
            id TEXT PRIMARY KEY, name TEXT NOT NULL, source_type TEXT NOT NULL,
            base_url TEXT NOT NULL, client_id TEXT NOT NULL, credential_ref TEXT NOT NULL
            REFERENCES dns_credentials(id), enabled INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL)""",
        """CREATE TABLE domain_jobs(
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, scope TEXT NOT NULL,
            idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL, request_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued', step TEXT NOT NULL DEFAULT 'persisted',
            result_json TEXT NOT NULL DEFAULT '{}', error_code TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL, updated_at REAL NOT NULL,
            UNIQUE(kind,scope,idempotency_key))""",
        "CREATE INDEX idx_domain_jobs_status ON domain_jobs(status,created_at)",
        """CREATE TABLE domain_claims(
            id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES domain_sources(id),
            domain TEXT NOT NULL, upstream_claim_id TEXT, external_id TEXT,
            client_id TEXT NOT NULL, upstream_status TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL, job_id TEXT NOT NULL REFERENCES domain_jobs(id),
            receipt_ref TEXT REFERENCES dns_credentials(id), dns_credential_ref TEXT
            REFERENCES dns_credentials(id), created_at REAL NOT NULL,
            UNIQUE(source_id,domain))""",
        """CREATE TABLE managed_dns_records(
            domain TEXT NOT NULL, credential_ref TEXT NOT NULL REFERENCES dns_credentials(id),
            zone_id TEXT NOT NULL, provider_record_id TEXT NOT NULL,
            record_type TEXT NOT NULL, record_name TEXT NOT NULL, role TEXT NOT NULL,
            last_content TEXT NOT NULL, updated_at REAL NOT NULL,
            PRIMARY KEY(domain,credential_ref,zone_id,provider_record_id))""",
    ]
    for statement in statements:
        connection.execute(statement)
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(3,?)", (time.time(),))



def _migrate_v4(connection):
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=4").fetchone():
        return
    connection.execute("ALTER TABLE managed_dns_records ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")
    connection.execute("ALTER TABLE managed_dns_records ADD COLUMN ownership_marker TEXT NOT NULL DEFAULT ''")
    connection.execute("""CREATE TABLE domain_dns_plans(
        id TEXT PRIMARY KEY, domain TEXT NOT NULL, credential_ref TEXT NOT NULL,
        config_hash TEXT NOT NULL, plan_hash TEXT NOT NULL, inventory_hash TEXT NOT NULL,
        snapshot_json TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL)""")
    connection.execute("""CREATE TABLE domain_dns_operations(
        id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES domain_jobs(id),
        domain TEXT NOT NULL, credential_ref TEXT NOT NULL, zone_id TEXT NOT NULL,
        action TEXT NOT NULL, target_json TEXT NOT NULL, before_hash TEXT NOT NULL,
        ownership_marker TEXT NOT NULL, provider_record_id TEXT,
        status TEXT NOT NULL, error_code TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL)""")
    connection.execute("CREATE INDEX idx_dns_operations_scope ON domain_dns_operations(domain,credential_ref,status)")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(4,?)", (time.time(),))


def _migrate_v5(connection):
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=5").fetchone():
        return
    connection.execute("""CREATE TABLE webhook_outbox(
        id INTEGER PRIMARY KEY,
        event_id TEXT NOT NULL,
        webhook_id INTEGER NOT NULL REFERENCES webhooks(id),
        message_id INTEGER NOT NULL REFERENCES messages(id),
        payload_json TEXT NOT NULL,
        raw_path TEXT,
        status TEXT NOT NULL DEFAULT 'queued',
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at REAL NOT NULL,
        last_error TEXT NOT NULL DEFAULT '',
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        UNIQUE(webhook_id,event_id))""")
    connection.execute("CREATE INDEX idx_webhook_outbox_ready ON webhook_outbox(status,next_attempt_at,id)")
    connection.execute("CREATE INDEX idx_webhook_outbox_message ON webhook_outbox(message_id)")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(5,?)", (time.time(),))


def _migrate_v6(connection):
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=6").fetchone():
        return
    connection.execute("""CREATE TABLE IF NOT EXISTS api_keys(
        id INTEGER PRIMARY KEY, name TEXT, key_hash TEXT UNIQUE, created_at REAL)""")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(api_keys)")}
    if "scopes" not in columns:
        connection.execute("ALTER TABLE api_keys ADD COLUMN scopes TEXT NOT NULL DEFAULT 'mail.read,mail.send,webhook.manage'")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(6,?)", (time.time(),))


def _migrate_v7(connection):
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=7").fetchone():
        return
    connection.execute("""CREATE TABLE IF NOT EXISTS projects(
        id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
        enabled INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL)""")
    connection.execute("""CREATE TABLE IF NOT EXISTS api_key_grants(
        key_id INTEGER NOT NULL REFERENCES api_keys(id),
        project_id TEXT NOT NULL REFERENCES projects(id),
        scopes TEXT NOT NULL, created_at REAL NOT NULL,
        PRIMARY KEY(key_id,project_id))""")
    connection.execute("""CREATE TABLE IF NOT EXISTS webhooks(
        id INTEGER PRIMARY KEY, url TEXT, secret TEXT, enabled INTEGER DEFAULT 1,
        created_at REAL)""")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(webhooks)")}
    if "project_id" not in columns:
        connection.execute("ALTER TABLE webhooks ADD COLUMN project_id TEXT REFERENCES projects(id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_project ON webhooks(project_id)")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(7,?)", (time.time(),))


def _migrate_v8(connection):
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=8").fetchone():
        return
    connection.execute("""CREATE TABLE IF NOT EXISTS outbound_outbox(
        id INTEGER PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        project_id TEXT REFERENCES projects(id),
        sender TEXT NOT NULL,
        recipients_json TEXT NOT NULL,
        raw_message BLOB NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at REAL NOT NULL,
        last_error TEXT NOT NULL DEFAULT '',
        accepted_json TEXT NOT NULL DEFAULT '[]',
        rejected_json TEXT NOT NULL DEFAULT '{}',
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL)""")
    connection.execute("CREATE INDEX idx_outbound_outbox_ready ON outbound_outbox(status,next_attempt_at,id)")
    connection.execute("CREATE INDEX idx_outbound_outbox_project ON outbound_outbox(project_id,created_at)")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(8,?)", (time.time(),))


def _migrate_v9(connection):
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=9").fetchone():
        return
    connection.execute("ALTER TABLE outbound_outbox ADD COLUMN request_hash TEXT NOT NULL DEFAULT ''")
    connection.execute("ALTER TABLE outbound_outbox ADD COLUMN rfc_message_id TEXT NOT NULL DEFAULT ''")
    for row in connection.execute("SELECT id,raw_message FROM outbound_outbox").fetchall():
        header = BytesHeaderParser().parsebytes(bytes(row["raw_message"])[:64 * 1024])
        connection.execute("UPDATE outbound_outbox SET rfc_message_id=? WHERE id=?",
                           (str(header.get("Message-ID") or ""), row["id"]))
    connection.execute("UPDATE outbound_outbox SET status='submitted_to_mta' WHERE status='delivered'")
    connection.execute("CREATE INDEX idx_outbound_message_id ON outbound_outbox(rfc_message_id)")
    connection.execute("""CREATE TABLE outbound_delivery_reports(
        id INTEGER PRIMARY KEY,
        outbound_id INTEGER NOT NULL REFERENCES outbound_outbox(id),
        report_key TEXT NOT NULL UNIQUE,
        inbound_message_id INTEGER NOT NULL,
        recipient TEXT NOT NULL,
        final_recipient TEXT NOT NULL,
        action TEXT NOT NULL,
        status_code TEXT NOT NULL,
        diagnostic TEXT NOT NULL,
        reporting_mta TEXT NOT NULL,
        trust TEXT NOT NULL DEFAULT 'unverified',
        received_at REAL NOT NULL)""")
    connection.execute("CREATE INDEX idx_outbound_reports ON outbound_delivery_reports(outbound_id,id)")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(9,?)", (time.time(),))


def _migrate_v10(connection):
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=10").fetchone():
        return
    columns = {row[1] for row in connection.execute("PRAGMA table_info(outbound_outbox)")}
    if "transport" not in columns:
        connection.execute("ALTER TABLE outbound_outbox ADD COLUMN transport TEXT NOT NULL DEFAULT 'smtp'")
    if "fallback_attempts" not in columns:
        connection.execute("ALTER TABLE outbound_outbox ADD COLUMN fallback_attempts INTEGER NOT NULL DEFAULT 0")
    connection.execute("UPDATE outbound_outbox SET transport='smtp' WHERE transport IS NULL OR transport=''")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(10,?)", (time.time(),))


def _migrate_v11(connection):
    """Classify webhook targets without changing existing delivery behavior."""
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=11").fetchone():
        return
    columns = {row[1] for row in connection.execute("PRAGMA table_info(webhooks)")}
    if "kind" not in columns:
        connection.execute("ALTER TABLE webhooks ADD COLUMN kind TEXT NOT NULL DEFAULT 'shared'")
    connection.execute(
        "UPDATE webhooks SET kind='mail_stack' "
        "WHERE lower(url) LIKE '%/api/webhook/mail-stack' AND (kind IS NULL OR kind='shared')"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_kind ON webhooks(kind)")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(11,?)", (time.time(),))


def _migrate_v12(connection):
    """Add explicit registration participation and random subdomain policy."""
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=12").fetchone():
        return
    columns = {row[1] for row in connection.execute("PRAGMA table_info(mail_domains)")}
    for name, declaration in {
        "registration_enabled": "INTEGER NOT NULL DEFAULT 1",
        "registration_random_subdomain_depth": "INTEGER NOT NULL DEFAULT 0",
    }.items():
        if name not in columns:
            connection.execute(f"ALTER TABLE mail_domains ADD COLUMN {name} {declaration}")
    connection.execute(
        "UPDATE mail_domains SET registration_enabled=1 "
        "WHERE registration_enabled IS NULL"
    )
    connection.execute(
        "UPDATE mail_domains SET registration_random_subdomain_depth=0 "
        "WHERE registration_random_subdomain_depth IS NULL"
    )
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(12,?)", (time.time(),))


def _migrate_v13(connection):
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=13").fetchone():
        return
    columns = {x[1] for x in connection.execute("PRAGMA table_info(domain_claims)")}
    if "nameservers_json" not in columns:
        connection.execute("ALTER TABLE domain_claims ADD COLUMN nameservers_json TEXT NOT NULL DEFAULT '[]'")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(13,?)", (time.time(),))


def _migrate_v14(connection):
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=14").fetchone():
        return
    connection.execute("ALTER TABLE api_keys ADD COLUMN global_access INTEGER NOT NULL DEFAULT 0")
    # Preserve existing integrations that never used project grants. Existing
    # project keys must not inherit a global escape hatch during this upgrade.
    connection.execute("""UPDATE api_keys SET global_access=1 WHERE NOT EXISTS(
        SELECT 1 FROM api_key_grants g WHERE g.key_id=api_keys.id)""")
    connection.execute("ALTER TABLE mail_domains ADD COLUMN project_id TEXT REFERENCES projects(id)")
    connection.execute("ALTER TABLE message_deliveries ADD COLUMN project_id TEXT REFERENCES projects(id)")
    connection.execute("CREATE INDEX idx_deliveries_project ON message_deliveries(project_id,message_id)")
    connection.execute("CREATE INDEX idx_domains_project ON mail_domains(project_id)")
    connection.execute("""CREATE TABLE auth_attempts(
        source TEXT PRIMARY KEY, attempts INTEGER NOT NULL, expires_at REAL NOT NULL)""")
    connection.execute("CREATE INDEX idx_auth_attempts_expiry ON auth_attempts(expires_at)")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(14,?)", (time.time(),))


def _migrate_v15(connection):
    """Keep worker polling independent of retained result JSON volume."""
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=15").fetchone():
        return
    # A > comparison implies IS NOT NULL, so both live backoff queries can
    # search this sparse expression index without reading historical blobs.
    connection.execute("""CREATE INDEX idx_domain_jobs_backoff_until ON domain_jobs(
        json_extract(result_json,'$.provider_backoff.until'))
        WHERE json_extract(result_json,'$.provider_backoff.until') IS NOT NULL""")
    # Cover the readiness retry scan without loading full task results.
    connection.execute("""CREATE INDEX idx_domain_jobs_readiness_attempts
        ON domain_jobs(kind,scope,updated_at,idempotency_key) WHERE kind='dns_validate'""")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(15,?)", (time.time(),))


def _migrate_v16(connection):
    """Read the newest tasks without sorting retained result payloads."""
    if connection.execute("SELECT 1 FROM schema_migrations WHERE version=16").fetchone():
        return
    # Supports installing the additive index online before the next release.
    connection.execute("""CREATE INDEX IF NOT EXISTS idx_domain_jobs_created
        ON domain_jobs(created_at DESC,id)""")
    connection.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(16,?)", (time.time(),))

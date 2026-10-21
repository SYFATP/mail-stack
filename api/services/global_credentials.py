"""Migrate and store the legacy Cloudflare configuration in CredentialStore."""
from api.repositories.credentials import CredentialStore, CredentialError

REFERENCE = "global_cloudflare_credential_ref"
LEGACY = ("cf_api_token", "cf_api_email", "cf_api_key")


def _save(c, secret):
    if set(secret) not in ({"api_token"}, {"api_email", "api_key"}):
        raise CredentialError("invalid Cloudflare credential fields")
    if any(not isinstance(value, str) or not value or len(value) > 8192
           or "\r" in value or "\n" in value for value in secret.values()):
        raise CredentialError("invalid Cloudflare credential field")
    row = c.execute("select value from settings where key=?", (REFERENCE,)).fetchone()
    reference = CredentialStore().put(c, "cloudflare", secret, label="Global Cloudflare",
                                     credential_id=row["value"] if row else None)
    c.execute("""insert into settings(key,value) values(?,?)
                 on conflict(key) do update set value=excluded.value""", (REFERENCE, reference))
    c.execute("delete from settings where key in (?,?,?)", LEGACY)


def save_cloudflare_secret(database, secret):
    c = database()
    try:
        c.execute("pragma secure_delete=ON")
        c.execute("BEGIN IMMEDIATE")
        with c:
            _save(c, secret)
    finally:
        c.close()


def load_cloudflare_secret(database):
    c = database()
    try:
        # Normal reads must not acquire a writer lock: DNS workers can read
        # credentials while another connection is updating job state.
        c.execute("BEGIN")
        row = c.execute("select value from settings where key=?", (REFERENCE,)).fetchone()
        legacy = c.execute("select 1 from settings where key in (?,?,?) limit 1", LEGACY).fetchone()
        if not legacy:
            return CredentialStore().get(c, row["value"], provider="cloudflare") if row else {}
        c.rollback()
        # Serialize legacy migration and updates so an old secret never
        # overwrites a concurrently saved new configuration.
        c.execute("pragma secure_delete=ON")
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("select value from settings where key=?", (REFERENCE,)).fetchone()
        if row:
            secret = CredentialStore().get(c, row["value"], provider="cloudflare")
            c.execute("delete from settings where key in (?,?,?)", LEGACY)
        else:
            legacy = {row["key"]: row["value"] for row in
                      c.execute("select key,value from settings where key in (?,?,?)", LEGACY)}
            token = legacy.get("cf_api_token", "").strip()
            api_email = legacy.get("cf_api_email", "").strip()
            api_key = legacy.get("cf_api_key", "").strip()
            secret = ({"api_token": token} if token else
                      {"api_email": api_email, "api_key": api_key} if api_email and api_key else {})
            if secret:
                # Missing keyrings fail closed; plaintext is never used for a
                # provider request or silently replaced by environment values.
                _save(c, secret)
            elif legacy:
                c.execute("delete from settings where key in (?,?,?)", LEGACY)
        c.commit()
        return secret
    finally:
        c.close()

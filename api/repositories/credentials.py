"""Encrypted credentials with explicit key ids and context-bound envelopes.

No plaintext fallback, no implicit password hashing, and no secret read API.
Keep the keyring separate from the SQLite backup. Rotation retains old keys
until every referenced ciphertext has been rewrapped.
"""
from __future__ import annotations
import base64
import json
import os
import re
import time
import uuid
from cryptography.fernet import Fernet, InvalidToken


class CredentialError(ValueError):
    pass


class CredentialStore:
    def __init__(self, keys=None, active_key=None):
        try:
            keys = json.loads(os.getenv("MAIL_CREDENTIAL_KEYS", "{}")) if keys is None else keys
            active_key = os.getenv("MAIL_CREDENTIAL_ACTIVE_KEY", "") if active_key is None else active_key
            self.keys = {}
            for key_id, value in keys.items():
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key_id):
                    raise ValueError()
                if not isinstance(value, str) or len(value) != 44:
                    raise ValueError()
                decoded = base64.b64decode(value, altchars=b"-_", validate=True)
                if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode() != value:
                    raise ValueError()
                self.keys[key_id] = Fernet(value.encode("ascii"))
            self.active_key = active_key
        except Exception:
            raise CredentialError("invalid credential keyring configuration") from None

    def require_writer(self):
        if self.active_key not in self.keys:
            raise CredentialError("credential encryption key is not configured")

    def put(self, connection, provider, secret, *, domain=None, label="", credential_id=None):
        self.require_writer()
        if not isinstance(secret, dict) or not secret:
            raise CredentialError("nonempty credential object required")
        credential_id = credential_id or uuid.uuid4().hex
        existing = connection.execute("SELECT provider,domain FROM dns_credentials WHERE id=?", (credential_id,)).fetchone()
        if existing and (existing["provider"] != provider or existing["domain"] != domain):
            raise CredentialError("credential context mismatch")
        envelope = {"id": credential_id, "provider": provider, "domain": domain, "secret": secret}
        ciphertext = self.keys[self.active_key].encrypt(json.dumps(envelope, separators=(",", ":")).encode()).decode()
        now = time.time()
        connection.execute("""INSERT INTO dns_credentials VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET key_id=excluded.key_id,ciphertext=excluded.ciphertext,
            label=excluded.label,updated_at=excluded.updated_at""",
            (credential_id, provider, domain, label, self.active_key, ciphertext, now, now))
        return credential_id

    def get(self, connection, credential_id, *, provider=None, domain=None):
        row = connection.execute("SELECT * FROM dns_credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise CredentialError("credential reference not found")
        if provider is not None and row["provider"] != provider:
            raise CredentialError("credential provider mismatch")
        if row["domain"] is not None and row["domain"] != domain:
            raise CredentialError("credential domain mismatch")
        try:
            plaintext = self.keys[row["key_id"]].decrypt(row["ciphertext"].encode())
            envelope = json.loads(plaintext)
            if any(envelope[field] != row[field] for field in ("id", "provider", "domain")):
                raise ValueError()
            return envelope["secret"]
        except (KeyError, ValueError, InvalidToken, TypeError):
            raise CredentialError("credential decrypt failed; verify keyring and context") from None

    def rewrap(self, connection, credential_id):
        row = connection.execute("SELECT * FROM dns_credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise CredentialError("credential reference not found")
        secret = self.get(connection, credential_id, domain=row["domain"])
        return self.put(connection, row["provider"], secret, domain=row["domain"],
                        label=row["label"], credential_id=credential_id)

    @staticmethod
    def public(connection):
        return [dict(row) for row in connection.execute(
            "SELECT id,provider,domain,label,key_id,created_at,updated_at FROM dns_credentials WHERE provider!='claim_receipt' ORDER BY created_at")]

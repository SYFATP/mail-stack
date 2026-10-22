"""Encrypted multi-account login and discovery of existing dynv6 HTTP Tokens."""
import re
import secrets
import threading
import time
import uuid
from api.providers.http import ProviderError
from api.repositories.credentials import CredentialError


class Dynv6Accounts:
    def __init__(self, manager):
        self.m = manager
        self._guard = threading.Lock()
        self._locks = {}

    @property
    def registration(self):
        return self.m.dynv6_registration

    def lock(self, key):
        with self._guard:
            return self._locks.setdefault(key, threading.RLock())

    @staticmethod
    def email(value):
        value = value.strip().casefold()
        if len(value) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("invalid dynv6 login email")
        return value

    def public(self, ref=None):
        rows = [row for row in self.registration.credentials() if row["provider"] == "dynv6"]
        if ref is None:
            return rows
        return next(row for row in rows if row["id"] == ref)

    def _existing(self, email, keys):
        c = self.m.db()
        try:
            for row in c.execute("SELECT * FROM dns_credentials WHERE provider='dynv6' AND domain IS NULL"):
                value = self.m.credentials().get(c, row["id"], provider="dynv6")
                if value.get("login_email") == email or any(
                        secrets.compare_digest(value["api_token"], key["token"]) for key in keys):
                    return row["id"], value
        finally:
            c.close()
        return None, None

    def _store(self, ref, expected, updates, *, label=None):
        with self.m.lock:
            c = self.m.db()
            try:
                c.execute("BEGIN IMMEDIATE")
                row = c.execute("SELECT * FROM dns_credentials WHERE id=?", (ref,)).fetchone()
                if expected is not None:
                    if not row:
                        raise CredentialError("credential reference not found")
                    current = self.m.credentials().get(c, ref, provider="dynv6", domain=row["domain"])
                    if (current.get("session_revision") != expected.get("session_revision")
                            or current["api_token"] != expected["api_token"]):
                        raise CredentialError("dynv6 account changed; refresh and try again")
                else:
                    if row:
                        raise CredentialError("dynv6 account changed; refresh and try again")
                    current = {}
                current.update(updates)
                current["session_revision"] = uuid.uuid4().hex
                self.m.credentials().put(
                    c, "dynv6", current, domain=row["domain"] if row else None,
                    label=label if label is not None else row["label"], credential_id=ref)
                c.commit()
                return current
            finally:
                c.close()

    def _discover(self, client, keys, expected, *, domain=None, email=None):
        same_login = bool(expected and email and expected.get("login_email") == email
                          and expected.get("login_password"))
        if expected and not same_login and not any(
                secrets.compare_digest(expected["api_token"], key["token"]) for key in keys):
            raise ProviderError("dynv6_session_account_mismatch")
        eligible = [key for key in keys if key["scope"] == "all" or domain is not None]
        eligible.sort(key=lambda key: (
            not bool(expected and secrets.compare_digest(expected["api_token"], key["token"])),
            int(key["id"])))
        if not eligible:
            raise ProviderError("dynv6_account_token_required")
        for key in eligible[:8]:
            try:
                zones = self.registration.zones({"api_token": key["token"]})
            except ProviderError as exc:
                if exc.code in {"provider_http_401", "provider_http_403"}:
                    continue
                raise
            return {
                "api_token": key["token"], "account_token_id": key["id"],
                "account_token_scope": key["scope"], "account_zone_count": str(len(zones)),
                "session_cookie": client.cookie(), "session_status": "valid",
                "session_checked_at": str(time.time()), "login_status": "valid",
                "login_checked_at": str(time.time()), "login_retry_at": "0",
            }
        raise ProviderError("dynv6_account_token_unusable")

    def save(self, email, password, label="", ref=None):
        email = self.email(email)
        self.m.credentials().require_writer()
        expected = self.registration.secret(ref) if ref else None
        if not password and expected and expected.get("login_email") == email:
            password = expected.get("login_password", "")
        if not isinstance(password, str) or not 1 <= len(password) <= 1024:
            raise ValueError("dynv6 login password is required")
        with self.lock(ref or email):
            client = self.registration.session_factory(None)
            keys = client.login(email, password)
            if ref is None:
                ref, expected = self._existing(email, keys)
            c = self.m.db()
            try:
                domain = (c.execute("SELECT domain FROM dns_credentials WHERE id=?", (ref,)).fetchone()[0]
                          if ref else None)
            finally:
                c.close()
            updates = self._discover(client, keys, expected, domain=domain, email=email)
            updates.update(login_email=email, login_password=password)
            with self.m.lock:
                # Aliases can resolve to one account after concurrent logins.
                # Keep discovery outside the mutation lock, then deduplicate atomically.
                if ref is None:
                    ref, expected = self._existing(email, keys)
                ref = ref or uuid.uuid4().hex
                self._store(ref, expected, updates, label=(label.strip() or email)[:80])
                return self.public(ref)

    def refresh(self, ref):
        """One login attempt per account; failures pause automatic attempts."""
        self.m.credentials().require_writer()
        with self.lock(ref):
            expected = self.registration.secret(ref)
            remaining = float(expected.get("login_retry_at", 0)) - time.time()
            if remaining > 0:
                raise ProviderError("dynv6_login_cooldown", retry_after=int(remaining) + 1)
            try:
                if expected.get("login_password"):
                    client = self.registration.session_factory(None)
                    keys = client.login(expected["login_email"], expected["login_password"])
                else:
                    if not expected.get("session_cookie"):
                        raise ProviderError("dynv6_session_required")
                    client = self.registration.session_factory(expected["session_cookie"])
                    keys = client.keys()
                c = self.m.db()
                try:
                    domain = c.execute("SELECT domain FROM dns_credentials WHERE id=?", (ref,)).fetchone()[0]
                finally:
                    c.close()
                updates = self._discover(client, keys, expected, domain=domain,
                                         email=expected.get("login_email"))
                self._store(ref, expected, updates)
            except ProviderError as exc:
                if expected.get("login_password"):
                    try:
                        self._store(ref, expected, {
                            "login_status": ("verification_required" if exc.code ==
                                             "dynv6_login_verification_required" else "failed"),
                            "login_checked_at": str(time.time()),
                            "login_retry_at": str(time.time() + max(300, exc.retry_after)),
                        })
                    except CredentialError:
                        pass
                raise
            return self.public(ref)

    def zones(self, ref, domain=None):
        value = self.registration.secret(ref, domain)
        try:
            return value, self.registration.zones(value)
        except ProviderError as exc:
            if exc.code not in {"provider_http_401", "provider_http_403"} or not value.get("login_password"):
                raise
            self.refresh(ref)
            value = self.registration.secret(ref, domain)
            return value, self.registration.zones(value)

    def prepared(self, ref, domain=None):
        """Renew before domain registration; never repeat a domain POST."""
        with self.lock(ref):
            value, zones = self.zones(ref, domain)
            try:
                if not value.get("session_cookie"):
                    raise ProviderError("dynv6_session_required")
                client = self.registration.session_factory(value["session_cookie"])
                if not zones and value.get("login_password"):
                    client.prepare(zones, token=value["api_token"])
                else:
                    client.prepare(zones)
            except ProviderError as exc:
                if exc.code not in {"dynv6_session_required", "dynv6_session_expired"} or not value.get("login_password"):
                    raise
                self.refresh(ref)
                value, zones = self.zones(ref, domain)
                client = self.registration.session_factory(value["session_cookie"])
                if not zones:
                    client.prepare(zones, token=value["api_token"])
                else:
                    client.prepare(zones)
            value = self.registration.store_session(ref, value, client.cookie(), "valid")
            return value, client

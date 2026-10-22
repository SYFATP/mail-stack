import io
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch
from urllib.parse import parse_qs
import test_domain_control as base
from api.providers.dynv6_session import Dynv6Session, _KeysPage
from api.providers.http import ProviderError
from api.repositories.credentials import CredentialError

EMAIL = "one@example.test"
PASSWORD = "fixture-login-password-private"
TOKEN = "fixture-account-one-token-private"
COOKIE = "fixture-authenticated-session-private"


def keys_html(keys):
    rows = []
    for key in keys:
        scope = "<em>all</em>" if key["scope"] == "all" else '<a href="/zones/100">anchor.test</a>'
        value = json.dumps({"id": int(key["id"]), "data": key["token"], "regen": True}).replace('"', "&quot;")
        rows.append(f'<b-collapse id="key_token_{key["id"]}"><dt>Token</dt><dd>'
                    f'<key-data :k="{value}"></key-data></dd><dt>Zone(s)</dt><dd>{scope}</dd></b-collapse>')
    return "HTTP Tokens" + "".join(rows)


class Wire:
    def __init__(self):
        self.keys = {
            EMAIL: [{"id": "10", "token": TOKEN, "scope": "all", "zone_ids": []}],
            "two@example.test": [{"id": "20", "token": TOKEN + "-two", "scope": "all", "zone_ids": []}],
        }
        self.zones = {email: [{"id": 100, "name": "anchor.test"}] for email in self.keys}
        self.cookies = {COOKIE: EMAIL}
        self.logins, self.posts, self.fail_login, self.revoked = 0, 0, "", set()

    def request(self, method, base_url, path, **kwargs):
        token = kwargs.get("headers", {}).get("Authorization", "").removeprefix("Bearer ")
        if token in self.revoked:
            raise ProviderError("provider_http_401")
        email = next((email for email, keys in self.keys.items()
                      if any(key["token"] == token for key in keys)), None)
        if email is None:
            raise ProviderError("provider_http_401")
        if path == "/api/v2/zones":
            return list(self.zones[email])
        if path.endswith("/records"):
            return []
        raise AssertionError((method, path))

    def session(self, cookie=None):
        wire = self
        class Client:
            def __init__(self):
                self.value = cookie
            def login(self, email, password):
                wire.logins += 1
                if wire.fail_login:
                    raise ProviderError(wire.fail_login)
                if email not in wire.keys or password != PASSWORD:
                    raise ProviderError("dynv6_login_rejected")
                self.value = COOKIE + str(wire.logins)
                wire.cookies[self.value] = email
                return self.keys()
            def keys(self):
                if self.value not in wire.cookies:
                    raise ProviderError("dynv6_session_expired")
                return wire.keys[wire.cookies[self.value]]
            def cookie(self):
                return self.value
            def prepare(self, zones, *, token=None):
                self.keys()
                if not zones and not any(key["token"] == token for key in self.keys()):
                    raise ProviderError("dynv6_session_account_mismatch")
            def register(self, domain):
                wire.posts += 1
                wire.zones[wire.cookies[self.value]].append({"id": 100 + wire.posts, "name": domain})
                return {"domain_id": "501"}
        return Client()


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.case = base.P2Tests(methodName="runTest")
        self.case.setUp()
        self.m, self.client = self.case.manager, self.case.client
        self.wire = Wire()
        self.m.http = self.wire
        self.registration = self.m.dynv6_registration
        self.registration.session_factory = self.wire.session
        self.accounts = self.m.dynv6_accounts

    def tearDown(self):
        self.case.tearDown()

    def save(self, email=EMAIL, ref=None, password=PASSWORD):
        return self.accounts.save(email, password, "fixture account", ref=ref)

    def test_api_login_discovery_encryption_and_public_redaction(self):
        url = "/api/v1/dynv6/accounts"
        payload = {"email": EMAIL, "password": PASSWORD, "label": "fixture"}
        self.assertEqual(self.client.post(url, json=payload).status_code, 401)
        response = self.client.post(url, headers=self.case.headers, json=payload)
        self.assertEqual(response.status_code, 201, response.text)
        ref = response.json()["id"]
        self.assertEqual(response.json()["login"]["email"], EMAIL)
        self.assertTrue(response.json()["login"]["configured"])
        for path in (url, "/api/v1/dns-credentials"):
            public = self.client.get(path, headers=self.case.headers)
            for secret in (PASSWORD, TOKEN, COOKIE):
                self.assertNotIn(secret, public.text)
        secret = self.registration.secret(ref)
        self.assertEqual(secret["login_password"], PASSWORD)
        self.assertEqual(secret["api_token"], TOKEN)
        c = self.m.db()
        try:
            ciphertext = c.execute("SELECT ciphertext FROM dns_credentials WHERE id=?", (ref,)).fetchone()[0]
            self.assertNotIn(PASSWORD, ciphertext)
            self.assertNotIn(TOKEN, ciphertext)
        finally:
            c.close()

    def test_accounts_are_isolated_and_repeated_save_reuses_reference(self):
        first, second = self.save(), self.save("two@example.test")
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(self.save()["id"], first["id"])
        self.assertEqual(len(self.accounts.public()), 2)
        self.assertNotEqual(self.registration.secret(first["id"])["api_token"],
                            self.registration.secret(second["id"])["api_token"])

    def test_parallel_alias_saves_with_the_same_token_reuse_one_reference(self):
        alias = "alias@example.test"
        self.wire.keys[alias] = self.wire.keys[EMAIL]
        self.wire.zones[alias] = self.wire.zones[EMAIL]
        barrier = Barrier(2)
        original = self.accounts._existing
        calls = {}
        def existing(email, keys):
            result = original(email, keys)
            calls[email] = calls.get(email, 0) + 1
            if calls[email] == 1:
                barrier.wait(timeout=5)
            return result
        with patch.object(self.accounts, "_existing", side_effect=existing):
            with ThreadPoolExecutor(max_workers=2) as pool:
                saved = list(pool.map(self.save, [EMAIL, alias]))
        self.assertEqual(saved[0]["id"], saved[1]["id"])
        self.assertEqual(len(self.accounts.public()), 1)

    def test_legacy_credential_is_adopted_without_losing_domain_binding(self):
        ref = self.m.add_dns_credential("dynv6", None, "legacy", {"api_token": TOKEN})["id"]
        self.case.domain(enabled=False, dns_provider="dynv6", dns_credential_ref=ref)
        account = self.save()
        self.assertEqual(account["id"], ref)
        self.assertEqual(self.m.domain("example.test")["dns_credential_ref"], ref)
        self.assertEqual(self.wire.posts, 0)

    def test_existing_reference_cannot_be_reassigned_to_another_account(self):
        first = self.save()
        with self.assertRaisesRegex(ProviderError, "dynv6_session_account_mismatch"):
            self.save("two@example.test", ref=first["id"])
        self.assertEqual(self.registration.secret(first["id"])["api_token"], TOKEN)

    def test_blank_password_retains_saved_password_only_for_same_email(self):
        first = self.save()
        self.save(ref=first["id"], password="")
        with self.assertRaisesRegex(ValueError, "password is required"):
            self.save("two@example.test", ref=first["id"], password="")

    def test_rejected_login_never_persists_new_password_or_echoes_it(self):
        response = self.client.post("/api/v1/dynv6/accounts", headers=self.case.headers,
                                    json={"email": EMAIL, "password": PASSWORD + "-wrong"})
        self.assertEqual(response.status_code, 409)
        self.assertNotIn(PASSWORD, response.text)
        self.assertEqual(self.accounts.public(), [])
        response = self.client.post("/api/v1/dynv6/accounts", headers=self.case.headers,
                                    json={"email": EMAIL, "password": {"secret": PASSWORD}})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(PASSWORD, response.text)

    def test_no_global_token_requires_existing_suitable_token(self):
        self.wire.keys[EMAIL][0]["scope"] = "zones"
        with self.assertRaisesRegex(ProviderError, "dynv6_account_token_required"):
            self.save()
        self.assertEqual(self.accounts.public(), [])

    def test_invalid_existing_token_is_skipped_for_another_global_token(self):
        self.wire.revoked.add(TOKEN)
        self.wire.keys[EMAIL].append({"id": "11", "token": TOKEN + "-new", "scope": "all"})
        saved = self.save()
        self.assertEqual(saved["login"]["token_id"], "11")

    def test_expired_session_renews_once_across_two_registration_jobs(self):
        saved = self.save()
        self.wire.cookies.clear()
        for domain in ("first.test", "second.test"):
            self.case.domain(domain=domain, enabled=False, dns_provider="manual")
            job = self.registration.enqueue(domain, "fixture-" + domain, saved["id"])
            self.assertTrue(self.m.run_once())
            self.assertEqual(self.m.jobs.get(job["id"])["status"], "succeeded")
        self.assertEqual(self.wire.logins, 2)
        self.assertEqual(self.wire.posts, 2)

    def test_login_timeout_does_not_mark_an_undispatched_domain_as_unknown(self):
        saved = self.save()
        self.wire.cookies.clear()
        self.wire.fail_login = "dynv6_session_transport_error"
        self.case.domain(enabled=False, dns_provider="manual")
        job = self.registration.enqueue("example.test", "fixture-login-timeout", saved["id"])
        self.m.run_once()
        result = self.m.jobs.get(job["id"])
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["result"]["registration_dispatched"])
        self.assertEqual(self.wire.posts, 0)

    def test_parallel_session_checks_share_one_renewal(self):
        saved = self.save()
        self.wire.cookies.clear()
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: self.accounts.prepared(saved["id"]), range(2)))
        self.assertEqual(self.wire.logins, 2)

    def test_failed_renewal_is_cooled_down_and_corrected_password_can_be_saved(self):
        saved = self.save()
        self.wire.cookies.clear()
        self.wire.fail_login = "dynv6_login_rejected"
        with self.assertRaisesRegex(ProviderError, "dynv6_login_rejected"):
            self.accounts.prepared(saved["id"])
        with self.assertRaisesRegex(ProviderError, "dynv6_login_cooldown"):
            self.accounts.prepared(saved["id"])
        self.assertEqual(self.wire.logins, 2)
        self.wire.fail_login = ""
        self.save(ref=saved["id"])
        self.assertEqual(self.accounts.public(saved["id"])["login"]["status"], "valid")

    def test_revoked_api_token_can_be_refreshed_for_the_same_login_account(self):
        saved = self.save()
        self.wire.revoked.add(TOKEN)
        self.wire.keys[EMAIL] = [{"id": "11", "token": TOKEN + "-new", "scope": "all"}]
        secret, zones = self.accounts.zones(saved["id"])
        self.assertEqual(secret["api_token"], TOKEN + "-new")
        self.assertEqual(len(zones), 1)

    def test_zero_zone_account_can_register_its_first_domain(self):
        self.wire.zones[EMAIL] = []
        saved = self.save()
        self.case.domain(enabled=False, dns_provider="manual")
        job = self.registration.enqueue("example.test", "fixture-first-zone", saved["id"])
        self.m.run_once()
        self.assertEqual(self.m.jobs.get(job["id"])["status"], "succeeded")
        self.assertEqual(self.wire.posts, 1)

    def test_legacy_session_cannot_replace_token_from_another_account(self):
        ref = self.m.add_dns_credential("dynv6", None, "legacy", {"api_token": TOKEN})["id"]
        self.registration.save_session(ref, COOKIE)
        self.wire.cookies[COOKIE] = "two@example.test"
        with self.assertRaisesRegex(ProviderError, "dynv6_session_account_mismatch"):
            self.accounts.refresh(ref)
        self.assertEqual(self.registration.secret(ref)["api_token"], TOKEN)

    def test_stale_updates_do_not_overwrite_new_login_and_refresh_api_works(self):
        saved = self.save()
        stale = self.registration.secret(saved["id"])
        response = self.client.post("/api/v1/dynv6/accounts/" + saved["id"] + "/refresh",
                                    headers=self.case.headers)
        self.assertEqual(response.status_code, 200, response.text)
        with self.assertRaises(CredentialError):
            self.accounts._store(saved["id"], stale, {"login_status": "failed"})


class Response(io.BytesIO):
    def __init__(self, code, text="", headers=None):
        super().__init__(text.encode())
        self.code, self.headers = code, headers or {}


LOGIN = ('<form id="new_user" action="/users/sign_in" method="post">'
         '<input name="authenticity_token" value="fixture-csrf">'
         '<input name="user[email]" type="email"><input name="user[password]" type="password">'
         '<input name="user[remember_me]" value="0"><input name="commit" value="Log in"></form>')


class FormTests(unittest.TestCase):
    def client(self, replies):
        self.requests = []
        class Opener:
            def open(inner, request, timeout):
                self.requests.append(request)
                return replies.pop(0)
        return Dynv6Session(COOKIE, opener=Opener())

    def test_login_uses_fresh_csrf_and_discovers_existing_plaintext_token(self):
        client = self.client([Response(200, LOGIN), Response(302, headers={"Location": "/zones"}),
                              Response(200, keys_html([{"id": "10", "token": TOKEN, "scope": "all"}]))])
        found = client.login(EMAIL, PASSWORD)
        self.assertEqual(found[0]["token"], TOKEN)
        self.assertEqual(found[0]["scope"], "all")
        fields = parse_qs(self.requests[1].data.decode())
        self.assertEqual(fields["user[password]"], [PASSWORD])
        self.assertEqual(fields["authenticity_token"], ["fixture-csrf"])
        self.assertEqual(self.requests[1].get_header("Referer"), "https://dynv6.com/users/sign_in")
        self.assertEqual(len(self.requests), 3)

    def test_keys_scope_and_types_are_not_confused(self):
        html = keys_html([{"id": "10", "token": TOKEN, "scope": "all"},
                          {"id": "11", "token": TOKEN + "-zone", "scope": "zones"}])
        keys = _KeysPage(html).keys
        self.assertEqual([key["scope"] for key in keys], ["all", "zones"])
        self.assertEqual(keys[1]["zone_ids"], ["100"])
        self.assertEqual(_KeysPage('<b-collapse id="key_tsig_10"><key-data :k="invalid"></key-data></b-collapse>').keys, [])

    def test_login_rejection_and_foreign_redirect_never_echo_password_or_retry(self):
        for reply, error in (
            (Response(401, PASSWORD), "dynv6_login_rejected"),
            (Response(302, headers={"Location": "https://other.test/"}), "dynv6_form_redirect_rejected"),
        ):
            client = self.client([Response(200, LOGIN), reply])
            with self.assertRaisesRegex(ProviderError, error) as caught:
                client.login(EMAIL, PASSWORD)
            self.assertNotIn(PASSWORD, str(caught.exception))
            self.assertEqual(len(self.requests), 2)

    def test_verification_or_changed_form_stops_before_submitting_password(self):
        for page, error in (
            (LOGIN + '<iframe src="https://captcha.example.test/">', "dynv6_login_verification_required"),
            (LOGIN.replace('name="user[password]"', 'name="different"'), "dynv6_login_contract_changed"),
        ):
            client = self.client([Response(200, page)])
            with self.assertRaisesRegex(ProviderError, error):
                client.login(EMAIL, PASSWORD)
            self.assertEqual(len(self.requests), 1)

    def test_rate_limit_preserves_delay_without_replaying_login(self):
        client = self.client([Response(200, LOGIN), Response(429, headers={"Retry-After": "900"})])
        with self.assertRaises(ProviderError) as caught:
            client.login(EMAIL, PASSWORD)
        self.assertEqual(caught.exception.code, "provider_http_429")
        self.assertEqual(caught.exception.retry_after, 900)
        self.assertFalse(caught.exception.uncertain)
        self.assertEqual(len(self.requests), 2)


if __name__ == "__main__":
    unittest.main()

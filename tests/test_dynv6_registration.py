import io
import json
import unittest
from unittest.mock import patch
import test_domain_control as base
from api.providers.dynv6_session import Dynv6Session, session_cookie
from api.providers.http import ProviderError
from api.repositories.domain_jobs import JobConflict

COOKIE = "fixture-session-cookie-must-never-be-public"


class SessionWire:
    def __init__(self):
        self.zones = [{"id": 100, "name": "anchor.test"}]
        self.calls, self.posts = [], 0
        self.failure = ""

    def request(self, method, url, path, **kwargs):
        self.calls.append((method, path))
        if method == "GET" and path == "/api/v2/zones":
            return list(self.zones)
        if method == "GET" and path.endswith("/records"):
            return []
        raise AssertionError((method, path))

    def session(self, cookie):
        wire = self
        class Client:
            def prepare(self, zones):
                if wire.failure == "expired":
                    raise ProviderError("dynv6_session_expired")
                if wire.failure == "mismatch":
                    raise ProviderError("dynv6_session_account_mismatch")
            def cookie(self):
                return cookie
            def register(self, name):
                wire.posts += 1
                if wire.failure == "rate":
                    raise ProviderError("provider_http_429", uncertain=True, retry_after=900)
                if wire.failure != "timeout_before_commit":
                    wire.zones.append({"id": 101, "name": name})
                if wire.failure.startswith("timeout"):
                    raise ProviderError("dynv6_session_transport_error", uncertain=True)
                return {"domain_id": "501"}
        return Client()


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.case = base.P2Tests(methodName="runTest")
        self.case.setUp()
        self.m, self.client = self.case.manager, self.case.client
        self.case.domain(enabled=False, dns_provider="digitalplat", max_subdomain_depth=6)
        self.wire = SessionWire()
        self.m.http = self.wire
        self.service = self.m.dynv6_registration
        self.service.session_factory = self.wire.session
        self.ref = self.m.add_dns_credential("dynv6", None, "fixture", {"api_token": base.TOKEN})["id"]
        self.service.save_session(self.ref, COOKIE)

    def tearDown(self):
        self.case.tearDown()

    def enqueue(self, key="fixture-register-key"):
        return self.service.enqueue("example.test", key, self.ref)

    def execute(self, key="fixture-register-key"):
        job = self.enqueue(key)
        self.m.run_once()
        return self.m.jobs.get(job["id"])

    def test_session_encryption_public_redaction_and_bad_validation(self):
        response = self.client.get("/api/v1/dns-credentials", headers=self.case.headers)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(COOKIE, response.text)
        self.assertNotIn(base.TOKEN, response.text)
        self.assertEqual(response.json()["items"][0]["session"]["status"], "valid")
        c = self.m.db()
        try:
            self.assertNotIn(COOKIE, c.execute("SELECT ciphertext FROM dns_credentials WHERE id=?", (self.ref,)).fetchone()[0])
        finally:
            c.close()
        response = self.client.put("/api/v1/dns-credentials/" + self.ref + "/dynv6-session",
                                   headers=self.case.headers, json={"cookie": {"secret": COOKIE}})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(COOKIE, response.text)

    def test_create_bind_and_depth_one_once(self):
        result = self.execute()
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(self.wire.posts, 1)
        self.assertTrue(result["result"]["bound"])
        row = self.m.domain("example.test")
        self.assertEqual((row["dns_provider"], row["dns_credential_ref"], row["max_subdomain_depth"]), ("dynv6", self.ref, 1))
        self.assertFalse(row["enabled"])
        self.assertNotIn(COOKIE, json.dumps(result))
        self.assertEqual(self.enqueue()["id"], result["id"])
        self.assertFalse(self.m.run_once())
        self.assertEqual(self.wire.posts, 1)

    def test_domain_scoped_session_can_be_saved_without_expanding_credential_scope(self):
        ref = self.m.add_dns_credential("dynv6", "example.test", "scoped fixture",
                                        {"api_token": base.TOKEN})["id"]
        saved = self.service.save_session(ref, COOKIE)
        self.assertEqual(saved["status"], "valid")
        self.assertEqual(self.service.check_session(ref)["status"], "valid")
        self.assertEqual(self.service.secret(ref, "example.test")["session_cookie"], COOKIE)
        with self.assertRaisesRegex(ValueError, "credential domain mismatch"):
            self.service.secret(ref, "other.test")
        self.assertEqual(self.wire.posts, 0)

    def test_existing_exact_zone_skips_session_and_never_creates(self):
        self.wire.zones.append({"id": 101, "name": "example.test"})
        self.wire.failure = "expired"
        result = self.execute()
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["result"]["already_registered"])
        self.assertEqual(self.wire.posts, 0)

    def test_parent_zone_does_not_count_as_custom_domain_registration(self):
        self.case.domain(enabled=False, domain="child.example.test", dns_provider="manual")
        self.wire.zones.append({"id": 102, "name": "example.test"})
        job = self.service.enqueue("child.example.test", "fixture-child-key", self.ref)
        self.m.run_once()
        self.assertEqual(self.m.jobs.get(job["id"])["status"], "succeeded")
        self.assertEqual(self.wire.posts, 1)

    def test_commit_then_timeout_is_observed_and_binding_can_complete(self):
        self.wire.failure = "timeout_after_commit"
        first = self.execute()
        self.assertEqual(first["status"], "partial")
        self.assertEqual(first["result"]["registration_status"], "registered")
        second = self.execute("fixture-after-timeout")
        self.assertEqual(second["status"], "succeeded")
        self.assertEqual(self.wire.posts, 1)

    def test_unknown_without_zone_is_never_replayed_even_with_new_key(self):
        self.wire.failure = "timeout_before_commit"
        self.assertEqual(self.execute()["status"], "unknown")
        again = self.execute("fixture-new-request")
        self.assertEqual(again["status"], "unknown")
        self.assertEqual(again["error_code"], "dynv6_registration_unconfirmed")
        self.assertEqual(self.wire.posts, 1)

    def test_restart_does_not_replay_a_dispatched_registration(self):
        job = self.enqueue()
        running = self.m.jobs.take()
        self.m.jobs.progress(running["id"], step="dynv6_register_dispatched",
                             result={"registration_dispatched": True})
        self.m.jobs.recover_interrupted()
        self.assertEqual(self.m.jobs.get(job["id"])["status"], "unknown")
        self.assertEqual(self.execute("fixture-after-restart")["status"], "unknown")
        self.assertEqual(self.wire.posts, 0)

    def test_readback_resolves_interrupted_post_without_another_submission(self):
        job = self.enqueue()
        running = self.m.jobs.take()
        self.m.jobs.progress(running["id"], step="dynv6_register_dispatched",
                             result={"registration_dispatched": True})
        self.m.jobs.recover_interrupted()
        self.wire.zones.append({"id": 101, "name": "example.test"})
        self.assertEqual(self.execute("fixture-reconcile-restart")["status"], "succeeded")
        self.assertEqual(self.wire.posts, 0)

    def test_session_expiry_fails_before_write_and_is_publicly_visible(self):
        self.wire.failure = "expired"
        result = self.execute()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "dynv6_session_expired")
        self.assertEqual(self.wire.posts, 0)
        self.assertEqual(self.service.credentials()[0]["session"]["status"], "expired")
        self.wire.failure = ""
        self.service.save_session(self.ref, COOKIE)
        self.assertEqual(self.execute("fixture-refreshed-cookie")["status"], "succeeded")

    def test_mismatched_cookie_account_does_not_write(self):
        self.wire.failure = "mismatch"
        self.assertEqual(self.execute()["error_code"], "dynv6_session_account_mismatch")
        self.assertEqual(self.wire.posts, 0)

    def test_enabled_domain_rejected_and_running_domain_configuration_locked(self):
        job = self.enqueue()
        running = self.m.jobs.take()
        self.assertEqual(running["id"], job["id"])
        self.assertEqual(self.enqueue()["id"], job["id"])
        with self.assertRaises(JobConflict):
            self.m.bind_dns_credential("example.test", self.ref)
        self.m.jobs.finish(job["id"], "failed", step="fixture_finished")
        row = self.m.domain("example.test")
        c = self.m.db()
        with c:
            c.execute("UPDATE mail_domains SET enabled=1 WHERE domain=?", (row["domain"],))
        c.close()
        with self.assertRaises(ValueError):
            self.enqueue("fixture-enabled-domain")

    def test_rate_limit_fences_registration_on_old_provider(self):
        self.wire.failure = "rate"
        result = self.execute()
        self.assertEqual(result["result"]["provider_backoff"]["provider"], "dynv6")
        self.assertEqual(self.m.domain("example.test")["dns_provider"], "digitalplat")
        queued = self.enqueue("fixture-after-rate-limit")
        self.assertIsNone(self.m.jobs.take())
        self.assertEqual(self.m.jobs.get(queued["id"])["wait_reason"], "provider_cooldown")

    def test_registration_post_shares_the_dns_write_gate(self):
        from concurrent.futures import ThreadPoolExecutor
        client = self.wire.session(COOKIE)
        register = client.register
        def guarded(name):
            def other_thread_can_write():
                acquired = self.m.lock.acquire(blocking=False)
                if acquired:
                    self.m.lock.release()
                return acquired
            with ThreadPoolExecutor(max_workers=1) as pool:
                self.assertFalse(pool.submit(other_thread_can_write).result(timeout=3))
            return register(name)
        client.register = guarded
        with patch.object(self.service, "session_factory", return_value=client):
            self.assertEqual(self.execute()["status"], "succeeded")
        self.assertEqual(self.wire.posts, 1)

    def test_registration_429_is_persisted_before_releasing_write_gate(self):
        self.wire.failure = "rate"
        store = self.service.store_session
        observed = []
        def save(ref, secret, cookie, status, **kw):
            if self.wire.posts:
                with self.assertRaises(ProviderError) as caught:
                    self.m.jobs.check_provider_backoff("dynv6")
                observed.append(caught.exception.code)
            return store(ref, secret, cookie, status, **kw)
        with patch.object(self.service, "store_session", side_effect=save):
            result = self.execute()
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(observed, ["provider_http_429"])
        self.assertEqual(self.wire.posts, 1)

    def test_batch_dedup_and_partial_errors_and_administrator_boundary(self):
        url = "/api/v1/dynv6/registrations"
        body = {"credential_ref": self.ref, "domains": ["example.test", "example.test", "missing.test"]}
        self.assertEqual(self.client.post(url, json=body).status_code, 401)
        headers = {**self.case.headers, "Idempotency-Key": "fixture-batch-key"}
        first = self.client.post(url, headers=headers, json=body)
        self.assertEqual(first.status_code, 202, first.text)
        self.assertEqual(len(first.json()["items"]), 1)
        self.assertEqual(len(first.json()["errors"]), 1)
        second = self.client.post(url, headers=headers, json=body)
        self.assertEqual(first.json()["items"][0]["id"], second.json()["items"][0]["id"])
        self.assertNotIn(COOKIE, first.text)

    def test_rotation_compare_prevents_overwriting_a_new_session(self):
        old = self.service.secret(self.ref)
        self.service.save_session(self.ref, COOKIE + "-new")
        with self.assertRaisesRegex(ValueError, "session changed"):
            self.service.store_session(self.ref, old, COOKIE, "valid")


class Response(io.BytesIO):
    def __init__(self, code, text="", headers=None):
        super().__init__(text.encode())
        self.code, self.headers = code, headers or {}


class FormClientTests(unittest.TestCase):
    def client(self, replies):
        self.requests = []
        class Opener:
            def open(inner, request, timeout):
                self.requests.append(request)
                reply = replies.pop(0)
                if isinstance(reply, Exception):
                    raise reply
                return reply
        return Dynv6Session(COOKIE, opener=Opener())

    def prepared(self, extra):
        return self.client([
            Response(200, '<a href="/zones/100/records">anchor.test</a>'),
            Response(200, '<form id="new_domain" action="/domains" method="post">'
                     '<input name="authenticity_token" value="fixture-fresh-csrf">'
                     '<input name="domain[name]"><input name="commit"></form>'),
            *extra,
        ])

    def test_fresh_form_token_and_explicit_same_origin_redirect(self):
        client = self.prepared([Response(302, headers={"Location": "/domains/501"}),
                                Response(200, "Domain was successfully created.")])
        client.prepare([{"id": 100}])
        self.assertEqual(client.register("example.test")["domain_id"], "501")
        self.assertIn(b"fixture-fresh-csrf", self.requests[2].data)
        self.assertEqual(self.requests[2].get_header("Origin"), "https://dynv6.com")
        self.assertEqual(len(self.requests), 4)
        with self.assertRaises(ProviderError):
            client.register("second.test")

    def test_foreign_redirect_is_never_followed(self):
        client = self.prepared([Response(302, headers={"Location": "https://other.test/domains/1"})])
        client.prepare([{"id": 100}])
        with self.assertRaisesRegex(ProviderError, "dynv6_form_redirect_rejected"):
            client.register("example.test")
        self.assertEqual(len(self.requests), 3)

    def test_login_redirect_expiry_and_wrong_account(self):
        client = self.client([Response(302, headers={"Location": "/users/sign_in"})])
        with self.assertRaisesRegex(ProviderError, "dynv6_session_expired"):
            client.prepare([{"id": 100}])
        client = self.client([Response(200, '<a href="/zones/999">different.test</a>')])
        with self.assertRaisesRegex(ProviderError, "dynv6_session_account_mismatch"):
            client.prepare([{"id": 100}])

    def test_cookie_inputs_reject_redaction_foreign_context_and_header_injection(self):
        exported = json.dumps([{"name": "_dynv6_session", "domain": "dynv6.com", "value": COOKIE},
                               {"name": "remember_user_token", "domain": "dynv6.com", "value": "ignored"}])
        self.assertEqual(session_cookie(exported), COOKIE)
        self.assertEqual(session_cookie("_dynv6_session=" + COOKIE + "; consent=ignored"), COOKIE)
        for bad in ("[REDACTED]", COOKIE + "\r\nHeader: injected", exported.replace("dynv6.com", "other.test")):
            with self.assertRaises(ValueError):
                session_cookie(bad)


if __name__ == "__main__":
    unittest.main()

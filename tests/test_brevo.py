import unittest
from email.message import EmailMessage
import base64

from api.providers.brevo import BrevoAPI
from api.providers.http import ProviderError


class Transport:
    def __init__(self, payloads=None):
        self.calls = []
        self.payloads = list(payloads or [])

    def request(self, method, base, path, **kwargs):
        self.calls.append((method, base, path, kwargs))
        payload = self.payloads.pop(0) if self.payloads else {}
        if isinstance(payload, Exception):
            raise payload
        return payload


class BrevoAdapterTests(unittest.TestCase):
    def test_list_and_create_use_api_key_header(self):
        transport = Transport([
            {"domains": [{"domain_name": "example.com", "authenticated": True}]},
            {"id": "new-domain"},
        ])
        api = BrevoAPI(transport, "xkeysib-fixture")
        self.assertEqual(api.list_domains()[0]["domain_name"], "example.com")
        self.assertEqual(api.create_domain("sender.example.test")["id"], "new-domain")
        self.assertEqual(transport.calls[0][3]["headers"], {"api-key": "xkeysib-fixture"})
        self.assertEqual(transport.calls[1][2], "/v3/senders/domains")
        self.assertEqual(transport.calls[1][3]["body"], {"name": "sender.example.test"})

    def test_get_domain_is_case_and_trailing_dot_insensitive(self):
        transport = Transport([{"domain_name": "sender.example.test"}])
        self.assertIsNotNone(BrevoAPI(transport, "key").get_domain("sender.example.test."))

    def test_authenticate_domain_quotes_path(self):
        transport = Transport([{"ok": True}])
        BrevoAPI(transport, "key").authenticate_domain("sender.example.test")
        self.assertEqual(transport.calls[0][0], "PUT")
        self.assertEqual(transport.calls[0][2], "/v3/senders/domains/sender.example.test/authenticate")
        self.assertNotIn("body", transport.calls[0][3])

    def test_invalid_domain_response_fails_closed(self):
        with self.assertRaises(ValueError):
            BrevoAPI(Transport([{"result": []}]), "key").list_domains()

    def test_send_transactional_maps_rfc822_to_brevo_payload(self):
        transport = Transport([{"messageId": "fixture-message"}])
        message = EmailMessage()
        message["From"] = "sender@example.test"
        message["To"] = "one@outside.test"
        message["Reply-To"] = "reply@example.test"
        message["Subject"] = "fixture"
        message.set_content("plain body")
        message.add_alternative("<p>html body</p>", subtype="html")
        message.add_attachment(b"hello", maintype="text", subtype="plain", filename="a.txt")

        result = BrevoAPI(transport, "key").send_transactional(
            message.as_bytes(), ["one@outside.test"]
        )
        self.assertEqual(result["messageId"], "fixture-message")
        method, base, path, kwargs = transport.calls[0]
        self.assertEqual((method, path), ("POST", "/v3/smtp/email"))
        self.assertEqual(kwargs["headers"], {"api-key": "key"})
        body = kwargs["body"]
        self.assertEqual(body["sender"], {"email": "sender@example.test"})
        self.assertEqual(body["to"], [{"email": "one@outside.test"}])
        self.assertEqual(body["replyTo"], {"email": "reply@example.test"})
        self.assertIn("plain body", body["textContent"])
        self.assertIn("html body", body["htmlContent"])
        self.assertEqual(body["attachment"][0]["name"], "a.txt")
        self.assertEqual(base64.b64decode(body["attachment"][0]["content"]), b"hello")


if __name__ == "__main__":
    unittest.main()

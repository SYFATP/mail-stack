"""Offline checks for provider service identity and header preservation."""
import io
import unittest
import urllib.error
from unittest.mock import patch

from api.providers.http import JsonTransport, ProviderError, retry_after_seconds, rate_limit_metadata


class ProviderHeaderTests(unittest.TestCase):
    def test_rate_limit_diagnostics_exclude_raw_message_and_use_body_delay(self):
        transport = JsonTransport()
        error = urllib.error.HTTPError(
            "https://provider.example", 429, "Too Many Requests", {},
            io.BytesIO(b'{"error":{"code":"dns_write_rate_limit","message":"Daily limit; fixture-secret","retry_after":1800}}'))
        with patch.object(transport.opener, "open", side_effect=error):
            with self.assertRaises(ProviderError) as caught:
                transport.request("POST", "https://provider.example", "/records", body={})
        self.assertEqual(caught.exception.retry_after, 1800)
        self.assertEqual(caught.exception.rate_limit, {"code": "dns_write_rate_limit", "window": "day", "retry_after": 1800})
        self.assertNotIn("fixture-secret", str(caught.exception.rate_limit))

    def test_rate_limit_diagnostics_reject_noncode_and_invalid_payload(self):
        for raw in (b"not-json", b'{"error":{"code":"Bearer fixture-secret","message":"private"}}'):
            self.assertEqual(rate_limit_metadata(raw), {"code": "", "window": "", "retry_after": 0})

    def test_only_allowlisted_missing_hosting_reason_is_retained(self):
        for code in ("hosted_dns_zone_not_found", "fixture-secret-must-not-leak"):
            body = ('{"error":{"code":"' + code + '","message":"fixture-secret-must-not-leak"}}').encode()
            error = urllib.error.HTTPError(
                "https://provider.example", 404, "Not Found", {}, io.BytesIO(body))
            transport = JsonTransport()
            with patch.object(transport.opener, "open", side_effect=error):
                with self.assertRaises(ProviderError) as caught:
                    transport.request("GET", "https://provider.example", "/records")
            self.assertEqual(caught.exception.upstream_code,
                             code if code == "hosted_dns_zone_not_found" else "")
            self.assertNotIn("fixture-secret-must-not-leak", str(caught.exception))

    def test_rate_limit_retains_numeric_retry_delay_without_replaying(self):
        transport = JsonTransport()
        error = urllib.error.HTTPError("https://provider.example", 429, "Too Many Requests",
                                       {"Retry-After": "900"}, io.BytesIO(b"fixture-secret"))
        with patch.object(transport.opener, "open", side_effect=error) as send:
            with self.assertRaises(ProviderError) as caught:
                transport.request("POST", "https://provider.example", "/records", body={})
        self.assertEqual(send.call_count, 1)
        self.assertTrue(caught.exception.uncertain)
        self.assertEqual(caught.exception.retry_after, 900)
        self.assertNotIn("fixture-secret", str(caught.exception))

    def test_retry_after_date_invalid_and_extreme_values_are_bounded(self):
        self.assertEqual(retry_after_seconds("Thu, 01 Jan 1970 00:20:00 GMT", now=1000), 200)
        self.assertEqual(retry_after_seconds("fixture-secret"), 0)
        self.assertEqual(retry_after_seconds("-20"), 0)
        self.assertEqual(retry_after_seconds("999999999999"), 604800)

    def test_rate_limit_without_retry_after_preserves_unknown_write(self):
        transport = JsonTransport()
        error = urllib.error.HTTPError("https://provider.example", 429, "Too Many Requests", None, io.BytesIO(b"private"))
        with patch.object(transport.opener, "open", side_effect=error):
            with self.assertRaises(ProviderError) as caught:
                transport.request("PATCH", "https://provider.example", "/records", body={})
        self.assertEqual(caught.exception.retry_after, 0)
        self.assertTrue(caught.exception.uncertain)

    def test_explicit_service_user_agent_preserves_authentication(self):
        transport = JsonTransport()
        with patch.object(transport.opener, "open", return_value=io.BytesIO(b'{"ok":true}')) as send:
            result = transport.request(
                "POST", "https://provider.example", "/records",
                headers={"Authorization": "Bearer fixture-token", "Idempotency-Key": "fixture-key"},
                body={"type": "TXT"},
            )
        request = send.call_args.args[0]
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertTrue(result["ok"])
        self.assertEqual(headers["user-agent"], "mail-stack-provider/1.0")
        self.assertEqual(headers["authorization"], "Bearer fixture-token")
        self.assertEqual(headers["idempotency-key"], "fixture-key")
        self.assertEqual(headers["content-type"], "application/json")

    def test_provider_specific_user_agent_can_override_default(self):
        transport = JsonTransport()
        with patch.object(transport.opener, "open", return_value=io.BytesIO(b'{"ok":true}')) as send:
            transport.request("GET", "https://provider.example", "/records",
                              headers={"User-Agent": "fixture-provider/2.0"})
        headers = {key.lower(): value for key, value in send.call_args.args[0].header_items()}
        self.assertEqual(headers["user-agent"], "fixture-provider/2.0")


if __name__ == "__main__":
    unittest.main()

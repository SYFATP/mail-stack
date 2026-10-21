import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from api.services.dns_records import select_record
from test_domain_routing import app
from fastapi import HTTPException


class CoreFixTests(unittest.TestCase):
    def test_dns_txt_selection_does_not_overwrite_verification(self):
        verification = {"id": "verify", "content": "service-verification=abc"}
        spf = {"id": "spf", "content": "v=spf1 -all"}
        wanted = {"type": "TXT", "content": "v=spf1 ip4:203.0.113.10 -all"}
        self.assertIsNone(select_record([verification], wanted))
        self.assertEqual(select_record([verification, spf], wanted)["id"], "spf")
        with self.assertRaises(ValueError):
            select_record([spf, {"content": "v=spf1 ~all"}], wanted)

    def test_empty_bootstrap_rejected_and_hash_supported(self):
        with patch.object(app, "setting_get", return_value=None), patch.dict(os.environ, {"ADMIN_PASSWORD": "", "ADMIN_PASSWORD_HASH": ""}):
            self.assertFalse(app.password_matches(""))
            self.assertFalse(app.password_matches("anything"))
            os.environ["ADMIN_PASSWORD_HASH"] = app.password_hash("correct")
            self.assertTrue(app.password_matches("correct"))
            self.assertFalse(app.password_matches("wrong"))
            from passlib.hash import argon2
            os.environ["ADMIN_PASSWORD_HASH"] = argon2.hash("correct")
            self.assertTrue(app.password_matches("correct"))

    def test_missing_dkim_never_submits_unsigned(self):
        item = app.OutboundMessage(sender="u@example.test", recipients=["x@outside.test"], subject="test", text="body")
        with tempfile.TemporaryDirectory() as temp, patch.object(app, "key_has_project_scope", return_value=True),              patch.object(app, "configured_domains", return_value=["example.test"]),              patch.object(app, "_domain_rows", return_value=[{"domain": "example.test", "dkim_selector": "default"}]),              patch.object(app, "Path", return_value=Path(temp)), patch.object(app.smtplib, "SMTP") as smtp:
            with self.assertRaises(HTTPException) as error:
                app.send_message(item, "key")
            self.assertEqual(error.exception.status_code, 409)
            smtp.assert_not_called()

    def test_partial_smtp_refusal_is_not_success(self):
        item = app.OutboundMessage(sender="u@example.test", recipients=["one@outside.test", "two@outside.test"], subject="test", text="body")
        key = MagicMock()
        key.exists.return_value = True
        key.read_bytes.return_value = b"test-only-key"
        key.__truediv__.return_value = key
        with patch.object(app, "key_has_project_scope", return_value=True), patch.object(app, "configured_domains", return_value=["example.test"]),              patch.object(app, "_domain_rows", return_value=[{"domain": "example.test"}]), patch.object(app, "Path", return_value=key),              patch.object(app.dkim, "sign", return_value=b"DKIM-Signature: test\r\n"), patch.object(app.smtplib, "SMTP") as smtp:
            smtp.return_value.__enter__.return_value.sendmail.return_value = {"two@outside.test": (550, b"rejected")}
            result = app.send_message(item, "key")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["accepted"], ["one@outside.test"])
        self.assertEqual(result["rejected"]["two@outside.test"]["code"], 550)


if __name__ == "__main__":
    unittest.main()

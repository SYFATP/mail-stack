"""Brevo domain and sender API adapter.

The adapter deliberately contains no DNS writes.  Brevo returns the DNS
verification records; mail-stack's existing DNS preview/apply pipeline remains
the only path that changes Cloudflare or DigitalPlat.
"""
from __future__ import annotations

import base64
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from urllib.parse import quote

from api.providers.http import validate_base_url


class BrevoAPI:
    def __init__(self, transport, api_key: str, base_url: str = "https://api.brevo.com"):
        if not isinstance(api_key, str) or not api_key or "\r" in api_key or "\n" in api_key:
            raise ValueError("Brevo API key is not configured")
        self.http = transport
        self.base = validate_base_url(base_url)
        self.headers = {"api-key": api_key}

    def list_domains(self):
        payload = self.http.request("GET", self.base, "/v3/senders/domains", headers=self.headers)
        domains = payload.get("domains") if isinstance(payload, dict) else None
        if not isinstance(domains, list):
            raise ValueError("invalid Brevo domains response")
        return domains

    def get_domain(self, domain: str):
        wanted = domain.rstrip(".").lower()
        path = "/v3/senders/domains/" + quote(wanted, safe="")
        try:
            payload = self.http.request("GET", self.base, path, headers=self.headers)
        except Exception as exc:
            # A missing domain is the only normal reason for the configuration
            # endpoint to return 404. Preserve the transport/provider error for
            # every other failure.
            if getattr(exc, "code", "") != "provider_http_404":
                raise
            return None
        return payload if isinstance(payload, dict) else {"result": payload}

    def create_domain(self, domain: str):
        payload = self.http.request(
            "POST",
            self.base,
            "/v3/senders/domains",
            headers=self.headers,
            body={"name": domain.rstrip(".").lower()},
        )
        return payload if isinstance(payload, dict) else {"result": payload}

    def authenticate_domain(self, domain: str):
        path = "/v3/senders/domains/" + quote(domain.rstrip(".").lower(), safe="") + "/authenticate"
        payload = self.http.request("PUT", self.base, path, headers=self.headers)
        return payload if isinstance(payload, dict) else {"result": payload}

    def send_transactional(self, raw_message: bytes, envelope_recipients: list[str] | None = None):
        """Submit an RFC822 message through Brevo's transactional API.

        The queue keeps the original RFC822 bytes for SMTP delivery.  For the
        explicit fallback path, Brevo expects structured JSON, so parse the
        already validated message and preserve text/html alternatives,
        Reply-To, and attachments without exposing the API key to callers.
        """
        message = BytesParser(policy=policy.default).parsebytes(raw_message)
        sender = parseaddr(str(message.get("From") or ""))[1].strip().lower()
        recipients = [str(value).strip().lower() for value in (envelope_recipients or []) if str(value).strip()]
        if not sender or not recipients:
            raise ValueError("transactional message is missing sender or recipients")

        body = {
            "sender": {"email": sender},
            "to": [{"email": address} for address in recipients],
            "subject": str(message.get("Subject") or ""),
        }
        reply_to = parseaddr(str(message.get("Reply-To") or ""))[1].strip().lower()
        if reply_to:
            body["replyTo"] = {"email": reply_to}

        plain = message.get_body(preferencelist=("plain",))
        html = message.get_body(preferencelist=("html",))
        if plain is not None:
            body["textContent"] = plain.get_content()
        if html is not None:
            body["htmlContent"] = html.get_content()

        attachments = []
        for part in message.iter_attachments():
            blob = part.get_payload(decode=True)
            if blob is None:
                continue
            name = part.get_filename() or "attachment"
            attachments.append({
                "name": name,
                "content": base64.b64encode(blob).decode("ascii"),
            })
        if attachments:
            body["attachment"] = attachments

        payload = self.http.request(
            "POST",
            self.base,
            "/v3/smtp/email",
            headers=self.headers,
            body=body,
        )
        return payload if isinstance(payload, dict) else {"result": payload}

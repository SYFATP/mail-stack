"""Small JSON transport: bounded responses, no redirects or implicit retries."""
from __future__ import annotations
import ipaddress
import math
import time
from email.utils import parsedate_to_datetime
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request


def retry_after_seconds(value, *, now=None):
    """Retain only a bounded delay, never arbitrary response header text."""
    try:
        text = str(value or "").strip()
        if text.isdigit():
            delay = int(text)
        else:
            stamp = parsedate_to_datetime(text)
            if stamp.tzinfo is None:
                return 0
            delay = math.ceil(stamp.timestamp() - (time.time() if now is None else now))
        return min(604800, max(0, delay))
    except (TypeError, ValueError, OverflowError):
        return 0


def rate_limit_metadata(raw):
    """Extract only bounded diagnostic codes and categorical window hints."""
    try:
        payload = json.loads(raw)
        error = payload.get("error", {}) if isinstance(payload, dict) else {}
        source = error if isinstance(error, dict) else payload
        code = str(source.get("code") or "")
        if not (re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code)
                and any(word in code for word in ("rate", "limit", "quota"))):
            code = ""
        message = str(source.get("message") or (error if isinstance(error, str) else "")).lower()
        window = next((label for label, pattern in (
            ("day", r"\bdaily\b|\bper day\b|\b24 hours\b"),
            ("hour", r"\bhourly\b|\bper hour\b"),
            ("minute", r"\bper minute\b"),
        ) if re.search(pattern, message)), "")
        delay = source.get("retry_after", source.get("retryAfter", 0))
        return {"code": code, "window": window,
                "retry_after": retry_after_seconds(delay)}
    except (TypeError, ValueError, AttributeError):
        return {"code": "", "window": "", "retry_after": 0}


class ProviderError(RuntimeError):
    def __init__(self, code, *, uncertain=False, upstream_code="", retry_after=0, rate_limit=None,
                 provider_backoff=None):
        self.code = code
        self.uncertain = uncertain
        self.retry_after = retry_after_seconds(retry_after)
        self.rate_limit = rate_limit or {}
        # Only the local write fence supplies an existing absolute cooldown.
        self.provider_backoff = provider_backoff
        # Only this explicit provider state may authorize Hosted DNS setup.
        # Never retain arbitrary upstream errors/messages or response bodies.
        self.upstream_code = upstream_code if upstream_code == "hosted_dns_zone_not_found" else ""
        super().__init__(code)  # Never include upstream body, URL, token or traceback text.


def validate_base_url(value):
    parsed = urllib.parse.urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
        raise ValueError("invalid provider base URL")
    if parsed.scheme != "https":
        local = parsed.hostname == "localhost"
        try:
            local = local or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            pass
        if parsed.scheme != "http" or not local or os.getenv("ALLOW_LOCAL_PROVIDER_HTTP") != "1":
            raise ValueError("provider base URL requires HTTPS")
    return value.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class JsonTransport:
    def __init__(self, timeout=20):
        self.timeout = timeout
        self.opener = urllib.request.build_opener(_NoRedirect())

    def request(self, method, base, path, *, headers=None, body=None, query=None):
        base = validate_base_url(base)
        if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
            raise ValueError("invalid provider API path")
        url = base + path + (("?" + urllib.parse.urlencode(query)) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        # DigitalPlat's edge rejects Python's default urllib signature with
        # Cloudflare 1010. Use an explicit service UA for all provider calls;
        # callers can still override it for a provider-specific contract.
        request_headers = {"Accept": "application/json", "User-Agent": "mail-stack-provider/1.0", **(headers or {})}
        if data is not None:
            request_headers["Content-Type"] = "application/json"
        try:
            request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(3 * 1024 * 1024 + 1)
                if len(raw) > 3 * 1024 * 1024:
                    raise ProviderError("provider_response_too_large", uncertain=True)
            payload = json.loads(raw)
        except urllib.error.HTTPError as exc:
            # 5xx, rate limit and unusual responses may follow committed side effects.
            code = exc.code
            retry_after = retry_after_seconds((exc.headers or {}).get("Retry-After")) if code == 429 else 0
            rate_limit = {}
            if code == 429:
                rate_limit = rate_limit_metadata(exc.read(32768))
                retry_after = retry_after or rate_limit["retry_after"]
            upstream_code = ""
            if code == 404:
                try:
                    error = json.loads(exc.read(32768)).get("error", {})
                    if isinstance(error, dict) and error.get("code") == "hosted_dns_zone_not_found":
                        upstream_code = "hosted_dns_zone_not_found"
                except Exception:
                    pass
            exc.close()
            raise ProviderError(f"provider_http_{code}", uncertain=code not in {400, 401, 403, 404, 405, 422},
                                upstream_code=upstream_code, retry_after=retry_after,
                                rate_limit=rate_limit) from None
        except ProviderError:
            raise
        except Exception:
            raise ProviderError("provider_transport_or_json_error", uncertain=True) from None
        if isinstance(payload, dict) and (payload.get("ok") is False or payload.get("success") is False):
            raise ProviderError("provider_rejected", uncertain=True)
        return payload

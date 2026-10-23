"""Small JSON transport: bounded responses, no redirects or implicit retries."""
from __future__ import annotations
import ipaddress
import http.client
import math
import threading
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
        # Only allowlisted codes authorize Hosted DNS setup or NS precheck confirmation.
        # Never retain arbitrary upstream errors/messages or response bodies.
        self.upstream_code = upstream_code if upstream_code in {"hosted_dns_zone_not_found", "external_nameserver_precheck_failed"} else ""
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


class _KeepAliveHTTPS(urllib.request.HTTPSHandler):
    """Bounded idle connections; never replay a request after a socket failure."""

    hosts = frozenset({"dynv6.com", "domain-api.digitalplat.org",
                       "api.cloudflare.com", "api.brevo.com"})

    def __init__(self):
        super().__init__()
        self._idle = []
        self._lock = threading.Lock()

    def https_open(self, req):
        # Preserve urllib's proxy handling and the transport for custom origins.
        if req.host not in self.hosts or req._tunnel_host:
            return super().https_open(req)
        connection = None
        now = time.monotonic()
        with self._lock:
            retained = []
            for host, stamp, candidate in self._idle:
                if now - stamp > 4:
                    candidate.close()
                elif host == req.host and connection is None:
                    connection = candidate
                else:
                    retained.append((host, stamp, candidate))
            self._idle = retained
        if connection is None:
            connection = http.client.HTTPSConnection(
                req.host, timeout=req.timeout, context=self._context)
        connection.timeout = req.timeout
        if connection.sock is not None:
            connection.sock.settimeout(req.timeout)
        headers = {**req.headers, **req.unredirected_hdrs}
        headers.setdefault("Connection", "keep-alive")
        try:
            connection.request(req.get_method(), req.selector, req.data, headers,
                               encode_chunked=req.has_header("Transfer-encoding"))
            response = connection.getresponse()
        except Exception:
            connection.close()
            raise
        response.url, response.msg = req.get_full_url(), response.reason
        original_close, released = response.close, False

        def close():
            nonlocal released
            if released:
                return
            released = True
            # A truncated/oversized/error response must never contaminate the
            # next request. Only completely consumed responses return to pool.
            reusable = response.isclosed() and not response.will_close and connection.sock is not None
            original_close()
            if not reusable:
                connection.close()
                return
            with self._lock:
                self._idle.append((req.host, time.monotonic(), connection))
                while len(self._idle) > 8:
                    self._idle.pop(0)[2].close()

        response.close = close
        return response


class JsonTransport:
    def __init__(self, timeout=20):
        self.timeout = timeout
        self.opener = urllib.request.build_opener(_NoRedirect(), _KeepAliveHTTPS())

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
            cloudflare_code = ""
            if urllib.parse.urlsplit(base).hostname == "api.cloudflare.com" and code != 429:
                try:
                    codes = json.loads(exc.read(32768)).get("errors", [])
                    value = str(codes[0].get("code", "")) if codes else ""
                    if re.fullmatch(r"[0-9]{1,8}", value):
                        cloudflare_code = "cloudflare_error_" + value
                except Exception:
                    pass
            if code in {404, 409} and not cloudflare_code:
                try:
                    error = json.loads(exc.read(32768)).get("error", {})
                    allowed = {404: "hosted_dns_zone_not_found", 409: "external_nameserver_precheck_failed"}
                    if isinstance(error, dict) and error.get("code") == allowed[code]:
                        upstream_code = allowed[code]
                except Exception:
                    pass
            exc.close()
            raise ProviderError(cloudflare_code or f"provider_http_{code}", uncertain=code not in {400, 401, 403, 404, 405, 422} and upstream_code != "external_nameserver_precheck_failed",
                                upstream_code=upstream_code, retry_after=retry_after,
                                rate_limit=rate_limit) from None
        except ProviderError:
            raise
        except Exception:
            raise ProviderError("provider_transport_or_json_error", uncertain=True) from None
        if isinstance(payload, dict) and (payload.get("ok") is False or payload.get("success") is False):
            if urllib.parse.urlsplit(base).hostname == "api.cloudflare.com":
                errors = payload.get("errors") or []
                value = str(errors[0].get("code", "")) if errors and isinstance(errors[0], dict) else ""
                if re.fullmatch(r"[0-9]{1,8}", value):
                    raise ProviderError("cloudflare_error_" + value, uncertain=False)
            raise ProviderError("provider_rejected", uncertain=True)
        return payload

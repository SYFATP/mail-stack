"""Bounded dynv6 website form client; session values never enter public errors."""
import http.cookiejar
import json
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from api.providers.http import ProviderError, retry_after_seconds

BASE = "https://dynv6.com"


def session_cookie(value):
    """Accept a session value, Cookie header, or browser cookie export JSON."""
    if not isinstance(value, str) or not value or len(value) > 32768:
        raise ValueError("invalid dynv6 session cookie")
    value = value.strip()
    try:
        if value.startswith("["):
            cookies = json.loads(value)
            matches = [c for c in cookies if isinstance(c, dict) and c.get("name") == "_dynv6_session"]
            if len(matches) != 1 or matches[0].get("domain", "").lstrip(".") != "dynv6.com":
                raise ValueError()
            value = matches[0]["value"]
        elif value.startswith("_dynv6_session=") or ";" in value:
            matches = re.findall(r"(?:^|;\s*)_dynv6_session=([^;]*)", value)
            if len(matches) != 1:
                raise ValueError()
            value = matches[0]
        if (not isinstance(value, str) or not 16 <= len(value) <= 8192
                or not re.fullmatch(r"[A-Za-z0-9%+/_=.\-]+", value)
                or "redacted" in value.lower()):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise ValueError("invalid dynv6 session cookie") from None
    return value


class _Page(HTMLParser):
    def __init__(self, text, form_id="new_domain"):
        super().__init__()
        self.links, self.fields = set(), set()
        self.in_form = False
        self.action = self.method = self.csrf = None
        self.form_id, self.submit, self.challenge = form_id, "", False
        self.feed(text)

    def handle_starttag(self, tag, pairs):
        attrs = dict(pairs)
        if (tag == "iframe" and any(word in attrs.get("src", "").lower()
                                   for word in ("captcha", "turnstile"))) or (
                tag == "input" and any(word in attrs.get("name", "").lower()
                                      for word in ("otp", "captcha", "two_factor"))):
            self.challenge = True
        if tag == "a" and attrs.get("href"):
            self.links.add(urllib.parse.urlsplit(attrs["href"]).path)
        if tag == "form":
            self.in_form = attrs.get("id") == self.form_id
            if self.in_form:
                self.action, self.method = attrs.get("action"), attrs.get("method", "get")
        if tag == "input" and self.in_form and attrs.get("name"):
            self.fields.add(attrs["name"])
            if attrs["name"] == "authenticity_token":
                self.csrf = attrs.get("value")
            if attrs["name"] == "commit":
                self.submit = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.in_form = False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _KeysPage(HTMLParser):
    """Only HTTP Token collapse blocks; scope and secret are parsed separately."""
    def __init__(self, text):
        super().__init__()
        self.keys, self.current = [], None
        self.term = self.value = ""
        self.in_term = self.in_value = False
        self.feed(text)

    def handle_starttag(self, tag, pairs):
        attrs = dict(pairs)
        if tag == "b-collapse" and re.fullmatch(r"key_token_[1-9][0-9]*", attrs.get("id", "")):
            self.current = {"id": attrs["id"].rsplit("_", 1)[1], "token": "",
                            "scope": "", "zone_ids": []}
        if not self.current:
            return
        if tag == "dt":
            self.term, self.in_term = "", True
        if tag == "dd":
            self.value, self.in_value = "", True
        if tag == "a" and self.in_value and self.term.strip() == "Zone(s)":
            path = urllib.parse.urlsplit(attrs.get("href", "")).path
            match = re.fullmatch(r"/zones/([1-9][0-9]*)(?:/records)?", path)
            if match:
                self.current["zone_ids"].append(match[1])
        if tag == "key-data":
            try:
                value = json.loads(attrs.get(":k", ""))
                token = value["data"]
                if (str(value["id"]) != self.current["id"] or not isinstance(token, str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{16,512}", token)):
                    raise ValueError()
                self.current["token"] = token
            except (ValueError, KeyError, TypeError):
                raise ProviderError("dynv6_keys_contract_changed") from None

    def handle_data(self, text):
        if self.in_term:
            self.term += text
        if self.in_value:
            self.value += text

    def handle_endtag(self, tag):
        if tag == "dt":
            self.in_term = False
        if tag == "dd":
            self.in_value = False
            if self.current and self.term.strip() == "Zone(s)":
                self.current["scope"] = "all" if self.value.strip() == "all" else "zones"
        if tag == "b-collapse" and self.current:
            if not self.current["token"] or not self.current["scope"]:
                raise ProviderError("dynv6_keys_contract_changed")
            self.keys.append(self.current)
            self.current = None


class Dynv6Session:
    def __init__(self, cookie=None, *, timeout=20, opener=None):
        self.jar = http.cookiejar.CookieJar()
        if cookie is not None:
            self.jar.set_cookie(http.cookiejar.Cookie(
                0, "_dynv6_session", session_cookie(cookie), None, False,
                "dynv6.com", False, False, "/", True, True, None, True,
                None, None, {"HttpOnly": None}, False,
            ))
        self.opener = opener or urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect()
        )
        self.timeout, self.csrf = timeout, None

    def cookie(self):
        values = [c.value for c in self.jar if c.name == "_dynv6_session"
                  and c.domain.lstrip(".") == "dynv6.com" and not c.is_expired()]
        if len(values) != 1:
            raise ProviderError("dynv6_session_expired")
        return session_cookie(values[0])

    def _send(self, method, path, fields=None):
        if not re.fullmatch(r"/(?:domains(?:/new|/[1-9][0-9]*)?|zones|keys|users/sign_in)?", path):
            raise ProviderError("dynv6_form_contract_changed")
        mutating = method == "POST" and path == "/domains"
        data = urllib.parse.urlencode(fields).encode() if fields is not None else None
        headers = {"Accept": "text/html,application/xhtml+xml", "User-Agent": "mail-stack-dynv6/1.0"}
        if data is not None:
            headers.update({"Content-Type": "application/x-www-form-urlencoded",
                            "Origin": BASE, "Referer": BASE + (
                                "/users/sign_in" if path == "/users/sign_in" else "/domains/new")})
        try:
            req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
            try:
                response = self.opener.open(req, timeout=self.timeout)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                status = response.code
                location = response.headers.get("Location", "")
                raw = response.read(1024 * 1024 + 1)
                delay = retry_after_seconds(response.headers.get("Retry-After"))
            if len(raw) > 1024 * 1024:
                raise ProviderError("dynv6_form_response_too_large", uncertain=mutating)
            if path == "/users/sign_in" and status in (400, 401, 403, 422):
                raise ProviderError("dynv6_login_verification_required" if status == 403
                                    or _Page(raw.decode("utf-8", "replace"), "new_user").challenge
                                    else "dynv6_login_rejected")
            if status in (401, 403) or "/users/sign_in" in location:
                raise ProviderError("dynv6_session_expired", uncertain=mutating)
            if status == 429:
                raise ProviderError("provider_http_429", uncertain=mutating, retry_after=delay)
            if status >= 400:
                raise ProviderError("dynv6_form_rejected" if status in (400, 422) else "dynv6_form_upstream_error",
                                    uncertain=mutating and status not in (400, 422))
            if location:
                redirect = urllib.parse.urlsplit(urllib.parse.urljoin(BASE + path, location))
                if (redirect.scheme != "https" or redirect.netloc != "dynv6.com"
                        or redirect.query or redirect.fragment):
                    raise ProviderError("dynv6_form_redirect_rejected", uncertain=mutating)
                location = redirect.path
            return status, raw.decode("utf-8", "replace"), location
        except ProviderError:
            raise
        except Exception:
            raise ProviderError("dynv6_session_transport_error", uncertain=mutating) from None

    def login(self, email, password):
        status, text, location = self._send("GET", "/users/sign_in")
        form = _Page(text, "new_user")
        if form.challenge:
            raise ProviderError("dynv6_login_verification_required")
        required = {"authenticity_token", "user[email]", "user[password]", "commit"}
        if (status != 200 or location or not form.csrf or form.method != "post"
                or form.action not in ("/users/sign_in", BASE + "/users/sign_in")
                or not required <= form.fields
                or form.fields - required - {"user[remember_me]"}):
            raise ProviderError("dynv6_login_contract_changed")
        status, text, location = self._send("POST", "/users/sign_in", {
            "authenticity_token": form.csrf, "user[email]": email,
            "user[password]": password, "user[remember_me]": "0",
            "commit": form.submit or "Log in",
        })
        if _Page(text, "new_user").challenge:
            raise ProviderError("dynv6_login_verification_required")
        if status not in (302, 303) or location not in ("/", "/zones", "/domains", "/keys"):
            raise ProviderError("dynv6_login_rejected")
        return self.keys()

    def keys(self):
        status, text, location = self._send("GET", "/keys")
        if status != 200 or location:
            raise ProviderError("dynv6_session_expired")
        if "HTTP Tokens" not in text:
            raise ProviderError("dynv6_keys_contract_changed")
        keys = _KeysPage(text).keys
        if len(keys) > 1000 or len({k["id"] for k in keys}) != len(keys):
            raise ProviderError("dynv6_keys_contract_changed")
        return keys

    def prepare(self, zones, *, token=None):
        status, text, location = self._send("GET", "/zones")
        if status != 200 or location:
            raise ProviderError("dynv6_session_expired")
        linked = {m.group(1) for path in _Page(text).links
                  if (m := re.fullmatch(r"/zones/([1-9][0-9]*)(?:/records)?", path))}
        expected = {str(z["id"]) for z in zones}
        empty_verified = not expected and token and any(
            secrets.compare_digest(k["token"], token) for k in self.keys())
        if not empty_verified and (not expected or not (linked & expected)):
            raise ProviderError("dynv6_session_account_mismatch")
        status, text, location = self._send("GET", "/domains/new")
        form = _Page(text)
        if (status != 200 or location or not form.csrf or form.method != "post"
                or form.action not in ("/domains", BASE + "/domains")
                or form.fields != {"authenticity_token", "domain[name]", "commit"}):
            raise ProviderError("dynv6_form_contract_changed")
        self.csrf = form.csrf
        return {"status": "valid"}

    def register(self, domain):
        if not self.csrf:
            raise ProviderError("dynv6_form_not_prepared")
        csrf, self.csrf = self.csrf, None
        status, text, location = self._send("POST", "/domains", {
            "authenticity_token": csrf, "domain[name]": domain, "commit": "Add domain",
        })
        if status not in (302, 303) or not re.fullmatch(r"/domains/[1-9][0-9]*", location):
            raise ProviderError("dynv6_registration_unconfirmed", uncertain=True)
        domain_id = location.rsplit("/", 1)[1]
        status, text, redirected = self._send("GET", location)
        if status != 200 or redirected or "Domain was successfully created." not in text:
            raise ProviderError("dynv6_registration_unconfirmed", uncertain=True)
        return {"domain_id": domain_id}

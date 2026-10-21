"""HTTPS-only webhook delivery with DNS pinning and no redirects or proxies."""
from __future__ import annotations
import http.client
import ipaddress
import os
import socket
import ssl
import urllib.parse


class WebhookDeliveryError(ValueError):
    """Only categorical errors may reach logs or persistent delivery records."""


def _public_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return (address.is_global and not address.is_multicast
            and not address.is_reserved and not address.is_unspecified)


def validate_webhook_url(value):
    value = str(value)
    try:
        parsed = urllib.parse.urlsplit(value)
        host, port = parsed.hostname, parsed.port
        if (len(value) > 2048 or parsed.scheme != "https" or not host
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value)):
            raise ValueError()
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
        if "%" in host or host == "localhost" or host.endswith(".localhost"):
            raise ValueError()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or any(not label or len(label) > 63 for label in host.split(".")):
                raise ValueError()
        else:
            if not _public_address(str(address)):
                raise ValueError()
        allowed = {item.strip().lower().rstrip(".") for item in
                   os.getenv("WEBHOOK_ALLOWED_HOSTS", "").split(",") if item.strip()}
        if allowed and host not in allowed:
            raise ValueError()
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
        return parsed, host, port or 443
    except (ValueError, UnicodeError):
        raise WebhookDeliveryError("webhook_target_not_allowed") from None


def _resolve(host, port):
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise WebhookDeliveryError("webhook_dns_failed") from None
    # A mixed public/private answer is denied in its entirety.
    if not addresses or any(not _public_address(item[4][0]) for item in addresses):
        raise WebhookDeliveryError("webhook_target_not_allowed")
    return addresses


def _connect_pinned(addresses, timeout):
    for family, kind, protocol, _, sockaddr in addresses:
        stream = socket.socket(family, kind, protocol)
        try:
            stream.settimeout(timeout)
            stream.connect(sockaddr)
            return stream
        except OSError:
            stream.close()
    raise WebhookDeliveryError("webhook_connect_failed")


def send_webhook_request(request, *, timeout):
    parsed, host, port = validate_webhook_url(request.full_url)
    addresses = _resolve(host, port)
    connection = http.client.HTTPSConnection(host, port, timeout=timeout,
                                              context=ssl.create_default_context())
    # HTTPSConnection still verifies the certificate/SNI against the original
    # hostname. Its socket connects only to the already validated DNS answers.
    connection._create_connection = lambda address, timeout, source_address=None: _connect_pinned(addresses, timeout)
    try:
        target = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        connection.request("POST", target, body=request.data, headers=dict(request.header_items()))
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise WebhookDeliveryError(f"webhook_http_{response.status}")
        return response.status
    except WebhookDeliveryError:
        raise
    except Exception:
        raise WebhookDeliveryError("webhook_transport_failed") from None
    finally:
        connection.close()

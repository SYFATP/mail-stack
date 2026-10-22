"""Real HTTP/1.1 fixture: connection reuse, bounded reads and no write replay."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from api.providers.http import JsonTransport, ProviderError, _KeepAliveHTTPS


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.requests.append((self.command, self.path))
        if self.path == "/huge":
            body = b"x" * (3 * 1024 * 1024 + 1024)
        else:
            body = json.dumps({"auth": self.headers.get("Authorization"),
                               "path": self.path}).encode()
        status = 302 if self.path == "/redirect" else 429 if self.path == "/limit" else 200
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        if status == 302:
            self.send_header("Location", "/unexpected")
        if status == 429:
            self.send_header("Retry-After", "45")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/lost-ack":
            self.server.requests.append((self.command, self.path))
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        self.do_GET()


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.connections, self.requests = 0, []
        super().__init__(("127.0.0.1", 0), Handler)

    def get_request(self):
        connection, address = super().get_request()
        self.connections += 1
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # Deterministic fixture cost for opening a new upstream connection.
        time.sleep(0.01)
        return connection, address

    def handle_error(self, *args):
        pass  # A deliberately truncated response closes its fixture socket.


class ProviderKeepAliveTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        # Test transport framing over local HTTP, without a real provider or TLS.
        self.transport = JsonTransport(timeout=2)
        self.connection_patch = patch(
            "api.providers.http.http.client.HTTPSConnection",
            side_effect=lambda *a, **kw: http.client.HTTPConnection(
                "127.0.0.1", self.server.server_port, timeout=kw.get("timeout", 2)))
        self.connection_patch.start()
        self.addCleanup(self.connection_patch.stop)
        self.proxy_patch = patch.dict("os.environ", {"no_proxy": "dynv6.com"})
        self.proxy_patch.start()
        self.addCleanup(self.proxy_patch.stop)
        self.pool = next(h for h in self.transport.opener.handlers if isinstance(h, _KeepAliveHTTPS))
        self.addCleanup(lambda: [entry[2].close() for entry in self.pool._idle])

    def request(self, path="/records", method="GET", **kwargs):
        return self.transport.request(method, "https://dynv6.com", path, **kwargs)

    def test_many_records_reuse_one_connection_without_reusing_authentication(self):
        for index in range(40):
            self.assertEqual(self.request(headers={"Authorization": f"Bearer fixture-{index}"})["auth"],
                             f"Bearer fixture-{index}")
        self.assertEqual(self.server.connections, 1)
        self.assertEqual(len(self.server.requests), 40)

    def test_parallel_requests_never_share_an_inflight_socket(self):
        with ThreadPoolExecutor(max_workers=3) as workers:
            results = list(workers.map(
                lambda i: self.request(f"/record-{i}", headers={"Authorization": f"Bearer fixture-{i}"}),
                range(30)))
        for index, result in enumerate(results):
            self.assertEqual(result["path"], f"/record-{index}")
            self.assertEqual(result["auth"], f"Bearer fixture-{index}")
        self.assertLessEqual(self.server.connections, 3)
        self.assertEqual(len(self.server.requests), 30)

    def test_lost_ack_is_uncertain_and_never_retried(self):
        with self.assertRaises(ProviderError) as caught:
            self.request("/lost-ack", "POST", body={"value": "fixture"})
        self.assertTrue(caught.exception.uncertain)
        self.assertEqual(self.server.requests, [("POST", "/lost-ack")])
        self.assertEqual(self.request()["path"], "/records")
        self.assertEqual(self.server.connections, 2)

    def test_truncated_oversized_body_discards_connection(self):
        with self.assertRaises(ProviderError) as caught:
            self.request("/huge")
        self.assertEqual(caught.exception.code, "provider_response_too_large")
        self.assertEqual(self.request()["path"], "/records")
        self.assertEqual(self.server.connections, 2)

    def test_redirect_is_not_followed_and_rate_limit_does_not_replay_write(self):
        with self.assertRaises(ProviderError) as caught:
            self.request("/redirect")
        self.assertEqual(caught.exception.code, "provider_http_302")
        self.assertNotIn(("GET", "/unexpected"), self.server.requests)
        with self.assertRaises(ProviderError) as caught:
            self.request("/limit", "POST", body={})
        self.assertEqual(caught.exception.retry_after, 45)
        self.assertEqual(self.server.requests.count(("POST", "/limit")), 1)
        self.assertEqual(self.request()["path"], "/records")

    def test_expired_idle_connection_is_replaced_before_dispatch(self):
        self.request()
        self.pool._idle = [(host, stamp - 5, connection) for host, stamp, connection in self.pool._idle]
        self.request()
        self.assertEqual(self.server.connections, 2)

    def test_custom_origins_and_proxies_preserve_urllib_transport(self):
        req = __import__("urllib.request").request.Request("https://custom.fixture.test/records")
        with patch("urllib.request.HTTPSHandler.https_open", return_value="fixture") as fallback:
            self.assertEqual(self.pool.https_open(req), "fixture")
            fallback.assert_called_once()
        req = __import__("urllib.request").request.Request("https://dynv6.com/records")
        req._tunnel_host = "dynv6.com"
        with patch("urllib.request.HTTPSHandler.https_open", return_value="proxy-fixture") as fallback:
            self.assertEqual(self.pool.https_open(req), "proxy-fixture")
            fallback.assert_called_once()


if __name__ == "__main__":
    unittest.main()

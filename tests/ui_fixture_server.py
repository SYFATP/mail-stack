"""Serve workspace UI against isolated API on loopback, for browser QA only."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import urllib.request
import urllib.error

HTML = Path(__file__).resolve().parents[1] / 'frontend/index.html'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def handle_request(self):
        if not self.path.startswith('/api/v1/'):
            if self.command == 'GET' and self.path == '/':
                self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8'); self.end_headers(); self.wfile.write(HTML.read_bytes()); return
            self.send_response(404); self.end_headers(); return
        length = int(self.headers.get('Content-Length', '0'))
        if length > 32768:
            self.send_response(413); self.end_headers(); return
        body = self.rfile.read(length) if length else None
        headers = {key: self.headers[key] for key in ('Content-Type', 'X-API-Key', 'Idempotency-Key') if key in self.headers}
        req = urllib.request.Request('http://127.0.0.1:18091' + self.path, data=body, headers=headers, method=self.command)
        try:
            result = urllib.request.urlopen(req, timeout=30)
        except urllib.error.HTTPError as error:
            result = error
        with result:
            self.send_response(result.code)
            self.send_header('Content-Type', result.headers.get('Content-Type', 'application/json'))
            self.end_headers(); self.wfile.write(result.read())
    do_GET = handle_request
    do_POST = handle_request
    do_PATCH = handle_request
    do_DELETE = handle_request


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 18092), Handler).serve_forever()

#!/usr/bin/env python
"""RED-GREEN test for bounded_request response-size cap."""
import os
import sys
import threading
import socketserver
import http.server

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from core.http_utils import bounded_request

MAX_BYTES = 2 * 1024 * 1024  # must match the helper default used in the test


class _BigHandler(http.server.BaseHTTPRequestHandler):
    """Return a 5 MB body of 'A' characters."""

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('X-Custom', 'yes')
        self.end_headers()
        self.wfile.write(b'A' * (5 * 1024 * 1024))

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        self.do_GET()

    def log_message(self, *args):
        pass


def test_bounded_request_caps_response_size():
    with socketserver.TCPServer(('127.0.0.1', 0), _BigHandler) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            base = f'http://127.0.0.1:{port}'

            session = requests.Session()

            # GET via session
            resp = bounded_request('GET', f'{base}/get', session=session)
            assert resp.status_code == 200
            assert resp.headers.get('X-Custom') == 'yes'
            assert resp.url == f'{base}/get'
            assert len(resp.content) <= MAX_BYTES
            assert resp.text.startswith('A' * 1024)
            assert len(resp.text) <= MAX_BYTES

            # POST via session
            resp2 = bounded_request(
                'POST', f'{base}/post', session=session, data={'k': 'v'}
            )
            assert resp2.status_code == 200
            assert len(resp2.content) <= MAX_BYTES

            # GET without session (bare requests)
            resp3 = bounded_request('GET', f'{base}/bare')
            assert resp3.status_code == 200
            assert len(resp3.content) <= MAX_BYTES
        finally:
            srv.shutdown()

    print('ALL PASS')


if __name__ == '__main__':
    test_bounded_request_caps_response_size()

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))
TOKEN = os.environ.get("PZADA_TOKEN", "")
MAX_BODY = 2 * 1024 * 1024

_lock = threading.Lock()
_latest_state = None
_latest_received_at = None


def json_bytes(payload):
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "PzADA/0.1"

    def send_json(self, status, payload):
        body = json_bytes(payload)

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        self.wfile.write(body)

    def authorized(self):
        if not TOKEN:
            return True

        return self.headers.get("X-PzADA-Token", "") == TOKEN

    def do_GET(self):
        if self.path == "/":
            self.send_json(
                200,
                {
                    "ok": True,
                    "service": "PzADA relay",
                    "endpoints": ["/health", "/state"],
                },
            )
            return

        if self.path == "/health":
            with _lock:
                has_state = _latest_state is not None
                received_at = _latest_received_at

            self.send_json(
                200,
                {
                    "ok": True,
                    "service": "PzADA relay",
                    "has_state": has_state,
                    "received_at": received_at,
                },
            )
            return

        if self.path == "/state":
            with _lock:
                state = _latest_state
                received_at = _latest_received_at

            if state is None:
                self.send_json(
                    503,
                    {
                        "ok": False,
                        "error": "no_state_received",
                    },
                )
                return

            self.send_json(
                200,
                {
                    "ok": True,
                    "received_at": received_at,
                    "state": state,
                },
            )
            return

        self.send_json(
            404,
            {
                "ok": False,
                "error": "not_found",
            },
        )

    def do_POST(self):
        global _latest_state, _latest_received_at

        if self.path != "/state":
            self.send_json(
                404,
                {
                    "ok": False,
                    "error": "not_found",
                },
            )
            return

        if not self.authorized():
            self.send_json(
                401,
                {
                    "ok": False,
                    "error": "unauthorized",
                },
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(
                400,
                {
                    "ok": False,
                    "error": "invalid_content_length",
                },
            )
            return

        if length <= 0:
            self.send_json(
                400,
                {
                    "ok": False,
                    "error": "empty_body",
                },
            )
            return

        if length > MAX_BODY:
            self.send_json(
                413,
                {
                    "ok": False,
                    "error": "payload_too_large",
                },
            )
            return

        try:
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            self.send_json(
                400,
                {
                    "ok": False,
                    "error": "invalid_json",
                    "detail": str(exc),
                },
            )
            return

        with _lock:
            _latest_state = payload
            _latest_received_at = time.time()
            received_at = _latest_received_at

        self.send_json(
            200,
            {
                "ok": True,
                "stored": True,
                "received_at": received_at,
            },
        )

    def log_message(self, format, *args):
        print("[PzADA Relay] " + (format % args), flush=True)


if __name__ == "__main__":
    print(f"[PzADA Relay] listening on {HOST}:{PORT}", flush=True)

    server = ThreadingHTTPServer((HOST, PORT), Handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

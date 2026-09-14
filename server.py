from __future__ import annotations

import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))
TOKEN = os.environ.get("PZADA_TOKEN", "")
MAX_BODY = 2 * 1024 * 1024
MAX_CHAT_TEXT = 1000

_lock = threading.Lock()
_latest_state = None
_latest_received_at = None
_commands = []
_last_command_id = 0


def json_bytes(payload):
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def next_command_id():
    global _last_command_id

    now = int(time.time() * 1000)

    if now <= _last_command_id:
        now = _last_command_id + 1

    _last_command_id = now
    return now


def first_command_after(command_id):
    for command in _commands:
        if command["id"] > command_id:
            return command

    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "PzADA/0.4"

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
            return False

        supplied = self.headers.get("X-PzADA-Token", "")
        return hmac.compare_digest(supplied, TOKEN)

    def require_auth(self):
        if self.authorized():
            return True

        self.send_json(
            401,
            {
                "ok": False,
                "error": "unauthorized",
            },
        )
        return False

    def read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("invalid_content_length")

        if length <= 0:
            raise ValueError("empty_body")

        if length > MAX_BODY:
            raise OverflowError("payload_too_large")

        raw = self.rfile.read(length)

        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"invalid_json: {exc}") from exc

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self.send_json(
                200,
                {
                    "ok": True,
                    "service": "PzADA relay",
                    "version": 4,
                    "endpoints": ["/health", "/state", "/command"],
                },
            )
            return

        if parsed.path == "/health":
            with _lock:
                has_state = _latest_state is not None
                received_at = _latest_received_at
                command_count = len(_commands)

            self.send_json(
                200,
                {
                    "ok": True,
                    "service": "PzADA relay",
                    "version": 4,
                    "has_state": has_state,
                    "received_at": received_at,
                    "commands_buffered": command_count,
                    "auth_configured": bool(TOKEN),
                },
            )
            return

        if parsed.path == "/state":
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

        if parsed.path == "/command":
            if not self.require_auth():
                return

            query = parse_qs(parsed.query)

            try:
                after = int(query.get("after", ["0"])[0])
            except ValueError:
                self.send_json(
                    400,
                    {
                        "ok": False,
                        "error": "invalid_after",
                    },
                )
                return

            with _lock:
                command = first_command_after(after)

            self.send_json(
                200,
                {
                    "ok": True,
                    "command": command,
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

        parsed = urlparse(self.path)

        if parsed.path == "/state":
            if not self.require_auth():
                return

            try:
                payload = self.read_json_body()
            except OverflowError as exc:
                self.send_json(413, {"ok": False, "error": str(exc)})
                return
            except ValueError as exc:
                self.send_json(400, {"ok": False, "error": str(exc)})
                return

            try:
                command_after = int(
                    self.headers.get("X-PzADA-Command-After", "0")
                )
            except ValueError:
                command_after = 0

            with _lock:
                _latest_state = payload
                _latest_received_at = time.time()
                received_at = _latest_received_at
                command = first_command_after(command_after)

            self.send_json(
                200,
                {
                    "ok": True,
                    "stored": True,
                    "received_at": received_at,
                    "command": command,
                },
            )
            return

        if parsed.path == "/command":
            if not self.require_auth():
                return

            try:
                payload = self.read_json_body()
            except OverflowError as exc:
                self.send_json(413, {"ok": False, "error": str(exc)})
                return
            except ValueError as exc:
                self.send_json(400, {"ok": False, "error": str(exc)})
                return

            if not isinstance(payload, dict):
                self.send_json(
                    400,
                    {
                        "ok": False,
                        "error": "command_must_be_object",
                    },
                )
                return

            action = payload.get("action")

            if action not in {"ping", "walk", "chat", "open_door", "loot_item", "equip", "eat"}:
                self.send_json(
                    400,
                    {
                        "ok": False,
                        "error": "unsupported_action",
                        "allowed": ["ping", "walk", "chat", "open_door", "loot_item", "equip", "eat"],
                    },
                )
                return

            command = {
                "id": next_command_id(),
                "created_at": time.time(),
                "action": action,
            }

            if action == "walk":
                try:
                    command["x"] = int(payload["x"])
                    command["y"] = int(payload["y"])
                    command["z"] = int(payload.get("z", 0))
                except (KeyError, TypeError, ValueError):
                    self.send_json(
                        400,
                        {
                            "ok": False,
                            "error": "walk_requires_integer_x_y_z",
                        },
                    )
                    return

            if action == "chat":
                text = payload.get("text")

                if not isinstance(text, str):
                    self.send_json(
                        400,
                        {
                            "ok": False,
                            "error": "chat_requires_text",
                        },
                    )
                    return

                text = text.replace("\r", " ").replace("\n", " ").strip()

                if not text:
                    self.send_json(
                        400,
                        {
                            "ok": False,
                            "error": "chat_text_empty",
                        },
                    )
                    return

                if len(text) > MAX_CHAT_TEXT:
                    self.send_json(
                        400,
                        {
                            "ok": False,
                            "error": "chat_text_too_long",
                            "max": MAX_CHAT_TEXT,
                        },
                    )
                    return

                command["text"] = text

            if action == "open_door":
                ref = payload.get("ref")
                if not isinstance(ref, str) or not ref.startswith("door_"):
                    self.send_json(
                        400,
                        {"ok": False, "error": "open_door_requires_ref"},
                    )
                    return
                command["ref"] = ref

            if action == "loot_item":
                container_ref = payload.get("container_ref")
                item_ref = payload.get("item_ref")
                if (
                    not isinstance(container_ref, str)
                    or not container_ref.startswith("container_")
                    or not isinstance(item_ref, str)
                    or not item_ref.startswith("item_")
                ):
                    self.send_json(
                        400,
                        {
                            "ok": False,
                            "error": "loot_item_requires_container_ref_and_item_ref",
                        },
                    )
                    return
                command["container_ref"] = container_ref
                command["item_ref"] = item_ref

            if action == "equip":
                item_ref = payload.get("item_ref")
                if not isinstance(item_ref, str) or not item_ref.startswith("item_"):
                    self.send_json(
                        400,
                        {"ok": False, "error": "equip_requires_item_ref"},
                    )
                    return
                command["item_ref"] = item_ref

            if action == "eat":
                item_ref = payload.get("item_ref")
                if not isinstance(item_ref, str) or not item_ref.startswith("item_"):
                    self.send_json(
                        400,
                        {"ok": False, "error": "eat_requires_item_ref"},
                    )
                    return

                try:
                    percentage = float(payload.get("percentage", 1.0))
                except (TypeError, ValueError):
                    self.send_json(
                        400,
                        {"ok": False, "error": "eat_percentage_invalid"},
                    )
                    return

                if percentage <= 0 or percentage > 1:
                    self.send_json(
                        400,
                        {"ok": False, "error": "eat_percentage_out_of_range"},
                    )
                    return

                command["item_ref"] = item_ref
                command["percentage"] = percentage

            with _lock:
                _commands.append(command)

                if len(_commands) > 100:
                    del _commands[:-100]

            self.send_json(
                200,
                {
                    "ok": True,
                    "accepted": True,
                    "command": command,
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

    def log_message(self, format, *args):
        print("[PzADA Relay] " + (format % args), flush=True)


if __name__ == "__main__":
    if not TOKEN:
        print(
            "[PzADA Relay] ERROR: PZADA_TOKEN environment variable is missing",
            flush=True,
        )

    print(f"[PzADA Relay] listening on {HOST}:{PORT}", flush=True)

    server = ThreadingHTTPServer((HOST, PORT), Handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

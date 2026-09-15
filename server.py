from __future__ import annotations

import asyncio
import hmac
import json
import os
import threading
import time
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))
TOKEN = os.environ.get("PZADA_TOKEN", "")

MAX_BODY = 2 * 1024 * 1024
MAX_CHAT_TEXT = 1000
MAX_RESULT_WAIT_SECONDS = 15.0

ALLOWED_ACTIONS = {
    "ping",
    "walk",
    "chat",
    "open_door",
    "loot_item",
    "equip",
    "eat",
    "attack_zombie",
}

_lock = threading.Lock()
_latest_state: dict[str, Any] | None = None
_latest_received_at: float | None = None
_commands: list[dict[str, Any]] = []
_last_command_id = 0


def now_seconds() -> float:
    return time.time()


def state_age_seconds(received_at: float | None) -> float | None:
    if received_at is None:
        return None
    return max(0.0, now_seconds() - received_at)


def next_command_id() -> int:
    global _last_command_id

    now_id = int(time.time() * 1000)

    with _lock:
        if now_id <= _last_command_id:
            now_id = _last_command_id + 1
        _last_command_id = now_id

    return now_id


def first_command_after(command_id: int) -> dict[str, Any] | None:
    for command in _commands:
        if int(command["id"]) > command_id:
            return command
    return None


def get_snapshot() -> tuple[
    dict[str, Any] | None,
    float | None,
    list[dict[str, Any]],
]:
    with _lock:
        state = _latest_state
        received_at = _latest_received_at
        commands = list(_commands)

    return state, received_at, commands


def build_command(payload: dict[str, Any]) -> tuple[
    dict[str, Any] | None,
    dict[str, Any] | None,
]:
    if not isinstance(payload, dict):
        return None, {
            "status": 400,
            "error": "command_must_be_object",
        }

    action = payload.get("action")

    if action not in ALLOWED_ACTIONS:
        return None, {
            "status": 400,
            "error": "unsupported_action",
            "allowed": sorted(ALLOWED_ACTIONS),
        }

    command: dict[str, Any] = {
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
            return None, {
                "status": 400,
                "error": "walk_requires_integer_x_y_z",
            }

    if action == "chat":
        text = payload.get("text")

        if not isinstance(text, str):
            return None, {
                "status": 400,
                "error": "chat_requires_text",
            }

        text = text.replace("\r", " ").replace("\n", " ").strip()

        if not text:
            return None, {
                "status": 400,
                "error": "chat_text_empty",
            }

        if len(text) > MAX_CHAT_TEXT:
            return None, {
                "status": 400,
                "error": "chat_text_too_long",
                "max": MAX_CHAT_TEXT,
            }

        command["text"] = text

    if action == "open_door":
        ref = payload.get("ref")

        if not isinstance(ref, str) or not ref.startswith("door_"):
            return None, {
                "status": 400,
                "error": "open_door_requires_ref",
            }

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
            return None, {
                "status": 400,
                "error": "loot_item_requires_container_ref_and_item_ref",
            }

        command["container_ref"] = container_ref
        command["item_ref"] = item_ref

    if action == "equip":
        item_ref = payload.get("item_ref")

        if not isinstance(item_ref, str) or not item_ref.startswith("item_"):
            return None, {
                "status": 400,
                "error": "equip_requires_item_ref",
            }

        command["item_ref"] = item_ref

    if action == "eat":
        item_ref = payload.get("item_ref")

        if not isinstance(item_ref, str) or not item_ref.startswith("item_"):
            return None, {
                "status": 400,
                "error": "eat_requires_item_ref",
            }

        try:
            percentage = float(payload.get("percentage", 1.0))
        except (TypeError, ValueError):
            return None, {
                "status": 400,
                "error": "eat_percentage_invalid",
            }

        if percentage <= 0 or percentage > 1:
            return None, {
                "status": 400,
                "error": "eat_percentage_out_of_range",
            }

        command["item_ref"] = item_ref
        command["percentage"] = percentage

    if action == "attack_zombie":
        target_ref = payload.get("target_ref")

        if (
            not isinstance(target_ref, str)
            or not target_ref.startswith("zombie_")
        ):
            return None, {
                "status": 400,
                "error": "attack_zombie_requires_target_ref",
            }

        command["target_ref"] = target_ref

    return command, None


def enqueue_command(payload: dict[str, Any]) -> tuple[
    dict[str, Any] | None,
    dict[str, Any] | None,
]:
    command, error = build_command(payload)

    if error:
        return None, error

    assert command is not None

    with _lock:
        _commands.append(command)

        if len(_commands) > 100:
            del _commands[:-100]

    return command, None


def command_result_from_state(
    state: dict[str, Any] | None,
    command_id: int,
) -> dict[str, Any] | None:
    if not isinstance(state, dict):
        return None

    result = state.get("last_command")

    if not isinstance(result, dict):
        return None

    if str(result.get("id")) != str(command_id):
        return None

    return result


async def parse_json_request(request: Request) -> tuple[
    dict[str, Any] | None,
    JSONResponse | None,
]:
    content_length = request.headers.get("content-length")

    if content_length:
        try:
            if int(content_length) > MAX_BODY:
                return None, JSONResponse(
                    {"ok": False, "error": "payload_too_large"},
                    status_code=413,
                )
        except ValueError:
            return None, JSONResponse(
                {"ok": False, "error": "invalid_content_length"},
                status_code=400,
            )

    try:
        payload = await request.json()
    except Exception:
        return None, JSONResponse(
            {"ok": False, "error": "invalid_json"},
            status_code=400,
        )

    if not isinstance(payload, dict):
        return None, JSONResponse(
            {"ok": False, "error": "json_object_required"},
            status_code=400,
        )

    return payload, None


def request_authorized(request: Request) -> bool:
    if not TOKEN:
        return False

    supplied = request.headers.get("X-PzADA-Token", "")
    return hmac.compare_digest(supplied, TOKEN)


def unauthorized_response() -> JSONResponse:
    return JSONResponse(
        {"ok": False, "error": "unauthorized"},
        status_code=401,
    )


# ---------------------------------------------------------------------------
# Existing relay HTTP API
# ---------------------------------------------------------------------------

async def root_http(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "ok": True,
            "service": "PzADA relay + MCP",
            "version": 7,
            "endpoints": [
                "/health",
                "/state",
                "/command",
                "/mcp",
            ],
        }
    )


async def health_http(request: Request) -> JSONResponse:
    state, received_at, commands = get_snapshot()

    return JSONResponse(
        {
            "ok": True,
            "service": "PzADA relay + MCP",
            "version": 7,
            "has_state": state is not None,
            "received_at": received_at,
            "state_age_seconds": state_age_seconds(received_at),
            "commands_buffered": len(commands),
            "auth_configured": bool(TOKEN),
            "mcp_endpoint": "/mcp",
        }
    )


async def state_get_http(request: Request) -> JSONResponse:
    state, received_at, _ = get_snapshot()

    if state is None:
        return JSONResponse(
            {"ok": False, "error": "no_state_received"},
            status_code=503,
        )

    return JSONResponse(
        {
            "ok": True,
            "received_at": received_at,
            "state": state,
        }
    )


async def state_post_http(request: Request) -> JSONResponse:
    global _latest_state, _latest_received_at

    if not request_authorized(request):
        return unauthorized_response()

    payload, error_response = await parse_json_request(request)

    if error_response:
        return error_response

    assert payload is not None

    try:
        command_after = int(
            request.headers.get("X-PzADA-Command-After", "0")
        )
    except ValueError:
        command_after = 0

    with _lock:
        _latest_state = payload
        _latest_received_at = time.time()
        received_at = _latest_received_at
        command = first_command_after(command_after)

    return JSONResponse(
        {
            "ok": True,
            "stored": True,
            "received_at": received_at,
            "command": command,
        }
    )


async def command_get_http(request: Request) -> JSONResponse:
    if not request_authorized(request):
        return unauthorized_response()

    try:
        after = int(request.query_params.get("after", "0"))
    except ValueError:
        return JSONResponse(
            {"ok": False, "error": "invalid_after"},
            status_code=400,
        )

    with _lock:
        command = first_command_after(after)

    return JSONResponse(
        {
            "ok": True,
            "command": command,
        }
    )


async def command_post_http(request: Request) -> JSONResponse:
    if not request_authorized(request):
        return unauthorized_response()

    payload, error_response = await parse_json_request(request)

    if error_response:
        return error_response

    assert payload is not None

    command, error = enqueue_command(payload)

    if error:
        status = int(error.get("status", 400))
        body = {"ok": False, **{k: v for k, v in error.items() if k != "status"}}
        return JSONResponse(body, status_code=status)

    return JSONResponse(
        {
            "ok": True,
            "accepted": True,
            "command": command,
        }
    )


async def state_http(request: Request) -> JSONResponse:
    if request.method == "GET":
        return await state_get_http(request)
    return await state_post_http(request)


async def command_http(request: Request) -> JSONResponse:
    if request.method == "GET":
        return await command_get_http(request)
    return await command_post_http(request)


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

mcp = MCPServer(
    "PzADA",
    version="0.1.0",
    title="PzADA Project Zomboid Control",
    description=(
        "Read PzADA game telemetry and send validated actions to the "
        "Project Zomboid Ada character."
    ),
    instructions=(
        "Always call get_state before acting. Use refs exactly as returned by "
        "state; never invent item, door, container, or zombie refs. "
        "After act returns a command id, call get_result with that id and wait "
        "for completion/failure. For tests, verify success with a fresh "
        "get_state after the result."
    ),
)


READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)

WRITE_ACTION = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    idempotent_hint=False,
    open_world_hint=False,
)


@mcp.tool(
    title="PzADA health",
    annotations=READ_ONLY,
)
def health() -> dict[str, Any]:
    """Check whether Render has fresh PzADA telemetry and report relay health."""
    state, received_at, commands = get_snapshot()

    return {
        "ok": True,
        "has_state": state is not None,
        "received_at": received_at,
        "state_age_seconds": state_age_seconds(received_at),
        "commands_buffered": len(commands),
        "allowed_actions": sorted(ALLOWED_ACTIONS),
    }


@mcp.tool(
    title="Read PzADA state",
    annotations=READ_ONLY,
)
def get_state(section: str = "all") -> dict[str, Any]:
    """
    Read current PzADA telemetry.

    section may be: all, player, inventory, nearby, last_command.
    Use all when deciding what to do; use a smaller section for cheap checks.
    """
    state, received_at, _ = get_snapshot()

    if state is None:
        return {
            "ok": False,
            "error": "no_state_received",
        }

    section = (section or "all").strip().lower()

    if section == "all":
        data: Any = state
    elif section == "player":
        data = state.get("player")
    elif section == "inventory":
        data = state.get("inventory")
    elif section == "nearby":
        data = state.get("nearby")
    elif section == "last_command":
        data = state.get("last_command")
    else:
        return {
            "ok": False,
            "error": "invalid_section",
            "allowed": [
                "all",
                "player",
                "inventory",
                "nearby",
                "last_command",
            ],
        }

    return {
        "ok": True,
        "received_at": received_at,
        "state_age_seconds": state_age_seconds(received_at),
        "section": section,
        "data": data,
    }


@mcp.tool(
    title="Act in Project Zomboid",
    annotations=WRITE_ACTION,
)
def act(
    action: str,
    args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Queue one validated PzADA action.

    Current actions and args:
    - ping: {}
    - walk: {"x": int, "y": int, "z": int}
    - open_door: {"ref": "door_..."}
    - loot_item: {"container_ref": "container_...", "item_ref": "item_..."}
    - equip: {"item_ref": "item_..."}
    - eat: {"item_ref": "item_...", "percentage": 0..1}
    - attack_zombie: {"target_ref": "zombie_..."}
    - chat: {"text": "..."} (parked in solo; intended for MP later)

    Read state first and only use refs that state returned.
    """
    payload: dict[str, Any] = {"action": action}

    if args:
        payload.update(args)

    command, error = enqueue_command(payload)

    if error:
        return {
            "ok": False,
            **{k: v for k, v in error.items() if k != "status"},
        }

    assert command is not None

    return {
        "ok": True,
        "accepted": True,
        "command": command,
        "next": "Call get_result with command.id, then verify with get_state.",
    }


@mcp.tool(
    title="Read PzADA command result",
    annotations=READ_ONLY,
)
async def get_result(
    command_id: int,
    wait_seconds: float = 0.0,
) -> dict[str, Any]:
    """
    Read the ACK/result for a queued PzADA command.

    Set wait_seconds up to 15 to wait for the Lua result.
    completed/ok=true means the action completed.
    failed/stopped returns detail explaining why.
    """
    try:
        command_id = int(command_id)
        wait_seconds = float(wait_seconds)
    except (TypeError, ValueError):
        return {
            "ok": False,
            "error": "invalid_command_id_or_wait",
        }

    wait_seconds = max(
        0.0,
        min(wait_seconds, MAX_RESULT_WAIT_SECONDS),
    )

    deadline = time.monotonic() + wait_seconds

    while True:
        state, received_at, commands = get_snapshot()
        result = command_result_from_state(state, command_id)

        if result is not None:
            return {
                "ok": True,
                "found": True,
                "result": result,
                "received_at": received_at,
                "state_age_seconds": state_age_seconds(received_at),
            }

        queued = next(
            (
                command
                for command in reversed(commands)
                if int(command["id"]) == command_id
            ),
            None,
        )

        if time.monotonic() >= deadline:
            return {
                "ok": True,
                "found": False,
                "pending": queued is not None,
                "command": queued,
                "received_at": received_at,
                "state_age_seconds": state_age_seconds(received_at),
            }

        await asyncio.sleep(0.25)


# Disable the localhost-only Host/Origin default so Render's stable hostname
# can serve this MCP endpoint. The endpoint exposes only the narrow PzADA tools
# above; relay /state and /command writes remain protected by PZADA_TOKEN.
transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=False
)

mcp_http_app = mcp.streamable_http_app(
    stateless_http=True,
    transport_security=transport_security,
)


@asynccontextmanager
async def lifespan(app: Starlette):
    async with mcp.session_manager.run():
        yield


app = Starlette(
    routes=[
        Route("/", root_http, methods=["GET"]),
        Route("/health", health_http, methods=["GET"]),
        Route("/state", state_http, methods=["GET", "POST"]),
        Route("/command", command_http, methods=["GET", "POST"]),
        # Keep this mount LAST. Its internal Streamable HTTP endpoint is /mcp.
        Mount("/", app=mcp_http_app),
    ],
    lifespan=lifespan,
)


if __name__ == "__main__":
    if not TOKEN:
        print(
            "[PzADA Relay] ERROR: PZADA_TOKEN environment variable is missing",
            flush=True,
        )

    print(
        f"[PzADA Relay] listening on {HOST}:{PORT} with MCP at /mcp",
        flush=True,
    )

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level="info",
    )

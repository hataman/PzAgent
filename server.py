from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import parse_qs, unquote, urlencode

import uvicorn
from pydantic import AnyHttpUrl, AnyUrl
from mcp.server import MCPServer
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Mount, Route

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))
TOKEN = os.environ.get("PZADA_TOKEN", "")

PUBLIC_BASE_URL = os.environ.get(
    "PZADA_PUBLIC_BASE_URL",
    "https://pzagent.onrender.com",
).rstrip("/")
RESOURCE_URL = f"{PUBLIC_BASE_URL}/mcp"

OAUTH_CLIENT_ID = os.environ.get("PZADA_OAUTH_CLIENT_ID", "")
OAUTH_CLIENT_SECRET = os.environ.get("PZADA_OAUTH_CLIENT_SECRET", "")
OAUTH_PASSWORD = os.environ.get("PZADA_OAUTH_PASSWORD", "")
OAUTH_REDIRECT_URI = os.environ.get("PZADA_OAUTH_REDIRECT_URI", "")

OAUTH_SCOPES = ["pzada", "offline_access"]
ACCESS_TOKEN_SECONDS = 3600
REFRESH_TOKEN_SECONDS = 90 * 24 * 3600
AUTH_CODE_SECONDS = 300
AUTH_REQUEST_SECONDS = 600

OAUTH_CONFIGURED = all(
    [
        OAUTH_CLIENT_ID,
        OAUTH_CLIENT_SECRET,
        OAUTH_PASSWORD,
        OAUTH_REDIRECT_URI,
    ]
)

MAX_BODY = 2 * 1024 * 1024
MAX_CHAT_TEXT = 1000
MAX_RESULT_WAIT_SECONDS = 15.0

ALLOWED_ACTIONS = {
    "ping",
    "walk",
    "chat",
    "open_door",
    "close_door",
    "open_window",
    "close_window",
    "loot_item",
    "equip",
    "wear",
    "unwear",
    "drop_item",
    "eat",
    "drink_item",
    "drink_source",
    "fill_water",
    "sit_ground",
    "stand_up",
    "rest",
    "get_on_bed",
    "bed_pose",
    "sleep",
    "wake_up",
    "bandage",
    "remove_bandage",
    "disinfect",
    "take_medicine",
    "attack_zombie",
    "pickup_ground_item",
    "transfer_item",
    "cancel_action",
    "set_sneak",
    "climb_window",
    "set_curtain",
    "set_light",
    "read_item",
    "set_media_device",
    "control_media",
    "set_appliance",
    "control_fire_source",
    "craft_recipe",
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

    if action in {"open_door", "close_door"}:
        ref = payload.get("ref")

        if not isinstance(ref, str) or not ref.startswith("door_"):
            return None, {
                "status": 400,
                "error": f"{action}_requires_ref",
            }

        command["ref"] = ref

    if action in {"open_window", "close_window"}:
        ref = payload.get("ref")

        if not isinstance(ref, str) or not ref.startswith("window_"):
            return None, {
                "status": 400,
                "error": f"{action}_requires_ref",
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

    if action in {"equip", "wear", "unwear", "drop_item", "take_medicine"}:
        item_ref = payload.get("item_ref")

        if not isinstance(item_ref, str) or not item_ref.startswith("item_"):
            return None, {
                "status": 400,
                "error": f"{action}_requires_item_ref",
            }

        command["item_ref"] = item_ref

    if action in {"eat", "drink_item"}:
        item_ref = payload.get("item_ref")

        if not isinstance(item_ref, str) or not item_ref.startswith("item_"):
            return None, {
                "status": 400,
                "error": f"{action}_requires_item_ref",
            }

        try:
            percentage = float(payload.get("percentage", 1.0))
        except (TypeError, ValueError):
            return None, {
                "status": 400,
                "error": f"{action}_percentage_invalid",
            }

        if percentage <= 0 or percentage > 1:
            return None, {
                "status": 400,
                "error": f"{action}_percentage_out_of_range",
            }

        command["item_ref"] = item_ref
        command["percentage"] = percentage

    if action == "drink_source":
        source_ref = payload.get("source_ref")

        if (
            not isinstance(source_ref, str)
            or not source_ref.startswith("water_")
        ):
            return None, {
                "status": 400,
                "error": "drink_source_requires_source_ref",
            }

        command["source_ref"] = source_ref

    if action == "fill_water":
        item_ref = payload.get("item_ref")
        source_ref = payload.get("source_ref")

        if (
            not isinstance(item_ref, str)
            or not item_ref.startswith("item_")
            or not isinstance(source_ref, str)
            or not source_ref.startswith("water_")
        ):
            return None, {
                "status": 400,
                "error": "fill_water_requires_item_ref_and_source_ref",
            }

        command["item_ref"] = item_ref
        command["source_ref"] = source_ref

    if action in {"bandage", "disinfect"}:
        item_ref = payload.get("item_ref")
        body_part_ref = payload.get("body_part_ref")

        if (
            not isinstance(item_ref, str)
            or not item_ref.startswith("item_")
            or not isinstance(body_part_ref, str)
            or not body_part_ref.startswith("bodypart_")
        ):
            return None, {
                "status": 400,
                "error": f"{action}_requires_item_ref_and_body_part_ref",
            }

        command["item_ref"] = item_ref
        command["body_part_ref"] = body_part_ref

    if action == "remove_bandage":
        body_part_ref = payload.get("body_part_ref")

        if (
            not isinstance(body_part_ref, str)
            or not body_part_ref.startswith("bodypart_")
        ):
            return None, {
                "status": 400,
                "error": "remove_bandage_requires_body_part_ref",
            }

        command["body_part_ref"] = body_part_ref

    if action in {"rest", "get_on_bed"}:
        furniture_ref = payload.get("furniture_ref")

        if (
            not isinstance(furniture_ref, str)
            or not furniture_ref.startswith("furniture_")
        ):
            return None, {
                "status": 400,
                "error": f"{action}_requires_furniture_ref",
            }

        command["furniture_ref"] = furniture_ref

    if action == "bed_pose":
        pose = payload.get("pose")

        if not isinstance(pose, str):
            return None, {
                "status": 400,
                "error": "bed_pose_requires_pose",
            }

        pose = pose.strip().lower()

        if pose not in {"awake", "asleep"}:
            return None, {
                "status": 400,
                "error": "bed_pose_pose_must_be_awake_or_asleep",
            }

        command["pose"] = pose

    if action == "sleep":
        furniture_ref = payload.get("furniture_ref")

        if furniture_ref is not None:
            if (
                not isinstance(furniture_ref, str)
                or not furniture_ref.startswith("furniture_")
            ):
                return None, {
                    "status": 400,
                    "error": "sleep_furniture_ref_invalid",
                }

            command["furniture_ref"] = furniture_ref

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

    if action in {"pickup_ground_item", "read_item"}:
        item_ref = payload.get("item_ref")

        if not isinstance(item_ref, str) or not item_ref.startswith("item_"):
            return None, {
                "status": 400,
                "error": f"{action}_requires_item_ref",
            }

        command["item_ref"] = item_ref

    if action == "transfer_item":
        item_ref = payload.get("item_ref")
        destination_ref = payload.get("destination_ref")

        destination_ok = (
            isinstance(destination_ref, str)
            and (
                destination_ref in {"inventory", "main_inventory"}
                or destination_ref.startswith("item_")
                or destination_ref.startswith("container_")
            )
        )

        if (
            not isinstance(item_ref, str)
            or not item_ref.startswith("item_")
            or not destination_ok
        ):
            return None, {
                "status": 400,
                "error": "transfer_item_requires_item_ref_and_destination_ref",
            }

        command["item_ref"] = item_ref
        command["destination_ref"] = destination_ref

    if action == "set_sneak":
        enabled = payload.get("enabled")

        if not isinstance(enabled, bool):
            return None, {
                "status": 400,
                "error": "set_sneak_requires_boolean_enabled",
            }

        command["enabled"] = enabled

    if action == "climb_window":
        ref = payload.get("ref")

        if not isinstance(ref, str) or not ref.startswith("window_"):
            return None, {
                "status": 400,
                "error": "climb_window_requires_ref",
            }

        command["ref"] = ref

    if action == "set_curtain":
        ref = payload.get("ref")
        open_value = payload.get("open")

        if (
            not isinstance(ref, str)
            or not ref.startswith("curtain_")
            or not isinstance(open_value, bool)
        ):
            return None, {
                "status": 400,
                "error": "set_curtain_requires_ref_and_boolean_open",
            }

        command["ref"] = ref
        command["open"] = open_value

    if action == "set_light":
        ref = payload.get("ref")
        on = payload.get("on")

        if (
            not isinstance(ref, str)
            or not ref.startswith("light_")
            or not isinstance(on, bool)
        ):
            return None, {
                "status": 400,
                "error": "set_light_requires_ref_and_boolean_on",
            }

        command["ref"] = ref
        command["on"] = on

    if action == "set_media_device":
        device_ref = payload.get("device_ref")

        if not isinstance(device_ref, str) or not device_ref.startswith("media_"):
            return None, {
                "status": 400,
                "error": "set_media_device_requires_device_ref",
            }

        command["device_ref"] = device_ref
        supplied_setting = False

        if "power" in payload:
            power = payload.get("power")
            if not isinstance(power, bool):
                return None, {
                    "status": 400,
                    "error": "set_media_device_power_must_be_boolean",
                }
            command["power"] = power
            supplied_setting = True

        if "channel" in payload:
            try:
                channel = int(payload.get("channel"))
            except (TypeError, ValueError):
                return None, {
                    "status": 400,
                    "error": "set_media_device_channel_must_be_integer",
                }
            if channel < 0:
                return None, {
                    "status": 400,
                    "error": "set_media_device_channel_out_of_range",
                }
            command["channel"] = channel
            supplied_setting = True

        if "volume" in payload:
            try:
                volume = float(payload.get("volume"))
            except (TypeError, ValueError):
                return None, {
                    "status": 400,
                    "error": "set_media_device_volume_must_be_number",
                }
            if volume < 0 or volume > 1:
                return None, {
                    "status": 400,
                    "error": "set_media_device_volume_out_of_range",
                }
            command["volume"] = volume
            supplied_setting = True

        if not supplied_setting:
            return None, {
                "status": 400,
                "error": "set_media_device_requires_power_channel_or_volume",
            }

    if action == "control_media":
        device_ref = payload.get("device_ref")
        operation = payload.get("operation")

        if not isinstance(device_ref, str) or not device_ref.startswith("media_"):
            return None, {
                "status": 400,
                "error": "control_media_requires_device_ref",
            }

        if not isinstance(operation, str):
            return None, {
                "status": 400,
                "error": "control_media_requires_operation",
            }

        operation = operation.strip().lower()
        if operation not in {"insert", "eject", "play", "stop"}:
            return None, {
                "status": 400,
                "error": "control_media_operation_invalid",
            }

        command["device_ref"] = device_ref
        command["operation"] = operation

        if operation == "insert":
            item_ref = payload.get("item_ref")
            if not isinstance(item_ref, str) or not item_ref.startswith("item_"):
                return None, {
                    "status": 400,
                    "error": "control_media_insert_requires_item_ref",
                }
            command["item_ref"] = item_ref

    if action == "set_appliance":
        appliance_ref = payload.get("appliance_ref") or payload.get("ref")
        on = payload.get("on")

        if (
            not isinstance(appliance_ref, str)
            or not appliance_ref.startswith("appliance_")
            or not isinstance(on, bool)
        ):
            return None, {
                "status": 400,
                "error": "set_appliance_requires_appliance_ref_and_boolean_on",
            }

        command["appliance_ref"] = appliance_ref
        command["on"] = on

    if action == "control_fire_source":
        fire_ref = payload.get("fire_ref") or payload.get("ref")
        operation = payload.get("operation")

        if not isinstance(fire_ref, str) or not fire_ref.startswith("fire_"):
            return None, {
                "status": 400,
                "error": "control_fire_source_requires_fire_ref",
            }

        if not isinstance(operation, str):
            return None, {
                "status": 400,
                "error": "control_fire_source_requires_operation",
            }

        operation = operation.strip().lower()
        if operation not in {"light", "add_fuel", "extinguish"}:
            return None, {
                "status": 400,
                "error": "control_fire_source_operation_invalid",
            }

        command["fire_ref"] = fire_ref
        command["operation"] = operation

        if operation == "add_fuel":
            item_ref = payload.get("item_ref")
            if not isinstance(item_ref, str) or not item_ref.startswith("item_"):
                return None, {
                    "status": 400,
                    "error": "control_fire_source_add_fuel_requires_item_ref",
                }
            command["item_ref"] = item_ref

        purpose = payload.get("purpose")
        if purpose is not None:
            if not isinstance(purpose, str):
                return None, {
                    "status": 400,
                    "error": "control_fire_source_purpose_must_be_string",
                }
            purpose = purpose.replace("\r", " ").replace("\n", " ").strip()
            if len(purpose) > 64:
                return None, {
                    "status": 400,
                    "error": "control_fire_source_purpose_too_long",
                }
            if purpose:
                command["purpose"] = purpose

    if action == "craft_recipe":
        recipe_ref = payload.get("recipe_ref") or payload.get("ref")

        if not isinstance(recipe_ref, str) or not recipe_ref.startswith("craft_"):
            return None, {
                "status": 400,
                "error": "craft_recipe_requires_recipe_ref",
            }

        command["recipe_ref"] = recipe_ref

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
# OAuth 2.1 authorization server for the ChatGPT MCP connection
# ---------------------------------------------------------------------------

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _oauth_signing_key() -> bytes:
    if not OAUTH_CLIENT_SECRET:
        raise RuntimeError("OAuth client secret is not configured")

    return hashlib.sha256(
        (OAUTH_CLIENT_SECRET + "|PzADA-OAuth-v1").encode("utf-8")
    ).digest()


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _encode_signed(kind: str, payload: dict[str, Any]) -> str:
    envelope = {
        "kind": kind,
        "iat": int(time.time()),
        **payload,
    }

    body = _b64url_encode(
        json.dumps(
            envelope,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )

    signature = hmac.new(
        _oauth_signing_key(),
        body.encode("ascii"),
        hashlib.sha256,
    ).digest()

    return body + "." + _b64url_encode(signature)


def _decode_signed(
    token: str,
    expected_kind: str,
) -> dict[str, Any] | None:
    try:
        body, supplied_signature = token.split(".", 1)

        expected_signature = hmac.new(
            _oauth_signing_key(),
            body.encode("ascii"),
            hashlib.sha256,
        ).digest()

        actual_signature = _b64url_decode(supplied_signature)

        if not hmac.compare_digest(expected_signature, actual_signature):
            return None

        payload = json.loads(_b64url_decode(body).decode("utf-8"))

        if payload.get("kind") != expected_kind:
            return None

        expires_at = int(payload.get("exp", 0))

        if expires_at <= int(time.time()):
            return None

        return payload

    except Exception:
        return None


class PzADAOAuthProvider(
    OAuthAuthorizationServerProvider[
        AuthorizationCode,
        RefreshToken,
        AccessToken,
    ]
):
    def __init__(self) -> None:
        self.revoked: set[str] = set()
        self.used_codes: set[str] = set()

    def client(self) -> OAuthClientInformationFull | None:
        if not OAUTH_CONFIGURED:
            return None

        return OAuthClientInformationFull(
            client_id=OAUTH_CLIENT_ID,
            client_secret=OAUTH_CLIENT_SECRET,
            redirect_uris=[AnyUrl(OAUTH_REDIRECT_URI)],
            token_endpoint_auth_method="client_secret_basic",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=" ".join(OAUTH_SCOPES),
            client_name="ChatGPT PzADA",
            application_type="web",
        )

    async def get_client(
        self,
        client_id: str,
    ) -> OAuthClientInformationFull | None:
        client = self.client()

        if client is None:
            return None

        if not hmac.compare_digest(client_id, OAUTH_CLIENT_ID):
            return None

        return client

    async def register_client(
        self,
        client_info: OAuthClientInformationFull,
    ) -> None:
        raise NotImplementedError("Dynamic client registration is disabled")

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        if not OAUTH_CONFIGURED:
            raise AuthorizeError(
                error="temporarily_unavailable",
                error_description="PzADA OAuth is not configured",
            )

        if client.client_id != OAUTH_CLIENT_ID:
            raise AuthorizeError(
                error="unauthorized_client",
                error_description="Unknown OAuth client",
            )

        resource = params.resource or RESOURCE_URL

        if resource != RESOURCE_URL:
            raise AuthorizeError(
                error="invalid_target",
                error_description="Unexpected OAuth resource",
            )

        scopes = params.scopes or list(OAUTH_SCOPES)

        if "pzada" not in scopes:
            raise AuthorizeError(
                error="invalid_scope",
                error_description="pzada scope is required",
            )

        for scope in scopes:
            if scope not in OAUTH_SCOPES:
                raise AuthorizeError(
                    error="invalid_scope",
                    error_description=f"Unsupported scope: {scope}",
                )

        request_token = _encode_signed(
            "auth_request",
            {
                "exp": int(time.time()) + AUTH_REQUEST_SECONDS,
                "jti": secrets.token_urlsafe(16),
                "client_id": client.client_id,
                "state": params.state,
                "scopes": scopes,
                "code_challenge": params.code_challenge,
                "redirect_uri": str(params.redirect_uri),
                "redirect_uri_provided_explicitly": (
                    params.redirect_uri_provided_explicitly
                ),
                "resource": resource,
            },
        )

        return (
            f"{PUBLIC_BASE_URL}/oauth/approve?"
            + urlencode({"request": request_token})
        )

    def _authorization_code_from_token(
        self,
        token: str,
    ) -> AuthorizationCode | None:
        if _token_fingerprint(token) in self.used_codes:
            return None

        payload = _decode_signed(token, "auth_code")

        if payload is None:
            return None

        try:
            return AuthorizationCode(
                code=token,
                client_id=str(payload["client_id"]),
                scopes=list(payload["scopes"]),
                expires_at=float(payload["exp"]),
                code_challenge=str(payload["code_challenge"]),
                redirect_uri=AnyUrl(str(payload["redirect_uri"])),
                redirect_uri_provided_explicitly=bool(
                    payload["redirect_uri_provided_explicitly"]
                ),
                resource=str(payload["resource"]),
                subject="pzada-owner",
            )
        except Exception:
            return None

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        code = self._authorization_code_from_token(authorization_code)

        if code is None:
            return None

        if code.client_id != client.client_id:
            return None

        return code

    def _mint_access_token(
        self,
        *,
        client_id: str,
        scopes: list[str],
        resource: str,
        subject: str = "pzada-owner",
    ) -> tuple[str, AccessToken]:
        expires_at = int(time.time()) + ACCESS_TOKEN_SECONDS

        token = _encode_signed(
            "access",
            {
                "exp": expires_at,
                "jti": secrets.token_urlsafe(16),
                "client_id": client_id,
                "scopes": scopes,
                "resource": resource,
                "subject": subject,
            },
        )

        access = AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
            resource=resource,
            subject=subject,
            claims={"iss": PUBLIC_BASE_URL},
        )

        return token, access

    def _mint_refresh_token(
        self,
        *,
        client_id: str,
        scopes: list[str],
        resource: str,
        subject: str = "pzada-owner",
    ) -> tuple[str, RefreshToken]:
        expires_at = int(time.time()) + REFRESH_TOKEN_SECONDS

        token = _encode_signed(
            "refresh",
            {
                "exp": expires_at,
                "jti": secrets.token_urlsafe(16),
                "client_id": client_id,
                "scopes": scopes,
                "resource": resource,
                "subject": subject,
            },
        )

        refresh = RefreshToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
            resource=resource,
            subject=subject,
        )

        return token, refresh

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        code_fingerprint = _token_fingerprint(authorization_code.code)

        if code_fingerprint in self.used_codes:
            raise TokenError(
                error="invalid_grant",
                error_description="Authorization code already used",
            )

        if authorization_code.client_id != client.client_id:
            raise TokenError(
                error="invalid_grant",
                error_description="Authorization code client mismatch",
            )

        resource = authorization_code.resource or RESOURCE_URL

        if resource != RESOURCE_URL:
            raise TokenError(
                error="invalid_target",
                error_description="Authorization code resource mismatch",
            )

        self.used_codes.add(code_fingerprint)

        scopes = list(authorization_code.scopes)

        access_token, _ = self._mint_access_token(
            client_id=client.client_id,
            scopes=scopes,
            resource=resource,
        )

        refresh_token = None

        if "offline_access" in scopes:
            refresh_token, _ = self._mint_refresh_token(
                client_id=client.client_id,
                scopes=scopes,
                resource=resource,
            )

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_SECONDS,
            scope=" ".join(scopes),
            refresh_token=refresh_token,
        )

    async def load_access_token(
        self,
        token: str,
    ) -> AccessToken | None:
        if _token_fingerprint(token) in self.revoked:
            return None

        payload = _decode_signed(token, "access")

        if payload is None:
            return None

        try:
            resource = str(payload["resource"])

            if resource != RESOURCE_URL:
                return None

            return AccessToken(
                token=token,
                client_id=str(payload["client_id"]),
                scopes=list(payload["scopes"]),
                expires_at=int(payload["exp"]),
                resource=resource,
                subject=str(payload.get("subject") or "pzada-owner"),
                claims={"iss": PUBLIC_BASE_URL},
            )
        except Exception:
            return None

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        if _token_fingerprint(refresh_token) in self.revoked:
            return None

        payload = _decode_signed(refresh_token, "refresh")

        if payload is None:
            return None

        if str(payload.get("client_id")) != client.client_id:
            return None

        try:
            resource = str(payload["resource"])

            if resource != RESOURCE_URL:
                return None

            return RefreshToken(
                token=refresh_token,
                client_id=client.client_id,
                scopes=list(payload["scopes"]),
                expires_at=int(payload["exp"]),
                resource=resource,
                subject=str(payload.get("subject") or "pzada-owner"),
            )
        except Exception:
            return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        requested_scopes = scopes or list(refresh_token.scopes)

        if any(scope not in refresh_token.scopes for scope in requested_scopes):
            raise TokenError(
                error="invalid_scope",
                error_description="Refresh request expanded the original scope",
            )

        resource = refresh_token.resource or RESOURCE_URL

        if resource != RESOURCE_URL:
            raise TokenError(
                error="invalid_target",
                error_description="Refresh token resource mismatch",
            )

        self.revoked.add(_token_fingerprint(refresh_token.token))

        access_token, _ = self._mint_access_token(
            client_id=client.client_id,
            scopes=requested_scopes,
            resource=resource,
        )

        new_refresh_token, _ = self._mint_refresh_token(
            client_id=client.client_id,
            scopes=requested_scopes,
            resource=resource,
        )

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_SECONDS,
            scope=" ".join(requested_scopes),
            refresh_token=new_refresh_token,
        )

    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        self.revoked.add(_token_fingerprint(token.token))

    def complete_authorization(
        self,
        request_token: str,
    ) -> str | None:
        payload = _decode_signed(request_token, "auth_request")

        if payload is None:
            return None

        if str(payload.get("client_id")) != OAUTH_CLIENT_ID:
            return None

        redirect_uri = str(payload.get("redirect_uri") or "")

        if redirect_uri != OAUTH_REDIRECT_URI:
            return None

        code = _encode_signed(
            "auth_code",
            {
                "exp": int(time.time()) + AUTH_CODE_SECONDS,
                "jti": secrets.token_urlsafe(16),
                "client_id": OAUTH_CLIENT_ID,
                "scopes": list(payload["scopes"]),
                "code_challenge": str(payload["code_challenge"]),
                "redirect_uri": redirect_uri,
                "redirect_uri_provided_explicitly": bool(
                    payload["redirect_uri_provided_explicitly"]
                ),
                "resource": str(payload["resource"]),
            },
        )

        return construct_redirect_uri(
            redirect_uri,
            code=code,
            state=payload.get("state"),
        )


oauth_provider = PzADAOAuthProvider()


def _oauth_login_page(
    request_token: str,
    error: str = "",
) -> str:
    escaped_request = html.escape(request_token, quote=True)

    error_html = ""

    if error:
        error_html = (
            '<div style="padding:10px;background:#ffe9e9;'
            'border:1px solid #cc7777;border-radius:8px;margin-bottom:14px">'
            + html.escape(error)
            + "</div>"
        )

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PzADA Authorization</title>
</head>
<body style="font-family:system-ui;margin:40px;max-width:520px">
<h1>PzADA</h1>
<p>Allow this ChatGPT connection to read PzADA state and run game actions.</p>
{error_html}
<form method="post" action="/oauth/approve">
<input type="hidden" name="request" value="{escaped_request}">
<label for="password">PzADA password</label><br>
<input id="password" type="password" name="password"
       autocomplete="current-password"
       style="padding:9px;width:300px;margin-top:8px">
<button type="submit" style="padding:9px 14px;margin-left:6px">Allow</button>
</form>
</body>
</html>"""


async def oauth_approve(request: Request):
    if not OAUTH_CONFIGURED:
        return HTMLResponse(
            "<h1>PzADA OAuth is not configured</h1>",
            status_code=503,
        )

    if request.method == "GET":
        request_token = request.query_params.get("request", "")

        if _decode_signed(request_token, "auth_request") is None:
            return HTMLResponse(
                "<h1>Invalid or expired authorization request</h1>",
                status_code=400,
            )

        return HTMLResponse(_oauth_login_page(request_token))

    body = await request.body()

    if len(body) > 64 * 1024:
        return HTMLResponse("<h1>Request too large</h1>", status_code=413)

    try:
        form = parse_qs(
            body.decode("utf-8"),
            keep_blank_values=True,
        )
        request_token = form.get("request", [""])[-1]
        password = form.get("password", [""])[-1]
    except Exception:
        return HTMLResponse("<h1>Invalid form</h1>", status_code=400)

    if not hmac.compare_digest(
        password.encode("utf-8"),
        OAUTH_PASSWORD.encode("utf-8"),
    ):
        return HTMLResponse(
            _oauth_login_page(
                request_token,
                "Wrong password.",
            ),
            status_code=401,
        )

    redirect_to = oauth_provider.complete_authorization(request_token)

    if redirect_to is None:
        return HTMLResponse(
            "<h1>Invalid or expired authorization request</h1>",
            status_code=400,
        )

    return RedirectResponse(redirect_to, status_code=302)


# ---------------------------------------------------------------------------
# Existing relay HTTP API
# ---------------------------------------------------------------------------

async def root_http(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "ok": True,
            "service": "PzADA relay + MCP",
            "version": 13,
            "endpoints": [
                "/health",
                "/state",
                "/command",
                "/mcp",
            ],
        }
    )


async def oauth_metadata_http(request: Request) -> JSONResponse:
    """
    Explicit RFC 8414 metadata for ChatGPT OAuth validation.

    The MCP SDK also exposes authorization-server metadata internally, but
    ChatGPT requires PKCE S256 to be advertised unambiguously. Keeping this
    route at the outer Starlette layer guarantees the exact document returned
    at /.well-known/oauth-authorization-server.
    """
    return JSONResponse(
        {
            "issuer": PUBLIC_BASE_URL,
            "authorization_endpoint": f"{PUBLIC_BASE_URL}/authorize",
            "token_endpoint": f"{PUBLIC_BASE_URL}/token",
            "scopes_supported": OAUTH_SCOPES,
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "code_challenge_methods_supported": ["S256"],
        }
    )


async def protected_resource_metadata_http(
    request: Request,
) -> JSONResponse:
    """Explicit RFC 9728 protected-resource metadata for /mcp."""
    return JSONResponse(
        {
            "resource": RESOURCE_URL,
            "authorization_servers": [PUBLIC_BASE_URL],
            "scopes_supported": ["pzada"],
            "bearer_methods_supported": ["header"],
        }
    )


async def health_http(request: Request) -> JSONResponse:
    state, received_at, commands = get_snapshot()

    return JSONResponse(
        {
            "ok": True,
            "service": "PzADA relay + MCP",
            "version": 13,
            "has_state": state is not None,
            "received_at": received_at,
            "state_age_seconds": state_age_seconds(received_at),
            "commands_buffered": len(commands),
            "auth_configured": bool(TOKEN),
            "mcp_endpoint": "/mcp",
            "oauth_configured": OAUTH_CONFIGURED,
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

auth_settings = AuthSettings(
    issuer_url=AnyHttpUrl(PUBLIC_BASE_URL),
    resource_server_url=AnyHttpUrl(RESOURCE_URL),
    required_scopes=["pzada"],
    client_registration_options=ClientRegistrationOptions(
        enabled=False,
        valid_scopes=OAUTH_SCOPES,
        default_scopes=OAUTH_SCOPES,
    ),
    validate_token_resource=True,
)


mcp = MCPServer(
    "PzADA",
    version="0.2.6",
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
    auth=auth_settings,
    auth_server_provider=oauth_provider,
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

    section may be: all, player, inventory, body_parts, nearby, world_time, crafting, last_command.
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
    elif section == "body_parts":
        data = state.get("body_parts")
    elif section == "nearby":
        data = state.get("nearby")
    elif section == "world_time":
        data = state.get("world_time")
    elif section == "crafting":
        data = state.get("crafting")
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
                "body_parts",
                "nearby",
                "world_time",
                "crafting",
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
    - chat: {"text": "..."}
    - open_door / close_door: {"ref": "door_..."}
    - open_window / close_window: {"ref": "window_..."}
    - loot_item: {"container_ref": "container_...", "item_ref": "item_..."}
    - equip / wear / unwear / drop_item: {"item_ref": "item_..."}
    - eat / drink_item: {"item_ref": "item_...", "percentage": 0..1}
    - drink_source: {"source_ref": "water_..."}
    - fill_water: {"item_ref": "item_...", "source_ref": "water_..."}
    - sit_ground / stand_up: {}
    - rest / get_on_bed: {"furniture_ref": "furniture_..."}
    - bed_pose: {"pose": "awake" | "asleep"}
    - sleep: {} or {"furniture_ref": "furniture_..."}
    - wake_up: {}
    - bandage / disinfect: {"item_ref": "item_...", "body_part_ref": "bodypart_..."}
    - remove_bandage: {"body_part_ref": "bodypart_..."}
    - take_medicine: {"item_ref": "item_..."}
    - attack_zombie: {"target_ref": "zombie_..."}
    - pickup_ground_item / read_item: {"item_ref": "item_..."}
    - transfer_item: {"item_ref": "item_...", "destination_ref": "inventory" | "main_inventory" | "item_..." | "container_..."}
    - cancel_action: {}
    - set_sneak: {"enabled": bool}
    - climb_window: {"ref": "window_..."}
    - set_curtain: {"ref": "curtain_...", "open": bool}
    - set_light: {"ref": "light_...", "on": bool}
    - set_media_device: {"device_ref": "media_...", optional "power": bool, "channel": int, "volume": 0..1}
    - control_media: {"device_ref": "media_...", "operation": "insert" | "eject" | "play" | "stop", optional "item_ref": "item_..."}
    - set_appliance: {"appliance_ref": "appliance_...", "on": bool}
    - control_fire_source: {"fire_ref": "fire_...", "operation": "light" | "add_fuel" | "extinguish", optional "item_ref": "item_...", "purpose": "..."}
    - craft_recipe: {"recipe_ref": "craft_..."}

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

# Register the human approval/login endpoint through MCPServer's public
# custom_route API. MCPServer.streamable_http_app() automatically includes
# registered custom routes alongside /authorize, /token and /mcp.
mcp.custom_route(
    "/oauth/approve",
    methods=["GET", "POST"],
)(oauth_approve)

mcp_http_app = mcp.streamable_http_app(
    stateless_http=True,
    transport_security=transport_security,
)


class TokenBasicClientIdCompat:
    """
    Compatibility shim for MCP Python SDK 2.2.0.

    Some OAuth clients correctly put confidential-client credentials only in
    Authorization: Basic. MCP Python SDK 2.2.0's server-side token handler
    nevertheless requires client_id to also exist in the form body.

    For POST /token only, if client_id is absent from the form body but a Basic
    Authorization header is present, copy only the client_id from that header
    into the form body. The client secret stays exclusively in the Basic
    header and is still verified by the SDK's normal ClientAuthenticator.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (
            scope.get("type") != "http"
            or scope.get("method") != "POST"
            or scope.get("path") != "/token"
        ):
            await self.app(scope, receive, send)
            return

        body_parts = []
        more_body = True

        while more_body:
            message = await receive()

            if message["type"] != "http.request":
                await self.app(scope, _single_message_receive(message), send)
                return

            body_parts.append(message.get("body", b""))
            more_body = bool(message.get("more_body", False))

        body = b"".join(body_parts)
        headers = list(scope.get("headers", []))
        header_map = {
            key.lower(): value
            for key, value in headers
        }

        content_type = header_map.get(b"content-type", b"").decode(
            "latin-1",
            errors="ignore",
        )
        auth_header = header_map.get(b"authorization", b"").decode(
            "latin-1",
            errors="ignore",
        )

        patched_body = body

        if (
            "application/x-www-form-urlencoded" in content_type
            and auth_header.startswith("Basic ")
        ):
            try:
                form = parse_qs(
                    body.decode("utf-8"),
                    keep_blank_values=True,
                )

                if "client_id" not in form:
                    encoded = auth_header[6:].strip()
                    decoded = base64.b64decode(encoded).decode("utf-8")

                    if ":" in decoded:
                        basic_client_id, _ = decoded.split(":", 1)
                        basic_client_id = unquote(basic_client_id)

                        if basic_client_id:
                            suffix = urlencode(
                                {"client_id": basic_client_id}
                            ).encode("utf-8")
                            patched_body = (
                                body + (b"&" if body else b"") + suffix
                            )

                            headers = [
                                (key, value)
                                for key, value in headers
                                if key.lower() != b"content-length"
                            ]
                            headers.append(
                                (
                                    b"content-length",
                                    str(len(patched_body)).encode("ascii"),
                                )
                            )
                            scope = dict(scope)
                            scope["headers"] = headers

                            print(
                                "[PzADA OAuth] /token: injected client_id "
                                "from HTTP Basic for MCP SDK 2.2.0 compatibility",
                                flush=True,
                            )
            except Exception as exc:
                print(
                    "[PzADA OAuth] /token compatibility shim skipped: "
                    f"{type(exc).__name__}",
                    flush=True,
                )

        sent = False

        async def patched_receive():
            nonlocal sent

            if not sent:
                sent = True
                return {
                    "type": "http.request",
                    "body": patched_body,
                    "more_body": False,
                }

            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        await self.app(scope, patched_receive, send)


def _single_message_receive(message):
    sent = False

    async def receive_once():
        nonlocal sent

        if not sent:
            sent = True
            return message

        return {
            "type": "http.request",
            "body": b"",
            "more_body": False,
        }

    return receive_once


mcp_http_app = TokenBasicClientIdCompat(mcp_http_app)


@asynccontextmanager
async def lifespan(app: Starlette):
    async with mcp.session_manager.run():
        yield


app = Starlette(
    routes=[
        Route("/", root_http, methods=["GET"]),
        Route(
            "/.well-known/oauth-authorization-server",
            oauth_metadata_http,
            methods=["GET"],
        ),
        Route(
            "/.well-known/oauth-protected-resource/mcp",
            protected_resource_metadata_http,
            methods=["GET"],
        ),
        Route("/health", health_http, methods=["GET"]),
        Route("/state", state_http, methods=["GET", "POST"]),
        Route("/command", command_http, methods=["GET", "POST"]),
        # Keep this mount LAST. Its internal Streamable HTTP endpoint is /mcp,
        # plus /authorize and /token. The explicit .well-known routes above
        # intentionally take precedence for ChatGPT discovery/validation.
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

    if not OAUTH_CONFIGURED:
        print(
            "[PzADA Relay] WARNING: OAuth is not fully configured. "
            "Set PZADA_OAUTH_CLIENT_ID, PZADA_OAUTH_CLIENT_SECRET, "
            "PZADA_OAUTH_PASSWORD and PZADA_OAUTH_REDIRECT_URI.",
            flush=True,
        )

    print(
        f"[PzADA Relay] listening on {HOST}:{PORT} with OAuth MCP at /mcp",
        flush=True,
    )

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level="info",
    )

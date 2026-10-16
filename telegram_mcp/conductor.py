"""Контракт кондуктора для telegram MCP.

Сервис живёт отдельно от кондуктора, поэтому подпись он проверяет по
опубликованным ключам (JWKS), а отзывы забирает списком: спрашивать
подтверждение на каждый вызов — это лишний хоп на каждый тул и зависимость
от кондуктора в горячем пути.

Права объявлены правилами по именам тулзов, а не списком из ста с лишним имён:
список пришлось бы править на каждое новое имя, а правило — нет. Тест
проверяет, что каждое настоящее имя попало ровно в одно правило.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

import httpx
import jwt

SERVER_ID = "telegram"
TITLE = "Telegram"
SCHEMA = 1
ALGORITHM = "EdDSA"

SCOPES: tuple[dict[str, object], ...] = (
    {
        "name": "telegram:read",
        "title": "Чтение чатов, контактов и сообщений",
        "group": "read",
        "default": True,
    },
    {
        "name": "telegram:send",
        "title": "Отправка сообщений, медиа и реакций",
        "group": "write",
        "default": False,
    },
    {
        "name": "telegram:manage",
        "title": "Удаление, блокировки, папки и настройки",
        "group": "write",
        "default": False,
    },
)

# Порядок проверок важен: имя попадает в первое подошедшее правило.
MANAGE_PREFIXES = (
    "delete_",
    "ban_",
    "unban_",
    "block_",
    "unblock_",
    "kick_",
    "leave_",
    "promote_",
    "demote_",
    "edit_admin",
    "edit_chat",
    "set_",
    "remove_",
    "add_",
    "create_",
    "import_",
    "export_",
    "reorder_",
    "clear_draft",
    "toggle_",
    "mute_",
    "unmute_",
    "archive_",
    "unarchive_",
    "unpin_",
)
SEND_PREFIXES = (
    "send_",
    "reply_",
    "forward_",
    "upload_",
    "pin_",
    "mark_as_read",
    "press_inline_button",
    "join_",
    "invite_",
    "subscribe_",
    "save_draft",
    "update_profile",
    "edit_message",
)
READ_PREFIXES = ("get_", "list_", "search_", "download_", "resolve_", "show_")


def scope_for(tool: str) -> str:
    """Какое право нужно этому тулзу. Пустая строка — правило не подошло."""
    for prefix in MANAGE_PREFIXES:
        if tool.startswith(prefix):
            return "telegram:manage"
    for prefix in SEND_PREFIXES:
        if tool.startswith(prefix):
            return "telegram:send"
    for prefix in READ_PREFIXES:
        if tool.startswith(prefix):
            return "telegram:read"
    return ""


# Список тулзов приходит из живого реестра сервера: он единственный знает,
# что объявлено на самом деле. Функция нужна, чтобы не тащить сервер сюда
# импортом и не плодить второй список.
_tool_source: Callable[[], list[str]] = lambda: []


def set_tool_source(source: Callable[[], list[str]]) -> None:
    global _tool_source
    _tool_source = source


def tool_names() -> list[str]:
    return sorted(_tool_source())


def unclassified(tools: list[str]) -> list[str]:
    """Тулзы, которым правило не нашлось: их видно, а не прячем."""
    return sorted(name for name in tools if not scope_for(name))


def version(tools: list[str] | None = None) -> str:
    """Отпечаток прав и тулзов: меняется вместе с их составом."""
    names = tool_names() if tools is None else tools
    canonical = json.dumps(
        {
            "schema": SCHEMA,
            "id": SERVER_ID,
            "scopes": [scope["name"] for scope in SCOPES],
            "tools": {name: scope_for(name) for name in sorted(names)},
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def build(public_url: str, issuer: str) -> dict:
    names = tool_names()
    return {
        "schema": SCHEMA,
        "id": SERVER_ID,
        "title": TITLE,
        "version": version(names),
        "auth": {"type": "conductor-jwt", "issuer": issuer.rstrip("/")},
        "scopes": [dict(scope) for scope in SCOPES],
        "credentials": {"server_side": True, "fields": []},
        "accounts": {"mode": "multiple", "label": "Аккаунт Telegram"},
        "tools": [
            {"name": name, "scopes": [scope_for(name)] if scope_for(name) else []}
            for name in names
        ],
        "health": {"path": "/health"},
        "drift": unclassified(names),
    }


# --- проверка токена ------------------------------------------------------


@dataclass
class Revocations:
    """Что сервис знает про отзывы. Обновляется списком, а не запросом."""

    jti: set[str] = field(default_factory=set)
    subjects: dict[str, float] = field(default_factory=dict)

    def covers(self, jti: str, subject: str, issued_at: int) -> bool:
        if jti and jti in self.jti:
            return True
        moment = self.subjects.get(subject)
        return moment is not None and moment >= issued_at


class ConductorTokenVerifier:
    """Проверка токена доступа: подпись по JWKS, claims, отзыв и права."""

    # Как часто переспрашивать список отзывов. Отзыв доходит за это время, а
    # хопа на каждый вызов нет.
    REVOCATION_TTL_SECONDS = 60
    KEYS_TTL_SECONDS = 3600

    def __init__(
        self,
        issuer: str,
        *,
        audience: str = SERVER_ID,
        service_token: str | None = None,
        key_provider: Callable[[str], Awaitable[object]] | None = None,
        revocation_provider: Callable[[], Awaitable[dict]] | None = None,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.service_token = service_token
        self._key_provider = key_provider or self._key_from_jwks
        self._revocation_provider = revocation_provider or self._revocations_from_conductor
        self._keys: dict[str, object] = {}
        self._keys_at = 0.0
        self._revoked = Revocations()
        self._revoked_at = 0.0

    # --- ключи ---

    async def _key_from_jwks(self, kid: str) -> object | None:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{self.issuer}/.well-known/jwks.json")
            response.raise_for_status()
            payload = response.json()
        for item in payload.get("keys", []):
            self._keys[str(item.get("kid"))] = jwt.PyJWK(item).key
        self._keys_at = time.monotonic()
        return self._keys.get(kid)

    async def _key(self, kid: str) -> object | None:
        stale = time.monotonic() - self._keys_at > self.KEYS_TTL_SECONDS
        if kid in self._keys and not stale:
            return self._keys[kid]
        return await self._key_provider(kid)

    # --- отзывы ---

    async def _revocations_from_conductor(self) -> dict:
        if not self.service_token:
            # Без сервисного токена список не спросить. Работать без него
            # нельзя: это означало бы «отзыв не действует вовсе».
            raise RuntimeError("нет CONDUCTOR_SERVICE_TOKEN: список отзывов недоступен")
        headers = {"Authorization": f"Bearer {self.service_token}"}
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{self.issuer}/state", headers=headers)
            response.raise_for_status()
            return response.json()

    async def _refresh(self) -> None:
        if time.monotonic() - self._revoked_at < self.REVOCATION_TTL_SECONDS:
            return
        payload = await self._revocation_provider()
        for row in payload.get("revoked", []):
            jti = row.get("jti")
            subject = row.get("subject")
            moment = row.get("revoked_at")
            if jti:
                self._revoked.jti.add(str(jti))
            if subject and moment:
                stamp = _epoch(moment)
                if stamp is not None:
                    self._revoked.subjects[str(subject)] = max(
                        stamp, self._revoked.subjects.get(str(subject), 0.0)
                    )
        self._revoked_at = time.monotonic()

    # --- сам токен ---

    async def verify_token(self, token: str):
        from mcp.server.auth.provider import AccessToken

        if token.count(".") != 2:
            return None

        try:
            header = jwt.get_unverified_header(token)
            key = await self._key(str(header.get("kid") or ""))
            if key is None:
                return None
            claims = jwt.decode(
                token,
                key,
                algorithms=[ALGORITHM],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "jti"]},
            )
        except jwt.InvalidTokenError:
            return None
        except Exception:  # сеть и всё прочее — токен не принят, причина в логе
            return None

        # Версия манифеста: изменились права или тулзы — токен пора перевыпустить.
        if str(claims.get("manifest_version") or "") != version():
            return None

        await self._refresh()
        if self._revoked.covers(
            str(claims.get("jti") or ""),
            str(claims.get("sub") or ""),
            int(claims.get("iat") or 0),
        ):
            return None

        scopes = [part for part in str(claims.get("scope") or "").split() if part]
        # В AccessToken этой версии SDK есть только token/client_id/scopes:
        # ни subject, ни claims туда не положить. Аккаунт и jti берутся из
        # самого токена там, где понадобятся (например, при обмене на креды).
        return AccessToken(
            token=token,
            client_id=str(claims.get("sub") or ""),
            scopes=scopes,
        )


def _epoch(moment: str) -> float | None:
    try:
        from datetime import datetime

        return datetime.fromisoformat(moment).timestamp()
    except ValueError:
        return None

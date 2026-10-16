"""Контракт кондуктора: правила прав, манифест и проверка токена."""

from __future__ import annotations

import ast
import base64
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from telegram_mcp import conductor


# --- правила прав --------------------------------------------------------


@pytest.mark.parametrize(
    "tool,expected",
    [
        ("get_chats", "telegram:read"),
        ("list_messages", "telegram:read"),
        ("search_global", "telegram:read"),
        ("download_media", "telegram:read"),
        ("send_message", "telegram:send"),
        ("reply_to_message", "telegram:send"),
        ("forward_message", "telegram:send"),
        ("pin_message", "telegram:send"),
        ("delete_message", "telegram:manage"),
        ("ban_user", "telegram:manage"),
        ("create_group", "telegram:manage"),
        ("set_privacy_settings", "telegram:manage"),
        ("leave_chat", "telegram:manage"),
    ],
)
def test_each_kind_of_tool_gets_its_scope(tool, expected):
    assert conductor.scope_for(tool) == expected


def test_an_unknown_name_is_reported_rather_than_guessed():
    assert conductor.scope_for("teleport_everywhere") == ""
    assert conductor.unclassified(["get_me", "teleport_everywhere"]) == [
        "teleport_everywhere"
    ]


def test_the_live_registry_has_no_unclassified_tools():
    """Главная проверка: ни один объявленный тул не остался без правила.

    Имена читаются из исходников разбором AST, а не импортом: сервер не
    поднимается без настоящей telegram-сессии, и проверка, которая для этого
    требует живой аккаунт, не запустилась бы никогда.
    """
    names = _declared_tool_names()
    assert names, "реестр тулзов пуст"
    assert conductor.unclassified(names) == []


def _declared_tool_names() -> list[str]:
    tools_dir = Path(__file__).resolve().parent.parent / "telegram_mcp" / "tools"
    names: list[str] = []
    for path in sorted(tools_dir.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(target, ast.Attribute) and target.attr == "tool":
                    names.append(node.name)
    return sorted(set(names))


def test_the_version_follows_the_tool_set():
    assert conductor.version(["get_me"]) == conductor.version(["get_me"])
    assert conductor.version(["get_me"]) != conductor.version(
        ["get_me", "send_message"]
    )


# --- манифест ------------------------------------------------------------


def test_the_manifest_declares_scopes_and_tools(monkeypatch):
    monkeypatch.setattr(
        conductor, "_tool_source", lambda: ["get_me", "send_message"]
    )
    payload = conductor.build("https://telegram.example", "https://conductor.example/")

    assert payload["id"] == "telegram"
    assert [scope["name"] for scope in payload["scopes"]] == [
        "telegram:read",
        "telegram:send",
        "telegram:manage",
    ]
    tools = {tool["name"]: tool["scopes"] for tool in payload["tools"]}
    assert tools == {"get_me": ["telegram:read"], "send_message": ["telegram:send"]}
    assert payload["drift"] == []
    assert payload["auth"]["issuer"] == "https://conductor.example"


# --- проверка токена -----------------------------------------------------


def _keypair():
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
    }
    return private, jwt.PyJWK(jwk).key


def _token(private, **overrides) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "iss": "https://conductor.example",
        "aud": "telegram",
        "sub": "device@example.com",
        "scope": "telegram:read",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": "abc",
        "manifest_version": conductor.version([]),
    }
    claims.update(overrides)
    return jwt.encode(claims, private, algorithm="EdDSA", headers={"kid": "test"})


async def _return(value):
    return value


async def _verify(private, token, revoked=None):
    # Ключ берём из своей пары, список отзывов — из аргумента: сеть и кондуктор
    # в этом тесте не участвуют.
    key = private.public_key()
    verifier = conductor.ConductorTokenVerifier(
        "https://conductor.example",
        key_provider=lambda kid: _return(key),
        revocation_provider=lambda: _return({"revoked": revoked or []}),
    )
    return await verifier.verify_token(token)


def test_a_valid_token_is_accepted():
    private, _ = _keypair()
    access = asyncio.run(_verify(private, _token(private)))
    assert access is not None
    assert access.client_id == "device@example.com"
    assert access.scopes == ["telegram:read"]


def test_a_token_for_another_service_is_refused():
    private, _ = _keypair()
    assert asyncio.run(_verify(private, _token(private, aud="storage"))) is None


def test_a_token_with_an_old_manifest_is_refused():
    private, _ = _keypair()
    assert (
        asyncio.run(_verify(private, _token(private, manifest_version="0000"))) is None
    )


def test_a_revoked_token_is_refused():
    private, _ = _keypair()
    revoked = [
        {
            "jti": "abc",
            "subject": None,
            "revoked_at": datetime.now(timezone.utc).isoformat(),
        }
    ]
    assert asyncio.run(_verify(private, _token(private), revoked=revoked)) is None

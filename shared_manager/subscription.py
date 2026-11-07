"""Revocable, single-account subscription links; no management token exposure."""
from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timezone

from fastapi import Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict

from .agent import AgentError
from .presentation import display_links


class SubscriptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rotate: bool = False


class SubscriptionView(BaseModel):
    url: str


def install_subscription_routes(app, store, agent, settings, current_user, authorize_write):
    with store.connection() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS subscriptions (
            user_id TEXT PRIMARY KEY REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE,
            encrypted_token BLOB NOT NULL)""")

    def lookup(user_id):
        with store.connection() as db:
            row = db.execute("SELECT encrypted_token FROM subscriptions WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "尚未生成订阅链接")
        value = row[0]
        token = store.cipher.decrypt(value[:12], value[12:], ("subscription:" + user_id).encode()).decode()
        return SubscriptionView(url=settings.origin + "/subscription/" + token)

    @app.get("/api/me/subscription", response_model=SubscriptionView)
    def read_subscription(user=Depends(current_user)):
        return lookup(user["id"])

    @app.post("/api/me/subscription", response_model=SubscriptionView)
    def issue_subscription(body: SubscriptionRequest, user=Depends(authorize_write)):
        profiles = store.list_profiles(user["id"])
        if not any(profile["ready"] for profile in profiles):
            raise HTTPException(409, "请先生成三协议连接")
        store.throttle("subscription-issue", user["id"], 30, 900)
        with store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT user_id FROM subscriptions WHERE user_id=?", (user["id"],)).fetchone()
            if body.rotate or not row:
                token = secrets.token_urlsafe(32)
                nonce = secrets.token_bytes(12)
                cipher = nonce + store.cipher.encrypt(nonce, token.encode(), ("subscription:" + user["id"]).encode())
                db.execute("""INSERT INTO subscriptions VALUES (?, ?, ?) ON CONFLICT(user_id)
                    DO UPDATE SET token_hash=excluded.token_hash, encrypted_token=excluded.encrypted_token""",
                    (user["id"], hashlib.sha256(token.encode()).hexdigest(), cipher))
        return lookup(user["id"])

    @app.get("/subscription/{token}", response_class=PlainTextResponse,
             responses={200: {"content": {"text/plain": {"schema": {"type": "string"}}},
                              "description": "账号全部连接的 VLESS、VMess、SOCKS5 订阅"}})
    def fetch_subscription(token: str):
        if len(token) != 43 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in token):
            raise HTTPException(404, "订阅不存在或已失效")
        digest = hashlib.sha256(token.encode()).hexdigest()
        with store.connection() as db:
            row = db.execute("""SELECT u.id FROM users u JOIN subscriptions s ON s.user_id=u.id
                WHERE s.token_hash=? AND u.enabled=1""", (digest,)).fetchone()
        if not row:
            raise HTTPException(404, "订阅不存在或已失效")
        store.throttle("subscription-fetch", digest, 120, 900)
        profiles = [profile for profile in store.list_profiles(row[0]) if profile["ready"]]
        if not profiles:
            raise HTTPException(404, "订阅暂不可用")
        values = []
        name_counts = {}
        for profile in profiles:
            name_counts[profile["name"]] = name_counts.get(profile["name"], 0) + 1
        for profile in profiles:
            try:
                result = agent.connections(profile)
                # Distinguish identically named connections in client lists
                # without exposing a node ID, UUID or network topology.
                name = profile["name"]
                if name_counts[name] > 1:
                    name += " [" + hashlib.sha256(profile["id"].encode()).hexdigest()[:6] + "]"
                values.extend(link["uri"] for link in display_links(result, name))
            except AgentError as exc:
                # One naturally expired connection must not break the account's
                # still-active connections. Confirmed renewal responses above
                # are kept even if the original create request was older.
                try:
                    expiry = datetime.fromisoformat(profile["request"]["expiresAt"].replace("Z", "+00:00"))
                    expired = expiry.astimezone(timezone.utc) <= datetime.now(timezone.utc)
                except (KeyError, ValueError, TypeError):
                    expired = False
                if exc.status == 409 and expired:
                    continue
                raise HTTPException(503 if exc.status >= 500 else 403, "订阅暂不可用，请联系管理员") from None
        if not values:
            raise HTTPException(403, "订阅中暂时没有可用连接")
        encoded = base64.b64encode(("\n".join(values) + "\n").encode()).decode()
        return PlainTextResponse(encoded, headers={"profile-update-interval": "12", "content-disposition": 'inline; filename="shared-node.txt"'})

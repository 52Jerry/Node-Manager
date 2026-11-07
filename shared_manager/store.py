from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import time
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .settings import Settings
from .json_database import JsonDatabase


def password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600000)
    return f"pbkdf2-sha256$600000${salt}${digest.hex()}"


def password_matches(password: str, encoded: str) -> bool:
    _, rounds, salt, expected = encoded.split("$")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
    return hmac.compare_digest(digest.hex(), expected)


class CapacityError(Exception):
    pass


class RateLimited(Exception):
    pass


class PendingUpstream(Exception):
    pass


class ProfileConflict(Exception):
    pass


class ProfileNotFound(LookupError):
    pass


class ProfileDeleting(ProfileConflict):
    pass


class Store:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.key = hashlib.sha256(("shared-portal-v1:" + settings.secret).encode()).digest()
        self.cipher = AESGCM(self.key)
        settings.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.json_database = JsonDatabase(settings.database) if settings.database.suffix.lower() == ".json" else None
        if self.json_database is None:
            # Legacy SQLite remains available only for explicit migration paths.
            descriptor = os.open(settings.database, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(descriptor)
            os.chmod(settings.database, 0o600)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL, created_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                    is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0, 1)));
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
                    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS allocations (
                    user_id TEXT PRIMARY KEY REFERENCES users(id), node_user_id TEXT NOT NULL UNIQUE,
                    payload BLOB NOT NULL, ready INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, until_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS upstreams (
                    user_id TEXT PRIMARY KEY REFERENCES users(id), applied BLOB,
                    pending BLOB, pending_id TEXT, pending_fingerprint TEXT);
                CREATE TABLE IF NOT EXISTS profiles (
                    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id),
                    name TEXT NOT NULL, created_at INTEGER NOT NULL,
                    node_user_id TEXT NOT NULL UNIQUE, payload BLOB NOT NULL,
                    ready INTEGER NOT NULL DEFAULT 0, deleting INTEGER NOT NULL DEFAULT 0,
                    policy_limit INTEGER);
                CREATE INDEX IF NOT EXISTS profiles_owner ON profiles(owner_id, created_at, id);
                CREATE TABLE IF NOT EXISTS profile_upstreams (
                    profile_id TEXT PRIMARY KEY REFERENCES profiles(id), applied BLOB,
                    pending BLOB, pending_id TEXT, pending_fingerprint TEXT);
                CREATE TABLE IF NOT EXISTS profile_create_requests (
                    owner_id TEXT NOT NULL REFERENCES users(id), key_hash TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, profile_id TEXT NOT NULL,
                    quota_version INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY(owner_id, key_hash));
                CREATE TABLE IF NOT EXISTS profile_tombstones (
                    profile_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id),
                    node_user_id TEXT NOT NULL UNIQUE, deleted_at INTEGER NOT NULL);
            """)
            db.execute("BEGIN IMMEDIATE")
            fingerprint = hashlib.sha256(self.key).hexdigest()
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('key_fingerprint', ?)", (fingerprint,))
            if db.execute("SELECT value FROM metadata WHERE key='key_fingerprint'").fetchone()[0] != fingerprint:
                raise ValueError("SHARED_SECRET 与账号数据库不匹配，请恢复原密钥")
            user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
            if "is_admin" not in user_columns:
                # Existing accounts remain ordinary users until explicitly granted.
                db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0, 1))")
            profile_columns = {row[1] for row in db.execute("PRAGMA table_info(profiles)")}
            if "policy_limit" not in profile_columns:
                db.execute("ALTER TABLE profiles ADD COLUMN policy_limit INTEGER")
            request_columns = {row[1] for row in db.execute("PRAGMA table_info(profile_create_requests)")}
            if "quota_version" not in request_columns:
                db.execute("ALTER TABLE profile_create_requests ADD COLUMN quota_version INTEGER NOT NULL DEFAULT 1")
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('instance_id', ?)", (secrets.token_hex(8),))
            self.instance_id = db.execute("SELECT value FROM metadata WHERE key='instance_id'").fetchone()[0]
            if not db.execute("SELECT 1 FROM metadata WHERE key='profiles_migration_v1'").fetchone():
                # IDs deliberately match the old owners so upstream ciphertext
                # AAD and all durable node identities stay byte-for-byte valid.
                db.execute("""INSERT INTO profiles (id, owner_id, name, created_at, node_user_id, payload, ready)
                              SELECT a.user_id, a.user_id, '默认连接', u.created_at,
                                     a.node_user_id, a.payload, a.ready
                              FROM allocations a JOIN users u ON u.id=a.user_id""")
                db.execute("""INSERT INTO profile_upstreams (profile_id, applied, pending, pending_id, pending_fingerprint)
                              SELECT x.user_id, x.applied, x.pending, x.pending_id, x.pending_fingerprint
                              FROM upstreams x JOIN profiles p ON p.id=x.user_id""")
                db.execute("INSERT INTO metadata VALUES ('profiles_migration_v1', 'done')")
        self.dummy_hash = password_hash(secrets.token_urlsafe(24))

    @contextmanager
    def connection(self):
        if self.json_database is not None:
            with self.json_database.connection() as db:
                yield db
            return
        db = sqlite3.connect(self.settings.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def throttle(self, bucket: str, subject: str, limit: int, window: int):
        key = hmac.new(self.key, (bucket + ":" + subject).encode(), "sha256").hexdigest()
        now = int(time.time())
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM rate_limits WHERE until_at <= ?", (now,))
            row = db.execute("SELECT count FROM rate_limits WHERE key=?", (key,)).fetchone()
            if row and row[0] >= limit:
                raise RateLimited()
            db.execute("INSERT INTO rate_limits VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET count=count+1", (key, now + window))

    def register(self, username: str, password: str):
        encoded = password_hash(password)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT count(*) FROM users").fetchone()[0] >= self.settings.max_accounts:
                raise CapacityError()
            user_id = uuid.uuid4().hex
            db.execute("INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                       (user_id, username.lower(), encoded, int(time.time())))
            return dict(db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())

    def authenticate(self, username: str, password: str):
        with self.connection() as db:
            row = db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username.lower(),)).fetchone()
        valid = password_matches(password, row["password_hash"] if row else self.dummy_hash)
        return dict(row) if row and valid and row["enabled"] else None

    def set_admin(self, username: str, enabled: bool = True) -> bool:
        """Grant or revoke an existing account's role from trusted offline code.

        Registration and HTTP endpoints never call this method. The role belongs
        to the durable account, so existing sessions observe grants and revokes.
        """
        if type(enabled) is not bool:
            raise ValueError("管理员权限须为布尔值")
        with self.connection() as db:
            result = db.execute("UPDATE users SET is_admin=? WHERE username=? COLLATE NOCASE",
                                (int(enabled), username.lower()))
            return result.rowcount == 1

    def admin_users(self, search: str = "", page: int = 1, page_size: int = 20) -> dict:
        """Return a credential-free account/count overview from one read snapshot.

        One profile is one connection group. A deleting group is counted only
        in total/deleting, never again as ready or pending. The global summary
        deliberately remains unchanged when the user list is filtered.
        """
        if not isinstance(search, str) or len(search) > 64:
            raise ValueError("搜索内容不能超过 64 字符")
        if type(page) is not int or not 1 <= page <= 1000000 or type(page_size) is not int or not 1 <= page_size <= 100:
            raise ValueError("分页参数无效")
        escaped = search.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = "%" + escaped + "%"
        with self.connection() as db:
            # SQLite otherwise starts no read transaction for independent SELECTs.
            db.execute("BEGIN")
            users = db.execute("""SELECT count(*) AS registered,
                                  coalesce(sum(CASE WHEN enabled=1 THEN 1 ELSE 0 END), 0) AS enabled
                                  FROM users""").fetchone()
            connections = db.execute("""SELECT count(*) AS total,
                coalesce(sum(CASE WHEN ready=1 AND deleting=0 THEN 1 ELSE 0 END), 0) AS ready,
                coalesce(sum(CASE WHEN ready=0 AND deleting=0 THEN 1 ELSE 0 END), 0) AS pending,
                coalesce(sum(CASE WHEN deleting=1 THEN 1 ELSE 0 END), 0) AS deleting
                FROM profiles""").fetchone()
            total = db.execute("SELECT count(*) FROM users WHERE username LIKE ? ESCAPE '\\'",
                               (pattern,)).fetchone()[0]
            rows = db.execute("""SELECT u.username, u.created_at, u.enabled, u.is_admin,
                count(p.id) AS total_connections,
                sum(CASE WHEN p.ready=1 AND p.deleting=0 THEN 1 ELSE 0 END) AS ready_connections,
                sum(CASE WHEN p.ready=0 AND p.deleting=0 THEN 1 ELSE 0 END) AS pending_connections,
                sum(CASE WHEN p.deleting=1 THEN 1 ELSE 0 END) AS deleting_connections
                FROM users u LEFT JOIN profiles p ON p.owner_id=u.id
                WHERE u.username LIKE ? ESCAPE '\\'
                GROUP BY u.id ORDER BY u.created_at DESC, u.id
                LIMIT ? OFFSET ?""", (pattern, page_size, (page - 1) * page_size)).fetchall()
        return {
            "summary": {"registeredUsers": users["registered"], "enabledUsers": users["enabled"],
                        "totalConnections": connections["total"], "readyConnections": connections["ready"],
                        "pendingConnections": connections["pending"], "deletingConnections": connections["deleting"]},
            "items": [{"username": row["username"],
                       "createdAt": datetime.fromtimestamp(row["created_at"], timezone.utc).isoformat(),
                       "enabled": bool(row["enabled"]), "isAdmin": bool(row["is_admin"]),
                       "totalConnections": row["total_connections"], "readyConnections": row["ready_connections"],
                       "pendingConnections": row["pending_connections"], "deletingConnections": row["deleting_connections"]}
                      for row in rows],
            "total": total, "page": page, "pageSize": page_size,
            "totalPages": max(1, (total + page_size - 1) // page_size),
        }

    def create_session(self, user_id: str):
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            db.execute("DELETE FROM sessions WHERE user_id=? AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC, rowid DESC LIMIT 4)", (user_id, user_id))
            db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                       (hashlib.sha256(token.encode()).hexdigest(), user_id, now, now + self.settings.session_seconds))
        return token

    def session_user(self, token: str):
        if not token or len(token) > 128:
            return None
        with self.connection() as db:
            row = db.execute("""SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id
                                WHERE s.token_hash=? AND s.expires_at>? AND u.enabled=1""",
                             (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))).fetchone()
            return dict(row) if row else None

    def revoke_session(self, token: str):
        with self.connection() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))

    def csrf(self, token: str):
        return hmac.new(self.key, ("csrf:" + token).encode(), "sha256").hexdigest()

    def _profile_dict(self, row):
        if row is None:
            return None
        result = dict(row)
        encrypted = result.pop("payload")
        result["request"] = json.loads(self.cipher.decrypt(encrypted[:12], encrypted[12:], result["node_user_id"].encode()))
        result["traffic_limit_bytes"] = (result["policy_limit"] if result.get("policy_limit") is not None
                                         else result["request"].get("trafficLimitBytes", self.settings.traffic_limit_bytes))
        result["idempotency_key"] = "shared-create:" + result["node_user_id"]
        result["user_id"] = result["owner_id"]
        return result

    def list_profiles(self, owner_id: str, include_deleting: bool = False):
        with self.connection() as db:
            rows = db.execute("SELECT * FROM profiles WHERE owner_id=? AND (? OR deleting=0) ORDER BY created_at, rowid", (owner_id, int(include_deleting))).fetchall()
        return [self._profile_dict(row) for row in rows]

    def get_profile(self, owner_id: str, profile_id: str):
        with self.connection() as db:
            row = db.execute("SELECT * FROM profiles WHERE id=? AND owner_id=?", (profile_id, owner_id)).fetchone()
        return self._profile_dict(row)

    @staticmethod
    def _profile_name(name):
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 64 or any(ord(char) < 32 for char in name):
            raise ValueError("连接名称须为 1–64 个可见字符")
        return name.strip()

    @staticmethod
    def _initial_proxy(payload):
        if payload is None:
            return None
        if not isinstance(payload, dict) or payload.get("mode") != "socks5":
            raise ValueError("初始住宅代理配置无效")
        values = {key: payload.get(key) for key in ("server", "resolvedServer", "port", "username", "password")}
        if any(not isinstance(values[key], str) for key in ("server", "resolvedServer", "username", "password")):
            raise ValueError("初始住宅代理配置无效")
        if not values["server"] or type(values["port"]) is not int or not 1 <= values["port"] <= 65535:
            raise ValueError("初始住宅代理配置无效")
        try:
            address = ipaddress.ip_address(values["resolvedServer"])
        except ValueError:
            raise ValueError("初始住宅代理必须固定到公网地址") from None
        if not address.is_global or address.is_multicast:
            raise ValueError("初始住宅代理必须固定到公网地址")
        if bool(values["username"]) != bool(values["password"]) or max(len(values["username"].encode()), len(values["password"].encode())) > 255:
            raise ValueError("初始住宅代理认证无效")
        return {"mode": "socks5", **values}

    @staticmethod
    def _traffic_limit(value):
        if type(value) is not int or not 1 <= value <= 9007199254740991:
            raise ValueError("流量额度须为有效的正整数字节数")
        return value

    def _insert_profile(self, db, owner_id, profile_id, name, initial_proxy=None, traffic_limit_bytes=None):
        if db.execute("SELECT count(*) FROM profiles WHERE owner_id=?", (owner_id,)).fetchone()[0] >= 100:
            raise CapacityError()
        node_id = f"shared-{self.instance_id}-{profile_id}"
        payload = {"userId": node_id, "uuid": str(uuid.uuid4()), "protocols": ["vless", "vmess", "socks"],
                   "socksUsername": f"shared-{self.instance_id}-{profile_id[:16]}", "socksPassword": secrets.token_urlsafe(24),
                   "trafficLimitBytes": self._traffic_limit(self.settings.traffic_limit_bytes if traffic_limit_bytes is None else traffic_limit_bytes),
                   "maxSourceIps": self.settings.max_source_ips,
                   "expiresAt": datetime.fromtimestamp(time.time() + self.settings.lifetime_days * 86400, timezone.utc).isoformat(),
                   "requireReadiness": True}
        if initial_proxy:
            # Node Manager creates users and their first residential route in
            # one configuration transaction. A failed bind cannot leave a
            # newly imported identity silently serving the default exit.
            payload["proxy"] = {"type": "socks5", "server": initial_proxy["resolvedServer"],
                                "port": initial_proxy["port"], "username": initial_proxy["username"],
                                "password": initial_proxy["password"]}
        nonce = secrets.token_bytes(12)
        encrypted = nonce + self.cipher.encrypt(nonce, json.dumps(payload).encode(), node_id.encode())
        db.execute("""INSERT INTO profiles (id, owner_id, name, created_at, node_user_id, payload)
                      VALUES (?, ?, ?, ?, ?, ?)""", (profile_id, owner_id, name, int(time.time()), node_id, encrypted))
        if initial_proxy:
            operation_id = uuid.uuid4().hex
            identity = {key: value for key, value in initial_proxy.items() if key != "resolvedServer"}
            fingerprint = hmac.new(self.key, json.dumps(identity, sort_keys=True).encode(), "sha256").hexdigest()
            db.execute("INSERT INTO profile_upstreams (profile_id, pending, pending_id, pending_fingerprint) VALUES (?, ?, ?, ?)",
                       (profile_id, self._encrypt_upstream(profile_id, initial_proxy), operation_id, fingerprint))
        if profile_id == owner_id:
            db.execute("INSERT INTO allocations (user_id, node_user_id, payload) VALUES (?, ?, ?)", (owner_id, node_id, encrypted))
        return db.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()

    def create_profile(self, owner_id: str, name: str, idempotency_key: str | None = None, initial_proxy: dict | None = None,
                       traffic_limit_bytes: int | None = None):
        name = self._profile_name(name)
        initial_proxy = self._initial_proxy(initial_proxy)
        if traffic_limit_bytes is not None:
            self._traffic_limit(traffic_limit_bytes)
        if idempotency_key is not None and (not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 128):
            raise ValueError("无效的连接创建请求标识")
        key_hash = hmac.new(self.key, ("profile-create:" + (idempotency_key or "")).encode(), "sha256").hexdigest()
        identity = {"name": name}
        if initial_proxy:
            identity["initial_proxy"] = {key: value for key, value in initial_proxy.items() if key != "resolvedServer"}
        def fingerprint(quota=None):
            payload = identity if quota is None else {**identity, "traffic_limit_bytes": quota}
            return hmac.new(self.key, json.dumps(payload, sort_keys=True).encode(), "sha256").hexdigest()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM users WHERE id=? AND enabled=1", (owner_id,)).fetchone():
                raise ProfileNotFound()
            if idempotency_key is not None:
                prior = db.execute("SELECT * FROM profile_create_requests WHERE owner_id=? AND key_hash=?", (owner_id, key_hash)).fetchone()
                if prior:
                    row = db.execute("SELECT * FROM profiles WHERE owner_id=? AND id=?", (owner_id, prior["profile_id"])).fetchone()
                    if not row or row["deleting"]:
                        raise ProfileConflict("原请求的连接已删除或正在删除")
                    profile = self._profile_dict(row)
                    original_quota = profile["request"].get("trafficLimitBytes", self.settings.traffic_limit_bytes)
                    # Omitted values mean the originally admitted default,
                    # never the current installation default or later override.
                    requested_quota = original_quota if traffic_limit_bytes is None else traffic_limit_bytes
                    expected = fingerprint(requested_quota) if prior["quota_version"] >= 2 else fingerprint()
                    if (not hmac.compare_digest(prior["fingerprint"], expected)
                            or (prior["quota_version"] < 2 and requested_quota != original_quota)):
                        raise ProfileConflict("相同创建标识的内容不同")
                    return profile
            chosen_quota = self._traffic_limit(self.settings.traffic_limit_bytes if traffic_limit_bytes is None else traffic_limit_bytes)
            row = self._insert_profile(db, owner_id, uuid.uuid4().hex, name, initial_proxy, chosen_quota)
            if idempotency_key is not None:
                db.execute("""INSERT INTO profile_create_requests (owner_id, key_hash, fingerprint, profile_id, quota_version)
                              VALUES (?, ?, ?, ?, 2)""", (owner_id, key_hash, fingerprint(chosen_quota), row["id"]))
            return self._profile_dict(row)

    def allocation(self, user_id: str, create: bool = False):
        """Compatibility: the first profile remains the old account endpoint."""
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM profiles WHERE owner_id=? ORDER BY (id=owner_id) DESC, rowid LIMIT 1", (user_id,)).fetchone()
            if row and row["deleting"]:
                raise ProfileDeleting()
            if not row and create:
                deleted = db.execute("SELECT 1 FROM profile_tombstones WHERE profile_id=?", (user_id,)).fetchone()
                row = self._insert_profile(db, user_id, uuid.uuid4().hex if deleted else user_id, "默认连接")
            return self._profile_dict(row)

    def mark_profile_ready(self, owner_id: str, profile_id: str):
        with self.connection() as db:
            changed = db.execute("UPDATE profiles SET ready=1 WHERE id=? AND owner_id=? AND deleting=0", (profile_id, owner_id)).rowcount
            if changed and profile_id == owner_id:
                db.execute("UPDATE allocations SET ready=1 WHERE user_id=?", (owner_id,))
            return bool(changed)

    def mark_ready(self, user_id: str):
        allocation = self.allocation(user_id)
        if allocation:
            return self.mark_profile_ready(user_id, allocation["id"])
        return False

    def rename_profile(self, owner_id: str, profile_id: str, name: str):
        name = self._profile_name(name)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._owned_profile(db, owner_id, profile_id, mutate=True)
            db.execute("UPDATE profiles SET name=? WHERE id=?", (name, row["id"]))
            return self._profile_dict(db.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone())

    def update_profile_policy(self, owner_id: str, profile_id: str, traffic_limit_bytes: int):
        """Record only a remotely confirmed override; creation stays immutable."""
        traffic_limit_bytes = self._traffic_limit(traffic_limit_bytes)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._owned_profile(db, owner_id, profile_id, mutate=True)
            if not row["ready"]:
                raise ProfileConflict("请先完成连接生成，再修改流量额度")
            db.execute("UPDATE profiles SET policy_limit=? WHERE owner_id=? AND id=?", (traffic_limit_bytes, owner_id, profile_id))
            return self._profile_dict(db.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone())

    def set_profile_traffic_limit(self, owner_id: str, profile_id: str, traffic_limit_bytes: int):
        return self.update_profile_policy(owner_id, profile_id, traffic_limit_bytes)

    def get_profile_policy(self, owner_id: str, profile_id: str):
        profile = self.get_profile(owner_id, profile_id)
        if profile is None:
            raise ProfileNotFound()
        return {"trafficLimitBytes": profile["traffic_limit_bytes"]}

    @staticmethod
    def _owned_profile(db, owner_id, profile_id, mutate=False):
        row = db.execute("SELECT * FROM profiles WHERE id=? AND owner_id=?", (profile_id, owner_id)).fetchone()
        if not row:
            raise ProfileNotFound()
        if mutate and row["deleting"]:
            raise ProfileDeleting()
        return row

    def begin_delete_profile(self, owner_id: str, profile_id: str):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._owned_profile(db, owner_id, profile_id)
            upstream = db.execute("SELECT * FROM profile_upstreams WHERE profile_id=?", (profile_id,)).fetchone()
            if upstream and upstream["pending_id"]:
                request_proxy = self._profile_dict(row)["request"].get("proxy")
                desired = self._decrypt_upstream(profile_id, upstream["pending"])
                initial_proxy = ({"type": "socks5", "server": desired.get("resolvedServer"),
                                  "port": desired.get("port"), "username": desired.get("username"),
                                  "password": desired.get("password")}
                                 if desired and desired.get("mode") == "socks5" else None)
                # A failed first atomic create can be reconciled by its same
                # immutable identity before remote deletion. An unrelated
                # later route mutation must still settle before deleting.
                if row["ready"] or not request_proxy or request_proxy != initial_proxy:
                    raise PendingUpstream()
            db.execute("UPDATE profiles SET deleting=1 WHERE id=?", (profile_id,))
            result = self._profile_dict(row)
            result["deleting"] = 1
            return result

    def delete_profile(self, owner_id: str, profile_id: str):
        """Complete deletion only after the caller confirms remote removal."""
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._owned_profile(db, owner_id, profile_id)
            if not row["deleting"]:
                raise ProfileConflict("删除前必须先冻结该连接")
            db.execute("INSERT INTO profile_tombstones VALUES (?, ?, ?, ?)", (profile_id, owner_id, row["node_user_id"], int(time.time())))
            db.execute("DELETE FROM profile_upstreams WHERE profile_id=?", (profile_id,))
            db.execute("DELETE FROM profiles WHERE id=? AND owner_id=?", (profile_id, owner_id))
            if profile_id == owner_id:
                db.execute("DELETE FROM upstreams WHERE user_id=?", (owner_id,))
                db.execute("DELETE FROM allocations WHERE user_id=?", (owner_id,))

    def _encrypt_upstream(self, user_id, payload):
        nonce = secrets.token_bytes(12)
        return nonce + self.cipher.encrypt(nonce, json.dumps(payload, sort_keys=True).encode(), ("upstream:" + user_id).encode())

    def _decrypt_upstream(self, user_id, encrypted):
        if not encrypted:
            return None
        return json.loads(self.cipher.decrypt(encrypted[:12], encrypted[12:], ("upstream:" + user_id).encode()))

    def get_profile_upstream(self, owner_id: str, profile_id: str):
        with self.connection() as db:
            self._owned_profile(db, owner_id, profile_id)
            row = db.execute("SELECT * FROM profile_upstreams WHERE profile_id=?", (profile_id,)).fetchone()
        if not row:
            return {"applied": {"mode": "direct"}, "pending": None, "pending_id": None}
        return {"applied": self._decrypt_upstream(profile_id, row["applied"]) or {"mode": "direct"},
                "pending": self._decrypt_upstream(profile_id, row["pending"]), "pending_id": row["pending_id"]}

    @staticmethod
    def _mirror_legacy_upstream(db, owner_id, profile_id):
        if owner_id == profile_id:
            row = db.execute("SELECT * FROM profile_upstreams WHERE profile_id=?", (profile_id,)).fetchone()
            if row:
                db.execute("""INSERT INTO upstreams VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET
                              applied=excluded.applied, pending=excluded.pending, pending_id=excluded.pending_id,
                              pending_fingerprint=excluded.pending_fingerprint""",
                           (owner_id, row["applied"], row["pending"], row["pending_id"], row["pending_fingerprint"]))

    def prepare_profile_upstream(self, owner_id: str, profile_id: str, payload: dict):
        """Durably fix one mutation identity before contacting the node.

        Retries compare the original host and credentials, retaining the pinned
        DNS address from the first attempt. Conflicting changes cannot overtake
        an unconfirmed write.
        """
        identity = {key: value for key, value in payload.items() if key != "resolvedServer"}
        fingerprint = hmac.new(self.key, json.dumps(identity, sort_keys=True).encode(), "sha256").hexdigest()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._owned_profile(db, owner_id, profile_id, mutate=True)
            row = db.execute("SELECT * FROM profile_upstreams WHERE profile_id=?", (profile_id,)).fetchone()
            if row and row["pending_id"]:
                if not hmac.compare_digest(row["pending_fingerprint"], fingerprint):
                    raise PendingUpstream()
                return {"payload": self._decrypt_upstream(profile_id, row["pending"]), "operation_id": row["pending_id"]}
            operation_id = uuid.uuid4().hex
            db.execute("""INSERT INTO profile_upstreams (profile_id, pending, pending_id, pending_fingerprint) VALUES (?, ?, ?, ?)
                          ON CONFLICT(profile_id) DO UPDATE SET pending=excluded.pending, pending_id=excluded.pending_id,
                          pending_fingerprint=excluded.pending_fingerprint""",
                       (profile_id, self._encrypt_upstream(profile_id, payload), operation_id, fingerprint))
            self._mirror_legacy_upstream(db, owner_id, profile_id)
            return {"payload": payload, "operation_id": operation_id}

    def apply_profile_upstream(self, owner_id: str, profile_id: str, operation_id: str):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._owned_profile(db, owner_id, profile_id, mutate=True)
            db.execute("""UPDATE profile_upstreams SET applied=pending, pending=NULL, pending_id=NULL, pending_fingerprint=NULL
                          WHERE profile_id=? AND pending_id=?""", (profile_id, operation_id))
            self._mirror_legacy_upstream(db, owner_id, profile_id)

    def reject_profile_upstream(self, owner_id: str, profile_id: str, operation_id: str):
        """Release an operation proven rejected before publication."""
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._owned_profile(db, owner_id, profile_id, mutate=True)
            db.execute("""UPDATE profile_upstreams SET pending=NULL, pending_id=NULL, pending_fingerprint=NULL
                          WHERE profile_id=? AND pending_id=?""", (profile_id, operation_id))
            self._mirror_legacy_upstream(db, owner_id, profile_id)

    def upstream(self, user_id: str):
        allocation = self.allocation(user_id)
        if not allocation:
            return {"applied": {"mode": "direct"}, "pending": None, "pending_id": None}
        return self.get_profile_upstream(user_id, allocation["id"])

    def prepare_upstream(self, user_id: str, payload: dict):
        allocation = self.allocation(user_id)
        if not allocation:
            raise ProfileNotFound()
        return self.prepare_profile_upstream(user_id, allocation["id"], payload)

    def apply_upstream(self, user_id: str, operation_id: str):
        allocation = self.allocation(user_id)
        if not allocation:
            raise ProfileNotFound()
        return self.apply_profile_upstream(user_id, allocation["id"], operation_id)

    def reject_upstream(self, user_id: str, operation_id: str):
        allocation = self.allocation(user_id)
        if not allocation:
            raise ProfileNotFound()
        return self.reject_profile_upstream(user_id, allocation["id"], operation_id)

#!/usr/bin/env python3
import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import asyncpg


BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
USER_ACTIONS_LOG_DIR = BASE_DIR / "var" / "log" / "actions"
SESSION_COOKIE = "bankweb_session"
SESSION_TTL_DAYS = 7
PBKDF2_ITERATIONS = 240_000
MAX_USER_ACCOUNTS = 3
BANKWEB_ENV = BASE_DIR / ".env"
ROOT_USERNAME = "root"
ROOT_EMAIL = "root@bankweb.local"


def load_env_file(path: Path, override: bool = False) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if override or key not in os.environ:
            os.environ[key] = value


load_env_file(BANKWEB_ENV, override=True)


DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "127.0.0.1"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "user": os.getenv("POSTGRES_USER", "database"),
    "password": os.getenv("POSTGRES_PASSWORD", ""),
    "database": os.getenv("POSTGRES_DB", "sunboy"),
    "command_timeout": float(os.getenv("POSTGRES_COMMAND_TIMEOUT", "30")),
}

ROOT_PASSWORD = os.getenv("BANKWEB_ROOT_PASSWORD", "")
if not ROOT_PASSWORD:
    raise RuntimeError("BANKWEB_ROOT_PASSWORD must be set in /home/www/bankweb/.env")

LOG_LOCK = threading.Lock()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def format_log_value(value):
    if value is None or value == "":
        return "-"
    return str(value).replace("\n", " ").replace("\r", " ")


def actor_label(actor):
    if not actor:
        return "anonymous"
    if isinstance(actor, dict):
        return "{}#{}<{}>".format(
            format_log_value(actor.get("username") or actor.get("email") or "user"),
            format_log_value(actor.get("id")),
            format_log_value(actor.get("role")),
        )
    return f"user#{format_log_value(actor)}"


def append_user_action(entry):
    timestamp = utcnow()
    USER_ACTIONS_LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = USER_ACTIONS_LOG_DIR / f"{timestamp.date().isoformat()}.log"
    source = entry.get("source", "action").upper()

    if entry.get("source") == "api":
        line = (
            "[{time}] API {method} {path} status={status} actor={actor} "
            "ip={ip} user_agent=\"{user_agent}\""
        ).format(
            time=timestamp.isoformat(),
            method=format_log_value(entry.get("method")),
            path=format_log_value(entry.get("path")),
            status=format_log_value(entry.get("status")),
            actor=actor_label(entry.get("actor")),
            ip=format_log_value(entry.get("ip")),
            user_agent=format_log_value(entry.get("userAgent")),
        )
        if entry.get("error"):
            line += f" error=\"{format_log_value(entry['error'])}\""
    elif entry.get("source") == "audit":
        metadata = entry.get("metadata") or {}
        line = (
            "[{time}] AUDIT action={action} actor={actor} entity={entity_type}:{entity_id} "
            "metadata={metadata}"
        ).format(
            time=timestamp.isoformat(),
            action=format_log_value(entry.get("action")),
            actor=actor_label(entry.get("actorUserId")),
            entity_type=format_log_value(entry.get("entityType")),
            entity_id=format_log_value(entry.get("entityId")),
            metadata=json.dumps(metadata, ensure_ascii=False, default=str),
        )
    else:
        line = f"[{timestamp.isoformat()}] {source} {entry}"

    with LOG_LOCK:
        with log_path.open("a", encoding="utf-8") as file:
            file.write(line + "\n")


def json_dumps(payload):
    return json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iteration_text, salt_text, digest_text = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iteration_text)
        salt = base64.b64decode(salt_text)
        expected = base64.b64decode(digest_text)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def money_to_minor(value) -> int:
    try:
        amount = Decimal(str(value).replace(",", "."))
    except (InvalidOperation, ValueError):
        raise ValueError("Некорректная сумма.")
    if amount < 0:
        raise ValueError("Сумма не может быть отрицательной.")
    return int((amount * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def normalize_account_number(value) -> str:
    return "".join(ch for ch in str(value or "") if ch.isdigit())


async def db_connect():
    return await asyncpg.connect(**DB_CONFIG)


def db_run(coro):
    return asyncio.run(coro)


async def init_db():
    conn = await db_connect()
    try:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS bankweb_users (
                id BIGSERIAL PRIMARY KEY,
                username TEXT UNIQUE,
                email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('client', 'manager', 'admin')),
                status TEXT NOT NULL CHECK (status IN ('active', 'blocked')),
                is_system BOOLEAN NOT NULL DEFAULT false,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS bankweb_sessions (
                token TEXT PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES bankweb_users(id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                expires_at TIMESTAMPTZ NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bankweb_accounts (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES bankweb_users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                account_number TEXT NOT NULL UNIQUE,
                balance_minor BIGINT NOT NULL DEFAULT 0,
                currency TEXT NOT NULL DEFAULT 'RUB',
                status TEXT NOT NULL CHECK (status IN ('active', 'frozen', 'closed')) DEFAULT 'active',
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS bankweb_transactions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES bankweb_users(id) ON DELETE CASCADE,
                account_id BIGINT REFERENCES bankweb_accounts(id) ON DELETE SET NULL,
                tx_type TEXT NOT NULL CHECK (tx_type IN ('transfer', 'deposit', 'withdrawal', 'adjustment')),
                title TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                counterparty TEXT NOT NULL DEFAULT '',
                amount_minor BIGINT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('completed', 'pending', 'rejected')) DEFAULT 'completed',
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS bankweb_audit_logs (
                id BIGSERIAL PRIMARY KEY,
                actor_user_id BIGINT REFERENCES bankweb_users(id) ON DELETE SET NULL,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );

            CREATE INDEX IF NOT EXISTS idx_bankweb_sessions_user ON bankweb_sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_bankweb_accounts_user ON bankweb_accounts(user_id);
            CREATE INDEX IF NOT EXISTS idx_bankweb_transactions_user ON bankweb_transactions(user_id, created_at DESC);
            """
        )
        await conn.execute("ALTER TABLE bankweb_users ADD COLUMN IF NOT EXISTS username TEXT UNIQUE")
        await conn.execute("ALTER TABLE bankweb_users ADD COLUMN IF NOT EXISTS is_system BOOLEAN NOT NULL DEFAULT false")
        await ensure_root_user(conn)
    finally:
        await conn.close()


async def audit(conn, actor_id, action, entity_type, entity_id, metadata=None):
    append_user_action(
        {
            "source": "audit",
            "actorUserId": actor_id,
            "action": action,
            "entityType": entity_type,
            "entityId": str(entity_id),
            "metadata": metadata or {},
        }
    )
    await conn.execute(
        """
        INSERT INTO bankweb_audit_logs (actor_user_id, action, entity_type, entity_id, metadata)
        VALUES ($1, $2, $3, $4, $5::jsonb)
        """,
        actor_id,
        action,
        entity_type,
        str(entity_id),
        json.dumps(metadata or {}, ensure_ascii=False),
    )


def user_payload(row):
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "name": row["name"],
        "role": row["role"],
        "status": row["status"],
        "isSystem": row["is_system"],
        "createdAt": row["created_at"].isoformat(),
        "permissions": permissions_for(row["role"]),
    }


def permissions_for(role: str):
    permissions = {
        "client": ["dashboard:read", "transfer:create"],
        "manager": ["dashboard:read", "transfer:create", "users:read", "accounts:manage"],
        "admin": [
            "dashboard:read",
            "transfer:create",
            "users:read",
            "users:manage",
            "accounts:manage",
            "audit:read",
        ],
    }
    return permissions.get(role, [])


async def create_account(conn, user_id, name="Основной счет", initial_balance_minor=0):
    account_number = "408178{}{}".format(str(user_id).zfill(6), f"{secrets.randbelow(10_000_000_000):010d}")
    return await conn.fetchrow(
        """
        INSERT INTO bankweb_accounts (user_id, name, account_number, balance_minor)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        """,
        user_id,
        name,
        account_number,
        initial_balance_minor,
    )


async def create_user(
    conn,
    *,
    email,
    name,
    password,
    role,
    status,
    initial_balance_minor=0,
    actor_id=None,
    username=None,
    is_system=False,
):
    async with conn.transaction():
        user = await conn.fetchrow(
            """
            INSERT INTO bankweb_users (username, email, name, role, status, is_system, password_hash)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            """,
            username.lower().strip() if username else None,
            email.lower().strip(),
            name.strip(),
            role,
            status,
            is_system,
            password_hash(password),
        )
        account = await create_account(conn, user["id"], initial_balance_minor=initial_balance_minor)
        if initial_balance_minor:
            await conn.execute(
                """
                INSERT INTO bankweb_transactions
                    (user_id, account_id, tx_type, title, note, amount_minor)
                VALUES ($1, $2, 'deposit', 'Начальное пополнение', 'Создано администратором', $3)
                """,
                user["id"],
                account["id"],
                initial_balance_minor,
            )
        await audit(conn, actor_id, "user.create", "user", user["id"], {"role": role})
        return user


async def ensure_root_user(conn):
    root = await conn.fetchrow(
        """
        SELECT * FROM bankweb_users
        WHERE username = $1 OR lower(email) = lower($2)
        ORDER BY CASE WHEN username = $1 THEN 0 ELSE 1 END
        LIMIT 1
        """,
        ROOT_USERNAME,
        ROOT_EMAIL,
    )
    hashed = password_hash(ROOT_PASSWORD)
    if root:
        await conn.execute(
            """
            UPDATE bankweb_users
            SET username = $1,
                email = $2,
                name = $3,
                role = 'admin',
                status = 'active',
                is_system = true,
                password_hash = $4,
                updated_at = now()
            WHERE id = $5
            """,
            ROOT_USERNAME,
            ROOT_EMAIL,
            "Root Administrator",
            hashed,
            root["id"],
        )
        account_exists = await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM bankweb_accounts WHERE user_id = $1)",
            root["id"],
        )
        if not account_exists:
            await create_account(conn, root["id"], name="Root счет")
        return

    user = await conn.fetchrow(
        """
        INSERT INTO bankweb_users
            (username, email, name, role, status, is_system, password_hash)
        VALUES ($1, $2, $3, 'admin', 'active', true, $4)
        RETURNING *
        """,
        ROOT_USERNAME,
        ROOT_EMAIL,
        "Root Administrator",
        hashed,
    )
    await create_account(conn, user["id"], name="Root счет")
    await audit(conn, user["id"], "system.root.ensure", "user", user["id"])


async def setup_status():
    conn = await db_connect()
    try:
        count = await conn.fetchval("SELECT COUNT(*) FROM bankweb_users")
        return {"needsSetup": count == 0, "rootLogin": ROOT_USERNAME}
    finally:
        await conn.close()


async def create_first_admin(payload):
    name = str(payload.get("name", "")).strip()
    email = str(payload.get("email", "")).lower().strip()
    password = str(payload.get("password", "")).strip()
    if not name or not email or len(password) < 12:
        raise ValueError("Укажите имя, email и пароль от 12 символов.")
    conn = await db_connect()
    try:
        count = await conn.fetchval("SELECT COUNT(*) FROM bankweb_users")
        if count:
            raise PermissionError("Первичная настройка уже выполнена.")
        user = await create_user(
            conn,
            email=email,
            name=name,
            password=password,
            role="admin",
            status="active",
            initial_balance_minor=0,
            actor_id=None,
        )
        token = await create_session(conn, user["id"])
        return user_payload(user), token
    finally:
        await conn.close()


async def create_session(conn, user_id):
    token = secrets.token_urlsafe(32)
    expires_at = utcnow() + timedelta(days=SESSION_TTL_DAYS)
    await conn.execute(
        """
        INSERT INTO bankweb_sessions (token, user_id, expires_at)
        VALUES ($1, $2, $3)
        """,
        token,
        user_id,
        expires_at,
    )
    return token


async def user_by_session(token):
    if not token:
        return None
    conn = await db_connect()
    try:
        row = await conn.fetchrow(
            """
            SELECT u.* FROM bankweb_sessions s
            JOIN bankweb_users u ON u.id = s.user_id
            WHERE s.token = $1 AND s.expires_at > now()
            """,
            token,
        )
        if not row or row["status"] != "active":
            return None
        return row
    finally:
        await conn.close()


async def login_user(payload):
    login = str(payload.get("email", "")).lower().strip()
    password = str(payload.get("password", ""))
    conn = await db_connect()
    try:
        row = await conn.fetchrow(
            "SELECT * FROM bankweb_users WHERE lower(email) = $1 OR lower(username) = $1",
            login,
        )
        if not row or not verify_password(password, row["password_hash"]):
            raise PermissionError("Неверный email или пароль.")
        if row["status"] != "active":
            raise PermissionError("Пользователь заблокирован.")
        token = await create_session(conn, row["id"])
        await audit(conn, row["id"], "auth.login", "user", row["id"])
        return user_payload(row), token
    finally:
        await conn.close()


async def register_client(payload):
    username = str(payload.get("username", "")).lower().strip() or None
    email = str(payload.get("email", "")).lower().strip()
    name = str(payload.get("name", "")).strip()
    password = str(payload.get("password", "")).strip()
    if username == ROOT_USERNAME or email == ROOT_EMAIL:
        raise ValueError("Этот логин недоступен.")
    if not email or not name or len(password) < 10:
        raise ValueError("Email, имя и пароль от 10 символов обязательны.")
    conn = await db_connect()
    try:
        user = await create_user(
            conn,
            email=email,
            name=name,
            password=password,
            role="client",
            status="active",
            initial_balance_minor=0,
            actor_id=None,
            username=username,
        )
        token = await create_session(conn, user["id"])
        await audit(conn, user["id"], "auth.register", "user", user["id"])
        return user_payload(user), token
    except asyncpg.UniqueViolationError:
        raise ValueError("Пользователь с таким email или логином уже существует.")
    finally:
        await conn.close()


async def logout_user(token):
    conn = await db_connect()
    try:
        await conn.execute("DELETE FROM bankweb_sessions WHERE token = $1", token)
    finally:
        await conn.close()


async def dashboard(user_id):
    conn = await db_connect()
    try:
        accounts = await conn.fetch(
            """
            SELECT * FROM bankweb_accounts
            WHERE user_id = $1
            ORDER BY id
            """,
            user_id,
        )
        transactions = await conn.fetch(
            """
            SELECT * FROM bankweb_transactions
            WHERE user_id = $1
            ORDER BY created_at DESC, id DESC
            LIMIT 80
            """,
            user_id,
        )
        return {
            "accounts": [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "number": row["account_number"],
                    "balance": row["balance_minor"],
                    "currency": row["currency"],
                    "status": row["status"],
                }
                for row in accounts
            ],
            "transactions": [
                {
                    "id": row["id"],
                    "accountId": row["account_id"],
                    "type": row["tx_type"],
                    "title": row["title"],
                    "note": row["note"],
                    "counterparty": row["counterparty"],
                    "amount": row["amount_minor"],
                    "status": row["status"],
                    "createdAt": row["created_at"].isoformat(),
                }
                for row in transactions
            ],
        }
    finally:
        await conn.close()


async def create_transfer(user, payload):
    account_id = int(payload.get("accountId"))
    amount_minor = money_to_minor(payload.get("amount", "0"))
    recipient_account_number = normalize_account_number(payload.get("recipient", ""))
    note = str(payload.get("note", "")).strip()
    if amount_minor <= 0 or not recipient_account_number:
        raise ValueError("Укажите номер счета получателя и сумму.")

    conn = await db_connect()
    try:
        async with conn.transaction():
            source = await conn.fetchrow(
                """
                SELECT * FROM bankweb_accounts
                WHERE id = $1 AND user_id = $2
                """,
                account_id,
                user["id"],
            )
            if not source:
                raise ValueError("Счет списания не найден.")

            target = await conn.fetchrow(
                """
                SELECT a.*, u.name AS owner_name, u.email AS owner_email
                FROM bankweb_accounts a
                JOIN bankweb_users u ON u.id = a.user_id
                WHERE a.account_number = $1
                """,
                recipient_account_number,
            )
            if not target:
                raise ValueError("Счет получателя не найден.")
            if source["id"] == target["id"]:
                raise ValueError("Нельзя перевести деньги на тот же счет.")

            locked_rows = await conn.fetch(
                """
                SELECT * FROM bankweb_accounts
                WHERE id = ANY($1::bigint[])
                ORDER BY id
                FOR UPDATE
                """,
                [source["id"], target["id"]],
            )
            locked = {row["id"]: row for row in locked_rows}
            source = locked[source["id"]]
            target = locked[target["id"]]

            if source["status"] != "active":
                raise ValueError("Счет списания недоступен для операций.")
            if target["status"] != "active":
                raise ValueError("Счет получателя недоступен для операций.")
            if source["currency"] != target["currency"]:
                raise ValueError("Переводы между разными валютами пока недоступны.")
            if amount_minor > source["balance_minor"]:
                raise ValueError("Недостаточно средств.")

            await conn.execute(
                "UPDATE bankweb_accounts SET balance_minor = balance_minor - $1 WHERE id = $2",
                amount_minor,
                account_id,
            )
            await conn.execute(
                "UPDATE bankweb_accounts SET balance_minor = balance_minor + $1 WHERE id = $2",
                amount_minor,
                target["id"],
            )
            debit = await conn.fetchrow(
                """
                INSERT INTO bankweb_transactions
                    (user_id, account_id, tx_type, title, note, counterparty, amount_minor)
                VALUES ($1, $2, 'transfer', $3, $4, $5, $6)
                RETURNING id
                """,
                user["id"],
                account_id,
                "Перевод по счету",
                note or "Исходящий перевод",
                target["account_number"],
                -amount_minor,
            )
            credit = await conn.fetchrow(
                """
                INSERT INTO bankweb_transactions
                    (user_id, account_id, tx_type, title, note, counterparty, amount_minor)
                VALUES ($1, $2, 'transfer', $3, $4, $5, $6)
                RETURNING id
                """,
                target["user_id"],
                target["id"],
                "Входящий перевод",
                note or "Входящий перевод",
                source["account_number"],
                amount_minor,
            )
            await audit(
                conn,
                user["id"],
                "transfer.create",
                "transaction",
                debit["id"],
                {
                    "amount": amount_minor,
                    "source_account": source["account_number"],
                    "target_account": target["account_number"],
                    "credit_transaction_id": credit["id"],
                },
            )
    finally:
        await conn.close()
    return await dashboard(user["id"])


async def create_own_account(user, payload):
    name = str(payload.get("name", "")).strip() or "Дополнительный счет"
    if len(name) > 80:
        raise ValueError("Название счета слишком длинное.")
    conn = await db_connect()
    try:
        async with conn.transaction():
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM bankweb_accounts WHERE user_id = $1",
                user["id"],
            )
            if count >= MAX_USER_ACCOUNTS:
                raise ValueError(f"Можно создать максимум {MAX_USER_ACCOUNTS} счета.")
            account = await create_account(conn, user["id"], name=name)
            await audit(conn, user["id"], "account.create.self", "account", account["id"])
    finally:
        await conn.close()
    return await dashboard(user["id"])


async def list_users():
    conn = await db_connect()
    try:
        rows = await conn.fetch("SELECT * FROM bankweb_users ORDER BY id DESC")
        return [user_payload(row) for row in rows]
    finally:
        await conn.close()


async def admin_create_user(actor, payload):
    email = str(payload.get("email", "")).lower().strip()
    username = str(payload.get("username", "")).lower().strip() or None
    name = str(payload.get("name", "")).strip()
    password = str(payload.get("password", "")).strip()
    role = str(payload.get("role", "client"))
    status = str(payload.get("status", "active"))
    initial_balance = money_to_minor(payload.get("initialBalance", "0"))
    if role not in ("client", "manager", "admin") or status not in ("active", "blocked"):
        raise ValueError("Некорректная роль или статус.")
    if not email or not name or len(password) < 10:
        raise ValueError("Email, имя и пароль от 10 символов обязательны.")
    conn = await db_connect()
    try:
        user = await create_user(
            conn,
            email=email,
            name=name,
            password=password,
            role=role,
            status=status,
            initial_balance_minor=initial_balance,
            actor_id=actor["id"],
            username=username,
        )
        return user_payload(user)
    except asyncpg.UniqueViolationError:
        raise ValueError("Пользователь с таким email уже существует.")
    finally:
        await conn.close()


async def admin_update_user(actor, user_id, payload):
    name = str(payload.get("name", "")).strip()
    role = str(payload.get("role", "client"))
    status = str(payload.get("status", "active"))
    password = str(payload.get("password", "")).strip()
    if role not in ("client", "manager", "admin") or status not in ("active", "blocked"):
        raise ValueError("Некорректная роль или статус.")
    if not name:
        raise ValueError("Имя обязательно.")
    conn = await db_connect()
    try:
        async with conn.transaction():
            row = await conn.fetchrow("SELECT * FROM bankweb_users WHERE id = $1", user_id)
            if not row:
                raise ValueError("Пользователь не найден.")
            if row["is_system"] or row["username"] == ROOT_USERNAME:
                role = "admin"
                status = "active"
            await conn.execute(
                """
                UPDATE bankweb_users
                SET name = $1, role = $2, status = $3, updated_at = now()
                WHERE id = $4
                """,
                name,
                role,
                status,
                user_id,
            )
            if password:
                if len(password) < 10:
                    raise ValueError("Пароль должен быть от 10 символов.")
                await conn.execute(
                    "UPDATE bankweb_users SET password_hash = $1, updated_at = now() WHERE id = $2",
                    password_hash(password),
                    user_id,
                )
            await audit(conn, actor["id"], "user.update", "user", user_id, {"role": role, "status": status})
        updated = await conn.fetchrow("SELECT * FROM bankweb_users WHERE id = $1", user_id)
        return user_payload(updated)
    finally:
        await conn.close()


async def admin_delete_user(actor, user_id):
    if actor["id"] == user_id:
        raise ValueError("Нельзя удалить текущего пользователя.")
    conn = await db_connect()
    try:
        async with conn.transaction():
            row = await conn.fetchrow("SELECT * FROM bankweb_users WHERE id = $1", user_id)
            if not row:
                raise ValueError("Пользователь не найден.")
            if row["is_system"] or row["username"] == ROOT_USERNAME:
                raise ValueError("Системного пользователя root нельзя удалить.")
            result = await conn.execute("DELETE FROM bankweb_users WHERE id = $1", user_id)
            await audit(conn, actor["id"], "user.delete", "user", user_id, {"result": result})
    finally:
        await conn.close()


async def admin_accounts():
    conn = await db_connect()
    try:
        rows = await conn.fetch(
            """
            SELECT a.*, u.email, u.name AS owner_name
            FROM bankweb_accounts a
            JOIN bankweb_users u ON u.id = a.user_id
            ORDER BY a.id DESC
            LIMIT 200
            """
        )
        return [
            {
                "id": row["id"],
                "userId": row["user_id"],
                "ownerName": row["owner_name"],
                "ownerEmail": row["email"],
                "name": row["name"],
                "number": row["account_number"],
                "balance": row["balance_minor"],
                "currency": row["currency"],
                "status": row["status"],
            }
            for row in rows
        ]
    finally:
        await conn.close()


async def admin_create_account(actor, payload):
    user_id = int(payload.get("userId"))
    name = str(payload.get("name", "")).strip() or "Дополнительный счет"
    initial_balance = money_to_minor(payload.get("initialBalance", "0"))
    conn = await db_connect()
    try:
        async with conn.transaction():
            user = await conn.fetchrow("SELECT * FROM bankweb_users WHERE id = $1", user_id)
            if not user:
                raise ValueError("Пользователь не найден.")
            account = await create_account(
                conn,
                user_id,
                name=name,
                initial_balance_minor=initial_balance,
            )
            if initial_balance:
                await conn.execute(
                    """
                    INSERT INTO bankweb_transactions
                        (user_id, account_id, tx_type, title, note, amount_minor)
                    VALUES ($1, $2, 'deposit', 'Начальное пополнение', 'Создано администратором', $3)
                    """,
                    user_id,
                    account["id"],
                    initial_balance,
                )
            await audit(conn, actor["id"], "account.create", "account", account["id"], {"user_id": user_id})
    finally:
        await conn.close()


async def admin_adjust_account(actor, payload):
    account_id = int(payload.get("accountId"))
    amount_minor = money_to_minor(payload.get("amount", "0"))
    direction = str(payload.get("direction", "deposit"))
    note = str(payload.get("note", "")).strip() or "Операция администратора"
    if direction not in ("deposit", "withdrawal"):
        raise ValueError("Некорректный тип операции.")
    if amount_minor <= 0:
        raise ValueError("Сумма должна быть больше нуля.")
    signed = amount_minor if direction == "deposit" else -amount_minor
    conn = await db_connect()
    try:
        async with conn.transaction():
            account = await conn.fetchrow(
                "SELECT * FROM bankweb_accounts WHERE id = $1 FOR UPDATE", account_id
            )
            if not account:
                raise ValueError("Счет не найден.")
            if direction == "withdrawal" and amount_minor > account["balance_minor"]:
                raise ValueError("Недостаточно средств на счете.")
            await conn.execute(
                "UPDATE bankweb_accounts SET balance_minor = balance_minor + $1 WHERE id = $2",
                signed,
                account_id,
            )
            tx = await conn.fetchrow(
                """
                INSERT INTO bankweb_transactions
                    (user_id, account_id, tx_type, title, note, amount_minor)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id
                """,
                account["user_id"],
                account_id,
                direction,
                "Пополнение" if direction == "deposit" else "Списание",
                note,
                signed,
            )
            await audit(conn, actor["id"], f"account.{direction}", "transaction", tx["id"], {"amount": amount_minor})
    finally:
        await conn.close()


class BankWebHandler(BaseHTTPRequestHandler):
    server_version = "BankWeb/2.0"

    def log_message(self, fmt, *args):
        print("{} - - [{}] {}".format(self.address_string(), self.log_date_time_string(), fmt % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self.handle_api_get(parsed.path)
            return
        self.serve_static(parsed.path)

    def do_HEAD(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            return
        self.serve_static(parsed.path, head_only=True)

    def do_POST(self):
        self.handle_write("POST")

    def do_PUT(self):
        self.handle_write("PUT")

    def do_DELETE(self):
        self.handle_write("DELETE")

    def handle_write(self, method):
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = {} if method == "DELETE" else self.read_json()
        if body is None:
            return
        if method == "POST":
            self.handle_api_post(parsed.path, body)
        elif method == "PUT":
            self.handle_api_put(parsed.path, body)
        elif method == "DELETE":
            self.handle_api_delete(parsed.path)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError:
            self.respond_json({"error": "Некорректный JSON."}, HTTPStatus.BAD_REQUEST)
            return None

    def respond_json(self, payload, status=HTTPStatus.OK, extra_headers=None):
        body = json_dumps(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)
        self.log_api_action(payload, status)

    def client_ip(self):
        forwarded_for = self.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            return forwarded_for.split(",", 1)[0].strip()
        return self.client_address[0] if self.client_address else ""

    def response_actor(self, payload):
        if isinstance(payload, dict) and isinstance(payload.get("user"), dict):
            return {
                "id": payload["user"].get("id"),
                "username": payload["user"].get("username"),
                "email": payload["user"].get("email"),
                "role": payload["user"].get("role"),
            }
        try:
            user = self.current_user()
        except Exception:
            user = None
        if not user:
            return None
        return {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        }

    def log_api_action(self, payload, status):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return
        entry = {
            "source": "api",
            "method": self.command,
            "path": path,
            "status": int(status),
            "actor": self.response_actor(payload),
            "ip": self.client_ip(),
            "userAgent": self.headers.get("User-Agent", ""),
        }
        if isinstance(payload, dict) and payload.get("error"):
            entry["error"] = payload["error"]
        append_user_action(entry)

    def cookie_token(self):
        cookies = SimpleCookie(self.headers.get("Cookie", ""))
        return cookies[SESSION_COOKIE].value if SESSION_COOKIE in cookies else ""

    def session_cookie(self, token, max_age=SESSION_TTL_DAYS * 86400):
        secure = ""
        if self.headers.get("X-Forwarded-Proto", "").lower() == "https":
            secure = "; Secure"
        return f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"

    def current_user(self):
        return db_run(user_by_session(self.cookie_token()))

    def require_user(self):
        user = self.current_user()
        if not user:
            self.respond_json({"error": "Требуется вход."}, HTTPStatus.UNAUTHORIZED)
            return None
        return user

    def require_admin(self):
        user = self.require_user()
        if not user:
            return None
        if user["role"] != "admin":
            self.respond_json({"error": "Нужны права администратора."}, HTTPStatus.FORBIDDEN)
            return None
        return user

    def handle_error(self, exc):
        if isinstance(exc, PermissionError):
            self.respond_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        elif isinstance(exc, ValueError):
            self.respond_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        else:
            print(f"Unhandled error: {exc!r}")
            self.respond_json({"error": "Внутренняя ошибка сервера."}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def handle_api_get(self, path):
        try:
            if path == "/api/setup/status":
                self.respond_json(db_run(setup_status()))
                return
            if path == "/api/session":
                user = self.current_user()
                self.respond_json({"user": user_payload(user) if user else None})
                return

            user = self.require_user()
            if not user:
                return
            if path == "/api/me/dashboard":
                self.respond_json(db_run(dashboard(user["id"])))
                return
            if path == "/api/admin/users":
                if not self.require_admin():
                    return
                self.respond_json({"users": db_run(list_users())})
                return
            if path == "/api/admin/accounts":
                if not self.require_admin():
                    return
                self.respond_json({"accounts": db_run(admin_accounts())})
                return
            self.respond_json({"error": "Маршрут не найден."}, HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self.handle_error(exc)

    def handle_api_post(self, path, payload):
        try:
            if path == "/api/setup/admin":
                user, token = db_run(create_first_admin(payload))
                self.respond_json(
                    {"user": user},
                    HTTPStatus.CREATED,
                    {"Set-Cookie": self.session_cookie(token)},
                )
                return
            if path == "/api/auth/login":
                user, token = db_run(login_user(payload))
                self.respond_json({"user": user}, extra_headers={"Set-Cookie": self.session_cookie(token)})
                return
            if path == "/api/auth/register":
                user, token = db_run(register_client(payload))
                self.respond_json(
                    {"user": user},
                    HTTPStatus.CREATED,
                    {"Set-Cookie": self.session_cookie(token)},
                )
                return
            if path == "/api/auth/logout":
                db_run(logout_user(self.cookie_token()))
                self.respond_json({"ok": True}, extra_headers={"Set-Cookie": self.session_cookie("", 0)})
                return

            user = self.require_user()
            if not user:
                return
            if path == "/api/me/transfer":
                self.respond_json({"ok": True, "dashboard": db_run(create_transfer(user, payload))})
                return
            if path == "/api/me/accounts":
                self.respond_json({"ok": True, "dashboard": db_run(create_own_account(user, payload))}, HTTPStatus.CREATED)
                return
            if path == "/api/admin/users":
                admin = self.require_admin()
                if not admin:
                    return
                self.respond_json({"user": db_run(admin_create_user(admin, payload))}, HTTPStatus.CREATED)
                return
            if path == "/api/admin/accounts":
                admin = self.require_admin()
                if not admin:
                    return
                db_run(admin_create_account(admin, payload))
                self.respond_json({"ok": True, "accounts": db_run(admin_accounts())}, HTTPStatus.CREATED)
                return
            if path == "/api/admin/accounts/adjust":
                admin = self.require_admin()
                if not admin:
                    return
                db_run(admin_adjust_account(admin, payload))
                self.respond_json({"ok": True, "accounts": db_run(admin_accounts())})
                return
            self.respond_json({"error": "Маршрут не найден."}, HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self.handle_error(exc)

    def handle_api_put(self, path, payload):
        try:
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[:3] == ["api", "admin", "users"]:
                admin = self.require_admin()
                if not admin:
                    return
                self.respond_json({"user": db_run(admin_update_user(admin, int(parts[3]), payload))})
                return
            self.respond_json({"error": "Маршрут не найден."}, HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self.handle_error(exc)

    def handle_api_delete(self, path):
        try:
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[:3] == ["api", "admin", "users"]:
                admin = self.require_admin()
                if not admin:
                    return
                db_run(admin_delete_user(admin, int(parts[3])))
                self.respond_json({"ok": True})
                return
            self.respond_json({"error": "Маршрут не найден."}, HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self.handle_error(exc)

    def serve_static(self, request_path, head_only=False):
        if request_path in ("", "/"):
            request_path = "/index.html"
        safe_path = Path(request_path.lstrip("/"))
        file_path = (PUBLIC_DIR / safe_path).resolve()
        public_root = PUBLIC_DIR.resolve()
        if public_root not in file_path.parents and file_path != public_root:
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not file_path.exists() or not file_path.is_file():
            file_path = PUBLIC_DIR / "index.html"
        content_type = "text/plain; charset=utf-8"
        if file_path.suffix == ".html":
            content_type = "text/html; charset=utf-8"
        elif file_path.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif file_path.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        body = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)


def main():
    db_run(init_db())
    host = os.environ.get("BANKWEB_HOST", "127.0.0.1")
    port = int(os.environ.get("BANKWEB_PORT", "8062"))
    server = ThreadingHTTPServer((host, port), BankWebHandler)
    print(f"BankWeb listening on http://{host}:{port}")
    print(f"Postgres database: {DB_CONFIG['user']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}")
    server.serve_forever()


if __name__ == "__main__":
    main()

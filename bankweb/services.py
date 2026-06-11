import json
import secrets
from datetime import timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

import asyncpg

from .config import (
    MAX_USER_ACCOUNTS,
    ROOT_EMAIL,
    ROOT_PASSWORD,
    ROOT_USERNAME,
    SESSION_TTL_DAYS,
)
from .db import db_connect
from .logging import append_user_action, utcnow
from .security import password_hash, verify_password


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

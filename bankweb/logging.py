import json
import threading
from datetime import datetime, timezone

from .config import BASE_DIR


USER_ACTIONS_LOG_DIR = BASE_DIR / "var" / "log" / "actions"
LOG_LOCK = threading.Lock()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def log_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


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
            time=log_time(timestamp),
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
            time=log_time(timestamp),
            action=format_log_value(entry.get("action")),
            actor=actor_label(entry.get("actorUserId")),
            entity_type=format_log_value(entry.get("entityType")),
            entity_id=format_log_value(entry.get("entityId")),
            metadata=json.dumps(metadata, ensure_ascii=False, default=str),
        )
    else:
        line = f"[{log_time(timestamp)}] {source} {entry}"

    with LOG_LOCK:
        with log_path.open("a", encoding="utf-8") as file:
            file.write(line + "\n")

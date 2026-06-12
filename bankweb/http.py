import json
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

from .config import PUBLIC_DIR, SESSION_COOKIE, SESSION_TTL_DAYS
from .db import db_run
from .logging import append_user_action
from .services import (
    admin_accounts,
    admin_adjust_account,
    admin_create_account,
    admin_create_user,
    admin_delete_user,
    admin_update_user,
    create_own_account,
    create_transfer,
    dashboard,
    list_users,
    login_user,
    logout_user,
    register_client,
    user_by_session,
    user_payload,
)


LOGIN_FAILURES = {}
LOGIN_LOCK = threading.Lock()
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_FAILURES = 8


def json_dumps(payload):
    return json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")


class BankWebHandler(BaseHTTPRequestHandler):
    server_version = "BankWeb/2.0"
    max_json_body_bytes = 64 * 1024

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
            self.security_headers()
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
        if not self.valid_write_origin():
            self.respond_json({"error": "Недопустимый источник запроса."}, HTTPStatus.FORBIDDEN)
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
        if length > self.max_json_body_bytes:
            self.respond_json({"error": "Слишком большой запрос."}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return None
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
        self.security_headers()
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

    def security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'self'; frame-ancestors 'none'")

    def valid_write_origin(self):
        origin = self.headers.get("Origin")
        referer = self.headers.get("Referer")
        host = self.headers.get("Host", "")
        allowed = {f"http://{host}", f"https://{host}"}
        if origin:
            return origin in allowed
        if referer:
            parsed = urlparse(referer)
            return f"{parsed.scheme}://{parsed.netloc}" in allowed
        return True

    def cookie_token(self):
        cookies = SimpleCookie(self.headers.get("Cookie", ""))
        return cookies[SESSION_COOKIE].value if SESSION_COOKIE in cookies else ""

    def session_cookie(self, token, max_age=SESSION_TTL_DAYS * 86400):
        secure = ""
        if self.headers.get("X-Forwarded-Proto", "").lower() == "https":
            secure = "; Secure"
        return f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"

    def login_rate_key(self, payload):
        login = ""
        if isinstance(payload, dict):
            login = str(payload.get("email", "")).lower().strip()
        return f"{self.client_ip()}:{login}"

    def login_blocked(self, payload):
        key = self.login_rate_key(payload)
        current_time = time.time()
        with LOGIN_LOCK:
            attempts = [
                attempt_time
                for attempt_time in LOGIN_FAILURES.get(key, [])
                if current_time - attempt_time < LOGIN_WINDOW_SECONDS
            ]
            LOGIN_FAILURES[key] = attempts
            return len(attempts) >= LOGIN_MAX_FAILURES

    def record_login_failure(self, payload):
        key = self.login_rate_key(payload)
        current_time = time.time()
        with LOGIN_LOCK:
            attempts = [
                attempt_time
                for attempt_time in LOGIN_FAILURES.get(key, [])
                if current_time - attempt_time < LOGIN_WINDOW_SECONDS
            ]
            attempts.append(current_time)
            LOGIN_FAILURES[key] = attempts

    def clear_login_failures(self, payload):
        with LOGIN_LOCK:
            LOGIN_FAILURES.pop(self.login_rate_key(payload), None)

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
            if path == "/api/auth/login":
                if self.login_blocked(payload):
                    self.respond_json({"error": "Слишком много попыток входа. Попробуйте позже."}, HTTPStatus.TOO_MANY_REQUESTS)
                    return
                try:
                    user, token = db_run(login_user(payload))
                except PermissionError:
                    self.record_login_failure(payload)
                    raise
                self.clear_login_failures(payload)
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
        self.security_headers()
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

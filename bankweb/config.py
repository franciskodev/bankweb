import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
PUBLIC_DIR = BASE_DIR / "public"
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

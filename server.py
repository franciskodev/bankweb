#!/usr/bin/env python3
import os
from http.server import ThreadingHTTPServer

from bankweb.config import DB_CONFIG
from bankweb.db import db_run
from bankweb.http import BankWebHandler
from bankweb.services import init_db


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

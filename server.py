#!/usr/bin/env python3
import os
import sys
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path

from bankweb.config import DB_CONFIG
from bankweb.db import db_run
from bankweb.http import BankWebHandler
from bankweb.services import init_db


@contextmanager
def port_lock(port: int):
    lock_path = Path(f"/tmp/bankweb-{port}.lock")
    lock_file = lock_path.open("w")
    try:
        try:
            import fcntl

            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"BankWeb port {port} is already managed by another process")
            sys.exit(0)
        lock_file.write(str(os.getpid()))
        lock_file.flush()
        yield
    finally:
        lock_file.close()


def main():
    db_run(init_db())
    host = os.environ.get("BANKWEB_HOST", "127.0.0.1")
    port = int(os.environ.get("BANKWEB_PORT", "8062"))
    with port_lock(port):
        try:
            server = ThreadingHTTPServer((host, port), BankWebHandler)
        except OSError as exc:
            if exc.errno == 98:
                print(f"BankWeb port {port} is already in use; not starting another instance")
                return
            raise
        print(f"BankWeb listening on http://{host}:{port}")
        print(f"Postgres database: {DB_CONFIG['user']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}")
        server.serve_forever()


if __name__ == "__main__":
    main()

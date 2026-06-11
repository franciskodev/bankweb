# BankWeb

BankWeb is a small banking web application with a Python backend, PostgreSQL storage, user authentication, client registration, account management, and internal transfers by account number.

## Features

- Login and client registration
- Protected root administrator account
- Roles: `client`, `manager`, `admin`
- Up to 3 accounts per user
- Internal transfers only to existing account numbers
- Admin user management
- Admin account creation, deposits, and withdrawals
- PostgreSQL persistence

## Requirements

- Python 3.13+
- PostgreSQL

Install Python dependencies:

```bash
python3.13 -m venv venv
./venv/bin/pip install -r requirements.txt
```

## Configuration

Create a local `.env` file:

```bash
cp .env.example .env
```

Then set the real values:

```env
BANKWEB_ROOT_PASSWORD=change-me
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_USER=bankweb
POSTGRES_PASSWORD=change-me
POSTGRES_DB=bankweb
POSTGRES_COMMAND_TIMEOUT=30
```

The app creates or restores the `root` administrator on startup. The root login is:

```text
root
```

The password is taken from `BANKWEB_ROOT_PASSWORD`.

## Run

```bash
BANKWEB_HOST=127.0.0.1 BANKWEB_PORT=8062 ./venv/bin/python server.py
```

Open:

```text
http://127.0.0.1:8062
```

## Notes

Runtime files such as `.env`, virtual environments, logs, nginx configs, and local service scripts should stay out of git.

User actions are written to:

```text
var/log/user-actions.log
```

The log format is JSON-lines: one JSON object per action.

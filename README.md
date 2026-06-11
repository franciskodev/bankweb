# BankWeb

BankWeb is a small banking web application with a Python backend, PostgreSQL storage, user authentication, account management, admin tools, and internal transfers by account number.

## Features

- Client registration and login
- Protected `root` administrator restored on startup
- Roles: `client`, `manager`, `admin`
- Up to 3 accounts per user
- Internal transfers only to existing active account numbers
- Admin user management
- Admin account creation, deposits, and withdrawals
- PostgreSQL persistence
- Plain text action logs split by date

## Project Layout

```text
server.py              # application entry point
bankweb/config.py      # env, paths, constants
bankweb/db.py          # PostgreSQL connection helpers
bankweb/http.py        # HTTP handler and API routes
bankweb/logging.py     # dated action logs
bankweb/security.py    # password hashing and verification
bankweb/services.py    # users, accounts, transfers, admin logic
public/                # frontend assets
```

Local runtime files such as `.env`, `venv/`, and `var/` should stay out of git.

## Requirements

- Python 3.13+
- PostgreSQL

Install dependencies:

```bash
python3.13 -m venv venv
./venv/bin/pip install -r requirements.txt
```

## Configuration

Create a local `.env` file:

```bash
cp .env.example .env
```

Set real values:

```env
BANKWEB_ROOT_PASSWORD=change-me
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_USER=bankweb
POSTGRES_PASSWORD=change-me
POSTGRES_DB=bankweb
POSTGRES_COMMAND_TIMEOUT=30
```

The root login is:

```text
root
```

The password is read from `BANKWEB_ROOT_PASSWORD`.

## Run

```bash
BANKWEB_HOST=127.0.0.1 BANKWEB_PORT=8062 ./venv/bin/python server.py
```

Open:

```text
http://127.0.0.1:8062
```

## Logs

Application logs:

```text
var/log/bankweb.log
```

User action logs are plain text and split by UTC date:

```text
var/log/actions/YYYY-MM-DD.log
```

Example:

```text
[2026-06-11 21:00:06] API POST /api/auth/login status=200 actor=root#2<admin> ip=127.0.0.1 user_agent="curl/7.81.0"
```

## Deployment

BankWeb is a plain Python HTTP application. In production, run it behind a reverse proxy such as nginx, Caddy, or Apache, and use a process manager such as systemd, Supervisor, Docker, or your hosting platform's service runner.

The application reads two optional runtime variables:

```env
BANKWEB_HOST=127.0.0.1
BANKWEB_PORT=8062
```

Typical production flow:

```bash
python3.13 -m venv venv
./venv/bin/pip install -r requirements.txt
cp .env.example .env
BANKWEB_HOST=127.0.0.1 BANKWEB_PORT=8062 ./venv/bin/python server.py
```

Configure your reverse proxy to forward public traffic to `BANKWEB_HOST:BANKWEB_PORT`.

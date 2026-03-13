# Architecture

## Overview

`tg-notify-deleted-messages` is a Telegram message deletion tracking service built with Telethon, SQLAlchemy, and Flask. It monitors incoming/outgoing messages, stores them in a database, and notifies when messages are deleted by interlocutors.

## Component Layout

```
app/src/
├── app.py                  # Main application: event handlers, Flask routes, orchestration
├── wsgi.py                 # WSGI entry point for production deployment
└── packages/
    ├── bootstrap.py        # Client lifecycle: TelegramClient creation, signal handlers, bot config
    ├── bot_assistant.py    # Optional bot notification channel via separate Telegram bot client
    ├── db_bootstrap.py     # Engine and session factory creation with env-configurable args
    ├── db_helpers.py       # Database URL handling, schema creation, column encryption
    ├── env_helpers.py      # .env loading and required-env-variable enforcement
    ├── filtering.py        # Message filtering: chat type checks, member threshold, outgoing exclusion
    ├── message_loading.py  # DB query construction and message retrieval with filter application
    ├── notifications.py    # Notification dispatch: base (mark deleted), default (send to self/bot)
    ├── telegram_helpers.py # Peer building, mention formatting, entity resolution, client refresh
    └── models/
        ├── __init__.py     # SQLAlchemy Base, encryption engine selection (AES, AES-GCM)
        ├── root/
        │   ├── TelegramMessage.py  # Message ORM: id, peers, text, media, timestamp, deleted flag
        │   └── TelegramPeer.py     # Peer ORM: peer_id, access_hash, type with unique constraint
        └── support/
            └── PeerType.py         # IntEnum mapping Telethon types to DB integers
```

## Data Flow

1. **Ingestion**: `NewMessage` event handler stores messages via `store_message_if_not_exists()`
2. **Deletion Detection**: `MessageDeleted` event triggers DB lookup via `load_messages_from_db()`
3. **Filtering**: `filter_loaded_messages()` applies chat type and member threshold filters
4. **Notification**: `notify_message_deletion()` marks message deleted in DB and dispatches notification
5. **Cleanup**: Background loop deletes messages older than `MESSAGES_TTL_DAYS`

## Key Design Decisions

- **Encryption at rest**: Columns encrypted via `sqlalchemy_utils.StringEncryptedType` when `DATABASE_ENCRYPTION_KEY` is set
- **Modular extraction**: Recent refactors extracted `filtering`, `message_loading`, `notifications`, `bootstrap`, `db_bootstrap`, and `telegram_helpers` from monolithic `app.py`
- **Dual notification**: Optional bot assistant sends notifications to a target chat; default sends to "me"
- **Retry resilience**: Tenacity retries on `IOError` and `DBAPIError` with 3 attempts

## Testing

- **Unit tests**: `tests/test_*.py` — 63 tests covering helpers, filtering, models, notifications
- **Integration tests**: `tests/integration_db_backends.py` — SQLite and PostgreSQL lifecycle tests
- **Test runner**: pytest configured in `pyproject.toml`

## Deployment

Multi-stage Dockerfile with configurable:
- Python runtime (CPython or PyPy)
- DB driver selection (psycopg2, psycopg3, pg8000, SQLite)
- Server selection (Gunicorn, Hypercorn, uWSGI, nginx+Gunicorn)

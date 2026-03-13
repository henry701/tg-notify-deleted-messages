# Architecture

## Overview

`tg-notify-deleted-messages` is a Telegram message deletion tracking service built with Telethon, SQLAlchemy, and Flask. It monitors incoming/outgoing messages, stores them in a database, and notifies when messages are deleted by interlocutors.

## Component Layout

```
app/src/
├── app.py                  # Thin entry point: main() calls bootstrap.create_app_and_start_jobs()
├── wsgi.py                 # WSGI entry point for production deployment
└── packages/
    ├── bootstrap.py        # App factory: client lifecycle, signal handlers, bot config, main loop orchestration
    ├── background_jobs.py  # Background loops: message preloading, old message cleanup, concurrency utils
    ├── bot_assistant.py    # Optional bot notification channel via separate Telegram bot client
    ├── db_bootstrap.py     # Engine and session factory creation with env-configurable args
    ├── db_helpers.py       # Database URL handling, schema creation, column encryption
    ├── env_helpers.py      # .env loading and required-env-variable enforcement
    ├── event_orchestration.py  # Event handlers (NewMessage, MessageDeleted), message storage, filtering integration
    ├── filtering.py        # Message filtering: chat type checks, member threshold, outgoing exclusion
    ├── http.py             # Flask app factory, HTTP routes (auth, health, status endpoints)
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

1. **Ingestion**: `NewMessage` event handler stores messages via `store_message_if_not_exists()` (`event_orchestration.py`)
2. **Deletion Detection**: `MessageDeleted` event triggers DB lookup via `load_messages_from_db()` (`event_orchestration.py`)
3. **Filtering**: `filter_loaded_messages()` applies chat type and member threshold filters (`filtering.py`)
4. **Notification**: `notify_message_deletion()` marks message deleted in DB and dispatches notification (`notifications.py`)
5. **Cleanup**: Background loop deletes messages older than `MESSAGES_TTL_DAYS` (`background_jobs.py`)

## Bootstrap Sequence

`create_app_and_start_jobs()` in `bootstrap.py` orchestrates startup:

1. Create asyncio event loop, apply `nest_asyncio`
2. Set up database engine, session factory, and Telegram session container
3. Configure optional bot assistant for notifications
4. Create and connect the main Telegram client
5. Start worker thread running the asyncio event loop
6. Queue main loop jobs: event handlers registration, message preloading, cleanup loop
7. Create Flask app via `http.create_app()`
8. Return `(flask_app, sync_closer)` tuple

## Key Design Decisions

- **Encryption at rest**: Columns encrypted via `sqlalchemy_utils.StringEncryptedType` when `DATABASE_ENCRYPTION_KEY` is set
- **Modular decomposition**: `app.py` decomposed into focused packages — `bootstrap`, `background_jobs`, `event_orchestration`, `http`
- **Dual notification**: Optional bot assistant sends notifications to a target chat; default sends to "me"
- **Retry resilience**: Tenacity retries on `IOError` and `DBAPIError` with 3 attempts
- **Concurrency control**: `gather_with_concurrency()` limits parallelism for message preloading and notifications

## Testing

- **Unit tests**: `tests/test_*.py` — covers helpers, filtering, models, notifications, and all new packages
- **Integration tests**: `tests/integration_db_backends.py` — SQLite and PostgreSQL lifecycle tests
- **Test runner**: pytest configured in `pyproject.toml`

## Deployment

Multi-stage Dockerfile with configurable:
- Python runtime (CPython or PyPy)
- DB driver selection (psycopg2, psycopg3, pg8000, SQLite)
- Server selection (Gunicorn, Hypercorn, uWSGI, nginx+Gunicorn)

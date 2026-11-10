# About

`tg-notify-deleted-messages` allows you to track messages which were deleted or
edited by your interlocutors. You receive notifications when messages are
deleted or edited in monitored chats.

## Configuration

1. Go to <https://my.telegram.org> . Select "API development tools" and create application.
2. Copy `.env.example` file with name `.env` and change values.

Searchable encrypted database columns pickle values before encryption. Set
`ENCRYPTED_TYPE_PICKLE_PROTOCOL` to an integer between `0` and the running
interpreter's `pickle.HIGHEST_PROTOCOL` (inclusive). The default is `5`. Use
`4` if you need to keep matching rows written under Python 3.12, which used
pickle protocol 4. An invalid value fails at startup.

## Start daemon

```bash
docker-compose up -d app
```

Then, interact with the application using the API described on [openapi.yaml](./openapi.yaml).

## Stop daemon

```bash
docker-compose stop app
```

## Run tests

Install the dependencies into a project virtualenv (not the system or user site):

```bash
python3 -m venv venv
venv/bin/python -m pip install -r app/meta/requirements/base.txt \
  -r app/meta/requirements/db_cripto.txt -r requirements-dev.txt \
  git+https://github.com/henry701/telethon-session-sqlalchemy@947580d6df54797ce94c30978926c030f8c03d88
```

The integration tests also need a driver for the database under test, e.g.
`venv/bin/python -m pip install -r app/meta/requirements/pgsql-psycopg3.txt`.

```bash
PYTHONPATH=app/src venv/bin/python -m pytest tests/test_*.py -v
```

Or with unittest discover:

```bash
PYTHONPATH=app/src venv/bin/python -m unittest discover -s tests -p "test_*.py" -v
```

## Run integration tests

SQLite (ephemeral file):

```bash
INTEGRATION_DATABASE_URL=sqlite+pysqlite:////tmp/tgdel-integration.sqlite3 \
PYTHONPATH=app/src venv/bin/python -m unittest discover -s tests -p "integration_*.py" -v
```

Postgres:

```bash
INTEGRATION_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:5432/postgres \
PYTHONPATH=app/src venv/bin/python -m unittest discover -s tests -p "integration_*.py" -v
```

## Disk usage and attachments

`tg-notify-deleted-messages` stores message history for the time specified
in the `MESSAGES_TTL_DAYS` environment variable, with default TTL: 14 days.

Preloading can also persist per-dialog checkpoints to avoid rescanning the same
TTL window on every restart. This behavior is enabled by default through
`PRELOAD_CHECKPOINTS_ENABLED=1`. The checkpoint flush cadence during preload is
controlled by `PRELOAD_CHECKPOINT_UPDATE_EVERY_MESSAGES`, with default `100`.

You can change this interval by changing the `.env` file or by defining environment
variables at the system level.

**Be careful, your messages can fill your disk space!**

## Roadmap

See [ROADMAP.md](./ROADMAP.md).

## Contribution

Feel free to create issues, bug reports and pull requests. I will be very
grateful if someone implements any of the features described in the roadmap!

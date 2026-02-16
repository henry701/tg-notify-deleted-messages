# About

`tg-notify-deleted-messages` allows you to track messages which were deleted by
your interlocutors.

## Configuration

1. Go to <https://my.telegram.org> . Select "API development tools" and create application.
2. Copy `.env.example` file with name `.env` and change values.

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

```bash
PYTHONPATH=app/src python3 -m unittest discover -s tests -p "test_*.py" -v
```

## Run integration tests

SQLite (ephemeral file):

```bash
INTEGRATION_DATABASE_URL=sqlite+pysqlite:////tmp/tgdel-integration.sqlite3 \
PYTHONPATH=app/src python3 -m unittest discover -s tests -p "integration_*.py" -v
```

Postgres:

```bash
INTEGRATION_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:5432/postgres \
PYTHONPATH=app/src python3 -m unittest discover -s tests -p "integration_*.py" -v
```

## Disk usage and attachments

`tg-notify-deleted-messages` stores message history for the time specified
in the `MESSAGES_TTL_DAYS` environment variable, with default TTL: 14 days.

You can change this interval by changing the `.env` file or by defining environment
variables at the system level.

**Be careful, your messages can fill your disk space!**

## Roadmap

See [ROADMAP.md](./ROADMAP.md).

## Contribution

Feel free to create issues, bug reports and pull requests. I will be very
grateful if someone implements any of the features described in the roadmap!

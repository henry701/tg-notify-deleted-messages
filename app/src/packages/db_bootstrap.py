"""Database engine and session factory bootstrap utilities."""

import json
import logging
import os

import sqlalchemy
from sqlalchemy.orm import sessionmaker

from packages.db_helpers import get_db_url

logger = logging.getLogger("tgdel-db-bootstrap")


def create_engine(
    database_url: str, pool: sqlalchemy.pool.Pool | None = None
) -> sqlalchemy.engine.Engine:
    """Create a SQLAlchemy engine from a database URL.

    Args:
        database_url: The database connection URL
        pool: Optional connection pool to reuse

    Returns:
        A configured SQLAlchemy engine instance
    """
    connect_arg_str = os.getenv("CUSTOM_SQLALCHEMY_CONNECT_ARGS")
    connect_args = json.loads(connect_arg_str) if connect_arg_str else {}
    create_engine_add_arg_str = os.getenv("CUSTOM_SQLALCHEMY_CREATE_ENGINE_ARGS")
    create_engine_add_args = (
        json.loads(create_engine_add_arg_str) if create_engine_add_arg_str else {}
    )

    # Start with the additional args from environment
    kwargs = dict(create_engine_add_args)

    # Override echo to always be False
    kwargs["echo"] = False

    # Handle pool parameter: if explicitly provided, use it; otherwise
    # leave whatever was in create_engine_add_args (or None)
    if pool is not None:
        kwargs["pool"] = pool

    return sqlalchemy.create_engine(database_url, connect_args=connect_args, **kwargs)


def create_engine_from_env() -> sqlalchemy.engine.Engine:
    """Create a SQLAlchemy engine using the DATABASE_URL from environment.

    Returns:
        A configured SQLAlchemy engine instance
    """
    database_url = get_db_url()
    return create_engine(database_url)


def create_session_factory(
    engine: sqlalchemy.engine.Engine,
) -> sessionmaker:
    """Create a session factory bound to the given engine.

    Args:
        engine: The SQLAlchemy engine to bind sessions to

    Returns:
        A configured sessionmaker instance
    """
    return sessionmaker(bind=engine, expire_on_commit=False)

# -*- coding: utf-8 -*-
"""Database engine and session factory bootstrap utilities."""

import json
import logging
import os
from typing import Union

import sqlalchemy
from sqlalchemy.orm import sessionmaker

from packages.db_helpers import get_db_url

logger = logging.getLogger("tgdel-db-bootstrap")


def create_engine(
    database_url: str, pool: Union[sqlalchemy.pool.Pool, None] = None
) -> sqlalchemy.engine.Engine:
    """Create a SQLAlchemy engine from a database URL.

    Args:
        database_url: The database connection URL
        pool: Optional connection pool to reuse

    Returns:
        A configured SQLAlchemy engine instance
    """
    if pool is not None:
        logger.debug("Reusing Pool")
        return sqlalchemy.create_engine(
            database_url,
            echo=False,
            pool=pool,
        )
    connect_args = (
        json.loads(os.getenv("CUSTOM_SQLALCHEMY_CONNECT_ARGS"))
        if os.getenv("CUSTOM_SQLALCHEMY_CONNECT_ARGS")
        else {}
    )
    create_engine_add_args = (
        json.loads(os.getenv("CUSTOM_SQLALCHEMY_CREATE_ENGINE_ARGS"))
        if os.getenv("CUSTOM_SQLALCHEMY_CREATE_ENGINE_ARGS")
        else {}
    )
    return sqlalchemy.create_engine(
        database_url, echo=False, connect_args=connect_args, **create_engine_add_args
    )


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

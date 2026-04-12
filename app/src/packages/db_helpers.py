import logging
import os
import re

import sqlalchemy
import sqlalchemy_utils
from sqlalchemy.schema import CreateColumn

import packages.models
from packages.env_helpers import require_env

ADDITIVE_COLUMN_MIGRATIONS = {
    "telegram_messages": (
        "grouped_id",
        "media_file_name",
        "media_mime_type",
        "media_document_attributes",
    ),
}


def get_db_url():
    database_url = require_env("DATABASE_URL")
    # Heroku Workaround
    database_url = database_url.replace("postgres://", "postgresql://")
    forced_protocol = os.getenv("DB_FORCE_URL_PROTOCOL")
    if forced_protocol:
        database_url = re.sub(r"^[^:]+:", forced_protocol + ":", database_url)
    return database_url


def create_database(sqlalchemy_engine):
    metadata = encrypt_database_metadata()
    metadata.create_all(sqlalchemy_engine)
    apply_additive_migrations(sqlalchemy_engine, metadata)


def encrypt_database_metadata():
    # Changing this logic for encryption selection requires adaptation of the underlying database, if existing!
    metadata: sqlalchemy.schema.MetaData = packages.models.Base.metadata
    for table in metadata.tables.values():
        for column in table.columns:
            logging.debug(f"Traversing Type: {column.type}")
            if should_encrypt_column(column):
                column.type = packages.models.encrypt_type_searchable(column.type)
    return metadata


def apply_additive_migrations(
    sqlalchemy_engine,
    metadata: sqlalchemy.schema.MetaData | None = None,
):
    if metadata is None:
        metadata = encrypt_database_metadata()
    inspector = sqlalchemy.inspect(sqlalchemy_engine)
    existing_tables = set(inspector.get_table_names())
    identifier_preparer = sqlalchemy_engine.dialect.identifier_preparer
    with sqlalchemy_engine.begin() as connection:
        for table_name, column_names in ADDITIVE_COLUMN_MIGRATIONS.items():
            if table_name not in existing_tables:
                continue
            table = metadata.tables.get(table_name)
            if table is None:
                continue
            existing_columns = {
                column_data["name"] for column_data in inspector.get_columns(table_name)
            }
            formatted_table_name = identifier_preparer.format_table(table)
            for column_name in column_names:
                if column_name in existing_columns:
                    continue
                column = table.columns[column_name]
                add_column_sql = str(
                    CreateColumn(column).compile(dialect=sqlalchemy_engine.dialect)
                ).strip()
                connection.execute(
                    sqlalchemy.text(
                        f"ALTER TABLE {formatted_table_name} ADD COLUMN {add_column_sql}"
                    )
                )
                existing_columns.add(column_name)
                logging.info(
                    "Added missing nullable column %s.%s during startup migration",
                    table_name,
                    column_name,
                )


def should_encrypt_column_traverser(col: sqlalchemy.Column):
    if col.autoincrement is True:
        return False
    for fk in col.foreign_keys:
        if not should_encrypt_column(fk.column):
            return False
    return True


def should_encrypt_column_even_if_not_allowed_type(col: sqlalchemy.Column):
    return col.name.endswith("_id") or col.name in [
        "id",
        "phone",
    ]


def should_encrypt_column(column: sqlalchemy.Column):
    never_encrypt_types = (
        sqlalchemy_utils.types.encrypted.encrypted_type.StringEncryptedType
    )
    allowed_encrypt_types = (sqlalchemy.types.String, sqlalchemy.types.LargeBinary)
    return (
        not isinstance(column.type, never_encrypt_types)
        and (
            isinstance(column.type, allowed_encrypt_types)
            or should_encrypt_column_even_if_not_allowed_type(column)
        )
        and should_encrypt_column_traverser(column)
    )

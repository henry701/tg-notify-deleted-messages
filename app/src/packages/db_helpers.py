# -*- coding: utf-8 -*-

import sqlalchemy
import sqlalchemy_utils
import logging
from packages.env_helpers import require_env

import packages.models

def get_db_url():
    database_url = require_env("DATABASE_URL")
    # Heroku Workaround
    database_url = database_url.replace("postgres://", "postgresql://")
    return database_url

def create_database(sqlalchemy_engine):
    metadata = encrypt_database_metadata()
    metadata.create_all(sqlalchemy_engine)

def encrypt_database_metadata():
    # Changing this logic for encryption selection requires adaptation of the underlying database, if existing!
    metadata : sqlalchemy.schema.MetaData = packages.models.Base.metadata
    for table in metadata.tables.values():
        for column in table.columns:
            logging.debug(f"Traversing Type: {column.type}")
            if should_encrypt_column(column):
                column.type = packages.models.encrypt_type_searchable(column.type)
    return metadata

def should_encrypt_column_traverser(col : sqlalchemy.Column):
        if col.autoincrement is True:
            return False
        for fk in col.foreign_keys:
            if not should_encrypt_column(fk.column):
                return False
        return True

def should_encrypt_column_even_if_not_allowed_type(col : sqlalchemy.Column):
    return col.name.endswith('_id') or col.name in ['id', 'phone', ]

def should_encrypt_column(column : sqlalchemy.Column):
    never_encrypt_types = (sqlalchemy_utils.types.encrypted.encrypted_type.StringEncryptedType)
    allowed_encrypt_types = (sqlalchemy.types.String, sqlalchemy.types.LargeBinary)
    return not isinstance(column.type, never_encrypt_types) and (isinstance(column.type, allowed_encrypt_types) or should_encrypt_column_even_if_not_allowed_type(column)) and should_encrypt_column_traverser(column)


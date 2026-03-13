import os
import unittest
from unittest.mock import patch

from sqlalchemy import BigInteger, Column, ForeignKey, Integer, MetaData, String, Table

from packages.db_helpers import (
    get_db_url,
    should_encrypt_column,
    should_encrypt_column_even_if_not_allowed_type,
    should_encrypt_column_traverser,
)


class DbHelpersTests(unittest.TestCase):
    def test_get_db_url_normalizes_postgres_scheme(self) -> None:
        with patch.dict(
            os.environ, {"DATABASE_URL": "postgres://user:pass@db/app"}, clear=True
        ):
            self.assertEqual(get_db_url(), "postgresql://user:pass@db/app")

    def test_get_db_url_forces_protocol_when_requested(self) -> None:
        env = {
            "DATABASE_URL": "postgresql+psycopg://user:pass@db/app",
            "DB_FORCE_URL_PROTOCOL": "postgresql+pg8000",
        }
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(get_db_url(), "postgresql+pg8000://user:pass@db/app")

    def test_should_encrypt_column_true_for_text_column(self) -> None:
        self.assertTrue(should_encrypt_column(Column("text", String())))

    def test_should_encrypt_column_false_for_non_sensitive_integer_column(self) -> None:
        self.assertFalse(should_encrypt_column(Column("counter", Integer())))

    def test_should_encrypt_column_true_for_identifier_column(self) -> None:
        self.assertTrue(should_encrypt_column(Column("id", BigInteger())))

    def test_should_encrypt_column_traverser_false_for_autoincrement_column(
        self,
    ) -> None:
        self.assertFalse(
            should_encrypt_column_traverser(
                Column("id", BigInteger(), autoincrement=True)
            )
        )

    def test_should_encrypt_column_traverser_false_for_fk_to_non_encrypted_column(
        self,
    ) -> None:
        metadata = MetaData()
        Table("parent", metadata, Column("counter", Integer(), primary_key=True))
        child = Table(
            "child",
            metadata,
            Column("parent_counter", Integer(), ForeignKey("parent.counter")),
        )
        self.assertFalse(should_encrypt_column_traverser(child.c.parent_counter))

    def test_should_encrypt_column_even_if_not_allowed_type_for_suffix_id(self) -> None:
        self.assertTrue(
            should_encrypt_column_even_if_not_allowed_type(Column("chat_id", Integer()))
        )

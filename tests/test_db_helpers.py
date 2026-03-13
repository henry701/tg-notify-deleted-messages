import os
import unittest
from unittest.mock import MagicMock, patch

from sqlalchemy import (
    BigInteger,
    Column,
    ForeignKey,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
)
from sqlalchemy_utils.types.encrypted.encrypted_type import StringEncryptedType

from packages.db_helpers import (
    create_database,
    encrypt_database_metadata,
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

    def test_should_encrypt_column_true_for_large_binary(self) -> None:
        self.assertTrue(should_encrypt_column(Column("data", LargeBinary())))

    def test_should_encrypt_column_false_for_already_encrypted_type(self) -> None:
        enc_type = StringEncryptedType(String(), "secret_key")
        col = Column("secret", enc_type)
        self.assertFalse(should_encrypt_column(col))

    def test_should_encrypt_column_traverser_true_for_fk_to_encrypted_column(
        self,
    ) -> None:
        metadata = MetaData()
        Table(
            "parent",
            metadata,
            Column("name", String(), primary_key=True),
        )
        child = Table(
            "child",
            metadata,
            Column("parent_name", String(), ForeignKey("parent.name")),
        )
        self.assertTrue(should_encrypt_column_traverser(child.c.parent_name))

    def test_encrypt_database_metadata_transforms_string_columns(self) -> None:
        metadata = MetaData()
        Table(
            "sample",
            metadata,
            Column("id", Integer(), primary_key=True),
            Column("label", String()),
        )
        with (
            patch("packages.models.Base") as mock_base,
            patch("packages.models.ENCRYPTION_KEY", "test-key-1234"),
        ):
            mock_base.metadata = metadata
            result = encrypt_database_metadata()
            label_col = result.tables["sample"].c.label
            self.assertIsInstance(label_col.type, StringEncryptedType)

    def test_encrypt_database_metadata_skips_autoincrement_columns(self) -> None:
        metadata = MetaData()
        Table(
            "sample",
            metadata,
            Column("id", Integer(), primary_key=True, autoincrement=True),
        )
        with patch("packages.models.Base") as mock_base:
            mock_base.metadata = metadata
            result = encrypt_database_metadata()
            id_col = result.tables["sample"].c.id
            self.assertNotIsInstance(id_col.type, StringEncryptedType)

    def test_create_database_calls_create_all_with_encrypted_metadata(self) -> None:
        mock_engine = MagicMock()
        mock_metadata = MagicMock()
        with patch(
            "packages.db_helpers.encrypt_database_metadata",
            return_value=mock_metadata,
        ):
            create_database(mock_engine)
            mock_metadata.create_all.assert_called_once_with(mock_engine)

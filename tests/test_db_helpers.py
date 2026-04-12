import os
import unittest
from unittest.mock import MagicMock, patch

import sqlalchemy
from packages.db_helpers import (
    ADDITIVE_COLUMN_MIGRATIONS,
    apply_additive_migrations,
    create_database,
    encrypt_database_metadata,
    get_db_url,
    should_encrypt_column,
    should_encrypt_column_even_if_not_allowed_type,
    should_encrypt_column_traverser,
)
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    ForeignKey,
    Integer,
    LargeBinary,
    MetaData,
    TIMESTAMP,
    String,
    Table,
)
from sqlalchemy_utils.types.encrypted.encrypted_type import StringEncryptedType


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

    def test_should_not_encrypt_checkpoint_chat_peer_fk_column(self) -> None:
        metadata = MetaData()
        Table(
            "telegram_peers",
            metadata,
            Column("id", BigInteger(), primary_key=True, autoincrement=True),
        )
        checkpoints = Table(
            "preload_checkpoints",
            metadata,
            Column("chat_peer_id", BigInteger(), ForeignKey("telegram_peers.id")),
        )
        self.assertFalse(should_encrypt_column(checkpoints.c.chat_peer_id))

    def test_should_encrypt_checkpoint_message_cursor_identifier(self) -> None:
        self.assertTrue(
            should_encrypt_column(Column("preloaded_through_message_id", BigInteger()))
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
        with (
            patch(
                "packages.db_helpers.encrypt_database_metadata",
                return_value=mock_metadata,
            ),
            patch("packages.db_helpers.apply_additive_migrations") as migrate_mock,
        ):
            create_database(mock_engine)
            mock_metadata.create_all.assert_called_once_with(mock_engine)
            migrate_mock.assert_called_once_with(mock_engine, mock_metadata)

    def test_additive_migrations_include_attachment_metadata_columns(self) -> None:
        self.assertEqual(
            ADDITIVE_COLUMN_MIGRATIONS["telegram_messages"],
            (
                "grouped_id",
                "media_file_name",
                "media_mime_type",
                "media_document_attributes",
            ),
        )

    def test_apply_additive_migrations_adds_missing_message_attachment_columns(
        self,
    ) -> None:
        engine = sqlalchemy.create_engine("sqlite:///:memory:")
        legacy_metadata = MetaData()
        Table(
            "telegram_peers",
            legacy_metadata,
            Column("id", BigInteger(), primary_key=True),
            Column("peer_id", BigInteger()),
            Column("access_hash", BigInteger()),
            Column("type", Integer()),
        )
        Table(
            "telegram_messages",
            legacy_metadata,
            Column("id", BigInteger(), primary_key=True),
            Column("chat_peer_id", BigInteger(), primary_key=True),
            Column("edit_date", TIMESTAMP(timezone=True), primary_key=True),
            Column("from_peer_id", BigInteger()),
            Column("text", String()),
            Column("media", LargeBinary()),
            Column("timestamp", TIMESTAMP(timezone=True)),
            Column("deleted", Boolean()),
        )
        legacy_metadata.create_all(engine)

        try:
            apply_additive_migrations(engine)
            columns = {
                column["name"]
                for column in sqlalchemy.inspect(engine).get_columns(
                    "telegram_messages"
                )
            }
            self.assertIn("grouped_id", columns)
            self.assertIn("media_file_name", columns)
            self.assertIn("media_mime_type", columns)
            self.assertIn("media_document_attributes", columns)
        finally:
            engine.dispose()

import os
import unittest
from datetime import datetime, timedelta, timezone

import sqlalchemy
from packages.db_helpers import create_database

# Import model modules so their table definitions are registered on Base.metadata.
from packages.models.root.TelegramMessage import TelegramMessage  # noqa: F401
from packages.models.root.TelegramPeer import TelegramPeer  # noqa: F401
from sqlalchemy import text


def build_test_engine(database_url: str) -> sqlalchemy.Engine:
    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    return sqlalchemy.create_engine(database_url, echo=False, connect_args=connect_args)


def bool_from_db(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.lower() in ("1", "true", "t", "yes", "y")
    raise TypeError(f"Unsupported boolean value from DB: {value!r}")


class DatabaseBackendsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        database_url = os.getenv("INTEGRATION_DATABASE_URL")
        if not database_url:
            raise unittest.SkipTest("INTEGRATION_DATABASE_URL is not set")
        cls.engine = build_test_engine(database_url)
        create_database(cls.engine)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.engine.dispose()

    def setUp(self) -> None:
        self._peer_pk_counter = 10000
        with self.engine.begin() as conn:
            conn.execute(text("DELETE FROM telegram_messages"))
            conn.execute(text("DELETE FROM telegram_peers"))

    def _insert_peer(self, peer_id: int, access_hash: int, peer_type: int) -> int:
        self._peer_pk_counter += 1
        peer_pk = self._peer_pk_counter
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO telegram_peers (id, peer_id, access_hash, type) "
                    "VALUES (:id, :peer_id, :access_hash, :peer_type)"
                ),
                {
                    "id": peer_pk,
                    "peer_id": peer_id,
                    "access_hash": access_hash,
                    "peer_type": peer_type,
                },
            )
        return int(peer_pk)

    def _insert_message(
        self,
        message_id: int,
        chat_peer_id: int,
        from_peer_id: int,
        message_text: str,
        message_timestamp: datetime,
        deleted: bool,
    ) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO telegram_messages "
                    "(id, chat_peer_id, from_peer_id, text, media, timestamp, deleted) "
                    "VALUES (:id, :chat_peer_id, :from_peer_id, :message_text, :media, :timestamp, :deleted)"
                ),
                {
                    "id": message_id,
                    "chat_peer_id": chat_peer_id,
                    "from_peer_id": from_peer_id,
                    "message_text": message_text,
                    "media": None,
                    "timestamp": message_timestamp,
                    "deleted": deleted,
                },
            )

    def test_message_lifecycle_with_ansi_sql(self) -> None:
        chat_peer_pk = self._insert_peer(peer_id=1001, access_hash=4001, peer_type=1)
        from_peer_pk = self._insert_peer(peer_id=1002, access_hash=4002, peer_type=1)
        now = datetime.now(tz=timezone.utc)

        self._insert_message(
            message_id=9001,
            chat_peer_id=chat_peer_pk,
            from_peer_id=from_peer_pk,
            message_text="hello world",
            message_timestamp=now,
            deleted=False,
        )

        with self.engine.begin() as conn:
            total_messages = conn.execute(
                text("SELECT COUNT(*) AS count FROM telegram_messages")
            ).scalar_one()
            self.assertEqual(int(total_messages), 1)

            db_row = conn.execute(
                text(
                    "SELECT text, deleted FROM telegram_messages "
                    "WHERE id = :id AND chat_peer_id = :chat_peer_id"
                ),
                {"id": 9001, "chat_peer_id": chat_peer_pk},
            ).one()
            self.assertEqual(str(db_row.text), "hello world")
            self.assertFalse(bool_from_db(db_row.deleted))

            conn.execute(
                text(
                    "UPDATE telegram_messages "
                    "SET deleted = :deleted "
                    "WHERE id = :id AND chat_peer_id = :chat_peer_id"
                ),
                {"deleted": True, "id": 9001, "chat_peer_id": chat_peer_pk},
            )

            deleted_row = conn.execute(
                text(
                    "SELECT deleted FROM telegram_messages "
                    "WHERE id = :id AND chat_peer_id = :chat_peer_id"
                ),
                {"id": 9001, "chat_peer_id": chat_peer_pk},
            ).one()
            self.assertTrue(bool_from_db(deleted_row.deleted))

    def test_ttl_style_cleanup_removes_only_old_messages(self) -> None:
        chat_peer_pk = self._insert_peer(peer_id=2001, access_hash=5001, peer_type=1)
        from_peer_pk = self._insert_peer(peer_id=2002, access_hash=5002, peer_type=1)
        now = datetime.now(tz=timezone.utc)
        cutoff = now - timedelta(days=1)

        self._insert_message(
            message_id=9101,
            chat_peer_id=chat_peer_pk,
            from_peer_id=from_peer_pk,
            message_text="old message",
            message_timestamp=now - timedelta(days=7),
            deleted=False,
        )
        self._insert_message(
            message_id=9102,
            chat_peer_id=chat_peer_pk,
            from_peer_id=from_peer_pk,
            message_text="new message",
            message_timestamp=now,
            deleted=False,
        )

        with self.engine.begin() as conn:
            conn.execute(
                text("DELETE FROM telegram_messages WHERE timestamp < :cutoff"),
                {"cutoff": cutoff},
            )

            remaining_count = conn.execute(
                text("SELECT COUNT(*) AS count FROM telegram_messages")
            ).scalar_one()
            self.assertEqual(int(remaining_count), 1)

            remaining_message = conn.execute(
                text("SELECT id, text FROM telegram_messages")
            ).one()
            self.assertEqual(int(remaining_message.id), 9102)
            self.assertEqual(str(remaining_message.text), "new message")


if __name__ == "__main__":
    unittest.main(verbosity=2)

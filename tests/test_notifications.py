import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import telethon.tl.types
from sqlalchemy import BigInteger
from sqlalchemy.ext.compiler import compiles, deregister

from packages.event_orchestration import (
    get_store_message,
    group_deleted_messages_for_notification,
    load_messages_from_deleted_event,
)
from packages.models.root.TelegramMessage import TelegramMessage
from packages.notifications import (
    get_base_notify_message_deletion,
    get_base_notify_message_edit,
    get_default_notify_message_deletion,
    get_default_notify_message_edit,
    get_default_notify_unknown_message,
    get_mention_text,
)


class NotificationsTests(unittest.IsolatedAsyncioTestCase):
    def test_get_base_notify_message_deletion_returns_callable(self):
        mock_session_maker = MagicMock()
        result = get_base_notify_message_deletion(mock_session_maker)
        self.assertTrue(callable(result))

    def test_get_default_notify_message_deletion_returns_callable(self):
        result = get_default_notify_message_deletion()
        self.assertTrue(callable(result))

    def test_get_default_notify_unknown_message_returns_callable(self):
        result = get_default_notify_unknown_message()
        self.assertTrue(callable(result))

    @patch("packages.notifications.send_stored_messages_with_optional_media")
    @patch("packages.notifications.format_default_message_batch_texts")
    async def test_default_notify_message_deletion_calls_send_message(
        self, mock_format_text, mock_send_with_media
    ):
        mock_client = AsyncMock()
        mock_message = MagicMock()
        mock_message.media = None

        mock_format_text.return_value = ["Test message"]

        notify_func = get_default_notify_message_deletion()
        await notify_func(mock_message, mock_client)

        mock_send_with_media.assert_awaited_once_with(
            sender_client=mock_client,
            entity="me",
            formatted_texts=["Test message"],
            messages=[mock_message],
        )

    @patch("packages.notifications.format_default_unknown_message_text")
    async def test_default_notify_unknown_message_calls_send_message(
        self, mock_format_text
    ):
        mock_client = AsyncMock()
        mock_event = MagicMock()
        message_ids = [1, 2, 3]

        mock_format_text.return_value = "Unknown messages"

        notify_func = get_default_notify_unknown_message()
        await notify_func(message_ids, mock_event, mock_client)

        mock_client.send_message.assert_called_once()
        call_args = mock_client.send_message.call_args
        self.assertEqual(call_args.kwargs["entity"], "me")
        self.assertEqual(call_args.kwargs["message"], "Unknown messages")

    @patch("packages.notifications.send_stored_messages_with_optional_media")
    @patch("packages.notifications.format_default_message_batch_texts")
    async def test_default_notify_message_deletion_includes_media(
        self, mock_format_text, mock_send_with_media
    ):
        mock_client = AsyncMock()
        mock_media = MagicMock()
        mock_message = MagicMock()
        mock_message.media = mock_media

        mock_format_text.return_value = ["Test message"]

        notify_func = get_default_notify_message_deletion()
        await notify_func(mock_message, mock_client)

        mock_send_with_media.assert_awaited_once_with(
            sender_client=mock_client,
            entity="me",
            formatted_texts=["Test message"],
            messages=[mock_message],
        )

    async def test_base_notify_message_deletion_merges_and_marks_deleted(self):
        mock_session = MagicMock()
        mock_session_maker = MagicMock()
        mock_session_maker.begin.return_value.__enter__.return_value = mock_session
        mock_session_maker.begin.return_value.__exit__.return_value = False

        mock_message = MagicMock()
        mock_message.deleted = False

        notify_func = get_base_notify_message_deletion(mock_session_maker)
        await notify_func(mock_message, MagicMock())

        mock_session_maker.begin.assert_called_once()
        mock_session.merge.assert_called_once_with(mock_message)
        # The flag must land on the instance merge() returns (the one the
        # session tracks), not on the detached original.
        self.assertIs(mock_session.merge.return_value.deleted, True)

    async def test_base_notify_message_deletion_marks_album_messages_deleted(self):
        mock_session = MagicMock()
        mock_session_maker = MagicMock()
        mock_session_maker.begin.return_value.__enter__.return_value = mock_session
        mock_session_maker.begin.return_value.__exit__.return_value = False

        first_message = MagicMock()
        first_message.deleted = False
        second_message = MagicMock()
        second_message.deleted = False
        first_persisted = MagicMock()
        second_persisted = MagicMock()
        mock_session.merge.side_effect = [first_persisted, second_persisted]

        notification_message = MagicMock()
        notification_message.album_messages = [first_message, second_message]

        notify_func = get_base_notify_message_deletion(mock_session_maker)
        await notify_func(notification_message, MagicMock())

        self.assertEqual(mock_session.merge.call_count, 2)
        self.assertIs(first_persisted.deleted, True)
        self.assertIs(second_persisted.deleted, True)

    def test_get_base_notify_message_edit_returns_callable(self):
        mock_session_maker = MagicMock()
        result = get_base_notify_message_edit(mock_session_maker)
        self.assertTrue(callable(result))

    def test_get_default_notify_message_edit_returns_callable(self):
        result = get_default_notify_message_edit()
        self.assertTrue(callable(result))

    @patch("packages.notifications.send_stored_message_with_optional_media")
    @patch("packages.notifications.format_default_message_edit_text")
    async def test_default_notify_message_edit_calls_send_message(
        self, mock_format_text, mock_send_with_media
    ):
        mock_client = AsyncMock()
        mock_message = MagicMock()
        mock_message.media = None
        mock_message.text = "Edited text"
        mock_format_text.return_value = "Formatted edit text"

        notify_func = get_default_notify_message_edit()
        await notify_func(mock_message, mock_client)

        mock_send_with_media.assert_awaited_once_with(
            sender_client=mock_client,
            entity="me",
            formatted_text="Formatted edit text",
            message=mock_message,
        )

    async def test_base_notify_message_edit_merges_without_marking_deleted(self):
        mock_session_maker = MagicMock()

        mock_message = MagicMock()
        mock_message.deleted = False

        notify_func = get_base_notify_message_edit(mock_session_maker)
        await notify_func(mock_message, MagicMock())

        mock_session_maker.begin.assert_not_called()
        self.assertFalse(mock_message.deleted)


class BaseNotifyMessageDeletionPersistenceTests(unittest.IsolatedAsyncioTestCase):
    """Persistence regression against a real database, driven through the
    app's own paths end to end: messages are seeded with the real
    store_message ingestion flow (build_telegram_peer peer upserts included),
    loaded the way the deletion flow loads them (load_messages_from_deleted_event
    + group_deleted_messages_for_notification), and the deleted flag is
    asserted in the database."""

    # Telegram-shaped fixture values (a private 1:1 chat: from_id == peer_id).
    USER_ID = 6046024752
    MESSAGE_ID = 4862
    ALBUM_MESSAGE_IDS = (4870, 4871)
    ALBUM_GROUPED_ID = 777
    MESSAGE_TEXT = "Hello from the other side"
    MESSAGE_DATETIME = datetime(2026, 11, 17, 9, 30, tzinfo=timezone.utc)

    @classmethod
    def setUpClass(cls):
        # Production Postgres generates BIGINT primary keys server-side, and the
        # app's peer write path (build_telegram_peer merge, no explicit id)
        # depends on that. SQLite only auto-generates ids for INTEGER PRIMARY
        # KEY, so stock SQLite DDL cannot run the app's write path at all.
        # Render BigInteger as INTEGER on SQLite for the lifetime of this class
        # to emulate the production id-generation behavior, then undo it.
        @compiles(BigInteger, "sqlite")
        def _biginteger_as_integer(element, compiler, **kw):
            return "INTEGER"

        cls._biginteger_sqlite_compilation = _biginteger_as_integer

    @classmethod
    def tearDownClass(cls):
        # Removes the class-owned BigInteger sqlite compiler registration
        # (no other test registers one; this restores pristine global state).
        deregister(BigInteger)

    def setUp(self):
        from packages.models.root import TelegramMessage, TelegramPeer  # noqa: F401
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        from packages.models import Base

        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        # expire_on_commit=False mirrors bootstrap.py's sessionmaker.
        self.session_maker = sessionmaker(bind=self.engine, expire_on_commit=False)

    def _user(self) -> telethon.tl.types.User:
        return telethon.tl.types.User(
            id=self.USER_ID,
            is_self=False,
            contact=False,
            mutual_contact=False,
            deleted=False,
            bot=False,
            bot_chat_history=False,
            bot_nochats=False,
            verified=False,
            restricted=False,
            min=False,
            first_name="Jane",
            last_name="Doe",
            username="janedoe",
            phone=None,
            photo=None,
            status=None,
        )

    def _client(self) -> AsyncMock:
        client = AsyncMock()
        client.get_entity.return_value = self._user()
        client.get_peer_id.return_value = self.USER_ID
        return client

    async def _store_message(
        self, client: AsyncMock, message_id: int, grouped_id: int | None = None
    ) -> None:
        """Seed one message through the app's real ingestion path, the way
        on_new_message stores a private-chat text message from a user."""
        message = MagicMock()
        message.id = message_id
        message.message = self.MESSAGE_TEXT
        message.date = self.MESSAGE_DATETIME
        message.edit_date = None
        message.media = None
        message.grouped_id = grouped_id
        message.from_id = telethon.tl.types.PeerUser(user_id=self.USER_ID)
        message.peer_id = telethon.tl.types.PeerUser(user_id=self.USER_ID)
        message.get_chat = AsyncMock(return_value=self._user())

        store_message = get_store_message(self.session_maker, client)
        await store_message(message, check_chat=True)

    async def _load_for_deleted_event(
        self, client: AsyncMock, message_ids: list[int]
    ) -> list[TelegramMessage]:
        """Load stored rows the way on_message_deleted does after receiving a
        MessageDeleted event for the private chat."""
        event = MagicMock()
        event.deleted_ids = message_ids
        event.get_input_chat = AsyncMock(
            return_value=telethon.tl.types.InputPeerUser(
                user_id=self.USER_ID, access_hash=0
            )
        )

        with self.session_maker.begin() as sqlalchemy_session:
            loaded_messages, _, _, _ = await load_messages_from_deleted_event(
                event,
                client,
                sqlalchemy_session,
                ignore_channels=False,
                ignore_groups=False,
                ignore_megagroups=False,
                ignore_gigagroups=False,
                member_ignore_threshold=0,
                should_notify_outgoing_messages=True,
            )
        return loaded_messages

    def _deleted_flag_in_db(self, message_id: int) -> bool:
        from sqlalchemy import select

        with self.session_maker() as session:
            return session.scalars(
                select(TelegramMessage.deleted).where(TelegramMessage.id == message_id)
            ).one()

    async def test_deleted_flag_persists_to_database(self):
        client = self._client()
        await self._store_message(client, self.MESSAGE_ID)
        self.assertIs(self._deleted_flag_in_db(self.MESSAGE_ID), False)

        loaded_messages = await self._load_for_deleted_event(client, [self.MESSAGE_ID])
        notification_batches = group_deleted_messages_for_notification(loaded_messages)
        notify_message_deletion = get_base_notify_message_deletion(self.session_maker)
        for batch in notification_batches:
            await notify_message_deletion(batch[0], client)

        self.assertIs(self._deleted_flag_in_db(self.MESSAGE_ID), True)

    async def test_deleted_flag_persists_for_grouped_messages(self):
        client = self._client()
        for message_id in self.ALBUM_MESSAGE_IDS:
            await self._store_message(client, message_id, grouped_id=self.ALBUM_GROUPED_ID)

        loaded_messages = await self._load_for_deleted_event(
            client, list(self.ALBUM_MESSAGE_IDS)
        )
        notification_batches = group_deleted_messages_for_notification(loaded_messages)
        notify_message_deletion = get_base_notify_message_deletion(self.session_maker)
        for batch in notification_batches:
            await notify_message_deletion(batch[0], client)

        for message_id in self.ALBUM_MESSAGE_IDS:
            self.assertIs(self._deleted_flag_in_db(message_id), True)


class GetMentionTextTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_unknown_when_peer_is_none(self):
        mock_client = AsyncMock()
        result = await get_mention_text(mock_client, None)
        self.assertEqual(result, "Unknown")

    async def test_returns_entity_title_when_present(self):
        mock_client = AsyncMock()
        mock_entity = MagicMock()
        mock_entity.title = "Test Group"
        mock_entity.first_name = None
        mock_entity.last_name = None
        mock_entity.username = None
        mock_entity.phone = None
        mock_entity.id = 123
        mock_client.get_entity.return_value = mock_entity

        mock_peer = MagicMock()

        result = await get_mention_text(mock_client, mock_peer)
        self.assertEqual(result, "Test Group")

    async def test_returns_first_name_only(self):
        mock_client = AsyncMock()
        mock_entity = MagicMock()
        mock_entity.title = None
        mock_entity.first_name = "John"
        mock_entity.last_name = None
        mock_entity.username = None
        mock_entity.phone = None
        mock_entity.id = 123
        mock_client.get_entity.return_value = mock_entity

        result = await get_mention_text(mock_client, MagicMock())
        self.assertEqual(result, "John ")

    async def test_returns_last_name_only(self):
        mock_client = AsyncMock()
        mock_entity = MagicMock()
        mock_entity.title = None
        mock_entity.first_name = None
        mock_entity.last_name = "Doe"
        mock_entity.username = None
        mock_entity.phone = None
        mock_entity.id = 123
        mock_client.get_entity.return_value = mock_entity

        result = await get_mention_text(mock_client, MagicMock())
        self.assertEqual(result, "Doe")

    async def test_returns_first_and_last_name(self):
        mock_client = AsyncMock()
        mock_entity = MagicMock()
        mock_entity.title = None
        mock_entity.first_name = "John"
        mock_entity.last_name = "Doe"
        mock_entity.username = None
        mock_entity.phone = None
        mock_entity.id = 123
        mock_client.get_entity.return_value = mock_entity

        result = await get_mention_text(mock_client, MagicMock())
        self.assertEqual(result, "John Doe")

    async def test_returns_username_when_no_name(self):
        mock_client = AsyncMock()
        mock_entity = MagicMock()
        mock_entity.title = None
        mock_entity.first_name = None
        mock_entity.last_name = None
        mock_entity.username = "testuser"
        mock_entity.phone = None
        mock_entity.id = 123
        mock_client.get_entity.return_value = mock_entity

        result = await get_mention_text(mock_client, MagicMock())
        self.assertEqual(result, "testuser")

    async def test_returns_phone_when_no_name_or_username(self):
        mock_client = AsyncMock()
        mock_entity = MagicMock()
        mock_entity.title = None
        mock_entity.first_name = None
        mock_entity.last_name = None
        mock_entity.username = None
        mock_entity.phone = "+1234567890"
        mock_entity.id = 123
        mock_client.get_entity.return_value = mock_entity

        result = await get_mention_text(mock_client, MagicMock())
        self.assertEqual(result, "+1234567890")

    async def test_returns_id_as_string_when_no_other_attrs(self):
        mock_client = AsyncMock()
        mock_entity = MagicMock()
        mock_entity.title = None
        mock_entity.first_name = None
        mock_entity.last_name = None
        mock_entity.username = None
        mock_entity.phone = None
        mock_entity.id = 42
        mock_client.get_entity.return_value = mock_entity

        result = await get_mention_text(mock_client, MagicMock())
        self.assertEqual(result, "42")

    async def test_returns_unknown_on_exception(self):
        mock_client = AsyncMock()
        mock_client.get_entity.side_effect = Exception("API error")

        result = await get_mention_text(mock_client, MagicMock())
        self.assertEqual(result, "Unknown")

    async def test_uses_to_telethon_input_peer_when_available(self):
        mock_client = AsyncMock()
        mock_entity = MagicMock()
        mock_entity.title = "Channel"
        mock_entity.first_name = None
        mock_entity.last_name = None
        mock_entity.username = None
        mock_entity.phone = None
        mock_entity.id = 99
        mock_client.get_entity.return_value = mock_entity

        mock_peer = MagicMock()
        input_peer = MagicMock()
        mock_peer.to_telethon_input_peer.return_value = input_peer

        result = await get_mention_text(mock_client, mock_peer)

        mock_peer.to_telethon_input_peer.assert_called_once()
        mock_client.get_entity.assert_called_once_with(input_peer)
        self.assertEqual(result, "Channel")

    async def test_uses_peer_directly_when_no_to_telethon_input_peer(self):
        mock_client = AsyncMock()
        mock_entity = MagicMock()
        mock_entity.title = "Direct Peer"
        mock_entity.first_name = None
        mock_entity.last_name = None
        mock_entity.username = None
        mock_entity.phone = None
        mock_entity.id = 77
        mock_client.get_entity.return_value = mock_entity

        mock_peer = MagicMock(spec=[])  # No to_telethon_input_peer

        result = await get_mention_text(mock_client, mock_peer)

        mock_client.get_entity.assert_called_once_with(mock_peer)
        self.assertEqual(result, "Direct Peer")

    @patch("packages.notifications.build_peer_entity", new_callable=AsyncMock)
    async def test_resolves_telegram_peer_via_shared_helper(
        self, mock_build_peer_entity
    ):
        mock_client = AsyncMock()
        mock_entity = MagicMock()
        mock_entity.title = "Resolved Peer"
        mock_entity.first_name = None
        mock_entity.last_name = None
        mock_entity.username = None
        mock_entity.phone = None
        mock_entity.id = 88
        mock_build_peer_entity.return_value = mock_entity

        mock_peer = MagicMock()

        result = await get_mention_text(mock_client, mock_peer)

        mock_build_peer_entity.assert_called_once_with(mock_peer, mock_client)
        mock_client.get_entity.assert_not_called()
        self.assertEqual(result, "Resolved Peer")


if __name__ == "__main__":
    unittest.main()

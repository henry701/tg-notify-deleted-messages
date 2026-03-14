import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from packages.models.root.TelegramPeer import TelegramPeer
from packages.models.support.PeerType import PeerType
from packages.telegram_helpers import (
    build_peer_entity,
    build_telegram_peer,
    format_default_message_text,
    format_default_unknown_message_text,
    get_mention_text,
    refresh_client,
    to_telethon_input_peer,
)
from telethon.tl.types import (
    InputPeerChannel,
    InputPeerChat,
    InputPeerSelf,
    InputPeerUser,
)


class GetMentionTextTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_title_when_entity_has_title(self):
        entity = MagicMock()
        entity.title = "My Channel"
        result = await get_mention_text(entity)
        self.assertEqual(result, "My Channel")

    async def test_returns_first_and_last_name(self):
        entity = MagicMock()
        entity.first_name = "John"
        entity.last_name = "Doe"
        entity.title = None
        result = await get_mention_text(entity)
        self.assertEqual(result, "John Doe")

    async def test_returns_first_name_only(self):
        entity = MagicMock()
        entity.first_name = "John"
        entity.last_name = ""
        entity.title = None
        result = await get_mention_text(entity)
        self.assertEqual(result, "John ")

    async def test_returns_last_name_only(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = "Doe"
        entity.title = None
        result = await get_mention_text(entity)
        self.assertEqual(result, "Doe")

    async def test_returns_username_when_no_name(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = ""
        entity.title = None
        entity.username = "johndoe"
        result = await get_mention_text(entity)
        self.assertEqual(result, "johndoe")

    async def test_returns_phone_when_no_name_or_username(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = ""
        entity.title = None
        entity.username = None
        entity.phone = "123456789"
        result = await get_mention_text(entity)
        self.assertEqual(result, "123456789")

    async def test_returns_id_when_no_name_username_or_phone(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = ""
        entity.title = None
        entity.username = None
        entity.phone = None
        entity.id = 42
        result = await get_mention_text(entity)
        self.assertEqual(result, 42)

    async def test_returns_chat_id_when_no_other_identifiers(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = ""
        entity.title = None
        entity.username = None
        entity.phone = None
        entity.id = None
        entity.chat_id = 99
        result = await get_mention_text(entity)
        self.assertEqual(result, 99)

    async def test_returns_anonymous_for_none_entity(self):
        result = await get_mention_text(None)
        self.assertEqual(result, "Anonymous")

    async def test_returns_type_name_when_no_identifiable_info(self):
        entity = MagicMock()
        entity.first_name = ""
        entity.last_name = ""
        entity.title = None
        entity.username = None
        entity.phone = None
        entity.id = None
        entity.chat_id = None
        result = await get_mention_text(entity)
        self.assertIn("UNKNOWN", result)


class ToTelethonInputPeerTests(unittest.TestCase):
    def test_user_type_with_access_hash_returns_input_peer_user(self):
        peer = TelegramPeer(
            id=1,
            peer_id=100,
            access_hash=200,
            type=PeerType.USER,
        )
        result = to_telethon_input_peer(peer)
        self.assertIsInstance(result, InputPeerUser)
        self.assertEqual(result.user_id, 100)
        self.assertEqual(result.access_hash, 200)

    def test_user_type_without_access_hash_returns_input_peer_self(self):
        peer = TelegramPeer(
            id=1,
            peer_id=100,
            access_hash=None,
            type=PeerType.USER,
        )
        result = to_telethon_input_peer(peer)
        self.assertIsInstance(result, InputPeerSelf)

    def test_channel_type_returns_input_peer_channel(self):
        peer = TelegramPeer(
            id=1,
            peer_id=100,
            access_hash=200,
            type=PeerType.CHANNEL,
        )
        result = to_telethon_input_peer(peer)
        self.assertIsInstance(result, InputPeerChannel)
        self.assertEqual(result.channel_id, 100)
        self.assertEqual(result.access_hash, 200)

    def test_chat_type_returns_input_peer_chat(self):
        peer = TelegramPeer(
            id=1,
            peer_id=100,
            access_hash=None,
            type=PeerType.CHAT,
        )
        result = to_telethon_input_peer(peer)
        self.assertIsInstance(result, InputPeerChat)
        self.assertEqual(result.chat_id, 100)

    def test_encrypted_chat_type_returns_input_encrypted_chat(self):
        from telethon.tl.types import InputEncryptedChat

        peer = TelegramPeer(
            id=1,
            peer_id=100,
            access_hash=200,
            type=PeerType.ENCRYPTED_CHAT,
        )
        result = to_telethon_input_peer(peer)
        self.assertIsInstance(result, InputEncryptedChat)
        self.assertEqual(result.chat_id, 100)
        self.assertEqual(result.access_hash, 200)

    def test_encrypted_chat_type_without_access_hash_returns_input_encrypted_chat(self):
        from telethon.tl.types import InputEncryptedChat

        peer = TelegramPeer(
            id=1,
            peer_id=100,
            access_hash=None,
            type=PeerType.ENCRYPTED_CHAT,
        )
        result = to_telethon_input_peer(peer)
        self.assertIsInstance(result, InputEncryptedChat)


class BuildPeerEntityTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_none_for_none_peer(self):
        client = AsyncMock()
        result = await build_peer_entity(None, client)
        self.assertIsNone(result)

    async def test_returns_none_for_peer_with_none_input_type(self):
        client = AsyncMock()
        # Create a TelegramPeer with an unknown type value that won't map to an InputPeer
        peer = MagicMock(spec=TelegramPeer)
        peer.id = 1
        peer.peer_id = 100
        peer.access_hash = None
        peer.type = 99  # Unknown type that won't map to any InputPeer
        result = await build_peer_entity(peer, client)
        self.assertIsNone(result)

    async def test_returns_entity_for_valid_peer(self):
        client = AsyncMock()
        mock_entity = MagicMock()
        client.get_entity.return_value = mock_entity

        peer = MagicMock(spec=TelegramPeer)
        peer.id = 1
        peer.peer_id = 100
        peer.access_hash = 200
        peer.type = PeerType.USER

        result = await build_peer_entity(peer, client)
        self.assertIs(result, mock_entity)
        client.get_entity.assert_called_once()


class RefreshClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_calls_expected_client_methods(self):
        client = AsyncMock()
        await refresh_client(client)
        client.get_dialogs.assert_called_once()
        client.get_me.assert_called_once()
        client.get_messages.assert_called_once_with(limit=10)


class BuildTelegramPeerTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_none_for_none_peer(self):
        client = AsyncMock()
        session_maker = MagicMock()
        result = await build_telegram_peer(None, client, session_maker)
        self.assertIsNone(result)


class FormatDefaultMessageTextTests(unittest.IsolatedAsyncioTestCase):
    async def test_formats_message_with_user_and_chat(self):
        from packages.models.root.TelegramMessage import TelegramMessage
        from packages.models.root.TelegramPeer import TelegramPeer
        from packages.models.support.PeerType import PeerType

        client = AsyncMock()
        user_entity = MagicMock()
        user_entity.id = 100
        user_entity.first_name = "John"
        user_entity.last_name = "Doe"
        user_entity.title = None
        user_entity.username = None
        user_entity.phone = None
        user_entity.chat_id = None

        chat_entity = MagicMock()
        chat_entity.id = 200
        chat_entity.title = "Test Chat"
        chat_entity.first_name = None
        chat_entity.last_name = None
        chat_entity.username = None
        chat_entity.phone = None
        chat_entity.chat_id = None

        client.get_entity.side_effect = [user_entity, chat_entity]

        from_peer = TelegramPeer(id=1, peer_id=100, access_hash=1, type=PeerType.USER)
        chat_peer = TelegramPeer(id=2, peer_id=200, access_hash=2, type=PeerType.CHAT)

        message = TelegramMessage(
            id=1,
            from_peer=from_peer,
            chat_peer=chat_peer,
            text="Hello",
            media=None,
            timestamp=None,
        )

        with patch(
            "packages.telegram_helpers.to_telethon_input_peer", return_value=MagicMock()
        ):
            result = await format_default_message_text(client, message)

        self.assertIn("John Doe", result)
        self.assertIn("Test Chat", result)
        self.assertIn("Hello", result)

    async def test_formats_message_with_no_text(self):
        from packages.models.root.TelegramMessage import TelegramMessage
        from packages.models.root.TelegramPeer import TelegramPeer
        from packages.models.support.PeerType import PeerType

        client = AsyncMock()
        user_entity = MagicMock()
        user_entity.id = 100
        user_entity.first_name = "John"
        user_entity.title = None
        user_entity.last_name = ""
        user_entity.username = None
        user_entity.phone = None
        user_entity.chat_id = None

        chat_entity = MagicMock()
        chat_entity.id = 200
        chat_entity.title = "Chat"
        chat_entity.first_name = None
        chat_entity.last_name = None
        chat_entity.username = None
        chat_entity.phone = None
        chat_entity.chat_id = None

        client.get_entity.side_effect = [user_entity, chat_entity]

        from_peer = TelegramPeer(id=1, peer_id=100, access_hash=1, type=PeerType.USER)
        chat_peer = TelegramPeer(id=2, peer_id=200, access_hash=2, type=PeerType.CHAT)

        message = TelegramMessage(
            id=1,
            from_peer=from_peer,
            chat_peer=chat_peer,
            text=None,
            media=None,
            timestamp=None,
        )

        with patch(
            "packages.telegram_helpers.to_telethon_input_peer", return_value=MagicMock()
        ):
            result = await format_default_message_text(client, message)

        self.assertIn("Deleted message", result)
        self.assertNotIn("**Message Text:**", result)

    async def test_raises_on_second_valueerror(self):
        from packages.models.root.TelegramMessage import TelegramMessage
        from packages.models.root.TelegramPeer import TelegramPeer
        from packages.models.support.PeerType import PeerType

        client = AsyncMock()
        client.get_entity = AsyncMock(side_effect=ValueError("Still not found"))

        from_peer = TelegramPeer(id=1, peer_id=100, access_hash=1, type=PeerType.USER)
        chat_peer = TelegramPeer(id=2, peer_id=200, access_hash=2, type=PeerType.CHAT)

        message = TelegramMessage(
            id=1,
            from_peer=from_peer,
            chat_peer=chat_peer,
            text="test",
            media=None,
            timestamp=None,
        )

        with patch(
            "packages.telegram_helpers.to_telethon_input_peer", return_value=MagicMock()
        ):
            with patch(
                "packages.telegram_helpers.refresh_client", new_callable=AsyncMock
            ):
                with self.assertRaises(ValueError):
                    await format_default_message_text(client, message, tried=True)


class FormatDefaultUnknownMessageTextTests(unittest.IsolatedAsyncioTestCase):
    async def test_formats_unknown_deleted_messages(self):
        client = AsyncMock()
        chat_entity = MagicMock()
        chat_entity.id = 300
        chat_entity.title = "Unknown Chat"
        chat_entity.first_name = None
        chat_entity.last_name = None
        chat_entity.username = None
        chat_entity.phone = None
        chat_entity.chat_id = None
        client.get_entity.return_value = chat_entity

        event_mock = AsyncMock()
        event_mock.get_input_chat = AsyncMock(return_value=MagicMock())

        result = await format_default_unknown_message_text(
            client, [10, 20, 30], event_mock
        )

        self.assertIn("Unknown deleted messages", result)
        self.assertIn("Unknown Chat", result)
        self.assertIn("3 total", result)
        self.assertIn("10", result)
        self.assertIn("20", result)
        self.assertIn("30", result)

    async def test_handles_none_chat(self):
        client = AsyncMock()
        client.get_entity.return_value = None

        event_mock = AsyncMock()
        event_mock.get_input_chat = AsyncMock(return_value=None)

        result = await format_default_unknown_message_text(client, [5], event_mock)

        self.assertIn("Anonymous", result)
        self.assertIn("1 total", result)

    async def test_retries_on_valueerror_then_succeeds(self):
        client = AsyncMock()
        chat_entity = MagicMock()
        chat_entity.id = 300
        chat_entity.title = "Retry Chat"
        chat_entity.first_name = None
        chat_entity.last_name = None
        chat_entity.username = None
        chat_entity.phone = None
        chat_entity.chat_id = None

        mock_input = MagicMock()
        event_mock = AsyncMock()
        event_mock.get_input_chat = AsyncMock(return_value=mock_input)

        call_count = 0

        async def get_entity_side_effect(entity):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("Entity not found")
            return chat_entity

        client.get_entity = get_entity_side_effect

        with patch("packages.telegram_helpers.refresh_client", new_callable=AsyncMock):
            result = await format_default_unknown_message_text(
                client, [10, 20], event_mock
            )

        self.assertIn("Retry Chat", result)
        self.assertIn("2 total", result)

    async def test_raises_on_second_valueerror(self):
        client = AsyncMock()
        mock_input = MagicMock()
        event_mock = AsyncMock()
        event_mock.get_input_chat = AsyncMock(return_value=mock_input)

        client.get_entity = AsyncMock(side_effect=ValueError("Still not found"))

        with patch("packages.telegram_helpers.refresh_client", new_callable=AsyncMock):
            with self.assertRaises(ValueError):
                await format_default_unknown_message_text(
                    client, [10], event_mock, tried=True
                )


if __name__ == "__main__":
    unittest.main()

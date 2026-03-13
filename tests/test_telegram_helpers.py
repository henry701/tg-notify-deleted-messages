import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from telethon.tl.types import (
    InputPeerChannel,
    InputPeerChat,
    InputPeerSelf,
    InputPeerUser,
    PeerChannel,
    PeerChat,
    PeerUser,
)

from packages.telegram_helpers import (
    get_mention_text,
    to_telethon_input_peer,
    build_peer_entity,
    refresh_client,
)
from packages.models.root.TelegramPeer import TelegramPeer
from packages.models.support.PeerType import PeerType


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


if __name__ == "__main__":
    unittest.main()

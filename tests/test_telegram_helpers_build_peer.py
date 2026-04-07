import unittest
from unittest.mock import AsyncMock, MagicMock
from packages.telegram_helpers import build_telegram_peer
from telethon.tl.types import User


class BuildTelegramPeerTests(unittest.IsolatedAsyncioTestCase):
    async def test_builds_existing_peer_from_database(self):
        # Setup mocks
        client_mock = AsyncMock()
        session_maker = MagicMock()
        session_mock = MagicMock()
        existing_peer = MagicMock()
        existing_peer.peer_id = 123
        existing_peer.type = 1  # PeerType.USER

        # Mock database query to return existing peer
        session_mock.execute.return_value.scalar.return_value = existing_peer

        # Setup session maker context manager
        session_maker.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker.begin.return_value.__exit__ = MagicMock(return_value=False)

        # Mock client methods
        client_mock.get_entity.return_value = User(id=42)
        client_mock.get_peer_id.return_value = 123

        result = await build_telegram_peer(
            peer=42, client=client_mock, sqlalchemy_session_maker=session_maker
        )

        self.assertEqual(result.peer_id, 123)
        self.assertEqual(result.type, 1)

    async def test_creates_new_peer_when_not_in_database(self):
        # Setup mocks
        client_mock = AsyncMock()
        session_maker = MagicMock()
        session_mock = MagicMock()

        # Mock database query to return None first, then return the new peer
        new_peer = MagicMock()
        new_peer.peer_id = 42
        new_peer.type = 1  # PeerType.USER
        new_peer.access_hash = 12345
        session_mock.execute.return_value.scalar.side_effect = [None, new_peer]

        # Setup session maker context manager
        session_maker.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker.begin.return_value.__exit__ = MagicMock(return_value=False)

        # Mock client methods
        user_entity = User(id=42, access_hash=12345)
        client_mock.get_entity.return_value = user_entity
        client_mock.get_peer_id.return_value = 42

        result = await build_telegram_peer(
            peer=42, client=client_mock, sqlalchemy_session_maker=session_maker
        )

        self.assertEqual(result.peer_id, 42)
        self.assertEqual(result.type, 1)  # PeerType.USER
        self.assertEqual(result.access_hash, 12345)

import asyncio
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from packages.bootstrap import make_client


class MakeClientChunkSizeOverrideTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_no_override(self):
        container_mock = MagicMock()
        session_mock = MagicMock()
        container_mock.new_session.return_value = session_mock

        loop = asyncio.get_event_loop()

        with patch.dict(os.environ, {}, clear=False):
            if "TELETHON_OVERRIDE_MAX_CHUNK_SIZE" in os.environ:
                del os.environ["TELETHON_OVERRIDE_MAX_CHUNK_SIZE"]
            if "TELEGRAM_MAX_CHUNK_SIZE" in os.environ:
                del os.environ["TELEGRAM_MAX_CHUNK_SIZE"]

            with patch("packages.bootstrap.TelegramClient") as MockClient:
                client_instance = AsyncMock()
                MockClient.return_value = client_instance
                import telethon.client.messages

                original_max_chunk = telethon.client.messages._MAX_CHUNK_SIZE

                await make_client(
                    container_mock, "api_id", "api_hash", "session1", loop
                )

                self.assertEqual(
                    telethon.client.messages._MAX_CHUNK_SIZE,
                    original_max_chunk,
                    "Default chunk size should not be modified when no env var set",
                )

    async def test_telethon_override_respected(self):
        container_mock = MagicMock()
        session_mock = MagicMock()
        container_mock.new_session.return_value = session_mock

        loop = asyncio.get_event_loop()
        test_chunk_size = 42

        with patch.dict(
            os.environ,
            {"TELETHON_OVERRIDE_MAX_CHUNK_SIZE": str(test_chunk_size)},
            clear=False,
        ):
            with patch("packages.bootstrap.TelegramClient") as MockClient:
                client_instance = AsyncMock()
                MockClient.return_value = client_instance

                import telethon.client.messages

                original_max_chunk = telethon.client.messages._MAX_CHUNK_SIZE

                await make_client(
                    container_mock, "api_id", "api_hash", "session1", loop
                )

                self.assertEqual(
                    telethon.client.messages._MAX_CHUNK_SIZE,
                    test_chunk_size,
                    "Telethon override should be respected when set",
                )

                telethon.client.messages._MAX_CHUNK_SIZE = original_max_chunk

    async def test_telegram_max_chunk_size_override(self):
        container_mock = MagicMock()
        session_mock = MagicMock()
        container_mock.new_session.return_value = session_mock

        loop = asyncio.get_event_loop()
        test_chunk_size = 100

        with patch.dict(
            os.environ, {"TELEGRAM_MAX_CHUNK_SIZE": str(test_chunk_size)}, clear=False
        ):
            with patch("packages.bootstrap.TelegramClient") as MockClient:
                client_instance = AsyncMock()
                MockClient.return_value = client_instance

                import telethon.client.messages

                original_max_chunk = telethon.client.messages._MAX_CHUNK_SIZE

                await make_client(
                    container_mock, "api_id", "api_hash", "session1", loop
                )

                self.assertEqual(
                    telethon.client.messages._MAX_CHUNK_SIZE,
                    test_chunk_size,
                    "TELEGRAM_MAX_CHUNK_SIZE override should be respected",
                )

                telethon.client.messages._MAX_CHUNK_SIZE = original_max_chunk

    async def test_invalid_override_ignored(self):
        container_mock = MagicMock()
        session_mock = MagicMock()
        container_mock.new_session.return_value = session_mock

        loop = asyncio.get_event_loop()

        with patch.dict(
            os.environ, {"TELEGRAM_MAX_CHUNK_SIZE": "invalid"}, clear=False
        ):
            with patch("packages.bootstrap.TelegramClient") as MockClient:
                client_instance = AsyncMock()
                MockClient.return_value = client_instance

                import telethon.client.messages

                original_max_chunk = telethon.client.messages._MAX_CHUNK_SIZE

                await make_client(
                    container_mock, "api_id", "api_hash", "session1", loop
                )

                self.assertEqual(
                    telethon.client.messages._MAX_CHUNK_SIZE,
                    original_max_chunk,
                    "Invalid override should be ignored",
                )


if __name__ == "__main__":
    unittest.main()

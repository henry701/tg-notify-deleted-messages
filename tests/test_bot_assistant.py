import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from packages.bot_assistant import BotAssistant


class BotAssistantInitTests(unittest.TestCase):
    def test_init_sets_attributes(self):
        bot = BotAssistant(
            target_chat="me",
            api_id=123,
            api_hash="hash",
            bot_token="token",
            session_maker=MagicMock(),
        )
        self.assertEqual(bot.target_chat, "me")
        self.assertEqual(bot.api_id, 123)
        self.assertEqual(bot.api_hash, "hash")
        self.assertEqual(bot.bot_token, "token")


class BotAssistantThrowIfUninitializedTests(unittest.TestCase):
    def test_raises_when_client_is_none(self):
        bot = BotAssistant("me", 123, "hash", "token", MagicMock())
        bot.client = None
        with self.assertRaises(RuntimeError):
            bot.throw_if_uninitialized()

    def test_does_not_raise_when_client_set(self):
        bot = BotAssistant("me", 123, "hash", "token", MagicMock())
        bot.client = MagicMock()
        bot.throw_if_uninitialized()


class BotAssistantNotifyTests(unittest.IsolatedAsyncioTestCase):
    async def test_notify_message_deletion(self):
        bot = BotAssistant("me", 123, "hash", "token", MagicMock())
        bot.client = AsyncMock()
        message_mock = MagicMock()
        message_mock.media = None
        message_mock.from_peer = None
        message_mock.chat_peer = None
        message_mock.text = "test"
        message_mock.id = 1

        client_mock = AsyncMock()

        with patch(
            "packages.bot_assistant.format_default_message_text",
            new_callable=AsyncMock,
        ) as fmt_mock:
            fmt_mock.return_value = "formatted text"
            await bot.notify_message_deletion(message_mock, client_mock)
            bot.client.send_message.assert_called_once()

    async def test_notify_unknown_message(self):
        bot = BotAssistant("me", 123, "hash", "token", MagicMock())
        bot.client = AsyncMock()
        event_mock = MagicMock()
        client_mock = AsyncMock()

        with patch(
            "packages.bot_assistant.format_default_unknown_message_text",
            new_callable=AsyncMock,
        ) as fmt_mock:
            fmt_mock.return_value = "unknown messages"
            await bot.notify_unknown_message([1, 2, 3], event_mock, client_mock)
            bot.client.send_message.assert_called_once()

    async def test_notify_raises_when_uninitialized(self):
        bot = BotAssistant("me", 123, "hash", "token", MagicMock())
        bot.client = None
        message_mock = MagicMock()
        client_mock = AsyncMock()
        with self.assertRaises(RuntimeError):
            await bot.notify_message_deletion(message_mock, client_mock)


class BotAssistantEnterExitTests(unittest.IsolatedAsyncioTestCase):
    async def test_aenter_creates_client(self):
        session_mock = MagicMock()
        session_maker = MagicMock(return_value=session_mock)
        bot = BotAssistant("me", 123, "hash", "token", session_maker)

        with patch("packages.bot_assistant.TelegramClient") as client_cls:
            client_instance = AsyncMock()
            client_cls.return_value = client_instance
            await bot.__aenter__()
            self.assertEqual(bot.client, client_instance)
            client_instance.connect.assert_called_once()
            client_instance.sign_in.assert_called_once_with(bot_token="token")

    async def test_aexit_disconnects(self):
        bot = BotAssistant("me", 123, "hash", "token", MagicMock())
        client_mock = AsyncMock()
        bot.client = client_mock
        await bot.__aexit__(None, None, None)
        client_mock.__aexit__.assert_called_once()
        self.assertIsNone(bot.client)

    async def test_aexit_raises_when_uninitialized(self):
        bot = BotAssistant("me", 123, "hash", "token", MagicMock())
        bot.client = None
        with self.assertRaises(RuntimeError):
            await bot.__aexit__(None, None, None)


if __name__ == "__main__":
    unittest.main()

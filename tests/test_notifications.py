import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from packages.notifications import (
    get_base_notify_message_deletion,
    get_default_notify_message_deletion,
    get_default_notify_unknown_message,
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

    @patch("packages.notifications.format_default_message_text")
    async def test_default_notify_message_deletion_calls_send_message(
        self, mock_format_text
    ):
        mock_client = AsyncMock()
        mock_message = MagicMock()
        mock_message.media = None

        mock_format_text.return_value = "Test message"

        notify_func = get_default_notify_message_deletion()
        await notify_func(mock_message, mock_client)

        mock_client.send_message.assert_called_once()
        call_args = mock_client.send_message.call_args
        self.assertEqual(call_args.kwargs["entity"], "me")
        self.assertEqual(call_args.kwargs["message"], "Test message")

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

    @patch("packages.notifications.format_default_message_text")
    async def test_default_notify_message_deletion_includes_media(
        self, mock_format_text
    ):
        mock_client = AsyncMock()
        mock_media = MagicMock()
        mock_message = MagicMock()
        mock_message.media = mock_media

        mock_format_text.return_value = "Test message"

        notify_func = get_default_notify_message_deletion()
        await notify_func(mock_message, mock_client)

        call_args = mock_client.send_message.call_args
        self.assertEqual(call_args.kwargs["file"], mock_media)

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
        self.assertTrue(mock_message.deleted)


if __name__ == "__main__":
    unittest.main()

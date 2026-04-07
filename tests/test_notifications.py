import unittest
from unittest.mock import AsyncMock, MagicMock, patch

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

    def test_get_base_notify_message_edit_returns_callable(self):
        mock_session_maker = MagicMock()
        result = get_base_notify_message_edit(mock_session_maker)
        self.assertTrue(callable(result))

    def test_get_default_notify_message_edit_returns_callable(self):
        result = get_default_notify_message_edit()
        self.assertTrue(callable(result))

    @patch("packages.notifications.get_mention_text")
    async def test_default_notify_message_edit_calls_send_message(
        self, mock_get_mention
    ):
        mock_client = AsyncMock()
        mock_message = MagicMock()
        mock_message.media = None
        mock_message.text = "Edited text"

        mock_get_mention.side_effect = (
            lambda client, peer: "TestUser"
            if peer and hasattr(peer, "id") and peer.id == 123
            else "TestChat"
        )

        mock_from_peer = MagicMock()
        mock_from_peer.id = 123
        mock_message.from_peer = mock_from_peer

        mock_chat_peer = MagicMock()
        mock_chat_peer.id = 456
        mock_message.chat_peer = mock_chat_peer

        notify_func = get_default_notify_message_edit()
        await notify_func(mock_message, mock_client)

        mock_client.send_message.assert_called_once()
        call_args = mock_client.send_message.call_args
        self.assertEqual(call_args.kwargs["entity"], "me")
        self.assertIn("Edited message", call_args.kwargs["message"])
        self.assertIn("TestUser", call_args.kwargs["message"])
        self.assertIn("TestChat", call_args.kwargs["message"])
        self.assertIn("Edited text", call_args.kwargs["message"])

    async def test_base_notify_message_edit_merges_without_marking_deleted(self):
        mock_session = MagicMock()
        mock_session_maker = MagicMock()
        mock_session_maker.begin.return_value.__enter__.return_value = mock_session
        mock_session_maker.begin.return_value.__exit__.return_value = False

        mock_message = MagicMock()
        # Ensure the mock doesn't have a deleted attribute set to True by default
        mock_message.deleted = False

        notify_func = get_base_notify_message_edit(mock_session_maker)
        await notify_func(mock_message, MagicMock())

        mock_session_maker.begin.assert_called_once()
        mock_session.merge.assert_called_once_with(mock_message)
        # For edited messages, we don't mark as deleted (should remain False)
        self.assertFalse(mock_message.deleted)


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


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import telethon.types
from packages.filtering import raw_should_ignore_message_chat


class FilteringTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client_mock = AsyncMock()

    async def test_returns_false_for_none_peer_entity(self):
        result = await raw_should_ignore_message_chat(
            None,
            self.client_mock,
            True,
            True,
            True,
            True,
            100,
        )
        self.assertFalse(result)

    async def test_ignores_channels_when_ignore_channels_true(self):
        channel_mock = MagicMock(spec=telethon.types.Channel)
        channel_mock.broadcast = True

        result = await raw_should_ignore_message_chat(
            channel_mock,
            self.client_mock,
            True,
            False,
            False,
            False,
            0,
        )
        self.assertTrue(result)

    async def test_does_not_ignore_channels_when_ignore_channels_false(self):
        channel_mock = MagicMock(spec=telethon.types.Channel)
        channel_mock.broadcast = True

        result = await raw_should_ignore_message_chat(
            channel_mock,
            self.client_mock,
            False,
            False,
            False,
            False,
            0,
        )
        self.assertFalse(result)

    async def test_ignores_groups_when_ignore_groups_true(self):
        chat_mock = MagicMock(spec=telethon.types.Chat)

        result = await raw_should_ignore_message_chat(
            chat_mock,
            self.client_mock,
            False,
            True,
            False,
            False,
            0,
        )
        self.assertTrue(result)

    async def test_ignores_megagroups_when_ignore_megagroups_true(self):
        channel_mock = MagicMock(spec=telethon.types.Channel)
        channel_mock.megagroup = True
        channel_mock.gigagroup = False

        result = await raw_should_ignore_message_chat(
            channel_mock,
            self.client_mock,
            False,
            False,
            True,
            False,
            0,
        )
        self.assertTrue(result)

    async def test_ignores_gigagroups_when_ignore_gigagroups_true(self):
        channel_mock = MagicMock(spec=telethon.types.Channel)
        channel_mock.gigagroup = True

        result = await raw_should_ignore_message_chat(
            channel_mock,
            self.client_mock,
            False,
            False,
            False,
            True,
            0,
        )
        self.assertTrue(result)

    async def test_member_threshold_filtering_for_channels(self):
        channel_mock = MagicMock(spec=telethon.types.Channel)
        channel_mock.broadcast = False

        input_entity_mock = MagicMock()
        input_channel_mock = MagicMock()
        channel_full_info_mock = MagicMock()
        full_chat_mock = MagicMock()
        full_chat_mock.participants_count = 150

        self.client_mock.get_input_entity = AsyncMock(return_value=input_entity_mock)
        with patch("telethon.utils.get_input_channel", return_value=input_channel_mock):
            with patch(
                "telethon.tl.functions.channels.GetFullChannelRequest"
            ) as get_full_channel_request_mock:
                get_full_channel_request_mock.return_value = MagicMock()
                self.client_mock.return_value = channel_full_info_mock
                channel_full_info_mock.full_chat = full_chat_mock

                result = await raw_should_ignore_message_chat(
                    channel_mock,
                    self.client_mock,
                    False,
                    False,
                    False,
                    False,
                    100,
                )
                self.assertTrue(result)

    async def test_member_threshold_filtering_for_chats(self):
        chat_mock = MagicMock(spec=telethon.types.Chat)
        type(chat_mock).participants_count = PropertyMock(return_value=150)

        result = await raw_should_ignore_message_chat(
            chat_mock,
            self.client_mock,
            False,
            False,
            False,
            False,
            100,
        )
        self.assertTrue(result)

    async def test_does_not_ignore_below_member_threshold(self):
        channel_mock = MagicMock(spec=telethon.types.Channel)
        channel_mock.broadcast = False
        channel_mock.megagroup = False
        channel_mock.gigagroup = False

        input_entity_mock = MagicMock()
        input_channel_mock = MagicMock()
        channel_full_info_mock = MagicMock()
        full_chat_mock = MagicMock()
        full_chat_mock.participants_count = 50

        self.client_mock.get_input_entity = AsyncMock(return_value=input_entity_mock)
        with patch("telethon.utils.get_input_channel", return_value=input_channel_mock):
            with patch(
                "telethon.tl.functions.channels.GetFullChannelRequest"
            ) as get_full_channel_request_mock:
                get_full_channel_request_mock.return_value = MagicMock()
                self.client_mock.return_value = channel_full_info_mock
                channel_full_info_mock.full_chat = full_chat_mock

                result = await raw_should_ignore_message_chat(
                    channel_mock,
                    self.client_mock,
                    False,
                    False,
                    False,
                    False,
                    100,
                )
                self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()

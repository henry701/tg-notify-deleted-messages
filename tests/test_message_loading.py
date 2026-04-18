import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from packages.message_loading import (
    filter_loaded_messages,
    load_messages_by_parameters,
    load_messages_from_db,
    message_exists_in_db,
)


class LoadMessagesFromDbTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_empty_for_empty_ids(self):
        session_mock = MagicMock()
        session_mock.execute.return_value.scalars.return_value.all.return_value = []
        query, results, unloaded = await load_messages_from_db([], None, session_mock)
        self.assertEqual(results, [])
        self.assertEqual(unloaded, [])

    async def test_returns_unloaded_ids(self):
        session_mock = MagicMock()
        session_mock.execute.return_value.scalars.return_value.all.return_value = []
        query, results, unloaded = await load_messages_from_db(
            [1, 2, 3], None, session_mock
        )
        self.assertEqual(results, [])
        self.assertEqual(unloaded, [1, 2, 3])

    async def test_returns_loaded_messages(self):
        msg1 = MagicMock()
        msg1.id = 1
        msg2 = MagicMock()
        msg2.id = 2
        session_mock = MagicMock()
        session_mock.execute.return_value.scalars.return_value.all.return_value = [
            msg1,
            msg2,
        ]
        query, results, unloaded = await load_messages_from_db(
            [1, 2, 3], None, session_mock
        )
        self.assertEqual(len(results), 2)
        self.assertEqual(unloaded, [3])


class LoadMessagesByParametersTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_empty_when_peer_ignored(self):
        import telethon.types

        client_mock = AsyncMock()
        session_mock = MagicMock()
        peer_mock = MagicMock(spec=telethon.types.Channel)
        peer_mock.broadcast = True

        with patch.dict("os.environ", {"IGNORE_CHANNELS": "1"}):
            results, query, unloaded, filtered = await load_messages_by_parameters(
                [1, 2],
                peer_mock,
                client_mock,
                session_mock,
                ignore_channels=True,
                ignore_groups=False,
                ignore_megagroups=False,
                ignore_gigagroups=False,
                member_ignore_threshold=0,
                should_load_outgoing_messages=True,
            )
            self.assertEqual(results, [])
            self.assertEqual(unloaded, [])
            self.assertEqual(filtered, [1, 2])


class FilterLoadedMessagesTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_all_when_no_filters(self):
        client_mock = AsyncMock()
        msg = MagicMock()
        msg.from_peer = None
        msg.chat_peer = None
        results = await filter_loaded_messages(
            ignore_channels=False,
            ignore_groups=False,
            ignore_megagroups=False,
            ignore_gigagroups=False,
            member_ignore_threshold=0,
            should_notify_outgoing_messages=False,
            client=client_mock,
            db_results=[msg],
        )
        self.assertEqual(len(results), 1)

    async def test_returns_empty_for_empty_results(self):
        client_mock = AsyncMock()
        results = await filter_loaded_messages(
            ignore_channels=False,
            ignore_groups=False,
            ignore_megagroups=False,
            ignore_gigagroups=False,
            member_ignore_threshold=0,
            should_notify_outgoing_messages=False,
            client=client_mock,
            db_results=[],
        )
        self.assertEqual(results, [])


class LoadMessagesFromDbPeerFilteringTests(unittest.IsolatedAsyncioTestCase):
    async def test_filters_by_peer_entity_id_and_type(self):
        from telethon.tl.types import User

        peer_entity = User(id=42)

        session_mock = MagicMock()
        session_mock.execute.return_value.scalars.return_value.all.return_value = []

        query, results, unloaded = await load_messages_from_db(
            [1, 2], peer_entity, session_mock
        )
        session_mock.execute.assert_called_once()
        self.assertEqual(results, [])
        self.assertEqual(unloaded, [1, 2])

    async def test_loads_matching_messages_with_peer_filter(self):
        from telethon.tl.types import Channel, ChatPhotoEmpty

        peer_entity = Channel(id=42, title="Test", photo=ChatPhotoEmpty(), date=None)

        msg = MagicMock()
        msg.id = 1

        session_mock = MagicMock()
        session_mock.execute.return_value.scalars.return_value.all.return_value = [msg]

        query, results, unloaded = await load_messages_from_db(
            [1, 2], peer_entity, session_mock
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(unloaded, [2])


class MessageExistsInDbTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_true_when_message_exists(self):
        session_mock = MagicMock()
        session_mock.execute.return_value.first.return_value = (1,)

        result = await message_exists_in_db(1, None, session_mock)

        self.assertTrue(result)

    async def test_returns_false_when_message_missing(self):
        session_mock = MagicMock()
        session_mock.execute.return_value.first.return_value = None

        result = await message_exists_in_db(1, None, session_mock)

        self.assertFalse(result)

    async def test_queries_only_message_identifier_for_existence(self):
        session_mock = MagicMock()
        session_mock.execute.return_value.first.return_value = None

        await message_exists_in_db(1, None, session_mock)

        query = session_mock.execute.call_args.args[0]
        compiled_query = str(query)
        self.assertIn("telegram_messages.id", compiled_query)
        self.assertNotIn("telegram_messages.media", compiled_query)


class LoadMessagesByParametersFullFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_filters_loaded_messages_when_peer_not_ignored(self):
        client_mock = AsyncMock()

        msg_pass = MagicMock()
        msg_pass.id = 1
        msg_pass.from_peer = None
        msg_pass.chat_peer = None

        msg_filtered = MagicMock()
        msg_filtered.id = 2
        msg_filtered.from_peer = None
        msg_filtered.chat_peer = None

        session_mock = MagicMock()
        session_mock.execute.return_value.scalars.return_value.all.return_value = [
            msg_pass,
            msg_filtered,
        ]

        async def _ignore_msg_side_effect(message, client_arg, *a, **kw):
            return message.id == 2

        with (
            patch(
                "packages.message_loading.raw_should_ignore_message_chat",
                new_callable=AsyncMock,
                return_value=False,
            ),
            patch(
                "packages.message_loading.should_ignore_deleted_message",
                new_callable=AsyncMock,
                side_effect=_ignore_msg_side_effect,
            ),
        ):
            results, query, unloaded, filtered = await load_messages_by_parameters(
                [1, 2],
                None,
                client_mock,
                session_mock,
                ignore_channels=False,
                ignore_groups=False,
                ignore_megagroups=False,
                ignore_gigagroups=False,
                member_ignore_threshold=0,
                should_load_outgoing_messages=True,
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].id, 1)
        self.assertEqual(unloaded, [])
        self.assertEqual(filtered, [2])


if __name__ == "__main__":
    unittest.main()

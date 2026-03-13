import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from packages.message_loading import (
    load_messages_from_db,
    load_messages_by_parameters,
    filter_loaded_messages,
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


if __name__ == "__main__":
    unittest.main()

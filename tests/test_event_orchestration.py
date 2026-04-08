import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import telethon.types
from packages.event_orchestration import (
    add_event_handlers,
    get_message_media_blob,
    get_on_message_deleted,
    get_on_message_edited,
    get_on_new_message,
    get_should_ignore_message,
    get_should_ignore_message_chat,
    get_store_message,
    get_store_message_if_not_exists,
    load_messages_from_deleted_event,
)


class GetShouldIgnoreMessageChatTests(unittest.IsolatedAsyncioTestCase):
    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
        },
    )
    async def test_returns_false_for_user(self):
        client_mock = AsyncMock()
        user_mock = MagicMock(spec=telethon.types.User)
        should_ignore = get_should_ignore_message_chat(client_mock)
        result = await should_ignore(user_mock)
        self.assertFalse(result)

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "1",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
        },
    )
    async def test_ignores_channel_when_enabled(self):
        client_mock = AsyncMock()
        channel_mock = MagicMock(spec=telethon.types.Channel)
        channel_mock.broadcast = True
        should_ignore = get_should_ignore_message_chat(client_mock)
        result = await should_ignore(channel_mock)
        self.assertTrue(result)

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
        },
    )
    async def test_returns_false_for_none_chat(self):
        client_mock = AsyncMock()
        should_ignore = get_should_ignore_message_chat(client_mock)
        result = await should_ignore(None)
        self.assertFalse(result)


class GetShouldIgnoreMessageTests(unittest.IsolatedAsyncioTestCase):
    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
        },
    )
    async def test_returns_false_when_check_chat_false(self):
        client_mock = AsyncMock()
        message_mock = AsyncMock()
        should_ignore = get_should_ignore_message(client_mock)
        result = await should_ignore(message_mock, check_chat=False)
        self.assertFalse(result)

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
        },
    )
    async def test_checks_chat_when_check_chat_true(self):
        client_mock = AsyncMock()
        message_mock = AsyncMock()
        chat_mock = MagicMock(spec=telethon.types.User)
        message_mock.get_chat = AsyncMock(return_value=chat_mock)
        should_ignore = get_should_ignore_message(client_mock)
        result = await should_ignore(message_mock, check_chat=True)
        self.assertFalse(result)


class GetMessageMediaBlobTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_none_for_no_media(self):
        message_mock = MagicMock()
        message_mock.media = None
        result = await get_message_media_blob(message_mock)
        self.assertIsNone(result)

    async def test_returns_none_for_no_file(self):
        message_mock = MagicMock()
        message_mock.media = True
        message_mock.file = None
        result = await get_message_media_blob(message_mock)
        self.assertIsNone(result)

    async def test_returns_none_for_no_file_size(self):
        message_mock = MagicMock()
        message_mock.media = True
        message_mock.file = MagicMock()
        message_mock.file.size = None
        result = await get_message_media_blob(message_mock)
        self.assertIsNone(result)

    async def test_returns_none_for_none_message(self):
        result = await get_message_media_blob(None)
        self.assertIsNone(result)


class AddEventHandlersTests(unittest.IsolatedAsyncioTestCase):
    async def test_adds_new_message_and_deleted_handlers(self):
        client_mock = MagicMock()
        session_maker_mock = MagicMock()
        notify_del = AsyncMock()
        notify_unknown = AsyncMock()
        notify_edit = AsyncMock()
        gather_func = AsyncMock()

        await add_event_handlers(
            client_mock,
            session_maker_mock,
            notify_del,
            notify_unknown,
            notify_edit,
            gather_func,
        )

        self.assertEqual(client_mock.add_event_handler.call_count, 3)


class LoadMessagesFromDeletedEventTests(unittest.IsolatedAsyncioTestCase):
    async def test_calls_load_messages_by_parameters(self):
        event_mock = AsyncMock()
        event_mock.deleted_ids = [1, 2, 3]
        event_mock.get_input_chat = AsyncMock(return_value=None)
        client_mock = AsyncMock()
        session_mock = MagicMock()

        with patch(
            "packages.event_orchestration.load_messages_by_parameters",
            new_callable=AsyncMock,
        ) as load_mock:
            load_mock.return_value = ([], None, [], [])
            result = await load_messages_from_deleted_event(
                event_mock,
                client_mock,
                session_mock,
                False,
                False,
                False,
                False,
                0,
                True,
            )
            load_mock.assert_called_once()
            self.assertEqual(result, ([], None, [], []))

    async def test_handles_valueerror_from_get_input_chat(self):
        event_mock = AsyncMock()
        event_mock.deleted_ids = [1]
        event_mock.get_input_chat = AsyncMock(side_effect=ValueError("no chat"))
        client_mock = AsyncMock()
        session_mock = MagicMock()

        with patch(
            "packages.event_orchestration.load_messages_by_parameters",
            new_callable=AsyncMock,
        ) as load_mock:
            load_mock.return_value = ([], None, [], [])
            result = await load_messages_from_deleted_event(
                event_mock,
                client_mock,
                session_mock,
                False,
                False,
                False,
                False,
                0,
                True,
            )
            load_mock.assert_called_once()
            self.assertEqual(result, ([], None, [], []))


class GetStoreMessageTests(unittest.IsolatedAsyncioTestCase):
    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "1",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
        },
    )
    async def test_returns_false_when_ignored(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()
        store_fn = get_store_message(session_maker_mock, client_mock)

        message_mock = AsyncMock()
        chat_mock = MagicMock(spec=telethon.types.Channel)
        chat_mock.broadcast = True
        message_mock.get_chat = AsyncMock(return_value=chat_mock)

        result = await store_fn(message_mock)
        self.assertFalse(result)


class GetOnNewMessageTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_callable(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()
        on_new = get_on_new_message(session_maker_mock, client_mock)
        self.assertTrue(callable(on_new))

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
        },
    )
    async def test_handler_calls_store_message(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()

        session_mock = MagicMock()
        session_mock.execute.return_value.scalar.return_value = None
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        on_new = get_on_new_message(session_maker_mock, client_mock)

        event_mock = AsyncMock()
        message_mock = AsyncMock()
        message_mock.id = 1
        message_mock.message = "test"
        message_mock.from_id = None
        message_mock.peer_id = None
        message_mock.media = None
        message_mock.date = None

        user_mock = MagicMock()
        user_mock.id = 123
        message_mock.get_chat = AsyncMock(return_value=user_mock)

        with patch(
            "packages.event_orchestration.build_telegram_peer",
            new_callable=AsyncMock,
        ) as build_peer:
            build_peer.return_value = None
            with patch(
                "packages.event_orchestration.get_message_media_blob",
                new_callable=AsyncMock,
            ) as get_blob:
                get_blob.return_value = None
                event_mock.message = message_mock
                await on_new(event_mock)


class GetOnMessageDeletedTests(unittest.IsolatedAsyncioTestCase):
    async def _await_all(self, _limit, *awaitables):
        return await asyncio.gather(*awaitables)

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
            "NOTIFY_OUTGOING_MESSAGES": "True",
            "DELETED_MESSAGES_NOTIFICATION_CONCURRENCY": "1",
        },
    )
    async def test_returns_callable(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()
        notify_del = AsyncMock()
        notify_unknown = AsyncMock()
        gather_func = AsyncMock(side_effect=self._await_all)
        handler = get_on_message_deleted(
            client_mock,
            session_maker_mock,
            notify_del,
            notify_unknown,
            gather_func,
        )
        self.assertTrue(callable(handler))

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
            "NOTIFY_OUTGOING_MESSAGES": "True",
            "DELETED_MESSAGES_NOTIFICATION_CONCURRENCY": "1",
        },
    )
    async def test_returns_early_on_empty_deleted_ids(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()
        notify_del = AsyncMock()
        notify_unknown = AsyncMock()
        gather_func = AsyncMock(side_effect=self._await_all)
        handler = get_on_message_deleted(
            client_mock,
            session_maker_mock,
            notify_del,
            notify_unknown,
            gather_func,
        )
        event_mock = AsyncMock()
        event_mock.deleted_ids = []
        await handler(event_mock)
        notify_del.assert_not_called()
        notify_unknown.assert_not_called()

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
            "NOTIFY_OUTGOING_MESSAGES": "True",
            "DELETED_MESSAGES_NOTIFICATION_CONCURRENCY": "1",
        },
    )
    async def test_notifies_on_deleted_messages(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()

        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        notify_del = AsyncMock()
        notify_unknown = AsyncMock()
        gather_func = AsyncMock(side_effect=self._await_all)

        mock_message = MagicMock()
        mock_message.id = 1

        with patch(
            "packages.event_orchestration.load_messages_from_deleted_event",
            new_callable=AsyncMock,
        ) as load_mock:
            load_mock.return_value = ([mock_message], MagicMock(), [], [])

            handler = get_on_message_deleted(
                client_mock,
                session_maker_mock,
                notify_del,
                notify_unknown,
                gather_func,
            )
            event_mock = AsyncMock()
            event_mock.deleted_ids = [1]
            await handler(event_mock)

            gather_func.assert_called_once()
            notify_del.assert_called_once_with(mock_message, client_mock)

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
            "NOTIFY_OUTGOING_MESSAGES": "True",
            "DELETED_MESSAGES_NOTIFICATION_CONCURRENCY": "1",
        },
    )
    async def test_notifies_unknown_messages(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()

        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        notify_del = AsyncMock()
        notify_unknown = AsyncMock()
        gather_func = AsyncMock(side_effect=self._await_all)

        with patch(
            "packages.event_orchestration.load_messages_from_deleted_event",
            new_callable=AsyncMock,
        ) as load_mock:
            load_mock.return_value = ([], MagicMock(), [10, 20], [])

            handler = get_on_message_deleted(
                client_mock,
                session_maker_mock,
                notify_del,
                notify_unknown,
                gather_func,
            )
            event_mock = AsyncMock()
            event_mock.deleted_ids = [10, 20]
            await handler(event_mock)

            notify_unknown.assert_called_once()
            args = notify_unknown.call_args[0]
            self.assertEqual(args[0], [10, 20])


class GetOnMessageEditedTests(unittest.IsolatedAsyncioTestCase):
    async def _await_all(self, _limit, *awaitables):
        return await asyncio.gather(*awaitables)

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
            "NOTIFY_OUTGOING_MESSAGES": "True",
            "EDITED_MESSAGES_NOTIFICATION_CONCURRENCY": "1",
        },
    )
    async def test_returns_callable(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()
        notify_edit = AsyncMock()
        gather_func = AsyncMock(side_effect=self._await_all)
        handler = get_on_message_edited(
            client_mock,
            session_maker_mock,
            notify_edit,
            gather_func,
        )
        self.assertTrue(callable(handler))

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
            "NOTIFY_OUTGOING_MESSAGES": "True",
            "EDITED_MESSAGES_NOTIFICATION_CONCURRENCY": "1",
        },
    )
    async def test_notifies_on_edited_message_found_in_db(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()

        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        notify_edit = AsyncMock()
        gather_func = AsyncMock(side_effect=self._await_all)

        mock_message = MagicMock()
        mock_message.id = 1

        event_mock = AsyncMock()
        event_mock.message_id = 1
        event_mock.get_input_chat = AsyncMock(return_value=None)
        event_mock.message = None

        with patch(
            "packages.event_orchestration.load_messages_by_parameters",
            new_callable=AsyncMock,
        ) as load_mock:
            load_mock.return_value = ([mock_message], MagicMock(), [], [])

            handler = get_on_message_edited(
                client_mock,
                session_maker_mock,
                notify_edit,
                gather_func,
            )
            await handler(event_mock)

        gather_func.assert_called_once()
        notify_edit.assert_called_once_with(mock_message, client_mock)

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
            "NOTIFY_OUTGOING_MESSAGES": "True",
            "EDITED_MESSAGES_NOTIFICATION_CONCURRENCY": "1",
        },
    )
    async def test_notifies_with_old_and_new_text(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()

        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        notify_edit = AsyncMock()
        gather_func = AsyncMock(side_effect=self._await_all)

        mock_message = MagicMock()
        mock_message.id = 1
        mock_message.text = "old text"

        event_mock = AsyncMock()
        event_mock.message_id = 1
        event_mock.get_input_chat = AsyncMock(return_value=None)
        event_mock.message = MagicMock()
        event_mock.message.text = "new text"

        with patch(
            "packages.event_orchestration.load_messages_by_parameters",
            new_callable=AsyncMock,
        ) as load_mock:
            load_mock.return_value = ([mock_message], MagicMock(), [], [])

            handler = get_on_message_edited(
                client_mock,
                session_maker_mock,
                notify_edit,
                gather_func,
            )
            await handler(event_mock)

        gather_func.assert_called_once()
        notify_edit.assert_called_once()
        called_text = notify_edit.call_args[0][0].text
        self.assertIn("OLD:", called_text)
        self.assertIn("NEW:", called_text)

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
            "NOTIFY_OUTGOING_MESSAGES": "True",
            "EDITED_MESSAGES_NOTIFICATION_CONCURRENCY": "1",
        },
    )
    async def test_handles_unloaded_ids_present(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()

        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        notify_edit = AsyncMock()
        gather_func = AsyncMock(side_effect=self._await_all)

        event_mock = AsyncMock()
        event_mock.message_id = 1
        event_mock.get_input_chat = AsyncMock(return_value=None)
        event_mock.message = None

        with patch(
            "packages.event_orchestration.load_messages_by_parameters",
            new_callable=AsyncMock,
        ) as load_mock:
            load_mock.return_value = ([], MagicMock(), [10, 20], [])

            handler = get_on_message_edited(
                client_mock,
                session_maker_mock,
                notify_edit,
                gather_func,
            )
            await handler(event_mock)

        notify_edit.assert_not_called()
        gather_func.assert_not_called()


class GetMessageMediaBlobThresholdTests(unittest.IsolatedAsyncioTestCase):
    @patch("packages.event_orchestration.file_size_threshold", 1000)
    async def test_returns_none_when_file_size_exceeds_threshold(self):
        message_mock = MagicMock()
        message_mock.media = True
        message_mock.file = MagicMock()
        message_mock.file.size = 2000
        result = await get_message_media_blob(message_mock)
        self.assertIsNone(result)

    @patch("packages.event_orchestration.file_size_threshold", 0)
    async def test_downloads_when_no_threshold(self):
        message_mock = AsyncMock()
        message_mock.media = True
        message_mock.file = MagicMock()
        message_mock.file.size = 2000
        message_mock.download_media = AsyncMock(return_value=b"data")
        result = await get_message_media_blob(message_mock)
        self.assertEqual(result, b"data")


class GetStoreMessageBranchTests(unittest.IsolatedAsyncioTestCase):
    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
        },
    )
    async def test_creates_new_message_when_not_existing(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()

        session_mock = MagicMock()
        query_mock = MagicMock()
        query_mock.filter.return_value.first.return_value = None
        session_mock.query.return_value = query_mock
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        store_fn = get_store_message(session_maker_mock, client_mock)

        message_mock = AsyncMock()
        message_mock.id = 1
        message_mock.message = "test"
        message_mock.from_id = None
        message_mock.peer_id = MagicMock()
        message_mock.media = None
        message_mock.date = None

        user_mock = MagicMock()
        user_mock.id = 123
        message_mock.get_chat = AsyncMock(return_value=user_mock)

        with (
            patch(
                "packages.event_orchestration.build_telegram_peer",
                new_callable=AsyncMock,
            ) as build_peer,
            patch(
                "packages.event_orchestration.get_message_media_blob",
                new_callable=AsyncMock,
            ) as get_blob,
        ):
            build_peer.return_value = None
            get_blob.return_value = None
            result = await store_fn(message_mock)
            self.assertTrue(result)
            session_mock.merge.assert_called_once()

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
        },
    )
    async def test_inserts_new_version_for_existing_message(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()
        built_chat_peer = MagicMock()
        built_chat_peer.id = 987

        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        store_fn = get_store_message(session_maker_mock, client_mock)

        message_mock = AsyncMock()
        message_mock.id = 1
        message_mock.message = "updated text"
        message_mock.from_id = None
        message_mock.peer_id = MagicMock(name="telethon_peer")
        message_mock.media = None
        message_mock.date = MagicMock()

        user_mock = MagicMock()
        user_mock.id = 123
        message_mock.get_chat = AsyncMock(return_value=user_mock)

        with (
            patch(
                "packages.event_orchestration.build_telegram_peer",
                new_callable=AsyncMock,
            ) as build_peer,
            patch(
                "packages.event_orchestration.get_message_media_blob",
                new_callable=AsyncMock,
            ) as get_blob,
        ):
            build_peer.side_effect = [None, built_chat_peer]
            get_blob.return_value = None
            result = await store_fn(message_mock)
            self.assertTrue(result)
            session_mock.merge.assert_called_once()


class GetStoreMessageIfNotExistsTests(unittest.IsolatedAsyncioTestCase):
    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "0",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
        },
    )
    async def test_returns_false_when_message_exists(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()

        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        store_fn = get_store_message_if_not_exists(client_mock, session_maker_mock)

        message_mock = AsyncMock()
        message_mock.id = 1
        message_mock.message = "test"
        message_mock.from_id = None
        message_mock.peer_id = MagicMock()
        message_mock.media = None
        message_mock.date = None

        user_mock = MagicMock()
        user_mock.id = 123
        message_mock.get_chat = AsyncMock(return_value=user_mock)

        existing_msg = MagicMock()
        with patch(
            "packages.event_orchestration.load_messages_from_db",
            new_callable=AsyncMock,
        ) as load_mock:
            load_mock.return_value = (MagicMock(), [existing_msg], [])
            result = await store_fn(message_mock)
            self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()

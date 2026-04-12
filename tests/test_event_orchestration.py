import asyncio
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
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

    async def test_downloads_when_file_size_is_missing(self):
        message_mock = AsyncMock()
        message_mock.media = True
        message_mock.file = MagicMock()
        message_mock.file.size = None
        message_mock.download_media = AsyncMock(return_value=b"data")

        result = await get_message_media_blob(message_mock)

        self.assertEqual(result, b"data")

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

        mock_message = SimpleNamespace(id=1, text="old text")

        event_mock = AsyncMock()
        event_mock.message_id = 1
        event_mock.get_input_chat = AsyncMock(return_value=None)
        event_mock.message = AsyncMock()
        event_mock.message.raw_text = "new text"
        event_mock.message.message = "new text"
        event_mock.message.text = "**new text**"
        event_mock.message.media = None

        with (
            patch(
                "packages.event_orchestration.load_messages_by_parameters",
                new_callable=AsyncMock,
            ) as load_mock,
            patch(
                "packages.event_orchestration.get_store_message",
            ) as get_store_message_mock,
        ):
            load_mock.return_value = ([mock_message], MagicMock(), [], [])
            store_message_mock = AsyncMock()
            get_store_message_mock.return_value = store_message_mock

            handler = get_on_message_edited(
                client_mock,
                session_maker_mock,
                notify_edit,
                gather_func,
            )
            await handler(event_mock)

        gather_func.assert_called_once()
        notify_edit.assert_called_once()
        called_message = notify_edit.call_args[0][0]
        self.assertIsNot(called_message, mock_message)
        self.assertEqual(mock_message.text, "old text")
        self.assertEqual(called_message.edit_old_text, "old text")
        self.assertEqual(called_message.text, "new text")
        store_message_mock.assert_awaited_once_with(event_mock.message, check_chat=True)

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
    async def test_notifies_when_new_text_is_empty_string(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()

        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        notify_edit = AsyncMock()
        gather_func = AsyncMock(side_effect=self._await_all)

        mock_message = SimpleNamespace(id=1, text="old text")

        event_mock = AsyncMock()
        event_mock.message_id = 1
        event_mock.get_input_chat = AsyncMock(return_value=None)
        event_mock.message = AsyncMock()
        event_mock.message.raw_text = ""
        event_mock.message.message = ""
        event_mock.message.text = ""
        event_mock.message.media = None

        with (
            patch(
                "packages.event_orchestration.load_messages_by_parameters",
                new_callable=AsyncMock,
            ) as load_mock,
            patch(
                "packages.event_orchestration.get_store_message",
            ) as get_store_message_mock,
        ):
            load_mock.return_value = ([mock_message], MagicMock(), [], [])
            store_message_mock = AsyncMock()
            get_store_message_mock.return_value = store_message_mock

            handler = get_on_message_edited(
                client_mock,
                session_maker_mock,
                notify_edit,
                gather_func,
            )
            await handler(event_mock)

        notify_edit.assert_called_once()
        called_message = notify_edit.call_args[0][0]
        self.assertEqual(called_message.edit_old_text, "old text")
        self.assertEqual(called_message.text, "")
        store_message_mock.assert_awaited_once_with(event_mock.message, check_chat=True)

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
    async def test_skips_same_text_edit(self):
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
        mock_message.text = "same text"
        mock_message.media = None

        event_mock = AsyncMock()
        event_mock.message_id = 1
        event_mock.get_input_chat = AsyncMock(return_value=None)
        event_mock.message = MagicMock()
        event_mock.message.raw_text = "same text"
        event_mock.message.message = "same text"
        event_mock.message.text = "same text"
        event_mock.message.media = None

        with (
            patch(
                "packages.event_orchestration.load_messages_by_parameters",
                new_callable=AsyncMock,
            ) as load_mock,
            patch(
                "packages.event_orchestration.get_store_message",
            ) as get_store_message_mock,
        ):
            load_mock.return_value = ([mock_message], MagicMock(), [], [])
            store_message_mock = AsyncMock()
            get_store_message_mock.return_value = store_message_mock

            handler = get_on_message_edited(
                client_mock,
                session_maker_mock,
                notify_edit,
                gather_func,
            )
            await handler(event_mock)

        notify_edit.assert_not_called()
        store_message_mock.assert_not_awaited()

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
    async def test_same_text_edit_with_media_still_stores_new_version(self):
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
        mock_message.text = "same text"
        mock_message.media = None

        event_mock = AsyncMock()
        event_mock.message_id = 1
        event_mock.get_input_chat = AsyncMock(return_value=None)
        event_mock.message = MagicMock()
        event_mock.message.raw_text = "same text"
        event_mock.message.message = "same text"
        event_mock.message.text = "same text"
        event_mock.message.media = MagicMock(name="replacement-media")

        with (
            patch(
                "packages.event_orchestration.load_messages_by_parameters",
                new_callable=AsyncMock,
            ) as load_mock,
            patch(
                "packages.event_orchestration.get_store_message",
            ) as get_store_message_mock,
        ):
            load_mock.return_value = ([mock_message], MagicMock(), [], [])
            store_message_mock = AsyncMock()
            get_store_message_mock.return_value = store_message_mock

            handler = get_on_message_edited(
                client_mock,
                session_maker_mock,
                notify_edit,
                gather_func,
            )
            await handler(event_mock)

        notify_edit.assert_not_called()
        store_message_mock.assert_awaited_once_with(event_mock.message, check_chat=True)

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
    async def test_same_text_edit_with_removed_media_still_stores_new_version(self):
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
        mock_message.text = "same text"
        mock_message.media = b"stored-media"

        event_mock = AsyncMock()
        event_mock.message_id = 1
        event_mock.get_input_chat = AsyncMock(return_value=None)
        event_mock.message = MagicMock()
        event_mock.message.raw_text = "same text"
        event_mock.message.message = "same text"
        event_mock.message.text = "same text"
        event_mock.message.media = None

        with (
            patch(
                "packages.event_orchestration.load_messages_by_parameters",
                new_callable=AsyncMock,
            ) as load_mock,
            patch(
                "packages.event_orchestration.get_store_message",
            ) as get_store_message_mock,
        ):
            load_mock.return_value = ([mock_message], MagicMock(), [], [])
            store_message_mock = AsyncMock()
            get_store_message_mock.return_value = store_message_mock

            handler = get_on_message_edited(
                client_mock,
                session_maker_mock,
                notify_edit,
                gather_func,
            )
            await handler(event_mock)

        notify_edit.assert_not_called()
        store_message_mock.assert_awaited_once_with(event_mock.message, check_chat=True)

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
    async def test_skips_format_only_edit_by_comparing_raw_text(self):
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
        mock_message.text = "Deleted message from: Henrique"
        mock_message.media = None

        event_mock = AsyncMock()
        event_mock.message_id = 1
        event_mock.get_input_chat = AsyncMock(return_value=None)
        event_mock.message = MagicMock()
        event_mock.message.raw_text = "Deleted message from: Henrique"
        event_mock.message.message = "Deleted message from: Henrique"
        event_mock.message.text = "**Deleted message** from: Henrique"
        event_mock.message.media = None

        with (
            patch(
                "packages.event_orchestration.load_messages_by_parameters",
                new_callable=AsyncMock,
            ) as load_mock,
            patch(
                "packages.event_orchestration.get_store_message",
            ) as get_store_message_mock,
        ):
            load_mock.return_value = ([mock_message], MagicMock(), [], [])
            store_message_mock = AsyncMock()
            get_store_message_mock.return_value = store_message_mock

            handler = get_on_message_edited(
                client_mock,
                session_maker_mock,
                notify_edit,
                gather_func,
            )
            await handler(event_mock)

        notify_edit.assert_not_called()
        store_message_mock.assert_not_awaited()

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
    async def test_skips_reaction_like_edit_for_captionless_message(self):
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
        mock_message.text = ""
        mock_message.media = None

        event_mock = AsyncMock()
        event_mock.message_id = 1
        event_mock.get_input_chat = AsyncMock(return_value=None)
        event_mock.message = MagicMock()
        event_mock.message.raw_text = None
        event_mock.message.message = None
        event_mock.message.text = None
        event_mock.message.media = None

        with (
            patch(
                "packages.event_orchestration.load_messages_by_parameters",
                new_callable=AsyncMock,
            ) as load_mock,
            patch(
                "packages.event_orchestration.get_store_message",
            ) as get_store_message_mock,
        ):
            load_mock.return_value = ([mock_message], MagicMock(), [], [])
            store_message_mock = AsyncMock()
            get_store_message_mock.return_value = store_message_mock

            handler = get_on_message_edited(
                client_mock,
                session_maker_mock,
                notify_edit,
                gather_func,
            )
            await handler(event_mock)

        notify_edit.assert_not_called()
        store_message_mock.assert_not_awaited()

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
    async def test_skips_reaction_update_objects_even_when_text_differs(self):
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
        event_mock.message.id = 1
        event_mock.message.raw_text = "new text"
        event_mock.message.message = "new text"
        event_mock.message.text = "new text"
        event_mock.message.media = None
        event_mock.original_update = telethon.types.UpdateMessageReactions(
            peer=telethon.types.PeerUser(user_id=1),
            msg_id=1,
            reactions=telethon.types.MessageReactions(results=[]),
        )

        with (
            patch(
                "packages.event_orchestration.load_messages_by_parameters",
                new_callable=AsyncMock,
            ) as load_mock,
            patch(
                "packages.event_orchestration.get_store_message",
            ) as get_store_message_mock,
        ):
            load_mock.return_value = ([mock_message], MagicMock(), [], [])
            store_message_mock = AsyncMock()
            get_store_message_mock.return_value = store_message_mock

            handler = get_on_message_edited(
                client_mock,
                session_maker_mock,
                notify_edit,
                gather_func,
            )
            await handler(event_mock)

        notify_edit.assert_not_called()
        store_message_mock.assert_not_awaited()

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

    @patch.dict(
        "os.environ",
        {
            "IGNORE_CHANNELS": "1",
            "IGNORE_GROUPS": "0",
            "IGNORE_MEGAGROUPS": "0",
            "IGNORE_GIGAGROUPS": "0",
            "MEMBER_IGNORE_THRESHOLD": "0",
            "NOTIFY_OUTGOING_MESSAGES": "True",
            "EDITED_MESSAGES_NOTIFICATION_CONCURRENCY": "1",
        },
    )
    async def test_stores_edited_messages_with_chat_filtering_enabled(self):
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
        event_mock.message = AsyncMock()
        event_mock.message.raw_text = "edited text"
        event_mock.message.message = "edited text"
        event_mock.message.text = "edited text"

        with (
            patch(
                "packages.event_orchestration.load_messages_by_parameters",
                new_callable=AsyncMock,
            ) as load_mock,
            patch(
                "packages.event_orchestration.get_store_message",
            ) as get_store_message_mock,
        ):
            load_mock.return_value = ([], MagicMock(), [], [1])
            store_message_mock = AsyncMock()
            get_store_message_mock.return_value = store_message_mock

            handler = get_on_message_edited(
                client_mock,
                session_maker_mock,
                notify_edit,
                gather_func,
            )
            await handler(event_mock)

        notify_edit.assert_not_called()
        store_message_mock.assert_awaited_once_with(event_mock.message, check_chat=True)


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

    @patch("packages.event_orchestration.file_size_threshold", 1000)
    async def test_downloads_when_file_size_is_unknown(self):
        message_mock = AsyncMock()
        message_mock.media = True
        message_mock.file = MagicMock()
        message_mock.file.size = None
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
        message_mock.date = datetime(2026, 4, 12, 12, 0, tzinfo=timezone.utc)
        message_mock.file = MagicMock()
        message_mock.file.name = "report.pdf"
        message_mock.file.mime_type = "application/pdf"

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
            get_blob.return_value = b"blob-data"
            result = await store_fn(message_mock)
            self.assertTrue(result)
            session_mock.merge.assert_called_once()
            merged_message = session_mock.merge.call_args.args[0]
            self.assertEqual(merged_message.media, b"blob-data")
            self.assertEqual(merged_message.media_file_name, "report.pdf")
            self.assertEqual(merged_message.media_mime_type, "application/pdf")

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
    async def test_preserves_previous_media_when_edit_version_lacks_blob_and_metadata(
        self,
    ):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()
        built_chat_peer = MagicMock()
        built_chat_peer.id = 987

        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        previous_message = MagicMock()
        previous_message.media = b"old-blob"
        previous_message.media_file_name = "photo.jpg"
        previous_message.media_mime_type = "image/jpeg"
        session_mock.execute.return_value.scalar.return_value = previous_message

        store_fn = get_store_message(session_maker_mock, client_mock)

        message_mock = AsyncMock()
        message_mock.id = 1
        message_mock.message = "updated caption"
        message_mock.from_id = None
        message_mock.peer_id = MagicMock(name="telethon_peer")
        message_mock.media = MagicMock(name="media-marker")
        message_mock.date = datetime(2026, 4, 12, 13, 0, tzinfo=timezone.utc)
        message_mock.file = MagicMock()
        message_mock.file.name = None
        message_mock.file.mime_type = None

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
        merged_message = session_mock.merge.call_args.args[0]
        self.assertEqual(merged_message.media, b"old-blob")
        self.assertEqual(merged_message.media_file_name, "photo.jpg")
        self.assertEqual(merged_message.media_mime_type, "image/jpeg")

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
    async def test_reuses_previous_metadata_when_download_fails_but_new_labels_exist(
        self,
    ):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()
        built_chat_peer = MagicMock()
        built_chat_peer.id = 987

        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        previous_message = MagicMock()
        previous_message.media = b"old-blob"
        previous_message.media_file_name = "photo.jpg"
        previous_message.media_mime_type = "image/jpeg"
        session_mock.execute.return_value.scalar.return_value = previous_message

        store_fn = get_store_message(session_maker_mock, client_mock)

        message_mock = AsyncMock()
        message_mock.id = 1
        message_mock.message = "updated caption"
        message_mock.from_id = None
        message_mock.peer_id = MagicMock(name="telethon_peer")
        message_mock.media = MagicMock(name="media-marker")
        message_mock.date = datetime(2026, 4, 12, 13, 15, tzinfo=timezone.utc)
        message_mock.file = MagicMock()
        message_mock.file.name = "replacement.png"
        message_mock.file.mime_type = "image/png"

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
        merged_message = session_mock.merge.call_args.args[0]
        self.assertEqual(merged_message.media, b"old-blob")
        self.assertEqual(merged_message.media_file_name, "photo.jpg")
        self.assertEqual(merged_message.media_mime_type, "image/jpeg")

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
    async def test_preserves_previous_metadata_when_new_blob_lacks_metadata(self):
        client_mock = AsyncMock()
        session_maker_mock = MagicMock()
        built_chat_peer = MagicMock()
        built_chat_peer.id = 987

        session_mock = MagicMock()
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        previous_message = MagicMock()
        previous_message.media = b"old-blob"
        previous_message.media_file_name = "photo.jpg"
        previous_message.media_mime_type = "image/jpeg"
        session_mock.execute.return_value.scalar.return_value = previous_message

        store_fn = get_store_message(session_maker_mock, client_mock)

        message_mock = AsyncMock()
        message_mock.id = 1
        message_mock.message = "updated caption"
        message_mock.from_id = None
        message_mock.peer_id = MagicMock(name="telethon_peer")
        message_mock.media = MagicMock(name="media-marker")
        message_mock.date = datetime(2026, 4, 12, 13, 30, tzinfo=timezone.utc)
        message_mock.file = MagicMock()
        message_mock.file.name = None
        message_mock.file.mime_type = None

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
            get_blob.return_value = b"new-blob"
            result = await store_fn(message_mock)

        self.assertTrue(result)
        merged_message = session_mock.merge.call_args.args[0]
        self.assertEqual(merged_message.media, b"new-blob")
        self.assertEqual(merged_message.media_file_name, "photo.jpg")
        self.assertEqual(merged_message.media_mime_type, "image/jpeg")


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

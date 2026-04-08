import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from packages.background_jobs import (
    clean_old_messages_loop,
    gather_with_concurrency,
    messages_ttl_delta,
    preload_messages,
)


class CleanOldMessagesLoopTests(unittest.IsolatedAsyncioTestCase):
    async def _raise_timeout_and_close_waiter(self, awaitable, _timeout):
        awaitable.close()
        raise asyncio.TimeoutError

    async def test_exits_on_stop_event(self):
        session_maker_mock = MagicMock()
        stop_event = asyncio.Event()
        stop_event.set()

        with patch("packages.background_jobs.delete") as delete_mock:
            delete_mock.return_value = MagicMock()
            session = MagicMock()
            session.execute.return_value = MagicMock(rowcount=0)
            session_maker_mock.begin.return_value.__enter__ = MagicMock(
                return_value=session
            )
            session_maker_mock.begin.return_value.__exit__ = MagicMock(
                return_value=False
            )

            await clean_old_messages_loop(
                session_maker_mock,
                seconds_interval=1,
                ttl=timedelta(days=14),
                stop_event=stop_event,
            )

    async def test_handles_exception_gracefully(self):
        session_maker_mock = MagicMock()
        stop_event = asyncio.Event()

        with patch("packages.background_jobs.delete") as delete_mock:
            delete_mock.side_effect = Exception("DB error")
            session_maker_mock.begin.return_value.__enter__ = MagicMock(
                return_value=MagicMock()
            )
            session_maker_mock.begin.return_value.__exit__ = MagicMock(
                return_value=False
            )

            with patch("asyncio.wait_for", new_callable=AsyncMock) as wait_mock:
                wait_mock.side_effect = self._raise_timeout_and_close_waiter
                stop_event.set()
                await clean_old_messages_loop(
                    session_maker_mock,
                    seconds_interval=0,
                    ttl=timedelta(days=14),
                    stop_event=stop_event,
                )

    async def test_outer_exception_handler(self):
        session_maker_mock = MagicMock()
        stop_event = asyncio.Event()
        stop_event.set()

        with patch("packages.background_jobs.delete") as delete_mock:
            delete_mock.side_effect = Exception("fatal")
            session_maker_mock.begin.side_effect = Exception("fatal outer")

            with patch("asyncio.wait_for", new_callable=AsyncMock) as wait_mock:
                wait_mock.side_effect = self._raise_timeout_and_close_waiter
                await clean_old_messages_loop(
                    session_maker_mock,
                    seconds_interval=0,
                    ttl=timedelta(days=14),
                    stop_event=stop_event,
                )

    async def test_outer_exception_handler_from_finally(self):
        session_maker_mock = MagicMock()
        stop_event = asyncio.Event()
        stop_event.set()

        with patch("packages.background_jobs.delete") as delete_mock:
            delete_mock.return_value = MagicMock()
            session_maker_mock.begin.return_value.__enter__ = MagicMock(
                return_value=MagicMock()
            )
            session_maker_mock.begin.return_value.__exit__ = MagicMock(
                return_value=False
            )

            with patch("asyncio.wait_for", new_callable=AsyncMock) as wait_mock:
                wait_mock.side_effect = RuntimeError("unexpected error in finally")
                await clean_old_messages_loop(
                    session_maker_mock,
                    seconds_interval=0,
                    ttl=timedelta(days=14),
                    stop_event=stop_event,
                )

    async def test_loop_continues_on_timeout(self):
        session_maker_mock = MagicMock()
        stop_event = asyncio.Event()
        call_count = 0

        with patch("packages.background_jobs.delete") as delete_mock:
            delete_mock.return_value = MagicMock()
            session_maker_mock.begin.return_value.__enter__ = MagicMock(
                return_value=MagicMock()
            )
            session_maker_mock.begin.return_value.__exit__ = MagicMock(
                return_value=False
            )

            with patch("asyncio.wait_for", new_callable=AsyncMock) as wait_mock:

                async def timeout_then_set(awaitable, timeout):
                    nonlocal call_count
                    call_count += 1
                    if call_count == 1:
                        raise asyncio.TimeoutError
                    else:
                        stop_event.set()
                        await awaitable

                wait_mock.side_effect = timeout_then_set
                await clean_old_messages_loop(
                    session_maker_mock,
                    seconds_interval=0,
                    ttl=timedelta(days=14),
                    stop_event=stop_event,
                )


class PreloadMessagesTests(unittest.IsolatedAsyncioTestCase):
    @patch.dict("os.environ", {"PRELOAD_MESSAGES": "0"})
    async def test_skips_when_disabled(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        session_maker_mock = MagicMock()
        await preload_messages(client_mock, session_maker_mock)
        client_mock.is_connected.assert_not_called()

    @patch.dict("os.environ", {"PRELOAD_MESSAGES": "1"})
    async def test_skips_when_not_connected(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=False)
        session_maker_mock = MagicMock()
        await preload_messages(client_mock, session_maker_mock)
        client_mock.is_connected.assert_called_once_with()
        client_mock.is_user_authorized.assert_not_called()

    @patch.dict("os.environ", {"PRELOAD_MESSAGES": "1"})
    async def test_skips_when_not_authorized(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        client_mock.is_user_authorized = AsyncMock(return_value=False)
        session_maker_mock = MagicMock()
        await preload_messages(client_mock, session_maker_mock)
        client_mock.is_connected.assert_called_once_with()
        client_mock.is_user_authorized.assert_called_once()

    @patch.dict(
        "os.environ",
        {"PRELOAD_MESSAGES": "1", "PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL": "60"},
    )
    async def test_preloads_with_no_dialogs(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        client_mock.is_user_authorized = AsyncMock(return_value=True)

        async def _empty_gen():
            return
            yield

        client_mock.iter_dialogs = _empty_gen
        session_maker_mock = MagicMock()
        await preload_messages(client_mock, session_maker_mock)

    @patch.dict(
        "os.environ",
        {"PRELOAD_MESSAGES": "1", "PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL": "0"},
    )
    async def test_preloads_with_zero_report_interval(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        client_mock.is_user_authorized = AsyncMock(return_value=True)

        async def _empty_gen():
            return
            yield

        client_mock.iter_dialogs = _empty_gen
        session_maker_mock = MagicMock()
        await preload_messages(client_mock, session_maker_mock)

    @patch.dict(
        "os.environ",
        {
            "PRELOAD_MESSAGES": "1",
            "PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL": "0",
            "PRELOAD_CHECKPOINTS_ENABLED": "1",
        },
    )
    async def test_preloads_messages_for_dialog_from_ttl_floor(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        client_mock.is_user_authorized = AsyncMock(return_value=True)

        dialog_mock = MagicMock()
        dialog_mock.id = 123
        dialog_mock.input_entity = MagicMock()

        entity_mock = MagicMock()
        client_mock.get_entity = AsyncMock(return_value=entity_mock)

        fixed_now = datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc)
        msg_mock = MagicMock()
        msg_mock.id = 1
        msg_mock.date = fixed_now - timedelta(hours=1)
        msg_mock.message = "test"

        async def iter_messages_gen():
            yield msg_mock

        client_mock.iter_messages = MagicMock(return_value=iter_messages_gen())

        async def iter_dialogs_gen():
            yield dialog_mock

        client_mock.iter_dialogs = iter_dialogs_gen

        session_maker_mock = MagicMock()
        chat_peer_mock = MagicMock()
        chat_peer_mock.id = 321

        with (
            patch("packages.background_jobs.datetime", wraps=datetime) as datetime_mock,
            patch(
                "packages.background_jobs.get_should_ignore_message_chat"
            ) as ignore_mock,
            patch(
                "packages.background_jobs.get_store_message_if_not_exists"
            ) as store_mock,
            patch(
                "packages.background_jobs.build_telegram_peer", new_callable=AsyncMock
            ) as build_peer_mock,
            patch(
                "packages.background_jobs.get_preload_checkpoint"
            ) as get_checkpoint_mock,
            patch(
                "packages.background_jobs.upsert_preload_checkpoint"
            ) as upsert_checkpoint_mock,
        ):
            datetime_mock.now.return_value = fixed_now
            ignore_fn = AsyncMock(return_value=False)
            ignore_mock.return_value = ignore_fn
            store_fn = AsyncMock(return_value=True)
            store_mock.return_value = store_fn
            build_peer_mock.return_value = chat_peer_mock
            get_checkpoint_mock.return_value = None

            await preload_messages(client_mock, session_maker_mock)

            client_mock.iter_messages.assert_called_once_with(
                entity_mock,
                reverse=True,
                offset_date=fixed_now - messages_ttl_delta,
            )
            upsert_checkpoint_mock.assert_called_once_with(
                chat_peer_id=321,
                preloaded_through_message_id=1,
                preloaded_through_timestamp=fixed_now,
                sqlalchemy_session_maker=session_maker_mock,
            )

    @patch.dict(
        "os.environ",
        {
            "PRELOAD_MESSAGES": "1",
            "PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL": "0",
            "PRELOAD_CHECKPOINTS_ENABLED": "1",
        },
    )
    async def test_resumes_from_checkpoint_message_id(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        client_mock.is_user_authorized = AsyncMock(return_value=True)

        dialog_mock = MagicMock()
        dialog_mock.id = 123
        dialog_mock.input_entity = MagicMock()

        entity_mock = MagicMock()
        client_mock.get_entity = AsyncMock(return_value=entity_mock)

        async def iter_messages_gen():
            if False:
                yield None

        client_mock.iter_messages = MagicMock(return_value=iter_messages_gen())

        async def iter_dialogs_gen():
            yield dialog_mock

        client_mock.iter_dialogs = iter_dialogs_gen

        session_maker_mock = MagicMock()
        chat_peer_mock = MagicMock()
        chat_peer_mock.id = 321
        fixed_now = datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc)
        checkpoint_mock = MagicMock()
        checkpoint_mock.preloaded_through_timestamp = fixed_now
        checkpoint_mock.preloaded_through_message_id = 55

        with (
            patch("packages.background_jobs.datetime", wraps=datetime) as datetime_mock,
            patch(
                "packages.background_jobs.get_should_ignore_message_chat"
            ) as ignore_mock,
            patch(
                "packages.background_jobs.get_store_message_if_not_exists"
            ) as store_mock,
            patch(
                "packages.background_jobs.build_telegram_peer", new_callable=AsyncMock
            ) as build_peer_mock,
            patch(
                "packages.background_jobs.get_preload_checkpoint"
            ) as get_checkpoint_mock,
            patch(
                "packages.background_jobs.upsert_preload_checkpoint"
            ) as upsert_checkpoint_mock,
        ):
            datetime_mock.now.return_value = fixed_now
            ignore_mock.return_value = AsyncMock(return_value=False)
            store_mock.return_value = AsyncMock(return_value=True)
            build_peer_mock.return_value = chat_peer_mock
            get_checkpoint_mock.return_value = checkpoint_mock

            await preload_messages(client_mock, session_maker_mock)

            client_mock.iter_messages.assert_called_once_with(
                entity_mock,
                reverse=True,
                min_id=55,
            )
            upsert_checkpoint_mock.assert_called_once_with(
                chat_peer_id=321,
                preloaded_through_message_id=55,
                preloaded_through_timestamp=fixed_now,
                sqlalchemy_session_maker=session_maker_mock,
            )

    @patch.dict(
        "os.environ",
        {
            "PRELOAD_MESSAGES": "1",
            "PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL": "0",
            "PRELOAD_CHECKPOINTS_ENABLED": "1",
        },
    )
    async def test_resumes_from_timestamp_only_checkpoint(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        client_mock.is_user_authorized = AsyncMock(return_value=True)

        dialog_mock = MagicMock()
        dialog_mock.id = 123
        dialog_mock.input_entity = MagicMock()

        entity_mock = MagicMock()
        client_mock.get_entity = AsyncMock(return_value=entity_mock)

        async def iter_messages_gen():
            if False:
                yield None

        client_mock.iter_messages = MagicMock(return_value=iter_messages_gen())

        async def iter_dialogs_gen():
            yield dialog_mock

        client_mock.iter_dialogs = iter_dialogs_gen

        session_maker_mock = MagicMock()
        chat_peer_mock = MagicMock()
        chat_peer_mock.id = 321
        fixed_now = datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc)
        checkpoint_timestamp = fixed_now - timedelta(hours=3)
        checkpoint_mock = MagicMock()
        checkpoint_mock.preloaded_through_timestamp = checkpoint_timestamp
        checkpoint_mock.preloaded_through_message_id = None

        with (
            patch("packages.background_jobs.datetime", wraps=datetime) as datetime_mock,
            patch(
                "packages.background_jobs.get_should_ignore_message_chat"
            ) as ignore_mock,
            patch(
                "packages.background_jobs.get_store_message_if_not_exists"
            ) as store_mock,
            patch(
                "packages.background_jobs.build_telegram_peer", new_callable=AsyncMock
            ) as build_peer_mock,
            patch(
                "packages.background_jobs.get_preload_checkpoint"
            ) as get_checkpoint_mock,
            patch(
                "packages.background_jobs.upsert_preload_checkpoint"
            ) as upsert_checkpoint_mock,
        ):
            datetime_mock.now.return_value = fixed_now
            ignore_mock.return_value = AsyncMock(return_value=False)
            store_mock.return_value = AsyncMock(return_value=True)
            build_peer_mock.return_value = chat_peer_mock
            get_checkpoint_mock.return_value = checkpoint_mock

            await preload_messages(client_mock, session_maker_mock)

            client_mock.iter_messages.assert_called_once_with(
                entity_mock,
                reverse=True,
                offset_date=checkpoint_timestamp,
            )
            upsert_checkpoint_mock.assert_called_once_with(
                chat_peer_id=321,
                preloaded_through_message_id=None,
                preloaded_through_timestamp=fixed_now,
                sqlalchemy_session_maker=session_maker_mock,
            )

    @patch.dict(
        "os.environ",
        {
            "PRELOAD_MESSAGES": "1",
            "PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL": "0",
            "PRELOAD_CHECKPOINTS_ENABLED": "1",
        },
    )
    async def test_ignores_stale_checkpoint_and_uses_ttl_floor(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        client_mock.is_user_authorized = AsyncMock(return_value=True)

        dialog_mock = MagicMock()
        dialog_mock.id = 123
        dialog_mock.input_entity = MagicMock()

        entity_mock = MagicMock()
        client_mock.get_entity = AsyncMock(return_value=entity_mock)

        async def iter_messages_gen():
            if False:
                yield None

        client_mock.iter_messages = MagicMock(return_value=iter_messages_gen())

        async def iter_dialogs_gen():
            yield dialog_mock

        client_mock.iter_dialogs = iter_dialogs_gen

        session_maker_mock = MagicMock()
        chat_peer_mock = MagicMock()
        chat_peer_mock.id = 321
        fixed_now = datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc)
        checkpoint_mock = MagicMock()
        checkpoint_mock.preloaded_through_timestamp = (
            fixed_now - messages_ttl_delta - timedelta(minutes=1)
        )
        checkpoint_mock.preloaded_through_message_id = 55

        with (
            patch("packages.background_jobs.datetime", wraps=datetime) as datetime_mock,
            patch(
                "packages.background_jobs.get_should_ignore_message_chat"
            ) as ignore_mock,
            patch(
                "packages.background_jobs.get_store_message_if_not_exists"
            ) as store_mock,
            patch(
                "packages.background_jobs.build_telegram_peer", new_callable=AsyncMock
            ) as build_peer_mock,
            patch(
                "packages.background_jobs.get_preload_checkpoint"
            ) as get_checkpoint_mock,
            patch(
                "packages.background_jobs.upsert_preload_checkpoint"
            ) as upsert_checkpoint_mock,
        ):
            datetime_mock.now.return_value = fixed_now
            ignore_mock.return_value = AsyncMock(return_value=False)
            store_mock.return_value = AsyncMock(return_value=True)
            build_peer_mock.return_value = chat_peer_mock
            get_checkpoint_mock.return_value = checkpoint_mock

            await preload_messages(client_mock, session_maker_mock)

            client_mock.iter_messages.assert_called_once_with(
                entity_mock,
                reverse=True,
                offset_date=fixed_now - messages_ttl_delta,
            )
            upsert_checkpoint_mock.assert_called_once_with(
                chat_peer_id=321,
                preloaded_through_message_id=55,
                preloaded_through_timestamp=fixed_now,
                sqlalchemy_session_maker=session_maker_mock,
            )

    @patch.dict(
        "os.environ",
        {
            "PRELOAD_MESSAGES": "1",
            "PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL": "0",
            "PRELOAD_CHECKPOINTS_ENABLED": "1",
            "PRELOAD_CHECKPOINT_UPDATE_EVERY_MESSAGES": "2",
        },
    )
    async def test_updates_checkpoints_periodically_and_on_completion(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        client_mock.is_user_authorized = AsyncMock(return_value=True)

        dialog_mock = MagicMock()
        dialog_mock.id = 123
        dialog_mock.input_entity = MagicMock()

        entity_mock = MagicMock()
        client_mock.get_entity = AsyncMock(return_value=entity_mock)

        fixed_now = datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc)
        message_one = MagicMock(
            id=1, date=fixed_now - timedelta(hours=3), message="one"
        )
        message_two = MagicMock(
            id=2, date=fixed_now - timedelta(hours=2), message="two"
        )
        message_three = MagicMock(
            id=3, date=fixed_now - timedelta(hours=1), message="three"
        )

        async def iter_messages_gen():
            yield message_one
            yield message_two
            yield message_three

        client_mock.iter_messages = MagicMock(return_value=iter_messages_gen())

        async def iter_dialogs_gen():
            yield dialog_mock

        client_mock.iter_dialogs = iter_dialogs_gen

        session_maker_mock = MagicMock()
        chat_peer_mock = MagicMock()
        chat_peer_mock.id = 321

        with (
            patch("packages.background_jobs.datetime", wraps=datetime) as datetime_mock,
            patch(
                "packages.background_jobs.get_should_ignore_message_chat"
            ) as ignore_mock,
            patch(
                "packages.background_jobs.get_store_message_if_not_exists"
            ) as store_mock,
            patch(
                "packages.background_jobs.build_telegram_peer", new_callable=AsyncMock
            ) as build_peer_mock,
            patch(
                "packages.background_jobs.get_preload_checkpoint"
            ) as get_checkpoint_mock,
            patch(
                "packages.background_jobs.upsert_preload_checkpoint"
            ) as upsert_checkpoint_mock,
        ):
            datetime_mock.now.return_value = fixed_now
            ignore_mock.return_value = AsyncMock(return_value=False)
            store_mock.return_value = AsyncMock(return_value=True)
            build_peer_mock.return_value = chat_peer_mock
            get_checkpoint_mock.return_value = None

            await preload_messages(client_mock, session_maker_mock)

            self.assertEqual(upsert_checkpoint_mock.call_count, 2)
            first_call = upsert_checkpoint_mock.call_args_list[0]
            self.assertEqual(first_call.kwargs["chat_peer_id"], 321)
            self.assertEqual(first_call.kwargs["preloaded_through_message_id"], 2)
            self.assertEqual(
                first_call.kwargs["preloaded_through_timestamp"], message_two.date
            )
            final_call = upsert_checkpoint_mock.call_args_list[-1]
            self.assertEqual(final_call.kwargs["chat_peer_id"], 321)
            self.assertEqual(final_call.kwargs["preloaded_through_message_id"], 3)
            self.assertEqual(
                final_call.kwargs["preloaded_through_timestamp"], fixed_now
            )

    @patch.dict(
        "os.environ",
        {
            "PRELOAD_MESSAGES": "1",
            "PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL": "0",
            "PRELOAD_CHECKPOINTS_ENABLED": "1",
        },
    )
    async def test_writes_timestamp_only_checkpoint_when_dialog_has_no_messages(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        client_mock.is_user_authorized = AsyncMock(return_value=True)

        dialog_mock = MagicMock()
        dialog_mock.id = 123
        dialog_mock.input_entity = MagicMock()

        entity_mock = MagicMock()
        client_mock.get_entity = AsyncMock(return_value=entity_mock)

        async def iter_messages_gen():
            if False:
                yield None

        client_mock.iter_messages = MagicMock(return_value=iter_messages_gen())

        async def iter_dialogs_gen():
            yield dialog_mock

        client_mock.iter_dialogs = iter_dialogs_gen

        session_maker_mock = MagicMock()
        chat_peer_mock = MagicMock()
        chat_peer_mock.id = 321
        fixed_now = datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc)

        with (
            patch("packages.background_jobs.datetime", wraps=datetime) as datetime_mock,
            patch(
                "packages.background_jobs.get_should_ignore_message_chat"
            ) as ignore_mock,
            patch(
                "packages.background_jobs.get_store_message_if_not_exists"
            ) as store_mock,
            patch(
                "packages.background_jobs.build_telegram_peer", new_callable=AsyncMock
            ) as build_peer_mock,
            patch(
                "packages.background_jobs.get_preload_checkpoint"
            ) as get_checkpoint_mock,
            patch(
                "packages.background_jobs.upsert_preload_checkpoint"
            ) as upsert_checkpoint_mock,
        ):
            datetime_mock.now.return_value = fixed_now
            ignore_mock.return_value = AsyncMock(return_value=False)
            store_mock.return_value = AsyncMock(return_value=True)
            build_peer_mock.return_value = chat_peer_mock
            get_checkpoint_mock.return_value = None

            await preload_messages(client_mock, session_maker_mock)

            upsert_checkpoint_mock.assert_called_once_with(
                chat_peer_id=321,
                preloaded_through_message_id=None,
                preloaded_through_timestamp=fixed_now,
                sqlalchemy_session_maker=session_maker_mock,
            )

    @patch.dict(
        "os.environ",
        {
            "PRELOAD_MESSAGES": "1",
            "PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL": "0",
            "PRELOAD_CHECKPOINTS_ENABLED": "1",
        },
    )
    async def test_completion_checkpoint_timestamp_is_monotonic(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        client_mock.is_user_authorized = AsyncMock(return_value=True)

        dialog_mock = MagicMock()
        dialog_mock.id = 123
        dialog_mock.input_entity = MagicMock()

        entity_mock = MagicMock()
        client_mock.get_entity = AsyncMock(return_value=entity_mock)

        fixed_now = datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc)
        future_message_timestamp = fixed_now + timedelta(minutes=1)
        msg_mock = MagicMock()
        msg_mock.id = 77
        msg_mock.date = future_message_timestamp
        msg_mock.message = "future"

        async def iter_messages_gen():
            yield msg_mock

        client_mock.iter_messages = MagicMock(return_value=iter_messages_gen())

        async def iter_dialogs_gen():
            yield dialog_mock

        client_mock.iter_dialogs = iter_dialogs_gen

        session_maker_mock = MagicMock()
        chat_peer_mock = MagicMock()
        chat_peer_mock.id = 321

        with (
            patch("packages.background_jobs.datetime", wraps=datetime) as datetime_mock,
            patch(
                "packages.background_jobs.get_should_ignore_message_chat"
            ) as ignore_mock,
            patch(
                "packages.background_jobs.get_store_message_if_not_exists"
            ) as store_mock,
            patch(
                "packages.background_jobs.build_telegram_peer", new_callable=AsyncMock
            ) as build_peer_mock,
            patch(
                "packages.background_jobs.get_preload_checkpoint"
            ) as get_checkpoint_mock,
            patch(
                "packages.background_jobs.upsert_preload_checkpoint"
            ) as upsert_checkpoint_mock,
        ):
            datetime_mock.now.return_value = fixed_now
            ignore_mock.return_value = AsyncMock(return_value=False)
            store_mock.return_value = AsyncMock(return_value=True)
            build_peer_mock.return_value = chat_peer_mock
            get_checkpoint_mock.return_value = None

            await preload_messages(client_mock, session_maker_mock)

            upsert_checkpoint_mock.assert_called_once_with(
                chat_peer_id=321,
                preloaded_through_message_id=77,
                preloaded_through_timestamp=future_message_timestamp,
                sqlalchemy_session_maker=session_maker_mock,
            )

    @patch.dict(
        "os.environ",
        {
            "PRELOAD_MESSAGES": "1",
            "PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL": "0",
            "PRELOAD_CHECKPOINTS_ENABLED": "0",
        },
    )
    async def test_does_not_use_checkpoints_when_disabled(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        client_mock.is_user_authorized = AsyncMock(return_value=True)

        dialog_mock = MagicMock()
        dialog_mock.id = 123
        dialog_mock.input_entity = MagicMock()

        entity_mock = MagicMock()
        client_mock.get_entity = AsyncMock(return_value=entity_mock)
        fixed_now = datetime(2026, 4, 8, 12, 0, tzinfo=timezone.utc)

        async def iter_messages_gen():
            if False:
                yield None

        client_mock.iter_messages = MagicMock(return_value=iter_messages_gen())

        async def iter_dialogs_gen():
            yield dialog_mock

        client_mock.iter_dialogs = iter_dialogs_gen

        session_maker_mock = MagicMock()

        with (
            patch("packages.background_jobs.datetime", wraps=datetime) as datetime_mock,
            patch(
                "packages.background_jobs.get_should_ignore_message_chat"
            ) as ignore_mock,
            patch(
                "packages.background_jobs.get_store_message_if_not_exists"
            ) as store_mock,
            patch(
                "packages.background_jobs.build_telegram_peer", new_callable=AsyncMock
            ) as build_peer_mock,
            patch(
                "packages.background_jobs.get_preload_checkpoint"
            ) as get_checkpoint_mock,
            patch(
                "packages.background_jobs.upsert_preload_checkpoint"
            ) as upsert_checkpoint_mock,
        ):
            datetime_mock.now.return_value = fixed_now
            ignore_mock.return_value = AsyncMock(return_value=False)
            store_mock.return_value = AsyncMock(return_value=True)

            await preload_messages(client_mock, session_maker_mock)

            client_mock.iter_messages.assert_called_once_with(
                entity_mock,
                reverse=True,
                offset_date=fixed_now - messages_ttl_delta,
            )
            build_peer_mock.assert_not_called()
            get_checkpoint_mock.assert_not_called()
            upsert_checkpoint_mock.assert_not_called()


class GatherWithConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_gathers_all_coroutines(self):
        results = []

        async def coro(x):
            results.append(x)
            return x

        out = await gather_with_concurrency(2, coro(1), coro(2), coro(3))
        self.assertEqual(sorted(out), [1, 2, 3])
        self.assertEqual(sorted(results), [1, 2, 3])

    async def test_limits_concurrency(self):
        max_concurrent = 0
        current = 0

        async def coro(x):
            nonlocal max_concurrent, current
            current += 1
            max_concurrent = max(max_concurrent, current)
            await asyncio.sleep(0.01)
            current -= 1
            return x

        await gather_with_concurrency(2, coro(1), coro(2), coro(3), coro(4))
        self.assertLessEqual(max_concurrent, 2)

    async def test_empty_coros(self):
        result = await gather_with_concurrency(1)
        self.assertEqual(list(result), [])


class MessagesTtlDeltaTests(unittest.TestCase):
    def test_is_timedelta(self):
        self.assertIsInstance(messages_ttl_delta, timedelta)

    def test_default_is_14_days(self):
        self.assertEqual(messages_ttl_delta.days, 14)


class PreloadMessagesIgnoredDialogTests(unittest.IsolatedAsyncioTestCase):
    @patch.dict(
        "os.environ",
        {
            "PRELOAD_MESSAGES": "1",
            "PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL": "0",
            "PRELOAD_CHECKPOINTS_ENABLED": "1",
        },
    )
    async def test_skips_ignored_dialog(self):
        client_mock = AsyncMock()
        client_mock.is_connected = MagicMock(return_value=True)
        client_mock.is_user_authorized = AsyncMock(return_value=True)

        dialog_mock = MagicMock()
        dialog_mock.id = 456
        dialog_mock.input_entity = MagicMock()

        entity_mock = MagicMock()
        client_mock.get_entity = AsyncMock(return_value=entity_mock)

        async def iter_dialogs_gen():
            yield dialog_mock

        client_mock.iter_dialogs = iter_dialogs_gen

        session_maker_mock = MagicMock()

        with patch(
            "packages.background_jobs.get_should_ignore_message_chat",
        ) as ignore_mock:
            ignore_fn = AsyncMock(return_value=True)
            ignore_mock.return_value = ignore_fn

            with (
                patch(
                    "packages.background_jobs.get_store_message_if_not_exists"
                ) as store_mock,
                patch(
                    "packages.background_jobs.build_telegram_peer",
                    new_callable=AsyncMock,
                ) as build_peer_mock,
                patch(
                    "packages.background_jobs.get_preload_checkpoint"
                ) as get_checkpoint_mock,
                patch(
                    "packages.background_jobs.upsert_preload_checkpoint"
                ) as upsert_checkpoint_mock,
            ):
                store_fn = AsyncMock(return_value=True)
                store_mock.return_value = store_fn

                await preload_messages(client_mock, session_maker_mock)

                ignore_fn.assert_called_once_with(entity_mock)
                store_fn.assert_not_called()
                build_peer_mock.assert_not_called()
                get_checkpoint_mock.assert_not_called()
                upsert_checkpoint_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()

import asyncio
import unittest
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from packages.background_jobs import (
    clean_old_messages_loop,
    gather_with_concurrency,
    messages_ttl_delta,
    preload_messages,
)


class CleanOldMessagesLoopTests(unittest.IsolatedAsyncioTestCase):
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
                wait_mock.side_effect = asyncio.TimeoutError
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
                wait_mock.side_effect = asyncio.TimeoutError
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
        session_maker_mock = MagicMock()
        await preload_messages(client_mock, session_maker_mock)
        client_mock.is_connected.assert_not_called()

    @patch.dict("os.environ", {"PRELOAD_MESSAGES": "1"})
    async def test_skips_when_not_connected(self):
        client_mock = AsyncMock()
        client_mock.is_connected = False
        session_maker_mock = MagicMock()
        await preload_messages(client_mock, session_maker_mock)
        client_mock.is_user_authorized.assert_not_called()

    @patch.dict("os.environ", {"PRELOAD_MESSAGES": "1"})
    async def test_skips_when_not_authorized(self):
        client_mock = AsyncMock()
        client_mock.is_connected = True
        client_mock.is_user_authorized = AsyncMock(return_value=False)
        session_maker_mock = MagicMock()
        await preload_messages(client_mock, session_maker_mock)
        client_mock.is_user_authorized.assert_called_once()

    @patch.dict(
        "os.environ",
        {"PRELOAD_MESSAGES": "1", "PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL": "60"},
    )
    async def test_preloads_with_no_dialogs(self):
        client_mock = AsyncMock()
        client_mock.is_connected = True
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
        client_mock.is_connected = True
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
    async def test_preloads_messages_for_dialog(self):
        client_mock = AsyncMock()
        client_mock.is_connected = True
        client_mock.is_user_authorized = AsyncMock(return_value=True)

        from datetime import datetime, timezone

        dialog_mock = MagicMock()
        dialog_mock.id = 123
        dialog_mock.input_entity = MagicMock()

        entity_mock = MagicMock()
        client_mock.get_entity = AsyncMock(return_value=entity_mock)

        msg_mock = MagicMock()
        msg_mock.id = 1
        msg_mock.date = datetime.now(tz=timezone.utc)
        msg_mock.message = "test"

        messages_list = MagicMock()
        messages_list.__len__ = MagicMock(return_value=1)
        messages_list.__iter__ = MagicMock(return_value=iter([msg_mock]))
        messages_list.__getitem__ = MagicMock(return_value=msg_mock)

        client_mock.get_messages = AsyncMock(side_effect=[[msg_mock], []])

        async def iter_dialogs_gen():
            yield dialog_mock

        client_mock.iter_dialogs = iter_dialogs_gen

        session_maker_mock = MagicMock()

        with patch(
            "packages.background_jobs.get_should_ignore_message_chat",
        ) as ignore_mock:
            ignore_fn = AsyncMock(return_value=False)
            ignore_mock.return_value = ignore_fn

            with patch(
                "packages.background_jobs.get_store_message_if_not_exists",
            ) as store_mock:
                store_fn = AsyncMock(return_value=True)
                store_mock.return_value = store_fn

                await preload_messages(client_mock, session_maker_mock)


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


if __name__ == "__main__":
    unittest.main()

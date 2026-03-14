import asyncio
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from packages.bootstrap import (
    Closer,
    add_signal_handlers,
    ask_exit,
    make_sync_closer,
)


class CloserTests(unittest.IsolatedAsyncioTestCase):
    async def test_initial_state(self):
        closer = Closer()
        self.assertFalse(closer.called)
        self.assertIsNone(closer.stop_event)
        self.assertIsNone(closer.client)
        self.assertIsNone(closer.bot)

    async def test_sets_stop_event(self):
        closer = Closer()
        closer.stop_event = asyncio.Event()
        closer.client = None
        closer.bot = None
        await closer()
        self.assertTrue(closer.stop_event.is_set())
        self.assertTrue(closer.called)

    async def test_prevents_reentry(self):
        closer = Closer()
        closer.stop_event = asyncio.Event()
        closer.client = None
        closer.bot = None
        await closer()
        closer.stop_event.clear()
        await closer()
        self.assertFalse(closer.stop_event.is_set())

    async def test_disconnects_client(self):
        closer = Closer()
        closer.stop_event = asyncio.Event()
        client_mock = AsyncMock()
        client_mock.disconnect = AsyncMock()
        closer.client = client_mock
        closer.bot = None
        await closer()
        client_mock.disconnect.assert_called_once()

    async def test_disconnects_bot(self):
        closer = Closer()
        closer.stop_event = asyncio.Event()
        closer.client = None
        closer.bot = AsyncMock()
        closer.bot.__aexit__ = AsyncMock()
        await closer()
        closer.bot.__aexit__.assert_called_once()


class MakeSyncCloserTests(unittest.TestCase):
    def test_returns_callable(self):
        closer = Closer()
        loop = MagicMock()
        sync_closer = make_sync_closer(closer, loop)
        self.assertTrue(callable(sync_closer))


class AddSignalHandlersTests(unittest.TestCase):
    def test_adds_handlers_for_signals(self):
        loop = MagicMock()
        closer = MagicMock()
        add_signal_handlers(loop, closer)
        self.assertEqual(loop.add_signal_handler.call_count, 2)


class AskExitTests(unittest.TestCase):
    @patch("packages.bootstrap.is_exiting", False)
    @patch("packages.bootstrap.asyncio.all_tasks", return_value=set())
    def test_logs_signal_name(self, mock_all_tasks):
        loop = MagicMock()
        closer_coro = MagicMock()

        with patch("packages.bootstrap.logger") as mock_logger:
            ask_exit("SIGTERM", loop, closer_coro)
            mock_logger.warning.assert_any_call("[exit] Got signal SIGTERM: exiting!")

    @patch("packages.bootstrap.is_exiting", False)
    @patch("packages.bootstrap.asyncio.all_tasks", return_value=set())
    def test_graceful_exit_without_signal(self, mock_all_tasks):
        loop = MagicMock()
        closer_coro = MagicMock()

        with patch("packages.bootstrap.logger") as mock_logger:
            ask_exit(None, loop, closer_coro)
            mock_logger.info.assert_any_call(
                "[exit] Gracefully exiting, called from code!"
            )

    @patch("packages.bootstrap.is_exiting", True)
    def test_reentry_detected(self):
        loop = MagicMock()
        closer_coro = MagicMock()

        with patch("packages.bootstrap.logger") as mock_logger:
            ask_exit("SIGINT", loop, closer_coro)
            mock_logger.info.assert_any_call("ask_exit re-entry detected, ignoring")

    @patch("packages.bootstrap.is_exiting", False)
    @patch("packages.bootstrap.asyncio.all_tasks")
    def test_cancels_all_tasks(self, mock_all_tasks):
        loop = MagicMock()
        closer_coro = MagicMock()

        task_mock = MagicMock()
        task_mock.cancel = MagicMock()
        mock_all_tasks.return_value = {task_mock}

        ask_exit(None, loop, closer_coro)
        task_mock.cancel.assert_called_once()

    @patch("packages.bootstrap.is_exiting", False)
    @patch("packages.bootstrap.asyncio.all_tasks", return_value=set())
    def test_stops_loop(self, mock_all_tasks):
        loop = MagicMock()
        closer_coro = MagicMock()

        ask_exit(None, loop, closer_coro)
        loop.stop.assert_called_once()

    @patch("packages.bootstrap.is_exiting", False)
    @patch("packages.bootstrap.asyncio.all_tasks", return_value=set())
    def test_runs_additional_cleaner(self, mock_all_tasks):
        loop = MagicMock()
        closer_coro = MagicMock()

        ask_exit(None, loop, closer_coro)
        loop.run_until_complete.assert_called_once_with(closer_coro())


class ConfigureBotTests(unittest.IsolatedAsyncioTestCase):
    @patch.dict("os.environ", {}, clear=False)
    async def test_returns_none_when_no_bot_token(self):
        with patch.dict("os.environ", {}, clear=False):
            if "TELEGRAM_BOT_TOKEN" in os.environ:
                del os.environ["TELEGRAM_BOT_TOKEN"]
            from packages.bootstrap import configure_bot

            container_mock = MagicMock()
            result = await configure_bot(
                container_mock, "api_id", "api_hash", "me", "session1"
            )
            notify_del, notify_unknown, bot = result
            self.assertIsNone(notify_del)
            self.assertIsNone(notify_unknown)
            self.assertIsNone(bot)


class MakeClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_creates_and_connects_client(self):
        from packages.bootstrap import make_client

        container_mock = MagicMock()
        session_mock = MagicMock()
        container_mock.new_session.return_value = session_mock

        loop = asyncio.get_event_loop()

        with patch("packages.bootstrap.TelegramClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value = client_instance

            result = await make_client(
                container_mock, "api_id", "api_hash", "session1", loop
            )

            container_mock.new_session.assert_called_with("session1")
            client_instance.connect.assert_called_once()
            self.assertIs(result, client_instance)

    async def test_recreates_session_on_auth_key_duplicated(self):
        from packages.bootstrap import make_client
        from telethon.errors.rpcerrorlist import AuthKeyDuplicatedError

        container_mock = MagicMock()
        session_mock = MagicMock()
        container_mock.new_session.return_value = session_mock

        loop = asyncio.get_event_loop()

        with patch("packages.bootstrap.TelegramClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.connect.side_effect = [
                AuthKeyDuplicatedError(request=None),
                None,
            ]
            MockClient.return_value = client_instance

            await make_client(container_mock, "api_id", "api_hash", "session1", loop)

            self.assertEqual(container_mock.new_session.call_count, 2)
            self.assertEqual(client_instance.connect.call_count, 2)


class ClientMainLoopJobTests(unittest.IsolatedAsyncioTestCase):
    async def test_creates_tasks_and_sets_started_event(self):
        from packages.bootstrap import client_main_loop_job

        stop_event = asyncio.Event()
        started_event = asyncio.Event()
        session_maker_mock = MagicMock()
        notify_del = AsyncMock()
        notify_unknown = AsyncMock()
        notify_edit = AsyncMock()  # Parameter for message edit notifications
        client_mock = AsyncMock()
        gather_mock = AsyncMock(return_value=[])

        with (
            patch(
                "packages.bootstrap.add_event_handlers", new_callable=AsyncMock
            ) as add_handlers,
            patch(
                "packages.bootstrap.preload_messages", new_callable=AsyncMock
            ) as preload,
        ):
            add_handlers.return_value = None
            preload.return_value = None

            stop_event.set()

            await client_main_loop_job(
                stop_event,
                started_event,
                session_maker_mock,
                notify_del,
                notify_unknown,
                notify_edit,  # Pass the new parameter
                client_mock,
                gather_mock,
            )

            self.assertTrue(started_event.is_set())


class WorkerFunctionTests(unittest.TestCase):
    @patch("packages.bootstrap.os._exit")
    @patch("packages.bootstrap.asyncio.set_event_loop")
    def test_sets_event_loop_and_exits(self, mock_set_loop, mock_exit):
        from packages.bootstrap import worker_function

        loop = MagicMock()
        closer = Closer()
        sync_closer = MagicMock()

        worker_function(loop, closer, sync_closer)

        mock_set_loop.assert_called_once_with(loop)
        loop.run_forever.assert_called_once()
        mock_exit.assert_called_with(0)

    @patch("packages.bootstrap.os._exit")
    @patch("packages.bootstrap.asyncio.set_event_loop")
    def test_calls_sync_closer_on_error(self, mock_set_loop, mock_exit):
        from packages.bootstrap import worker_function

        loop = MagicMock()
        closer = Closer()
        sync_closer = MagicMock()

        loop.run_forever.side_effect = RuntimeError("test error")

        worker_function(loop, closer, sync_closer)

        sync_closer.assert_called_once()
        mock_exit.assert_any_call(1)


if __name__ == "__main__":
    unittest.main()

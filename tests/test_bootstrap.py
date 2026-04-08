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

    async def test_disconnects_client_with_none_return(self):
        closer = Closer()
        closer.stop_event = asyncio.Event()
        client_mock = MagicMock()
        client_mock.disconnect = MagicMock(return_value=None)
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

    async def test_handles_none_stop_event(self):
        closer = Closer()
        closer.stop_event = None
        closer.client = None
        closer.bot = None
        await closer()
        self.assertTrue(closer.called)

    async def test_handles_none_client(self):
        closer = Closer()
        closer.stop_event = asyncio.Event()
        closer.client = None
        closer.bot = None
        await closer()
        self.assertTrue(closer.stop_event.is_set())
        self.assertTrue(closer.called)

    async def test_handles_bot_exists(self):
        closer = Closer()
        closer.stop_event = asyncio.Event()
        closer.client = None
        bot_mock = AsyncMock()
        bot_mock.__aexit__ = AsyncMock()
        closer.bot = bot_mock
        await closer()
        bot_mock.__aexit__.assert_called_once_with(None, None, None)

    async def test_handles_exception_in_gather(self):
        closer = Closer()
        closer.stop_event = asyncio.Event()
        closer.client = None
        bot_mock = AsyncMock()
        bot_mock.__aexit__ = AsyncMock(side_effect=RuntimeError("test error"))
        closer.bot = bot_mock
        with patch("packages.bootstrap.os._exit") as mock_exit:
            await closer()
            mock_exit.assert_called_once_with(1)


class MakeSyncCloserTests(unittest.TestCase):
    def test_returns_callable(self):
        closer = Closer()
        loop = MagicMock()
        sync_closer = make_sync_closer(closer, loop)
        self.assertTrue(callable(sync_closer))

    @patch("packages.bootstrap.is_exiting", False)
    @patch("packages.bootstrap.asyncio.all_tasks", return_value=set())
    def test_triggers_ask_exit_when_called(self, mock_all_tasks):
        closer = Closer()
        loop = MagicMock()
        loop.run_until_complete.side_effect = lambda coro: coro.close()
        sync_closer = make_sync_closer(closer, loop)
        with patch("packages.bootstrap.logger"):
            sync_closer()
        loop.run_until_complete.assert_called_once()
        loop.stop.assert_called_once()


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

    @patch("packages.bootstrap.is_exiting", False)
    @patch("packages.bootstrap.asyncio.all_tasks", return_value=set())
    def test_skips_additional_when_none(self, mock_all_tasks):
        loop = MagicMock()

        ask_exit(None, loop, None)
        loop.run_until_complete.assert_not_called()
        loop.stop.assert_called_once()

    @patch("packages.bootstrap.is_exiting", False)
    @patch("packages.bootstrap.asyncio.all_tasks", return_value=set())
    def test_runtimeerror_event_loop_stopped_ignored(self, mock_all_tasks):
        loop = MagicMock()
        loop.run_until_complete.side_effect = RuntimeError(
            "Event loop stopped before Future completed"
        )
        closer_coro = MagicMock()

        with patch("packages.bootstrap.logger") as mock_logger:
            ask_exit(None, loop, closer_coro)
            mock_logger.error.assert_not_called()
            loop.stop.assert_called_once()

    @patch("packages.bootstrap.is_exiting", False)
    @patch("packages.bootstrap.asyncio.all_tasks", return_value=set())
    def test_runtimeerror_other_logged(self, mock_all_tasks):
        loop = MagicMock()
        loop.run_until_complete.side_effect = RuntimeError("some other error")
        closer_coro = MagicMock()

        with patch("packages.bootstrap.logger") as mock_logger:
            ask_exit(None, loop, closer_coro)
            mock_logger.error.assert_called_once()

    @patch("packages.bootstrap.is_exiting", False)
    @patch("packages.bootstrap.asyncio.all_tasks", return_value=set())
    def test_successful_additional_runs_else_branch(self, mock_all_tasks):
        loop = MagicMock()
        closer_coro = MagicMock()

        with patch("packages.bootstrap.logger") as mock_logger:
            ask_exit(None, loop, closer_coro)
            mock_logger.info.assert_any_call(
                "[exit] Successfully ran user-provided cleanupper"
            )


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
            notify_del, notify_unknown, notify_edit, bot = result
            self.assertIsNone(notify_del)
            self.assertIsNone(notify_unknown)
            self.assertIsNone(notify_edit)
            self.assertIsNone(bot)

    @patch("packages.bootstrap.os._exit", side_effect=SystemExit)
    @patch.dict(
        "os.environ",
        {"TELEGRAM_BOT_TOKEN": "test_token", "TARGET_CHAT_IS_ID": "0"},
    )
    async def test_exits_when_target_chat_is_me(self, mock_exit):
        from packages.bootstrap import configure_bot

        container_mock = MagicMock()
        with self.assertRaises(SystemExit):
            await configure_bot(container_mock, "api_id", "api_hash", "me", "session1")
        mock_exit.assert_called_once_with(1)

    @patch("packages.bootstrap.BotAssistant")
    @patch.dict(
        "os.environ",
        {"TELEGRAM_BOT_TOKEN": "test_token", "TARGET_CHAT_IS_ID": "1"},
    )
    async def test_creates_bot_with_valid_target_chat(self, mock_bot_class):
        from packages.bootstrap import configure_bot

        container_mock = MagicMock()
        session_mock = MagicMock()
        container_mock.new_session.return_value = session_mock

        bot_instance = AsyncMock()
        bot_instance.__aenter__ = AsyncMock(return_value=bot_instance)
        bot_instance.__aexit__ = AsyncMock()
        mock_bot_class.return_value = bot_instance

        notify_del, notify_unknown, notify_edit, bot = await configure_bot(
            container_mock, "12345", "api_hash", "12345", "session1"
        )

        mock_bot_class.assert_called_once()
        args, kwargs = mock_bot_class.call_args
        self.assertEqual(args[0], 12345)
        self.assertEqual(args[1], "12345")
        self.assertEqual(args[2], "api_hash")
        self.assertEqual(args[3], "test_token")
        self.assertTrue(callable(notify_edit))
        self.assertIn("session_maker", kwargs)
        session_maker = kwargs["session_maker"]
        self.assertTrue(callable(session_maker))
        # session_maker should call container.new_session with session_id + "_bot"
        returned_session = session_maker()
        container_mock.new_session.assert_called_with("session1_bot")
        self.assertIs(returned_session, session_mock)

        bot_instance.__aenter__.assert_called_once()
        self.assertIsNotNone(notify_del)
        self.assertIsNotNone(notify_unknown)
        self.assertIs(bot, bot_instance)
        self.assertEqual(notify_del, bot_instance.notify_message_deletion)
        self.assertEqual(notify_unknown, bot_instance.notify_unknown_message)


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
            "EDITED_MESSAGES_NOTIFICATION_CONCURRENCY": "1",
        },
    )
    async def test_uses_default_notify_when_none(self):
        from packages.bootstrap import client_main_loop_job

        stop_event = asyncio.Event()
        started_event = asyncio.Event()
        session_maker_mock = MagicMock()

        session_mock = MagicMock()
        session_mock.execute.return_value.scalar.return_value = None
        session_maker_mock.begin.return_value.__enter__ = MagicMock(
            return_value=session_mock
        )
        session_maker_mock.begin.return_value.__exit__ = MagicMock(return_value=False)

        client_mock = AsyncMock()
        client_mock.get_entity = AsyncMock(return_value=MagicMock())
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
                None,
                None,
                None,
                client_mock,
                gather_mock,
            )

            self.assertTrue(started_event.is_set())
            add_handlers.assert_called_once()
            args = add_handlers.call_args
            self.assertIsNotNone(args[0][2])
            self.assertIsNotNone(args[0][3])
            self.assertIsNotNone(args[0][4])


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


class CreateAppAndStartJobsTests(unittest.TestCase):
    def test_passes_configured_edit_notifier_to_main_loop_job(self):
        from packages.bootstrap import create_app_and_start_jobs

        test_loop = asyncio.new_event_loop()
        notify_del = MagicMock(name="notify_del")
        notify_unknown = MagicMock(name="notify_unknown")
        notify_edit = MagicMock(name="notify_edit")
        bot_mock = AsyncMock()
        bot_mock.__aexit__ = AsyncMock()
        client_mock = AsyncMock()
        client_mock.disconnect = AsyncMock()
        sessionmaker_mock = MagicMock(name="sessionmaker_mock")
        container_mock = MagicMock(name="alchemy_container")
        future_mock = MagicMock(name="main_loop_future")
        flask_app_mock = MagicMock(name="flask_app")

        def make_thread_side_effect(*args, **kwargs):
            closer = kwargs["args"][1]
            closer.stop_event = asyncio.Event()
            closer.started_event = asyncio.Event()
            thread_mock = MagicMock()
            thread_mock.is_alive.return_value = True
            thread_mock.start.return_value = None
            return thread_mock

        def run_coro_side_effect(coro, loop):
            coro.close()
            return future_mock

        with (
            patch(
                "packages.bootstrap.asyncio.events.new_event_loop",
                return_value=test_loop,
            ),
            patch("packages.bootstrap.add_signal_handlers"),
            patch("sqlalchemy.orm.sessionmaker", return_value=sessionmaker_mock),
            patch("packages.bootstrap.AlchemySessionContainer", return_value=container_mock),
            patch("packages.db_helpers.get_db_url", return_value="sqlite:///:memory:"),
            patch("packages.db_bootstrap.create_engine", return_value=MagicMock()),
            patch("packages.db_helpers.create_database"),
            patch(
                "packages.env_helpers.require_env",
                side_effect=["api_id", "api_hash", "session_id"],
            ),
            patch(
                "packages.bootstrap.configure_bot",
                new_callable=AsyncMock,
                return_value=(notify_del, notify_unknown, notify_edit, bot_mock),
            ),
            patch(
                "packages.bootstrap.make_client",
                new_callable=AsyncMock,
                return_value=client_mock,
            ),
            patch("packages.bootstrap.threading.Thread", side_effect=make_thread_side_effect),
            patch(
                "packages.bootstrap.client_main_loop_job",
                new_callable=AsyncMock,
                return_value=None,
            ) as client_main_loop_job_mock,
            patch(
                "packages.bootstrap.asyncio.run_coroutine_threadsafe",
                side_effect=run_coro_side_effect,
            ),
            patch("packages.http.create_app", return_value=flask_app_mock),
        ):
            flask_app, sync_closer = create_app_and_start_jobs()

        self.assertIs(flask_app, flask_app_mock)
        self.assertIs(client_main_loop_job_mock.call_args.args[5], notify_edit)

        with (
            patch("packages.bootstrap.is_exiting", False),
            patch("packages.bootstrap.asyncio.all_tasks", return_value=set()),
        ):
            sync_closer()
        test_loop.close()


if __name__ == "__main__":
    unittest.main()

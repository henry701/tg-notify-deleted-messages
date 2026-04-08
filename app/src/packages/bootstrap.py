import asyncio
import concurrent
import functools
import logging
import os
import signal
import threading
import time
from collections.abc import Callable
from distutils.util import strtobool

import telethon
from alchemysession import AlchemySessionContainer
from telethon import TelegramClient
from telethon.errors.rpcerrorlist import AuthKeyDuplicatedError

from packages.background_jobs import (
    clean_old_messages_loop,
    messages_ttl_delta,
    preload_messages,
)
from packages.config import (
    compute_effective_chunk_size,
    get_env_int,
    validate_chunk_size,
)
from packages.bot_assistant import BotAssistant
from packages.event_orchestration import add_event_handlers
from packages.models.root.TelegramMessage import TelegramMessage
from packages.notifications import (
    get_base_notify_message_deletion,
    get_base_notify_message_edit,
    get_default_notify_message_deletion,
    get_default_notify_message_edit,
    get_default_notify_unknown_message,
)
from packages.restart_manager import (
    get_inactivity_hours_from_env,
    get_restart_cron_from_env,
    inactivity_restart_loop,
    scheduled_restart_loop,
)

logger = logging.getLogger("tgdel-bootstrap")

is_exiting = False


def ask_exit(
    signame: str | None,
    loop: asyncio.AbstractEventLoop,
    additional: Callable,
):
    if signame:
        logger.warning("[exit] Got signal %s: exiting!" % signame)
    else:
        logger.info("[exit] Gracefully exiting, called from code!")
    global is_exiting
    if is_exiting:
        logger.info("ask_exit re-entry detected, ignoring")
        return
    is_exiting = True
    if additional is not None:
        logger.info("[exit] Running user-provided cleanupper")
        try:
            loop.run_until_complete(additional())
        except RuntimeError as e:
            if "Event loop stopped before Future completed" not in str(e):
                logger.error(
                    "[exit] Error while running user-provided cleanupper",
                    exc_info=True,
                )
        else:
            logger.info("[exit] Successfully ran user-provided cleanupper")
    all_tasks = asyncio.all_tasks(loop)
    tasklen = len(all_tasks)
    if tasklen > 0:
        logger.warning(f"[exit] Cancelling all remaining {tasklen} asyncio tasks!")
        for task in all_tasks:
            task.cancel()
        logger.warning(f"[exit] Cancelled all remaining {tasklen} asyncio tasks!")
    logger.info("[exit] Stopping the loop!")
    loop.stop()
    logger.info("[exit] Bye bye! Gracefully exited.")


async def make_client(
    alchemy_telegram_container: AlchemySessionContainer,
    telegram_api_id,
    telegram_api_hash,
    session_id,
    loop: asyncio.AbstractEventLoop,
):
    # Determine effective max chunk size using centralized config helper
    override_env_val = get_env_int("TELETHON_OVERRIDE_MAX_CHUNK_SIZE", -1)
    telegram_max_chunk_size_env = os.getenv("TELEGRAM_MAX_CHUNK_SIZE")
    effective_size = compute_effective_chunk_size(
        override_env_val, telegram_max_chunk_size_env
    )
    # Safety: clamp to sane bounds for reliability and testability
    effective_size = validate_chunk_size(effective_size, -1, 65536)
    if effective_size > 0:
        telethon.client.messages._MAX_CHUNK_SIZE = effective_size

    def construct_client():
        return TelegramClient(
            session=telegram_session,
            api_id=telegram_api_id,
            api_hash=telegram_api_hash,
            loop=loop,
            flood_sleep_threshold=65500,
            request_retries=50,
            connection_retries=None,
            entity_cache_limit=int(os.getenv("TELETHON_ENTITY_CACHE_LIMIT", "5000")),
            use_ipv6=bool(strtobool(os.getenv("USE_IPV6", "0"))),
        )

    telegram_session = alchemy_telegram_container.new_session(session_id)
    client = construct_client()
    logger.info("Connecting Telegram Client")
    try:
        await client.connect()
    except AuthKeyDuplicatedError:
        logger.error(
            "AuthKeyDuplicatedError, disconnecting telegram client and re-creating session!",
            exc_info=True,
        )
        telegram_session.delete()
        telegram_session = alchemy_telegram_container.new_session(session_id)
        client = construct_client()
        logger.info("Connecting Telegram Client again")
        await client.connect()
    logger.info("Telegram Client Connected!")
    return client


def add_signal_handlers(loop: asyncio.AbstractEventLoop, closer: Callable):
    for signame in {"SIGINT", "SIGTERM"}:
        loop.add_signal_handler(
            getattr(signal, signame),
            functools.partial(ask_exit, signame, loop, closer),
        )


async def configure_bot(
    alchemy_telegram_container,
    telegram_api_id,
    telegram_api_hash,
    target_chat,
    session_id,
):
    logger.info("Configuring Bot")
    telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    configured_notify_message_deletion = None
    configured_notify_unknown_message = None
    bot = None
    if telegram_bot_token is not None:
        if target_chat is None or target_chat == "me":
            logger.critical(
                'Must provide TARGET_CHAT (except "me") if you want to use bot assistant!'
            )
            os._exit(1)
        logger.info("Using bot for message notification")
        bot = BotAssistant(
            int(target_chat)
            if bool(strtobool(os.getenv("TARGET_CHAT_IS_ID", "0")))
            else target_chat,
            telegram_api_id,
            telegram_api_hash,
            telegram_bot_token,
            session_maker=lambda: alchemy_telegram_container.new_session(
                session_id + "_bot"
            ),
        )
        await bot.__aenter__()
        configured_notify_message_deletion = bot.notify_message_deletion
        configured_notify_unknown_message = bot.notify_unknown_message
        configured_notify_message_edit = bot.notify_message_edit
    logger.info("Configured Bot")
    return (
        configured_notify_message_deletion,
        configured_notify_unknown_message,
        configured_notify_message_edit,
        bot,
    )


async def client_main_loop_job(
    stop_event: asyncio.Event,
    started_event: asyncio.Event,
    sqlalchemy_session_maker,
    configured_notify_message_deletion,
    configured_notify_unknown_message,
    configured_notify_message_edit,
    client: TelegramClient,
    gather_with_concurrency_func: Callable,
):
    if not configured_notify_message_deletion:
        configured_notify_message_deletion = get_default_notify_message_deletion()
    if not configured_notify_unknown_message:
        configured_notify_unknown_message = get_default_notify_unknown_message()
    if not configured_notify_message_edit:
        configured_notify_message_edit = get_default_notify_message_edit()
    base_notify_message_deletion = get_base_notify_message_deletion(
        sqlalchemy_session_maker=sqlalchemy_session_maker
    )
    base_notify_message_edit = get_base_notify_message_edit(
        sqlalchemy_session_maker=sqlalchemy_session_maker
    )

    async def actual_notify_message_deletion(
        message: TelegramMessage, client: TelegramClient
    ):
        await base_notify_message_deletion(message, client)
        await configured_notify_message_deletion(message, client)

    async def actual_notify_message_edit(
        message: TelegramMessage, client: TelegramClient
    ):
        await base_notify_message_edit(message, client)
        await configured_notify_message_edit(message, client)

    add_event_handlers_task = asyncio.create_task(
        add_event_handlers(
            client,
            sqlalchemy_session_maker,
            actual_notify_message_deletion,
            configured_notify_unknown_message,
            actual_notify_message_edit,
            gather_with_concurrency_func,
        )
    )
    preload_messages_task = asyncio.create_task(
        preload_messages(client, sqlalchemy_session_maker)
    )
    old_messages_clean_loop_task = asyncio.create_task(
        clean_old_messages_loop(
            sqlalchemy_session_maker=sqlalchemy_session_maker,
            seconds_interval=int(os.getenv("CLEAN_OLD_MESSAGES_SECONDS_INTERVAL", 900)),
            ttl=messages_ttl_delta,
            stop_event=stop_event,
        )
    )
    scheduled_restart_task = asyncio.create_task(
        scheduled_restart_loop(
            cron_expression=get_restart_cron_from_env(),
            stop_event=stop_event,
        )
    )
    inactivity_restart_task = asyncio.create_task(
        inactivity_restart_loop(
            inactivity_threshold_hours=get_inactivity_hours_from_env(),
            stop_event=stop_event,
        )
    )
    stop_event_task = asyncio.create_task(stop_event.wait())

    def on_stop(fut):
        add_event_handlers_task.cancel()
        preload_messages_task.cancel()
        old_messages_clean_loop_task.cancel()
        scheduled_restart_task.cancel()
        inactivity_restart_task.cancel()

    stop_event_task.add_done_callback(on_stop)
    await asyncio.gather(add_event_handlers_task, preload_messages_task)
    started_event.set()
    await old_messages_clean_loop_task
    await scheduled_restart_task
    await inactivity_restart_task
    await stop_event_task


class Closer:
    def __init__(self):
        self.called = False
        self.stop_event: asyncio.Event | None = None
        self.started_event: asyncio.Event | None = None
        self.client: TelegramClient | None = None
        self.bot: BotAssistant | None = None

    async def __call__(self):
        close_coros = []
        logger.info("Inside closer()")
        if self.called:
            logger.info("Closer re-entry detected, ignoring")
            return
        self.called = True
        if self.stop_event is not None:
            logger.info("Setting stop event flag")
            self.stop_event.set()
        if self.client is not None:
            logger.info("Disconnecting Client")
            disconnecter_coro = self.client.disconnect()
            if disconnecter_coro is not None:
                close_coros.append(disconnecter_coro)
            self.client = None
        if self.bot is not None:
            logger.info("Disconnecting Bot")
            close_coros.append(self.bot.__aexit__(None, None, None))
        try:
            await asyncio.gather(*close_coros)
        except Exception:
            logger.critical("Error while running closer coroutines!", exc_info=True)
            os._exit(1)


def make_sync_closer(closer: Closer, loop: asyncio.AbstractEventLoop):
    def sync_closer():
        ask_exit(None, loop, closer)

    return sync_closer


def worker_function(
    loop: asyncio.AbstractEventLoop,
    closer: Closer,
    sync_closer: Callable,
):
    logger.info("Entering worker function!")
    try:
        asyncio.set_event_loop(loop)
        closer.stop_event = asyncio.Event()
        closer.started_event = asyncio.Event()
        loop.run_forever()
    except Exception as e:
        logger.critical(f"Error on worker function! {e}", exc_info=True)
        sync_closer()
        os._exit(1)
    finally:
        logger.info("Exiting worker function!")
    os._exit(0)


def create_app_and_start_jobs() -> tuple:
    from packages.background_jobs import gather_with_concurrency

    loop: asyncio.AbstractEventLoop = asyncio.events.new_event_loop()
    import nest_asyncio

    nest_asyncio.apply(loop)

    closer = Closer()

    sync_closer = make_sync_closer(closer, loop)

    add_signal_handlers(loop, closer)

    from sqlalchemy.orm import sessionmaker

    from packages.db_bootstrap import create_engine
    from packages.db_helpers import create_database, get_db_url
    from packages.env_helpers import require_env
    from packages.models import Base

    database_url = get_db_url()

    sqlalchemy_engine = create_engine(database_url)
    sqlalchemy_session_maker = sessionmaker(
        bind=sqlalchemy_engine, expire_on_commit=False
    )
    alchemy_telegram_container = AlchemySessionContainer(
        engine=sqlalchemy_engine,
        table_base=Base,
        manage_tables=False,
        table_prefix=os.getenv("SESSION_TABLE_PREFIX", "thon_"),
    )
    alchemy_telegram_container.core_mode = True

    create_database(sqlalchemy_engine)

    telegram_api_id = require_env("TELEGRAM_API_ID")
    telegram_api_hash = require_env("TELEGRAM_API_HASH")

    target_chat = os.getenv("TARGET_CHAT", "me")

    session_id = require_env("SESSION_ID")

    (
        configured_notify_message_deletion,
        configured_notify_unknown_message,
        configured_notify_message_edit,
        bot,
    ) = loop.run_until_complete(
        configure_bot(
            alchemy_telegram_container,
            telegram_api_id,
            telegram_api_hash,
            target_chat,
            session_id,
        )
    )
    closer.bot = bot

    client = loop.run_until_complete(
        make_client(
            alchemy_telegram_container,
            telegram_api_id,
            telegram_api_hash,
            session_id,
            loop,
        )
    )
    closer.client = client

    worker_thread = threading.Thread(
        target=worker_function,
        args=(loop, closer, sync_closer),
        name="loop-app-client-bgthread",
    )
    worker_thread.start()

    while (
        closer.stop_event is None or closer.started_event is None
    ) and worker_thread.is_alive():
        time.sleep(0)

    if closer.stop_event is None or closer.started_event is None:
        raise RuntimeError(
            "Worker thread died before setting stop_event and start_event!"
        )

    main_loop_job_future = asyncio.run_coroutine_threadsafe(
        client_main_loop_job(
            closer.stop_event,
            closer.started_event,
            sqlalchemy_session_maker,
            configured_notify_message_deletion,
            configured_notify_unknown_message,
            None,
            client,
            gather_with_concurrency,
        ),
        loop,
    )

    def handle_main_loop_job_future_end(main_inner_future: concurrent.futures.Future):
        try:
            main_inner_future.result()
        except Exception as e:
            if closer.stop_event is not None and closer.stop_event.is_set():
                return
            logger.error(f"Error while running main job: {e}", exc_info=True)
            sync_closer()
            os._exit(1)
        else:
            logger.info("Main job loop finished, calling sync closer")
            sync_closer()

    main_loop_job_future.add_done_callback(handle_main_loop_job_future_end)

    from packages.http import create_app

    flask_app = create_app(client, bot, loop, sqlalchemy_session_maker, sync_closer)

    logger.info("Returning from create_app_and_start_jobs")
    return (flask_app, sync_closer)

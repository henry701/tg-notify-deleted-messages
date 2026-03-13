# -*- coding: utf-8 -*-

import asyncio
import functools
import logging
import os
import signal
from typing import Callable, Union

from tenacity import retry, retry_if_exception_type, stop_after_attempt

import telethon
from alchemysession import AlchemySessionContainer
from telethon import TelegramClient
from telethon.errors.rpcerrorlist import AuthKeyDuplicatedError

from distutils.util import strtobool

from packages.bot_assistant import BotAssistant

logger = logging.getLogger("tgdel-bootstrap")

is_exiting = False


def ask_exit(
    signame: Union[str, None],
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
    if additional:
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
        logger.warning(
            "[exit] Cancelling all remaining {tasklen} asyncio tasks!".format(
                tasklen=tasklen
            )
        )
        for task in all_tasks:
            task.cancel()
        logger.warning(
            "[exit] Cancelled all remaining {tasklen} asyncio tasks!".format(
                tasklen=tasklen
            )
        )
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
    override_max_chunk_size = int(os.getenv("TELETHON_OVERRIDE_MAX_CHUNK_SIZE", "-1"))
    if override_max_chunk_size > 0:
        telethon.client.messages._MAX_CHUNK_SIZE = override_max_chunk_size

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
    logger.info("Configured Bot")
    return configured_notify_message_deletion, configured_notify_unknown_message, bot

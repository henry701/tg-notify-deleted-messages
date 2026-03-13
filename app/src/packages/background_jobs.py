# -*- coding: utf-8 -*-
"""Background job loops for message preloading and cleanup."""

import asyncio
import contextlib
import logging
import os

from datetime import datetime, timedelta, timezone
from distutils.util import strtobool

import telethon
from telethon import TelegramClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.expression import delete

from packages.event_orchestration import (
    get_should_ignore_message_chat,
    get_store_message_if_not_exists,
)
from packages.models.root.TelegramMessage import TelegramMessage

logger = logging.getLogger("tgdel-background-jobs")

messages_ttl_delta = timedelta(days=int(os.getenv("MESSAGES_TTL_DAYS", 14)))


async def clean_old_messages_loop(
    sqlalchemy_session_maker: sessionmaker,
    seconds_interval: int,
    ttl: timedelta,
    stop_event: asyncio.Event,
):
    logger.info("Starting Clean Old Messages Loop")
    try:
        while True:
            try:
                delete_from_time = datetime.now(tz=timezone.utc) - ttl
                with sqlalchemy_session_maker.begin() as sqlalchemy_session:
                    res = sqlalchemy_session.execute(
                        delete(TelegramMessage).where(
                            TelegramMessage.timestamp < delete_from_time
                        )
                    )
                count = res.rowcount
                logger.info(
                    f"Deleted {str(count)} messages older than {str(delete_from_time)} from DB. Sleeping for {seconds_interval} seconds..."
                )
            except Exception as e:
                logger.critical(
                    "Error on Clean Old Messages Inner Loop Handler! {e}".format(e=e)
                )
            finally:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop_event.wait(), seconds_interval)
            if stop_event.is_set():
                logger.info(
                    "Stop event is set, breaking from Clean Old Messages Inner Loop!"
                )
                break
    except Exception as e:
        logger.critical(
            "Error on Clean Old Messages Outer Loop Handler! {e}".format(e=e)
        )
    finally:
        logger.info("Exiting Clean Old Messages Loop")


async def preload_messages(
    client: TelegramClient, sqlalchemy_session_maker: sessionmaker
):
    if not bool(strtobool(os.getenv("PRELOAD_MESSAGES", "0"))):
        logger.info("PRELOAD_MESSAGES is disabled, skipping preloading messages")
        return

    if not client.is_connected or not await client.is_user_authorized():
        logger.info("No client connected and authorized, skipping preloading messages")
        return

    min_message_date = datetime.now(tz=timezone.utc) - messages_ttl_delta
    logger.info(
        "Preloading existing messages from {min_message_date}".format(
            min_message_date=min_message_date
        )
    )

    iterated_messages = 0
    preloaded_messages = 0

    preload_status_report_interval = int(
        os.getenv("PRELOAD_MESSAGES_STATUS_REPORT_INTERVAL", "60")
    )

    async def preload_messages_status_loop():
        if preload_status_report_interval <= 0:
            return
        while True:
            try:
                await asyncio.sleep(preload_status_report_interval)
            except asyncio.CancelledError:
                return
            logger.info(
                "Preloading still in progress. Total so far: {preloaded_messages} preloaded, {iterated_messages} iterated".format(
                    preloaded_messages=preloaded_messages,
                    iterated_messages=iterated_messages,
                )
            )

    preload_messages_status_task = asyncio.create_task(preload_messages_status_loop())

    store_message_if_not_exists = get_store_message_if_not_exists(
        client, sqlalchemy_session_maker
    )
    should_ignore_message_chat = get_should_ignore_message_chat(client)

    async def preload_messages_for_dialog(dialog):
        logger.debug(
            "Preloading existing messages for dialog={dialog}".format(dialog=dialog.id)
        )

        peer = dialog.input_entity
        full_peer = await client.get_entity(peer)

        if await should_ignore_message_chat(full_peer):
            logger.debug(
                "Preloading ignoring filtered dialog={dialog}".format(dialog=dialog.id)
            )
            return

        iterated_messages_this_dialog = 0
        preloaded_messages_this_dialog = 0

        message: telethon.types.Message = None
        messages: telethon.hints.TotalList[
            telethon.types.Message
        ] = await client.get_messages(
            full_peer, limit=telethon.client.messages._MAX_CHUNK_SIZE
        )

        while True:
            if messages is None or len(messages) < 1:
                break
            last_message = None
            for message in messages:
                if message is None or isinstance(message, telethon.types.MessageEmpty):
                    break
                if message.date is None or message.date < min_message_date:
                    break
                last_message = message
                nonlocal iterated_messages
                nonlocal preloaded_messages
                iterated_messages = iterated_messages + 1
                iterated_messages_this_dialog = iterated_messages_this_dialog + 1
                # Already checked chat for ignore, don't re-check ignore logic.
                message_result = await store_message_if_not_exists(message, False)
                if message_result is not False:
                    preloaded_messages = preloaded_messages + 1
                    preloaded_messages_this_dialog = preloaded_messages_this_dialog + 1
                # Yield
                await asyncio.sleep(0)
            if not last_message:
                break
            messages = await client.get_messages(
                full_peer,
                limit=telethon.client.messages._MAX_CHUNK_SIZE,
                offset_id=message.id,
            )
            # Yield
            await asyncio.sleep(0)

        logger.debug(
            "Preloaded {preloaded_messages_this_dialog} existing messages for dialog={dialog}".format(
                dialog=dialog.id,
                preloaded_messages_this_dialog=preloaded_messages_this_dialog,
            )
        )

    dialog_coros = []
    dialog: telethon.tl.custom.dialog.Dialog = None
    async for dialog in client.iter_dialogs():
        dialog_coros.append(preload_messages_for_dialog(dialog))
    if len(dialog_coros) > 0:
        await gather_with_concurrency(
            int(os.getenv("PRELOAD_MESSAGES_DIALOG_CONCURRENCY", "8")), *dialog_coros
        )

    preload_messages_status_task.cancel()
    logger.info(
        "Preloading finished! Existing message preloaded count: {preloaded_messages}. Total messages iterated: {iterated_messages}".format(
            preloaded_messages=preloaded_messages, iterated_messages=iterated_messages
        )
    )


async def gather_with_concurrency(n, *coros):
    semaphore = asyncio.Semaphore(n)

    async def sem_coro(coro):
        async with semaphore:
            return await coro

    return await asyncio.gather(*(sem_coro(c) for c in coros))

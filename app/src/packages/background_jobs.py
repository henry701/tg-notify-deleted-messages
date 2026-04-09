"""Background job loops for message preloading and cleanup."""

import asyncio
import contextlib
import logging
import os
from datetime import datetime, timedelta, timezone
from distutils.util import strtobool

import telethon
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.expression import delete
from telethon import TelegramClient

from packages.event_orchestration import (
    get_should_ignore_message_chat,
    get_store_message_if_not_exists,
)
from packages.models.root.TelegramMessage import TelegramMessage
from packages.preload_checkpoints import (
    get_preload_checkpoint,
    upsert_preload_checkpoint,
)
from packages.telegram_helpers import build_telegram_peer

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
                logger.critical(f"Error on Clean Old Messages Inner Loop Handler! {e}")
            finally:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop_event.wait(), seconds_interval)
            if stop_event.is_set():
                logger.info(
                    "Stop event is set, breaking from Clean Old Messages Inner Loop!"
                )
                break
    except Exception as e:
        logger.critical(f"Error on Clean Old Messages Outer Loop Handler! {e}")
    finally:
        logger.info("Exiting Clean Old Messages Loop")


async def preload_messages(
    client: TelegramClient, sqlalchemy_session_maker: sessionmaker
):
    if not bool(strtobool(os.getenv("PRELOAD_MESSAGES", "0"))):
        logger.info("PRELOAD_MESSAGES is disabled, skipping preloading messages")
        return

    if not client.is_connected() or not await client.is_user_authorized():
        logger.info("No client connected and authorized, skipping preloading messages")
        return

    logger.info("Preloading existing messages")

    iterated_messages = 0
    preloaded_messages = 0
    checkpoints_enabled = bool(strtobool(os.getenv("PRELOAD_CHECKPOINTS_ENABLED", "1")))
    checkpoint_update_every_messages = int(
        os.getenv("PRELOAD_CHECKPOINT_UPDATE_EVERY_MESSAGES", "100")
    )

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
                f"Preloading still in progress. Total so far: {preloaded_messages} preloaded, {iterated_messages} iterated"
            )

    preload_messages_status_task = asyncio.create_task(preload_messages_status_loop())

    store_message_if_not_exists = get_store_message_if_not_exists(
        client, sqlalchemy_session_maker
    )
    should_ignore_message_chat = get_should_ignore_message_chat(client)

    async def preload_messages_for_dialog(dialog):
        logger.debug(f"Preloading existing messages for dialog={dialog.id}")

        peer = dialog.input_entity
        full_peer = await client.get_entity(peer)

        if await should_ignore_message_chat(full_peer):
            logger.debug(f"Preloading ignoring filtered dialog={dialog.id}")
            return

        dialog_scan_started_at = datetime.now(tz=timezone.utc)
        min_message_date = dialog_scan_started_at - messages_ttl_delta
        iterated_messages_this_dialog = 0
        preloaded_messages_this_dialog = 0
        dialog_chat_peer = None
        checkpoint = None
        checkpoint_kwargs: dict = {"reverse": True}
        last_processed_message_id = None
        last_processed_message_timestamp = None
        uncheckpointed_messages = 0
        resumed_from_valid_checkpoint_id = False

        if checkpoints_enabled:
            dialog_chat_peer = await build_telegram_peer(
                full_peer, client, sqlalchemy_session_maker
            )
            if dialog_chat_peer is not None:
                checkpoint = get_preload_checkpoint(
                    int(dialog_chat_peer.id), sqlalchemy_session_maker
                )
            if (
                checkpoint is not None
                and checkpoint.preloaded_through_timestamp >= min_message_date
            ):
                if checkpoint.preloaded_through_message_id is not None:
                    resumed_from_valid_checkpoint_id = True
                    checkpoint_kwargs["min_id"] = int(
                        str(checkpoint.preloaded_through_message_id)
                    )
                else:
                    checkpoint_kwargs["offset_date"] = (
                        checkpoint.preloaded_through_timestamp
                    )
            else:
                checkpoint_kwargs["offset_date"] = min_message_date
        else:
            checkpoint_kwargs["offset_date"] = min_message_date

        async for message in client.iter_messages(full_peer, **checkpoint_kwargs):
            if message is None or isinstance(message, telethon.types.MessageEmpty):
                continue
            if message.date is None or message.date < min_message_date:
                continue
            last_processed_message_id = int(message.id)
            last_processed_message_timestamp = message.date
            nonlocal iterated_messages
            nonlocal preloaded_messages
            iterated_messages = iterated_messages + 1
            iterated_messages_this_dialog = iterated_messages_this_dialog + 1
            # Already checked chat for ignore, don't re-check ignore logic.
            message_result = await store_message_if_not_exists(message, False)
            if message_result is not False:
                preloaded_messages = preloaded_messages + 1
                preloaded_messages_this_dialog = preloaded_messages_this_dialog + 1
            if (
                checkpoints_enabled
                and dialog_chat_peer is not None
                and checkpoint_update_every_messages > 0
                and last_processed_message_timestamp is not None
            ):
                uncheckpointed_messages = uncheckpointed_messages + 1
                if uncheckpointed_messages >= checkpoint_update_every_messages:
                    upsert_preload_checkpoint(
                        chat_peer_id=int(dialog_chat_peer.id),
                        preloaded_through_message_id=last_processed_message_id,
                        preloaded_through_timestamp=last_processed_message_timestamp,
                        sqlalchemy_session_maker=sqlalchemy_session_maker,
                    )
                    uncheckpointed_messages = 0
            await asyncio.sleep(0)

        if checkpoints_enabled and dialog_chat_peer is not None:
            completion_message_id = last_processed_message_id
            completion_timestamp = dialog_scan_started_at
            if (
                completion_message_id is None
                and checkpoint is not None
                and resumed_from_valid_checkpoint_id
            ):
                if checkpoint.preloaded_through_message_id is not None:
                    completion_message_id = int(
                        str(checkpoint.preloaded_through_message_id)
                    )
            if (
                last_processed_message_timestamp is not None
                and last_processed_message_timestamp > completion_timestamp
            ):
                completion_timestamp = last_processed_message_timestamp
            upsert_preload_checkpoint(
                chat_peer_id=int(dialog_chat_peer.id),
                preloaded_through_message_id=completion_message_id,
                preloaded_through_timestamp=completion_timestamp,
                sqlalchemy_session_maker=sqlalchemy_session_maker,
            )

        logger.debug(
            f"Preloaded {preloaded_messages_this_dialog} existing messages for dialog={dialog.id}"
        )

    try:
        dialog_coros = []
        dialog: telethon.tl.custom.dialog.Dialog = None
        async for dialog in client.iter_dialogs():
            dialog_coros.append(preload_messages_for_dialog(dialog))
        if len(dialog_coros) > 0:
            await gather_with_concurrency(
                int(os.getenv("PRELOAD_MESSAGES_DIALOG_CONCURRENCY", "8")),
                *dialog_coros,
            )
        logger.info(
            f"Preloading finished! Existing message preloaded count: {preloaded_messages}. Total messages iterated: {iterated_messages}"
        )
    finally:
        preload_messages_status_task.cancel()


async def gather_with_concurrency(n, *coros):
    semaphore = asyncio.Semaphore(n)

    async def sem_coro(coro):
        async with semaphore:
            return await coro

    return await asyncio.gather(*(sem_coro(c) for c in coros))

"""Event handlers and message storage orchestration."""

import asyncio
import logging
import os
from collections.abc import Awaitable, Callable
from distutils.util import strtobool
from typing import Any

import sqlalchemy
import sqlalchemy.exc
import telethon
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.selectable import Select
from telethon import TelegramClient, events
from telethon.events import MessageDeleted, MessageEdited, NewMessage
from tenacity import retry, retry_if_exception_type, stop_after_attempt

from packages.filtering import raw_should_ignore_message_chat
from packages.message_loading import load_messages_by_parameters, load_messages_from_db
from packages.models.root.TelegramMessage import TelegramMessage
from packages.telegram_helpers import build_telegram_peer

logger = logging.getLogger("tgdel-event-orchestration")

download_semaphore = asyncio.Semaphore(
    int(os.getenv("MEDIA_DOWNLOADS_CONCURRENCY", "1"))
)
file_size_threshold = int(os.getenv("MEDIA_FILE_SIZE_THRESHOLD", "0"))


async def load_messages_from_deleted_event(
    event: MessageDeleted.Event,
    client: TelegramClient,
    sqlalchemy_session: Session,
    ignore_channels: bool,
    ignore_groups: bool,
    ignore_megagroups: bool,
    ignore_gigagroups: bool,
    member_ignore_threshold: int,
    should_notify_outgoing_messages: bool,
) -> tuple[list[TelegramMessage], Select | None, list[int], list[int]]:
    logger.debug(f"Searching for messages in {event.deleted_ids}")

    chat = None
    try:
        input_chat = await event.get_input_chat()
        chat = await client.get_entity(input_chat) if input_chat else None
    except ValueError:
        pass

    return await load_messages_by_parameters(
        event.deleted_ids,
        chat,
        client,
        sqlalchemy_session,
        ignore_channels,
        ignore_groups,
        ignore_megagroups,
        ignore_gigagroups,
        member_ignore_threshold,
        should_notify_outgoing_messages,
    )


def get_on_message_deleted(
    client: TelegramClient,
    sqlalchemy_session_maker: sessionmaker,
    notify_message_deletion: Callable[
        [TelegramMessage, TelegramClient], Awaitable[Any]
    ],
    notify_unknown_message: Callable[
        [list[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]
    ],
    gather_with_concurrency_func: Callable,
):
    ignore_channels = bool(strtobool(os.getenv("IGNORE_CHANNELS", "0")))
    ignore_groups = bool(strtobool(os.getenv("IGNORE_GROUPS", "0")))
    ignore_megagroups = bool(strtobool(os.getenv("IGNORE_MEGAGROUPS", "0")))
    ignore_gigagroups = bool(strtobool(os.getenv("IGNORE_GIGAGROUPS", "0")))
    member_ignore_threshold = int(os.getenv("MEMBER_IGNORE_THRESHOLD", "0"))
    should_notify_outgoing_messages = bool(
        strtobool(os.getenv("NOTIFY_OUTGOING_MESSAGES", "True"))
    )
    deleted_messages_notification_concurrency = int(
        os.getenv("DELETED_MESSAGES_NOTIFICATION_CONCURRENCY", "1")
    )

    @retry(
        retry=retry_if_exception_type((IOError, sqlalchemy.exc.DBAPIError)),
        stop=stop_after_attempt(3),
    )
    async def on_message_deleted(event: MessageDeleted.Event):
        deleted_messages_count = len(event.deleted_ids)

        if deleted_messages_count == 0:
            logger.debug("Got empty deleted message event. Returning early!")
            return

        with sqlalchemy_session_maker.begin() as sqlalchemy_session:
            (
                messages,
                query,
                unloaded_ids,
                filtered_away_ids,
            ) = await load_messages_from_deleted_event(
                event,
                client,
                sqlalchemy_session,
                ignore_channels,
                ignore_groups,
                ignore_megagroups,
                ignore_gigagroups,
                member_ignore_threshold,
                should_notify_outgoing_messages,
            )

        deleted_messages_count_str = str(deleted_messages_count)

        db_messages_count = len(messages)
        db_messages_count_str = str(db_messages_count)

        filtered_away_messages_count = len(filtered_away_ids)
        filtered_away_messages_count_str = str(filtered_away_messages_count)

        logger.info(
            f"Got {deleted_messages_count_str} deleted messages. Has matching in DB: {db_messages_count_str}. Filtered away: {filtered_away_messages_count_str}"
        )

        if deleted_messages_count > db_messages_count + filtered_away_messages_count:
            try:
                logger.warning(
                    "Got {deleted_messages_count} deleted messages but only found {db_messages_count} (with {filtered_away_messages_count} filtered away) matching in database! Query: {query_str}".format(
                        deleted_messages_count=deleted_messages_count_str,
                        db_messages_count=db_messages_count_str,
                        filtered_away_messages_count=filtered_away_messages_count_str,
                        query_str=str(
                            query.compile(compile_kwargs={"literal_binds": True})
                        )
                        if query
                        else "(no query)",
                    )
                )
            except Exception as e:
                logger.error(
                    f"Error while logging missing deleted message (has {db_messages_count_str} of {deleted_messages_count_str}, with {filtered_away_messages_count_str} filtered away): {e}",
                    exc_info=True,
                )

        awaitables: list[Awaitable[Any]] = []
        for message in messages:
            awaitables.append(notify_message_deletion(message, client))
        if unloaded_ids and len(unloaded_ids):
            awaitables.append(notify_unknown_message(unloaded_ids, event, client))
        if len(awaitables) > 0:
            await gather_with_concurrency_func(
                deleted_messages_notification_concurrency, *awaitables
            )

    return on_message_deleted


def get_on_new_message(sqlalchemy_session_maker: sessionmaker, client: TelegramClient):
    store_message_if_not_exists = get_store_message_if_not_exists(
        client, sqlalchemy_session_maker
    )

    @retry(
        retry=retry_if_exception_type((IOError, sqlalchemy.exc.DBAPIError)),
        stop=stop_after_attempt(3),
    )
    async def on_new_message(event: NewMessage.Event):
        effective_level = logger.getEffectiveLevel()
        if effective_level <= 5:
            logger.log(5, f"on_new_message: {event}")
        else:
            logger.debug("in on_new_message")
        message: telethon.tl.custom.message.Message = event.message
        await store_message_if_not_exists(message)

    return on_new_message


def get_on_message_edited(
    client: TelegramClient,
    sqlalchemy_session_maker: sessionmaker,
    notify_message_edit: Callable[[TelegramMessage, TelegramClient], Awaitable[Any]],
    gather_with_concurrency_func: Callable,
):
    ignore_channels = bool(strtobool(os.getenv("IGNORE_CHANNELS", "0")))
    ignore_groups = bool(strtobool(os.getenv("IGNORE_GROUPS", "0")))
    ignore_megagroups = bool(strtobool(os.getenv("IGNORE_MEGAGROUPS", "0")))
    ignore_gigagroups = bool(strtobool(os.getenv("IGNORE_GIGAGROUPS", "0")))
    member_ignore_threshold = int(os.getenv("MEMBER_IGNORE_THRESHOLD", "0"))
    should_notify_outgoing_messages = bool(
        strtobool(os.getenv("NOTIFY_OUTGOING_MESSAGES", "True"))
    )
    edited_messages_notification_concurrency = int(
        os.getenv("EDITED_MESSAGES_NOTIFICATION_CONCURRENCY", "1")
    )

    @retry(
        retry=retry_if_exception_type((IOError, sqlalchemy.exc.DBAPIError)),
        stop=stop_after_attempt(3),
    )
    async def on_message_edited(event: MessageEdited.Event):
        edited_messages_count = 1  # MessageEdited events only contain one message

        if edited_messages_count == 0:
            logger.debug("Got empty edited message event. Returning early!")
            return

        # Try to get the chat from the event
        chat = None
        try:
            input_chat = await event.get_input_chat()
            chat = await client.get_entity(input_chat) if input_chat else None
        except ValueError:
            pass

        # Load the message from database with the current version
        with sqlalchemy_session_maker.begin() as sqlalchemy_session:
            (
                messages,
                query,
                unloaded_ids,
                filtered_away_ids,
            ) = await load_messages_by_parameters(
                [event.message_id],
                chat,
                client,
                sqlalchemy_session,
                ignore_channels,
                ignore_groups,
                ignore_megagroups,
                ignore_gigagroups,
                member_ignore_threshold,
                should_notify_outgoing_messages,
            )

        edited_messages_count_str = str(edited_messages_count)
        db_messages_count = len(messages)
        db_messages_count_str = str(db_messages_count)
        filtered_away_messages_count = len(filtered_away_ids)
        filtered_away_messages_count_str = str(filtered_away_messages_count)

        logger.info(
            f"Got {edited_messages_count_str} edited message. Has matching in DB: {db_messages_count_str}. Filtered away: {filtered_away_messages_count_str}"
        )

        if edited_messages_count > db_messages_count + filtered_away_messages_count:
            try:
                logger.warning(
                    "Got {edited_messages_count} edited messages but only found {db_messages_count} (with {filtered_away_messages_count} filtered away) matching in database! Query: {query_str}".format(
                        edited_messages_count=edited_messages_count_str,
                        db_messages_count=db_messages_count_str,
                        filtered_away_messages_count=filtered_away_messages_count_str,
                        query_str=str(
                            query.compile(compile_kwargs={"literal_binds": True})
                        )
                        if query
                        else "(no query)",
                    )
                )
            except Exception as e:
                logger.error(
                    f"Error while logging missing edited message (has {db_messages_count_str} of {edited_messages_count_str}, with {filtered_away_messages_count_str} filtered away): {e}",
                    exc_info=True,
                )

        awaitables: list[Awaitable[Any]] = []
        for message in messages:
            awaitables.append(notify_message_edit(message, client))
        if unloaded_ids and len(unloaded_ids):
            # For edited messages, we might want to notify about unloaded messages differently
            # For now, we'll skip notification for unloaded edited messages
            pass
        if len(awaitables) > 0:
            await gather_with_concurrency_func(
                edited_messages_notification_concurrency, *awaitables
            )

    return on_message_edited


def get_should_ignore_message(client: TelegramClient):
    should_ignore_message_chat = get_should_ignore_message_chat(client)

    async def should_ignore_message(
        message: telethon.tl.custom.message.Message, check_chat: bool = True
    ) -> bool:
        if not check_chat:
            return False
        return await should_ignore_message_chat(await message.get_chat())

    return should_ignore_message


def get_should_ignore_message_chat(client: TelegramClient):
    ignore_channels = bool(strtobool(os.getenv("IGNORE_CHANNELS", "0")))
    ignore_groups = bool(strtobool(os.getenv("IGNORE_GROUPS", "0")))
    ignore_megagroups = bool(strtobool(os.getenv("IGNORE_MEGAGROUPS", "0")))
    ignore_gigagroups = bool(strtobool(os.getenv("IGNORE_GIGAGROUPS", "0")))
    member_ignore_threshold = int(os.getenv("MEMBER_IGNORE_THRESHOLD", "0"))

    async def should_ignore_message_chat(
        chat: telethon.types.User | telethon.types.Chat | telethon.types.Channel | None,
    ) -> bool:
        return await raw_should_ignore_message_chat(
            chat,
            client,
            ignore_channels,
            ignore_groups,
            ignore_megagroups,
            ignore_gigagroups,
            member_ignore_threshold,
        )

    return should_ignore_message_chat


@retry(retry=retry_if_exception_type(IOError), stop=stop_after_attempt(3))
async def get_message_media_blob(message: telethon.tl.custom.message.Message):
    if (
        not message
        or not message.media
        or not message.file
        or not message.file.size
        or (file_size_threshold > 0 and message.file.size > file_size_threshold)
    ):
        return None
    async with download_semaphore:
        logger.info("Downloading file with %s bytes size", message.file.size)
        return await message.download_media(file=bytes)


def get_store_message(sqlalchemy_session_maker: sessionmaker, client: TelegramClient):
    should_ignore_message = get_should_ignore_message(client)

    @retry(
        retry=retry_if_exception_type((IOError, sqlalchemy.exc.DBAPIError)),
        stop=stop_after_attempt(3),
    )
    async def store_message(
        message: telethon.tl.custom.message.Message, check_chat: bool = True
    ):
        should_ignore: bool = await should_ignore_message(message, check_chat)
        if should_ignore:
            return False
        built_from_peer = await build_telegram_peer(
            message.from_id, client, sqlalchemy_session_maker
        )
        built_chat_peer = await build_telegram_peer(
            message.peer_id, client, sqlalchemy_session_maker
        )
        blob = await get_message_media_blob(message)
        built_chat_peer_id = getattr(built_chat_peer, "id", None)
        with sqlalchemy_session_maker.begin() as sqlalchemy_session:
            existing = None
            if built_chat_peer_id is not None:
                existing = (
                    sqlalchemy_session.query(TelegramMessage)
                    .filter(
                        TelegramMessage.id == message.id,
                        TelegramMessage.chat_peer_id == built_chat_peer_id,
                    )
                    .first()
                )

            if existing:
                existing.text = message.message
                existing.media = blob
                existing.timestamp = message.date
                existing.edit_date = message.date
                orm_message = existing
            else:
                orm_message = TelegramMessage(
                    id=message.id,
                    from_peer=built_from_peer,
                    chat_peer=built_chat_peer,
                    text=message.message,
                    media=blob,
                    timestamp=message.date,
                    edit_date=None,
                )
            sqlalchemy_session.merge(orm_message)
        return True

    return store_message


def get_store_message_if_not_exists(
    client: TelegramClient, sqlalchemy_session_maker: sessionmaker
):
    store_message = get_store_message(sqlalchemy_session_maker, client)
    should_ignore_message = get_should_ignore_message(client)

    @retry(
        retry=retry_if_exception_type((IOError, sqlalchemy.exc.DBAPIError)),
        stop=stop_after_attempt(3),
    )
    async def store_message_if_not_exists(
        message: telethon.tl.custom.message.Message, check_chat: bool = True
    ):
        if await should_ignore_message(message, check_chat):
            return False
        peer_entity = await message.get_chat()
        with sqlalchemy_session_maker.begin() as sqlalchemy_session:
            (the_query, messages, unloaded_ids) = await load_messages_from_db(
                [message.id],
                peer_entity,
                sqlalchemy_session,
            )
            # Message already exists, ignore
            if len(messages) > 0:
                return False
        return await store_message(message)

    return store_message_if_not_exists


async def add_event_handlers(
    client: TelegramClient,
    sqlalchemy_session_maker: sessionmaker,
    notify_message_deletion: Callable[
        [TelegramMessage, TelegramClient], Awaitable[Any]
    ],
    notify_unknown_message: Callable[
        [list[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]
    ],
    notify_message_edit: Callable[[TelegramMessage, TelegramClient], Awaitable[Any]],
    gather_with_concurrency_func: Callable,
):
    logger.info("Adding event handlers")
    new_message_event = events.NewMessage(incoming=True, outgoing=True)
    client.add_event_handler(
        get_on_new_message(
            sqlalchemy_session_maker=sqlalchemy_session_maker, client=client
        ),
        new_message_event,
    )
    client.add_event_handler(
        get_on_message_deleted(
            client=client,
            sqlalchemy_session_maker=sqlalchemy_session_maker,
            notify_message_deletion=notify_message_deletion,
            notify_unknown_message=notify_unknown_message,
            gather_with_concurrency_func=gather_with_concurrency_func,
        ),
        events.MessageDeleted(),
    )
    client.add_event_handler(
        get_on_message_edited(
            client=client,
            sqlalchemy_session_maker=sqlalchemy_session_maker,
            notify_message_edit=notify_message_edit,
            gather_with_concurrency_func=gather_with_concurrency_func,
        ),
        events.MessageEdited(),
    )
    logger.info("Added event handlers")

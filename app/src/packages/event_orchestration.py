"""Event handlers and message storage orchestration."""

import asyncio
import copy
import logging
import os
from collections.abc import Awaitable, Callable
from distutils.util import strtobool
from typing import Any

import sqlalchemy
import sqlalchemy.exc
import telethon
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.selectable import Select
from telethon import TelegramClient, events
from telethon.events import MessageDeleted, MessageEdited, NewMessage
from tenacity import retry, retry_if_exception_type, stop_after_attempt

from packages.filtering import raw_should_ignore_message_chat
from packages.message_loading import load_messages_by_parameters, load_messages_from_db
from packages.models.root.TelegramMessage import TelegramMessage
from packages.restart_manager import update_last_activity
from packages.telegram_helpers import (
    build_telegram_peer,
    get_canonical_message_text,
    get_message_media_metadata,
)

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
                        if query is not None
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
        try:
            effective_level = logger.getEffectiveLevel()
            if effective_level <= 5:
                logger.log(5, f"on_new_message: {event}")
            else:
                logger.debug("in on_new_message")
            message: telethon.tl.custom.message.Message = event.message
            await store_message_if_not_exists(message)
            await update_last_activity()
        except Exception as e:
            logger.error(
                f"Error in on_new_message handler: {e}",
                exc_info=True,
            )

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

    store_message_for_edit = get_store_message(sqlalchemy_session_maker, client)

    @retry(
        retry=retry_if_exception_type((IOError, sqlalchemy.exc.DBAPIError)),
        stop=stop_after_attempt(3),
    )
    async def on_message_edited(event: MessageEdited.Event):
        try:
            message_id = None
            if event.message is not None:
                message_id = event.message.id
            elif hasattr(event, "message_id") and event.message_id is not None:
                message_id = event.message_id
            else:
                logger.debug("Got empty message in edited event. Returning early!")
                return

            edited_messages_count = 1

            if edited_messages_count == 0:
                logger.debug("Got empty edited message event. Returning early!")
                return

            chat = None
            try:
                input_chat = await event.get_input_chat()
                chat = await client.get_entity(input_chat) if input_chat else None
            except ValueError:
                pass

            with sqlalchemy_session_maker.begin() as sqlalchemy_session:
                (
                    messages,
                    query,
                    unloaded_ids,
                    filtered_away_ids,
                ) = await load_messages_by_parameters(
                    [message_id],
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
                            if query is not None
                            else "(no query)",
                        )
                    )
                    if event.message is not None:
                        msg_text = get_canonical_message_text(event.message)
                        if msg_text:
                            logger.log(
                                5, f"Edited message text (not found in DB): {msg_text}"
                            )
                except Exception as e:
                    logger.error(
                        f"Error while logging missing edited message (has {db_messages_count_str} of {edited_messages_count_str}, with {filtered_away_messages_count_str} filtered away): {e}",
                        exc_info=True,
                    )

            awaitables: list[Awaitable[Any]] = []
            new_text = (
                get_canonical_message_text(event.message) if event.message else ""
            )

            should_skip_edit_notification = False
            should_skip_edit_storage = False
            original_update = getattr(event, "original_update", None)
            reaction_update_types = (
                telethon.types.UpdateMessageReactions,
                telethon.types.UpdateBotMessageReaction,
                telethon.types.UpdateBotMessageReactions,
            )
            if isinstance(original_update, reaction_update_types):
                logger.debug(
                    "Edit event is a reaction update. Skipping notification and storage."
                )
                should_skip_edit_notification = True
                should_skip_edit_storage = True
            elif messages:
                db_text = messages[0].text or "" if messages else ""
                if db_text == new_text:
                    message_has_media = (
                        getattr(event.message, "media", None) is not None
                    )
                    db_has_media = getattr(messages[0], "media", None) is not None
                    should_store_same_text_edit = message_has_media or db_has_media
                    logger.debug(
                        "Edit event with same canonical text. Skipping notification.%s",
                        (
                            " Still storing because attachment state may have changed."
                            if should_store_same_text_edit
                            else " Skipping storage too because no attachment state changed."
                        ),
                    )
                    should_skip_edit_notification = True
                    should_skip_edit_storage = not should_store_same_text_edit

            if not should_skip_edit_notification:
                for message in messages:
                    old_text = message.text or ""
                    notification_message = copy.copy(message)
                    notification_message.text = new_text
                    notification_message.edit_old_text = old_text
                    awaitables.append(notify_message_edit(notification_message, client))
            if unloaded_ids and len(unloaded_ids):
                pass
            if len(awaitables) > 0:
                await gather_with_concurrency_func(
                    edited_messages_notification_concurrency, *awaitables
                )

            if (
                hasattr(event, "message")
                and event.message
                and not should_skip_edit_storage
            ):
                await store_message_for_edit(event.message, check_chat=True)
        except Exception as e:
            logger.error(
                f"Error in on_message_edited handler: {e}",
                exc_info=True,
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
    message_file = getattr(message, "file", None) if message is not None else None
    message_file_size = getattr(message_file, "size", None)
    if (
        not message
        or not message.media
        or not message_file
        or (
            file_size_threshold > 0
            and message_file_size is not None
            and message_file_size > file_size_threshold
        )
    ):
        return None
    async with download_semaphore:
        logger.info("Downloading file with %s bytes size", message_file_size)
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
        def load_previous_latest_message(sqlalchemy_session):
            if built_chat_peer is None:
                return None
            return sqlalchemy_session.execute(
                select(TelegramMessage)
                .where(TelegramMessage.id == message.id)
                .where(TelegramMessage.chat_peer_id == built_chat_peer.id)
                .order_by(TelegramMessage.edit_date.desc())
                .limit(1)
            ).scalar()

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
        media_file_name, media_mime_type = get_message_media_metadata(message)

        with sqlalchemy_session_maker.begin() as sqlalchemy_session:
            previous_latest_message = None
            if getattr(message, "media", None):
                previous_latest_message = load_previous_latest_message(
                    sqlalchemy_session
                )

            reusing_previous_media_blob = (
                blob is None and previous_latest_message is not None
            )
            inherited_blob = (
                previous_latest_message.media if reusing_previous_media_blob else blob
            )
            if reusing_previous_media_blob:
                inherited_media_file_name = previous_latest_message.media_file_name
                inherited_media_mime_type = previous_latest_message.media_mime_type
            else:
                inherited_media_file_name = (
                    previous_latest_message.media_file_name
                    if previous_latest_message is not None and media_file_name is None
                    else media_file_name
                )
                inherited_media_mime_type = (
                    previous_latest_message.media_mime_type
                    if previous_latest_message is not None and media_mime_type is None
                    else media_mime_type
                )

            edit_date = getattr(message, "edit_date", None) or message.date
            orm_message = TelegramMessage(
                id=message.id,
                from_peer=built_from_peer,
                chat_peer=built_chat_peer,
                text=message.message,
                media=inherited_blob,
                media_file_name=inherited_media_file_name,
                media_mime_type=inherited_media_mime_type,
                timestamp=message.date,
                edit_date=edit_date,
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
    new_message_event = events.NewMessage()
    new_message_handler = get_on_new_message(
        sqlalchemy_session_maker=sqlalchemy_session_maker, client=client
    )
    logger.info(
        f"Registering NewMessage handler: {new_message_handler}, event: {new_message_event}"
    )
    client.add_event_handler(
        new_message_handler,
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

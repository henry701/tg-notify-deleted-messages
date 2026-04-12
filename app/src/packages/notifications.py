from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy.orm import sessionmaker
from telethon import TelegramClient
from telethon.events.messagedeleted import MessageDeleted

from packages.models.root.TelegramMessage import TelegramMessage
from packages.telegram_helpers import (
    build_peer_entity,
    format_default_message_batch_texts,
    format_default_message_edit_text,
    format_default_unknown_message_text,
    get_mention_text as get_entity_mention_text,
    send_stored_messages_with_optional_media,
    send_stored_message_with_optional_media,
)


def get_base_notify_message_deletion(
    sqlalchemy_session_maker: sessionmaker,
) -> Callable[[TelegramMessage, TelegramClient], Awaitable[Any]]:
    async def base_notify_message_deletion(
        message: TelegramMessage, client: TelegramClient
    ):
        raw_album_messages = getattr(message, "album_messages", None)
        album_messages = (
            raw_album_messages
            if isinstance(raw_album_messages, list) and len(raw_album_messages) > 0
            else [message]
        )
        with sqlalchemy_session_maker.begin() as session:
            for stored_message in album_messages:
                session.merge(stored_message)
                stored_message.deleted = True  # type: ignore

    return base_notify_message_deletion


def get_default_notify_message_deletion() -> Callable[
    [TelegramMessage, TelegramClient], Awaitable[Any]
]:
    async def default_notify_message_deletion(
        message: TelegramMessage, client: TelegramClient
    ):
        raw_album_messages = getattr(message, "album_messages", None)
        album_messages = (
            raw_album_messages
            if isinstance(raw_album_messages, list) and len(raw_album_messages) > 0
            else [message]
        )
        await send_stored_messages_with_optional_media(
            sender_client=client,
            entity="me",
            formatted_texts=await format_default_message_batch_texts(
                client, album_messages
            ),
            messages=album_messages,
        )

    return default_notify_message_deletion


def get_default_notify_unknown_message() -> Callable[
    [list[int], MessageDeleted.Event, TelegramClient], Awaitable[Any]
]:
    async def default_notify_unknown_message(
        message_ids: list[int], event: MessageDeleted.Event, client: TelegramClient
    ):
        await client.send_message(
            entity="me",
            message=await format_default_unknown_message_text(
                client, message_ids, event
            ),  # type: ignore
        )

    return default_notify_unknown_message


def get_base_notify_message_edit(
    sqlalchemy_session_maker: sessionmaker,
) -> Callable[[TelegramMessage, TelegramClient], Awaitable[Any]]:
    async def base_notify_message_edit(
        message: TelegramMessage, client: TelegramClient
    ):
        return None

    return base_notify_message_edit


def get_default_notify_message_edit() -> Callable[
    [TelegramMessage, TelegramClient], Awaitable[Any]
]:
    async def default_notify_message_edit(
        message: TelegramMessage, client: TelegramClient
    ):
        await send_stored_message_with_optional_media(
            sender_client=client,
            entity="me",
            formatted_text=await format_default_message_edit_text(client, message),
            message=message,
        )

    return default_notify_message_edit


async def get_mention_text(client: TelegramClient, peer):
    if not peer:
        return "Unknown"
    try:
        entity = await build_peer_entity(peer, client)
        if entity is None:
            entity = await client.get_entity(
                peer.to_telethon_input_peer()
                if hasattr(peer, "to_telethon_input_peer")
                else peer
            )
        mention_text = await get_entity_mention_text(entity)
        return str(mention_text) if mention_text is not None else "Unknown"
    except Exception:
        return "Unknown"

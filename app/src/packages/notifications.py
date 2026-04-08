from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy.orm import sessionmaker
from telethon import TelegramClient
from telethon.events.messagedeleted import MessageDeleted

from packages.models.root.TelegramMessage import TelegramMessage
from packages.telegram_helpers import (
    format_default_message_edit_text,
    format_default_message_text,
    format_default_unknown_message_text,
)


def get_base_notify_message_deletion(
    sqlalchemy_session_maker: sessionmaker,
) -> Callable[[TelegramMessage, TelegramClient], Awaitable[Any]]:
    async def base_notify_message_deletion(
        message: TelegramMessage, client: TelegramClient
    ):
        with sqlalchemy_session_maker.begin() as session:
            session.merge(message)
            message.deleted = True  # type: ignore

    return base_notify_message_deletion


def get_default_notify_message_deletion() -> Callable[
    [TelegramMessage, TelegramClient], Awaitable[Any]
]:
    async def default_notify_message_deletion(
        message: TelegramMessage, client: TelegramClient
    ):
        await client.send_message(
            entity="me",
            message=await format_default_message_text(client, message),  # type: ignore
            file=message.media,  # type: ignore
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
        await client.send_message(
            entity="me",
            message=await format_default_message_edit_text(client, message),
            file=message.media,  # type: ignore
        )

    return default_notify_message_edit


async def get_mention_text(client: TelegramClient, peer):
    if not peer:
        return "Unknown"
    try:
        entity = await client.get_entity(
            peer.to_telethon_input_peer()
            if hasattr(peer, "to_telethon_input_peer")
            else peer
        )
        if getattr(entity, "title", None):
            return entity.title
        elif getattr(entity, "first_name", None) or getattr(entity, "last_name", None):
            return (
                (getattr(entity, "first_name", "") + " ")
                if getattr(entity, "first_name", "")
                else ""
            ) + (
                getattr(entity, "last_name", "")
                if getattr(entity, "last_name", "")
                else ""
            )
        elif getattr(entity, "username", None):
            return entity.username
        elif getattr(entity, "phone", None):
            return entity.phone
        else:
            return str(getattr(entity, "id", "Unknown"))
    except Exception:
        return "Unknown"
